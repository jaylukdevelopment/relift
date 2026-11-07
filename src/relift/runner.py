"""Planning and execution — the only part that touches the target."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from . import catalog
from . import chains as chain_engine
from .audit import AuditLog
from .models import (
    SEVERITY_RANK,
    Execution,
    Finding,
    Risk,
    RunRecord,
    Target,
    utcnow,
)
from .modules import MODULES, MissingInput, MissingTool, ScanContext, tool_path
from .scope import Scope


@dataclass
class Plan:
    """An ordered, allowed subset of the catalogue for one target."""

    target: Target
    profile: str
    ceiling: Risk
    specs: list[Any] = field(default_factory=list)
    note: str = ""
    analyst: str = "offline"
    notes: list[str] = field(default_factory=list)

    @property
    def ids(self) -> list[str]:
        return [spec.id for spec in self.specs]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "profile": self.profile,
            "ceiling": self.ceiling.value,
            "analyst": self.analyst,
            "note": self.note,
            "notes": list(self.notes),
            "techniques": [spec.to_dict() for spec in self.specs],
        }


def make_plan(
    target: Target,
    scope: Scope,
    profile_name: str,
    analyst: Any = None,
) -> Plan:
    """Build the plan: profile ∩ scope ceiling, optionally reordered by the analyst."""
    profile = catalog.PROFILES.get(profile_name)
    if profile is None:
        raise ValueError(
            f"unknown profile {profile_name!r}; choose from {', '.join(catalog.PROFILES)}"
        )

    ceiling = scope.risk_ceiling(profile.max_risk)
    specs = catalog.select(
        profile_name, max_risk=ceiling, families=target.families
    )
    # A plan is what will actually run: design-only entries stay in 'list' but
    # never appear here; the narrative is written at render time and the chain
    # analysis runs over whatever the modules found.
    specs = [
        spec
        for spec in specs
        if spec.implemented and spec.category not in ("report", "analysis")
    ]

    note = ""
    if analyst is not None:
        order, note = analyst.order_plan(target, profile_name, specs)
        by_id = {spec.id: spec for spec in specs}
        specs = [by_id[item] for item in order if item in by_id]

    return Plan(
        target=target,
        profile=profile_name,
        ceiling=ceiling,
        specs=specs,
        note=note,
        analyst=getattr(analyst, "label", "offline"),
        notes=list(getattr(analyst, "notes", []) or []),
    )


def execute(plan: Plan, ctx: ScanContext, audit: AuditLog | None = None) -> RunRecord:
    """Run the plan. A broken module never aborts the run."""
    record = RunRecord(
        target=plan.target,
        profile=plan.profile,
        provider=plan.analyst,
        engagement=ctx.scope.engagement,
        scope_sha256=ctx.scope.digest,
        authorized_by=ctx.scope.authorized_by,
    )

    for spec in plan.specs:
        module = MODULES.get(spec.id)
        if module is None:
            record.executions.append(
                Execution(
                    attack_id=spec.id,
                    status="skipped",
                    reason="design-only: no module in this build",
                )
            )
            continue

        missing = [binary for binary in spec.requires if not tool_path(binary)]
        if missing:
            record.executions.append(
                Execution(
                    attack_id=spec.id,
                    status="skipped",
                    reason="missing tool: " + ", ".join(missing),
                )
            )
            continue

        started_at = utcnow()
        began = time.monotonic()
        findings: list[Finding] = []
        status, error = "ok", ""
        try:
            findings = module.run(ctx) or []
        except MissingTool as exc:
            status, error = "skipped", f"missing tool: {exc}"
        except MissingInput as exc:
            status, error = "skipped", f"needs input: {exc}"
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad module must not kill the run
            status, error = "error", f"{type(exc).__name__}: {exc}"

        elapsed = int((time.monotonic() - began) * 1000)
        record.executions.append(
            Execution(
                attack_id=spec.id,
                status=status,
                started=started_at,
                finished=utcnow(),
                duration_ms=elapsed,
                error=error,
                finding_count=len(findings),
                command=[],
            )
        )
        record.findings.extend(findings)

        if audit is not None:
            audit.event(
                "module",
                run_id=record.run_id,
                attack_id=spec.id,
                status=status,
                findings=len(findings),
                duration_ms=elapsed,
            )

    record.finished = utcnow()
    record.findings = dedupe(record.findings)
    record.chains = chain_engine.analyse([item.to_dict() for item in record.findings])

    if audit is not None:
        audit.event(
            "chains",
            run_id=record.run_id,
            chains=[chain.id for chain in record.chains],
            worst=record.chains[0].severity.value if record.chains else "none",
        )

    return record


def analyse_record(record: RunRecord) -> list[Any]:
    """Recompute attack threads for a stored run (used by 'relift chains')."""
    return chain_engine.analyse([item.to_dict() for item in record.findings])


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (technique, target, title), worst severity first."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = item.key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    unique.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.attack_id))
    return unique
