# Contributing to Relift

Relift is a small codebase with a strict safety model. Contributions are welcome
when they respect that model; a feature that makes the tool easier to point at a
stranger's server will be declined.

## Set up

```bash
git clone https://github.com/jaylukdevelopment/relift
cd relift
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
ruff check src tests packaging
```

Python 3.9 or newer. The runtime is stdlib-only; `dev` adds pytest and ruff,
`desktop` adds pywebview for the window.

## Non-negotiables

1. **The scope gate runs first.** Every new code path that sends traffic must go
   through `ScanContext` and an authorised `Scope`. No helper may take a host and
   "just connect".
2. **No destructive capability.** No writes, deletes, config changes, account
   creation, or payload delivery. Intrusive means "may be logged and may fail an
   assertion", not "may damage".
3. **No credential guessing.** No wordlists, no default-credential lists, no
   retry loops. Credentials come from a file the operator supplies, one attempt
   each.
4. **No shells.** External tools get argument lists, never a string passed to a
   shell, and never a user-controlled flag.
5. **The catalogue comes first.** A technique that is not in
   `src/relift/catalog.py` with a risk tier and families cannot run.
6. **Nothing silently degrades.** Missing tools, missing inputs and skipped
   techniques are reported as skipped with a reason, not swallowed.
7. **Credentials never reach disk.** The audit log and run artefacts are
   redacted; keep it that way.

## Adding a technique

1. Add an `AttackSpec` to `src/relift/catalog.py`: id (`category.name`), name,
   category, risk tier, families, summary, what it produces, MITRE id, and an
   `ai_hint` that explains how to read the result.
2. Implement the module in `src/relift/modules/` and register it in
   `src/relift/modules/__init__.py`. Keep it read-only.
3. Add tests in `tests/` that prove the finding shape and the refusal paths
   (out of scope, missing input, missing tool).
4. Add a row to [`docs/02-ATTACK-CATALOG.md`](docs/02-ATTACK-CATALOG.md). The
   catalogue is the contract; documentation drift is a bug.
5. If the technique needs a new attack thread, extend `src/relift/chains.py`
   with a rule that names the evidence it requires.

## Style

- Type hints on public functions; `from __future__ import annotations` at the top.
- No new runtime dependencies. If you need something, the answer is usually the
  standard library or an existing external-tool wrapper.
- Keep output plain and readable at 80 columns; the report renderer is part of
  the product.
- Comments explain *why*, not *what*. The scope gate and the redaction rules
  deserve the most explanation.

## Commits and pull requests

Small, focused commits with an imperative subject:

```
Add Redis ACL audit to the datastore tier
Fix scope expiry check for naive timestamps
```

A pull request should state what changed, how it was tested, and whether it
touches the scope gate, credentials or the desktop API. CI must be green on
Linux and Windows, Python 3.9 and 3.13. Screenshots help for desktop changes.

## Reporting bugs and vulnerabilities

Bugs go to [Issues](https://github.com/jaylukdevelopment/relift/issues). Security
issues go through [`SECURITY.md`](SECURITY.md), never a public issue.

By contributing you agree that your contribution is licensed under the
repository's [LICENSE](LICENSE).
