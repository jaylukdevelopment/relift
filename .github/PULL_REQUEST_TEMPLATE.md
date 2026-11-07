## What changed

<!-- One paragraph. Link the issue if there is one. -->

## Safety checklist

- [ ] The scope gate still runs before any traffic; no new path connects to a
      host outside an authorised scope.
- [ ] No destructive behaviour, credential guessing, wordlist or shell
      interpolation was added.
- [ ] Credentials and target data stay out of logs, artefacts and tests.
- [ ] New techniques are in `catalog.py` first, with a risk tier and families.

## Verification

<!-- Commands you ran and what they printed. "CI will tell me" is not a result. -->

```bash
pytest -q
ruff check src tests packaging
```

## Docs

- [ ] `docs/02-ATTACK-CATALOG.md` updated for a new technique.
- [ ] `docs/06-CLI-REFERENCE.md` updated for a new command or flag.
- [ ] `CHANGELOG.md` updated when behaviour changes.
