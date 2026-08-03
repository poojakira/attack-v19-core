# Runbook

## What this is

`attack-v19-core` is the shared ATT&CK v19 data model library. Other repos in this project depend on it.

## Build and test locally

```bash
make install    # Install dependencies into venv
make lint       # Ruff linter
make format     # Ruff auto-format
make test       # pytest (52 tests as of last check)
make build      # Build wheel
make security   # Run security scan (bandit, pip-audit)
make verify     # All of the above in sequence
```

## Data files

The library downloads pinned MITRE ATT&CK v19.1 STIX bundles. Downloads are verified with SHA-256 checksums.

Run `python scripts/download_attack_data.py` to fetch them.

## Dashboard

There's a static HTML dashboard at `dashboard/index.html`. Serve it locally with `make dashboard`. It's for visual inspection only — not a test artifact.

## Things to check before pushing

- Tests pass locally (`make test`)
- Linter is clean (`make lint`)
- Wheel builds without errors (`make build`)
- CI will also run on Linux (GitHub Actions), so avoid Windows-only path assumptions

## Limitations

- Local dashboard scores are informational, not a certification of anything.
- Don't claim this is production-ready without current CI passing, dependency audit, and runtime smoke tests.
