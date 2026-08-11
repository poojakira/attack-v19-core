# Operator Runbook

## Supported operating model

`attack-v19-core` is an in-process utility. The operator owns the Python environment, read-only ATT&CK data directory, application logging, and rollback of dependent applications. There is no hosted service or autonomous action path.

Supported runtime: Python 3.11 or 3.12 with dependencies resolved from `uv.lock`.

## Provision

```bash
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
uv sync --locked --extra dev
uv run python scripts/download_attack_data.py
```

The download succeeds only when all official v19.2 bundle hashes match. The default data directory is `~/attack_data`; override it with `ATTACK_DATA_DIR` for runtime use and `--data-dir` for download.

## Pre-deployment verification

```bash
ATTACK_DATA_DIR="$HOME/attack_data" uv run pytest tests -q
uv run ruff check attack_core tests scripts
uv run ruff format --check attack_core tests scripts
uv build
```

Record the Git commit, Python version, `uv.lock` hash, bundle hashes, and complete command output. Do not convert a source-file count into a passing-test claim.

## Runtime smoke test

```bash
ATTACK_DATA_DIR="$HOME/attack_data" uv run attack-v19 lookup T1059
ATTACK_DATA_DIR="$HOME/attack_data" uv run attack-v19 lookup T1562.009
```

Expected behavior:

- `T1059` resolves from the pinned Enterprise bundle.
- `T1562.009` resolves to `T1688` through the reviewed v19 release map.
- Missing or corrupt bundles fail closed with an error; the loader does not download data implicitly.

## Update ATT&CK data

1. Confirm the release on MITRE's version history and official GitHub data repository.
2. Change `ATTACK_STIX_TAG` and all three hashes in `scripts/download_attack_data.py`.
3. Add or update hash tests.
4. Review tactic, technique, sub-technique, and revocation changes.
5. Run the complete verification against freshly downloaded bundles.
6. Update README, migration guide, changelog, and evidence policy.
7. Release only after independent review.

Never bypass a hash mismatch. A mismatch means the configured artifact and downloaded bytes differ.

## Failure response

- Hash mismatch: retain the prior verified bundles; investigate the official release and URL. Do not update hashes from an unverified mirror.
- Missing file: rerun the downloader with network access or restore the prior verified artifact.
- Parse failure: preserve the failing bundle and traceback, compare its hash, and roll back the library or data release as a unit.
- Downstream mapping regression: pin the prior commit and lock file, then reproduce with the same bundle hashes.
- Dirty data directory: replace it from verified artifacts; do not modify STIX JSON in place.

## Rollback

Deploy the prior reviewed Git commit with its matching `uv.lock` and ATT&CK bundle hashes. Re-run smoke tests before restoring traffic in the consuming application. No database migration is involved.

## Monitoring responsibility

The library emits Python exceptions and mapping warnings. The consuming service must route those logs, define alert thresholds, and own its SLOs. This repository makes no availability or latency claim.
