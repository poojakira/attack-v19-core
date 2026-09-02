# RUNBOOK  --  attack-v19-core

## Overview
Python package providing MITRE ATT&CK v19 data models (techniques, tactics, mitigations).

## Install
```bash
pip install -e .
# or from requirements
pip install -r requirements.txt
```

## Download STIX Data (required before first use)
```bash
python -m attack_core.download
# or using the helper script:
python scripts/download_attack_data.py
# re-download / refresh even if cached:
python -m attack_core.download --force
```
This fetches the real MITRE ATT&CK **v19.2** STIX bundles (Enterprise, Mobile,
ICS; ~60-80 MB total) from MITRE's SHA-256-pinned `v19.2` tag on
`raw.githubusercontent.com` and caches them in `~/attack_data/`. Each bundle's
SHA-256 is pinned in `attack_core/download.py`; a mismatch aborts and deletes
the file. Downloads are size-capped (128 MB), HTTPS + host-allowlisted, and
every HTTP redirect target is re-validated before it is followed. After hash
verification each file is checked to be a well-formed STIX 2.x bundle.

> Note: `attack_core` is a deprecated compatibility shim that still hosts the
> CLI and downloader; importing it emits a `DeprecationWarning`. Library code
> should import from `attack_v19_core`. See `MIGRATION_GUIDE.md`.

## CLI Commands

**Look up a technique by ID:**
```bash
python -m attack_core lookup T1059
python -m attack_core lookup T1059.001 --json
```

**List all v19 revocations and legacy remaps:**
```bash
python -m attack_core revoked
```

**Generate an ATT&CK Navigator layer:**
```bash
python -m attack_core navigator --output layer.json
python -m attack_core navigator --domain mobile --output mobile_layer.json
python -m attack_core navigator --name "My Org" --domain enterprise
```

## Python API Quick Start
```python
from attack_core import ATTACKLoader, ATTACKIndex
from attack_core.models import Domain

loader = ATTACKLoader()
techniques = loader.get_techniques(Domain.ENTERPRISE)
print(f"Loaded {len(techniques)} techniques")

index = ATTACKIndex(loader)
t1059 = index.get("T1059")
print(t1059.name)        # "Command and Scripting Interpreter"
print(t1059.tactic_ids)  # associated tactic IDs
```

## Running Tests
```bash
python -m pytest tests/
```

## Troubleshooting
- **ImportError**: Ensure package is installed in editable mode (`pip install -e .`).
- **FileNotFoundError on load**: Run `python -m attack_core.download` to fetch STIX bundles.
- **Test failures after update**: Check for schema changes in upstream STIX bundle.
