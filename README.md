# attack-v19-core

Shared Python utility for loading pinned MITRE ATT&CK v19.2 STIX bundles into Pydantic models, performing domain-aware lookups, applying documented technique remaps, and exporting matrix or Navigator JSON.

This is a supporting library, not a detector, monitoring service, or security control. A technique mapping describes taxonomy context; it does not prove detection coverage or attack prevention.

## Verified scope

- Loads Enterprise, Mobile, and ICS bundles through `mitreattack-python`.
- Pins the official `attack-stix-data` v19.2 bundle URLs and SHA-256 hashes.
- Models tactics, techniques, sub-techniques, groups, software, mitigations, and data sources.
- Normalizes slash-form sub-technique IDs such as `T1683/001` to dot form.
- Exposes the 22 technique revocations listed in MITRE's April 2026 v19 release notes, plus seven explicitly separated legacy compatibility aliases.
- Escapes STIX-controlled text when producing HTML tables.

MITRE reports 15 Enterprise tactics, 222 techniques, and 475 sub-techniques for ATT&CK v19. The August 6, 2026 v19.2 agile release updates Enterprise groups and software without changing those technique counts. Sources retrieved 2026-08-10: [MITRE April 2026 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/) and [MITRE August 2026 v19.2 release notes](https://attack.mitre.org/resources/updates/updates-august-2026/).

## Install from source

Requirements: Python 3.11 or 3.12 and Git. No `attack-v19-core` distribution was found on PyPI when checked on 2026-08-10, so this repository does not document a PyPI install path.

```bash
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Windows PowerShell activation:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
```

For a fully resolved environment, use the committed lock file:

```bash
uv sync --locked --extra dev
```

## Download verified ATT&CK data

```bash
python scripts/download_attack_data.py
```

The downloader streams three official v19.2 bundles into `~/attack_data`, rejects files larger than 128 MiB, and validates each SHA-256 hash before use. Set `ATTACK_DATA_DIR` to use a different directory.

## Use the library

```python
from attack_core import ATTACKIndex, ATTACKLoader, Domain

index = ATTACKIndex(ATTACKLoader())

technique = index.get("T1059", Domain.ENTERPRISE)
assert technique is not None
print(technique.attack_id, technique.name)

replacement = index.resolve_attack_id("T1562.009")
assert replacement == "T1688"

windows = index.by_platform("Windows")
```

Generate a mapping-based Navigator layer:

```python
from attack_core.mapping import ATTACKMappingBuilder
from attack_core.matrix import NavigatorLayerReporter

builder = ATTACKMappingBuilder(index)
mappings = builder.build_many(["T1059", "T1059.001"], confidence=0.8)
layer_json = NavigatorLayerReporter().generate("my-detector", mappings)
```

The confidence value is supplied by the caller. This library does not calculate or validate detection confidence.

## CLI

```bash
attack-v19 lookup T1059
attack-v19 lookup T1683/001 --json
attack-v19 revoked
attack-v19 navigator --domain enterprise --output enterprise-layer.json
```

The `navigator` command exports an unscored technique inventory. It is not a coverage report.

## Verify

```bash
python scripts/download_attack_data.py
python -m pytest tests -q
python -m ruff check attack_core tests scripts
python -m ruff format --check attack_core tests scripts
```

CI repeats data hash verification, linting, full package type checks, tests, locked runtime dependency audit, SAST, and SBOM generation. Test results apply only to the tested commit, Python version, dependency lock, and pinned data bundles.

The wheel contains `attack_core` as the canonical API and `attack_v19_core` as a compatibility namespace. New code should import `attack_core`.

## Operational limits

- Status: **beta supporting component; not production-ready**.
- No authentication, authorization, tenancy, service SLO, telemetry, or incident automation exists because this is an in-process library.
- STIX bundles can contain rich text. HTML export escapes data fields, but JSON consumers must still encode output for their destination.
- The compatibility map is intentionally finite. Unknown or future revoked IDs are not inferred.
- v19.2 data is immutable by hash; upgrading ATT&CK requires a reviewed code and checksum change.
- `ATTACK_DATA_DIR` is trusted operator configuration. Do not point it at untrusted writable locations.

See [RUNBOOK.md](RUNBOOK.md), [SECURITY.md](SECURITY.md), [SECURITY_AUDIT.md](SECURITY_AUDIT.md), and [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md).

## License

MIT. MITRE ATT&CK data remains subject to MITRE's own terms and branding requirements. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
