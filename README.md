> ℹ️ **UTILITY LIBRARY — Typed Pydantic models + v19 revocation map around [mitreattack-python](https://github.com/mitre-attack/mitreattack-python). The delta over using mitreattack-python directly is the V19_REVOCATION_MAP (13 remapped IDs) and typed Navigator layer generation. Used internally by other portfolio repos.**

---
# attack-v19-core

[![Demo Dashboard (static)](https://img.shields.io/badge/Demo_Dashboard-Static-lightgrey)](https://poojakira.github.io/attack-v19-core/)

A Python library that provides typed data models and lookup utilities for MITRE ATT&CK v19 techniques across Enterprise, Mobile, and ICS domains.

It parses ATT&CK STIX bundles into Pydantic v2 models, lets you search/filter techniques, and handles the 13 revoked technique IDs from v19 by automatically remapping them to their replacements.

## Numbers

- 222 Enterprise techniques, 475 sub-techniques
- 15 Enterprise tactics (including the v19 additions: TA0005 "Stealth" and TA0112 "Defense Impairment")
- 13 revoked technique IDs auto-remapped via `V19_REVOCATION_MAP` (this count covers all IDs in the map, including both true revocations and identity mappings for ICS techniques that received new sub-techniques)
- 46 new technique/sub-technique IDs added in v19 (23 Enterprise + 23 ICS)

## Installation

### Prerequisites
- Python 3.10 or newer
- pip (comes with Python)
- ATT&CK STIX bundle JSON files (downloaded automatically via included script)
- Dependencies: mitreattack-python, pydantic, stix2, networkx, pandas (installed automatically)

### Install from PyPI

```powershell
# Windows PowerShell
py -m pip install attack-v19-core
```

```bash
# Linux / Mac
pip install attack-v19-core
```

### Install from source (with dev dependencies)

```powershell
# Windows PowerShell
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
py -m pip install -e ".[dev]"
```

```bash
# Linux / Mac
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
pip install -e ".[dev]"
```

### Download ATT&CK data files

The library needs ATT&CK STIX bundles. Download them with the included script:

```powershell
# Windows PowerShell
py scripts/download_attack_data.py
# Downloads to ~/attack_data/enterprise-attack.json, mobile-attack.json, ics-attack.json
```

```bash
# Linux / Mac
python scripts/download_attack_data.py
```

Or download manually to `~/attack_data/`:
```
~/attack_data/enterprise-attack.json
~/attack_data/mobile-attack.json
~/attack_data/ics-attack.json
```

### Verify installation

```powershell
# Windows PowerShell
py -c "from attack_core import ATTACKLoader, ATTACKIndex; from attack_core.constants import V19_REVOCATION_MAP; print(f'OK - {len(V19_REVOCATION_MAP)} revocations mapped')"
```

```bash
# Linux / Mac
python -c "from attack_core import ATTACKLoader, ATTACKIndex; from attack_core.constants import V19_REVOCATION_MAP; print(f'OK - {len(V19_REVOCATION_MAP)} revocations mapped')"
```

### Run tests

```powershell
# Windows PowerShell
py -m pytest tests/ -v
# Expected: all tests passed
```

```bash
# Linux / Mac
pytest tests/ -v
# Expected: all tests passed
```

### Common issues

| Problem | Fix |
|---------|-----|
| `py` not recognized (Windows) | Use `python` instead, or install Python from python.org and ensure it's on PATH |
| `FileNotFoundError: enterprise-attack.json` | Run `py scripts/download_attack_data.py` to download ATT&CK STIX bundles |
| `ModuleNotFoundError: No module named 'mitreattack'` | Run `py -m pip install mitreattack-python==3.0.3` |
| Permission denied on install | Use a virtual environment: `py -m venv .venv && .venv\Scripts\activate` |
| `pydantic` validation errors | Ensure pydantic v2: `py -m pip install pydantic>=2.7` |
| Tests fail on network timeout | The download script requires internet access to fetch STIX bundles from MITRE's GitHub |

## Usage

```python
from attack_core import ATTACKLoader, ATTACKIndex, Domain
from attack_core.constants import V19_REVOCATION_MAP

loader = ATTACKLoader()
index = ATTACKIndex(loader)

# Look up a technique by ID
technique = index.get("T1059")
print(technique.name)

# Revoked IDs are automatically remapped
technique = index.get("T1562")  # Returns T1685 (the replacement)

# Search by keyword
results = index.search("credential dumping")
for r in results:
    print(f"{r.attack_id}: {r.name}")

# Filter by tactic
stealth_techniques = index.by_tactic("TA0005")
defense_impairment = index.by_tactic("TA0112")

# Filter by platform
windows_techniques = index.by_platform("Windows")

# Check counts
assert index.count_techniques(Domain.ENTERPRISE) == 222
assert index.count_subtechniques(Domain.ENTERPRISE) == 475
```

### Generating ATT&CK Navigator layers

```python
from attack_core.matrix import ATTACKMatrix

matrix = ATTACKMatrix()
# Generate Navigator v4.9-compatible JSON layer from your detection mappings
layer_json = matrix.generate("my_detector", mappings)
```

### Revocation map

If you need to manually check whether a technique ID was revoked:

```python
from attack_core.constants import V19_REVOCATION_MAP

# Returns the replacement ID, or None if not revoked
replacement = V19_REVOCATION_MAP.get("T1562.001")  # → "T1685"
```

## API Reference

### Classes

| Class | Purpose |
|-------|---------|
| `ATTACKLoader` | Loads and parses STIX bundles from disk |
| `ATTACKIndex` | Indexes loaded data for lookup/search/filter |
| `ATTACKMatrix` | Generates ATT&CK Navigator layer JSON |
| `ATTACKMappingBuilder` | Builds mapping objects linking detections to techniques |
| `MappingResolution` | Resolution status for technique mappings |

### Models (Pydantic v2)

| Model | Description |
|-------|-------------|
| `Tactic` | ATT&CK tactic (TA0001-TA0112) |
| `Technique` | Base technique (Txxxx) |
| `SubTechnique` | Sub-technique (Txxxx.xxx) |
| `Group` | Threat group (Gxxxx) |
| `Software` | Malware or tool (Sxxxx) |
| `Mitigation` | Mitigation (Mxxxx) |
| `DataSource` | Data source (DSxxxx) |
| `ATTACKMapping` | Links a detection to one or more techniques |
| `Domain` | Enum: ENTERPRISE, MOBILE, ICS |

### Constants

- `ENTERPRISE_TACTICS` - ordered list of Enterprise tactic IDs
- `V19_REVOCATION_MAP` - dict mapping 13 revoked IDs to their replacements
- `PLATFORMS_ENTERPRISE`, `PLATFORMS_MOBILE`, `PLATFORMS_ICS` - valid platform strings

## v19 Breaking Changes

If you are migrating from v18, the main things to know:

- "Defense Evasion" (TA0005) was renamed to "Stealth"
- A new tactic "Defense Impairment" (TA0112) was split out from the old TA0005
- **13 technique IDs were revoked and are auto-remapped.** This count covers all entries in `V19_REVOCATION_MAP`—it includes both true revocations (e.g. T1562→T1685) and identity mappings for ICS techniques that received new sub-techniques. The library remaps all 13 transparently.
- 46 new technique/sub-technique IDs were added (T1682-T1695 range, plus ICS sub-techniques)

See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for details.

## Development

```bash
make install    # Install dependencies
make test       # Run tests (pytest)
make lint       # Run ruff linter
make format     # Auto-format with ruff
make verify     # Run all checks (lint + test + build)
```

## License

MIT
