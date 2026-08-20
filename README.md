# attack-v19-core

Python library providing typed data models and lookup API for MITRE ATT&CK v19. Parses STIX bundles into Pydantic models, handles v18→v19 technique revocations/renames, and exposes a stable interface for downstream security tools.

## Why This Exists

ATT&CK v19 introduced breaking changes: renamed TA0005 ("Defense Evasion" → "Stealth"), added TA0112 ("Defense Impairment"), revoked 12 techniques, and added 48 new ones. Code hardcoding v18 IDs produces incorrect mappings. This library absorbs the churn.

## Coverage

| Matrix     | Tactics | Techniques | Sub-techniques |
|------------|---------|------------|----------------|
| Enterprise | 15      | 222        | 475            |
| Mobile     | ✓       | ✓          | ✓              |
| ICS        | ✓       | ✓          | ✓              |

## Install

```bash
pip install -r requirements.txt
python -m attack_core download   # fetches STIX bundles from MITRE, caches locally
```

## Usage

```python
from attack_v19_core import ATTACKLoader, ATTACKIndex
from attack_v19_core.models import Domain

loader = ATTACKLoader()

# Enumerate the Enterprise matrix
techniques = loader.get_techniques(Domain.ENTERPRISE)
tactics = loader.get_tactics(Domain.ENTERPRISE)
print(len(techniques), "techniques across", len(tactics), "tactics")

# Fast lookup by ID or name
index = ATTACKIndex(loader)
t = index.get("T1059")
print(t.name)  # "Command and Scripting Interpreter"
```

## Key Modules

```
attack_v19_core/
  models.py       Domain enum + models: Technique, Tactic, SubTechnique
  loader.py       ATTACKLoader: STIX bundle parser with local caching
  matrix.py       ATTACKMatrix builder (Enterprise/Mobile/ICS)
  mapping.py      ATTACKMappingBuilder + NavigatorLayerReporter
  constants.py    V19_REVOCATION_MAP (revoked technique IDs)
  index.py        ATTACKIndex: fast lookup by ID/name
  constants.py    Tactic IDs, technique counts, version metadata
attack_core/
  cli.py          CLI: download, validate, query
  download.py     STIX bundle fetcher
```

## Tests

104 test functions across 10 test files:
- Unit tests for models, loader, matrix, mapping, index
- Integration tests validating against official STIX data
- CLI tests
- v19 structure validation (tactic counts, revocation correctness)

```bash
make test        # pytest tests/ -q
make lint        # ruff check
```

## Used By

Imported as `attack_v19_core` by other repos in this portfolio (unified-ml-security-platform, adversarial-ml-lab, mcp-agent-security-gateway).

## License

MIT
