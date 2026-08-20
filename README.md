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
from attack_v19_core import AttackDatabase

db = AttackDatabase()

# Technique lookup by ID
t = db.get_technique("T1059.006")
print(t.name, t.tactic)  # "Python/Scripting", "Execution"

# v18→v19 remapping (revoked techniques resolve to successors)
t = db.get_technique("T1064")  # revoked in v19
print(t.name)  # maps to replacement technique

# Matrix enumeration
for tactic in db.enterprise_matrix():
    print(tactic.name, len(tactic.techniques))
```

## Key Modules

```
attack_v19_core/
  models.py       Pydantic models: Technique, Tactic, SubTechnique
  loader.py       STIX bundle parser with local caching
  matrix.py       Matrix builder (Enterprise/Mobile/ICS)
  mapping.py      V19_REVOCATION_MAP + v18→v19 remapping logic
  index.py        Fast lookup index by ID/name
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
