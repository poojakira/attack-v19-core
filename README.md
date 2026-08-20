# attack-v19-core

Python package providing typed data models for MITRE ATT&CK v19. Parses STIX bundles and exposes a lookup API for techniques, tactics, and sub-techniques. Handles v19 breaking changes (renamed tactics, revoked techniques, new additions) so downstream repos can use a stable interface.

## What It Provides

- Pydantic models for ATT&CK techniques, tactics, and sub-techniques
- STIX bundle loader with local caching
- Technique lookup by ID with automatic v18→v19 remapping via `V19_REVOCATION_MAP`
- Matrix builder for Enterprise (15 tactics, 222 techniques, 475 sub-techniques), Mobile, and ICS
- CLI for downloading and validating ATT&CK data

## Install

```bash
pip install -r requirements.txt
python -m attack_core download  # fetches STIX bundles
```

## Usage

```python
from attack_v19_core import AttackDatabase

db = AttackDatabase()
t = db.get_technique("T1059.006")  # Python/scripting
print(t.name, t.tactic)
```

## Why v19 Matters

ATT&CK v19 renamed TA0005 ("Defense Evasion" → "Stealth"), added TA0112 ("Defense Impairment"), revoked 12 techniques, and added 48 new ones. Code hardcoding v18 IDs produces wrong mappings. This package handles the translation.

## Structure

```
attack_v19_core/   - Package source (models, loader, matrix, mapping)
attack_core/       - CLI interface and download logic
scripts/           - Data download helper
tests/             - Unit and integration tests
```

## Status

Functional library used by other repos in this portfolio (`import attack_v19_core`). Tests pass against downloaded STIX data.

## License

MIT
