# attack-v19-core

Python package for MITRE ATT&CK v19 data models. Enterprise (15 tactics, 222 techniques, 475 sub-techniques), Mobile, ICS. Handles v19 breaking changes so downstream repos don't have to.

[![CI](https://github.com/poojakira/attack-v19-core/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/attack-v19-core/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MIT](https://img.shields.io/badge/license-MIT-green)

## Why It Exists

ATT&CK v19 (July 2026) renamed TA0005 ("Defense Evasion" → "Stealth"), added TA0112 ("Defense Impairment"), revoked 12 techniques, and added 48 new ones. Any tool hardcoding v18 IDs silently produces wrong mappings. This package ingests STIX bundles and provides a typed lookup API with auto-remapping through `V19_REVOCATION_MAP`.

Other repos in this portfolio (`import attack_v19_core`) use it as their ATT&CK backend.

## Install

```bash
pip install -r requirements.txt
# Requires STIX bundles in ~/attack_data/
```

## Usage

```python
from attack_v19_core import AttackDatabase
db = AttackDatabase()
t = db.get_technique("T1059.006")  # Python scripting interpreter
```

See `MIGRATION_GUIDE.md` for v18 → v19 migration.

## License

MIT.
