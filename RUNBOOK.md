# RUNBOOK — attack-v19-core

## Overview
Python package providing MITRE ATT&CK v19 data models (techniques, tactics, mitigations).

## Install
```bash
pip install -e .
# or from requirements
pip install -r requirements.txt
```

## Import Techniques
```python
from attack_v19_core import techniques

all_techniques = techniques.get_all()
print(f"Loaded {len(all_techniques)} techniques")
```

## Query by ID
```python
from attack_v19_core import techniques

t1059 = techniques.get_by_id("T1059")
print(t1059.name)        # "Command and Scripting Interpreter"
print(t1059.tactics)     # associated tactics
print(t1059.platforms)   # target platforms
```

## Update Data
1. Pull latest ATT&CK STIX data:
   ```bash
   python scripts/update_data.py
   ```
2. Verify integrity:
   ```bash
   python -m pytest tests/
   ```
3. Commit updated data files and bump version if schema changed.

## Troubleshooting
- **ImportError**: Ensure package is installed in editable mode (`pip install -e .`).
- **Stale data**: Re-run `update_data.py` to pull latest from MITRE CTI repo.
- **Test failures after update**: Check for schema changes in upstream STIX bundle.
