# Reproduce the Work - Poster 08

**Repository:** `github.com/poojakira/attack-v19-core`  
**Historical poster code snapshot (2026-09-30):** `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d`  
**CI run:** `36783662812`

```bash
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
git checkout 22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d
python -m pip install -e ".[dev]"
python scripts/download_attack_data.py
pytest tests/ -q --cov=attack_core --cov=attack_v19_core --cov-report=term
```

Expected evidence for the cited historical poster snapshot:

- **165 passed**
- **63.83% statement coverage**
- **113 test functions across 11 files**

Coverage percentages depend on the selected packages, environment and dependency versions. Match the CI coverage scope before comparing results.

## Later CI checkpoint — 2026-10-14

At code commit `8b2a6508117ad963eaeae15725abc4c491642d3a`, [CI run 38626019410](https://github.com/poojakira/attack-v19-core/actions/runs/38626019410) independently recorded **165 passed, 1 warning / 63.83% statement coverage** on Python 3.12.15. Coverage includes both `attack_core` and `attack_v19_core`. The Python 3.10–3.12 matrix, lint, type checking, security scan and performance benchmark jobs passed. This is a separate dated checkpoint; it does not relabel the poster's September snapshot as current-main evidence.
