# Reproduce the Work - Poster 08

**Repository:** `github.com/poojakira/attack-v19-core`  
**Verified code snapshot:** `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d`  
**CI run:** `36783662812`

```bash
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
git checkout 22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d
python -m pip install -e ".[dev]"
pytest tests/ -q --cov=attack_v19_core --cov-report=term
```

Expected current-main evidence:

- **165 passed**
- **63.83% statement coverage**
- **113 test functions across 11 files**
