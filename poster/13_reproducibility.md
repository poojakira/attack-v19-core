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

Expected cited-snapshot evidence:

- **165 passed**
- **63.83% statement coverage**
- **113 test functions across 11 files**


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
