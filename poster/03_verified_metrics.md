# Verified Metrics - Poster 08

**Code snapshot:** `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d`  
**CI run:** https://github.com/poojakira/attack-v19-core/actions/runs/36783662812

| Metric | Cited snapshot value |
|---|---:|
| Tests passed | **165** |
| Statement coverage | **63.83%** |
| Test functions | **113** |
| Test files | **11** |
| Revoked technique IDs | **22** |
| Total remaps | **29** |
| Unique entries in repository new-technique map | **46** |

ATT&CK normalization/mapping is taxonomy evidence, not proof that an attack occurred.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
