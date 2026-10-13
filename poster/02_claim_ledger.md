# Claim Ledger - Poster 08

> Verified code snapshot: `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d`; successful CI run `36783662812`, 2026-09-30.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 165 tests pass | VERIFIED_AT_SNAPSHOT | Cited snapshot Python 3.12 CI. |
| 2 | 63.83% statement coverage | VERIFIED_AT_SNAPSHOT | Cited snapshot Python 3.12 CI. |
| 3 | 113 test functions across 11 files | VERIFIED_AT_SNAPSHOT | Current README/test tree; parametrized execution yields 165 tests. |
| 4 | 22 revoked IDs, 29 total remaps, 46 new-technique map entries | VERIFIED_AT_SNAPSHOT | Current migration map / README / changelog evidence. |
| 5 | SHA-256 verification of downloaded ATT&CK data | VERIFIED_AT_SNAPSHOT | Download validation path and CI. |
| 6 | Indexed in-memory lookup by id/tactic/platform/keyword | VERIFIED_AT_SNAPSHOT | Current index implementation. |
| 7 | ATT&CK mapping proves observed compromise | UNSUPPORTED | Taxonomy normalization is not occurrence evidence. |

The old poster's 108-test-function figure has been replaced by the current 113-function / 165-executed-test evidence.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
