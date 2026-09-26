# Claim Ledger — Poster 08 (08-attack-v19-core)

MIT • Python 3.12 • HEAD 756bf03 • verified 2026-09-26. Classification: VERIFIED_CURRENT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 108 test functions across suite | VERIFIED_CURRENT | Counted def test_ in tests/ (HEAD 756bf03). |
| 2 | v19: 22 revoked IDs, 29 total remaps, 48 new techniques | VERIFIED_CURRENT | README/CHANGELOG; V19_REVOCATION_MAP resolves deprecated IDs. |
| 3 | SHA-256 verification of downloaded STIX bundles | VERIFIED_CURRENT | README + download.py description. |
| 4 | O(1) in-memory indexes (id/tactic/platform/keyword) | VERIFIED_CURRENT | README architecture + index.py. |
| 5 | ATT&CK mapping proves an attack occurred | UNSUPPORTED (disclaimed) | README-consistent scope; poster states mapping != occurrence. |

## Policy applied
- Only VERIFIED_CURRENT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
