# Claim Ledger — Poster 08 (08-attack-v19-core)

> Evidence status: This is a dated repository snapshot at the commit identified below. `VERIFIED_AT_SNAPSHOT` means verified for that commit and environment; it does not assert the same result on the latest `main`. Compare newer claims with the repository evidence before reuse.

MIT • Python 3.12 • HEAD 734c633 • verified 2026-09-26. Classification: VERIFIED_AT_SNAPSHOT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 108 test functions across suite | VERIFIED_AT_SNAPSHOT | Counted def test_ in tests/ (HEAD 734c633). |
| 2 | v19: 22 revoked IDs, 29 total remaps, 48 new techniques | VERIFIED_AT_SNAPSHOT | README/CHANGELOG; V19_REVOCATION_MAP resolves deprecated IDs. |
| 3 | SHA-256 verification of downloaded STIX bundles | VERIFIED_AT_SNAPSHOT | README + download.py description. |
| 4 | O(1) in-memory indexes (id/tactic/platform/keyword) | VERIFIED_AT_SNAPSHOT | README architecture + index.py. |
| 5 | ATT&CK mapping proves an attack occurred | UNSUPPORTED (disclaimed) | README-consistent scope; poster states mapping != occurrence. |

## Policy applied
- Only VERIFIED_AT_SNAPSHOT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
