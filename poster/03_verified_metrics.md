# Verified Metrics — Poster 08

> Evidence status: This is a dated repository snapshot at the commit identified below. `VERIFIED_AT_SNAPSHOT` means verified for that commit and environment; it does not assert the same result on the latest `main`. Compare newer claims with the repository evidence before reuse.

MIT • Python 3.12 • HEAD 734c633 • verified 2026-09-26. Verified for this poster on Windows / CPython 3.12.10.

## Headline cards
- 108 — TEST FUNCTIONS
- O(1) — LOOKUP
Notes: 108 test_ functions across the suite (HEAD 734c633). In-memory indexes by id/tactic/platform/keyword.

## Verified surface
| Item | Value |
|---|---|
| Revoked technique IDs | 22 |
| Total remaps | 29 |
| New techniques | 48 |

## Chart values
| Series | Value |
|---|---|
| New techniques (48) | 62 |
| Total remaps (29) | 37 |
| Revoked IDs (22) | 28 |
Note: ATT&CK v19 change counts from README/CHANGELOG. Bars scaled to the largest category.

## Historical / provenance
STIX bundles are SHA-256 verified on download. attack_core is a deprecated shim (DeprecationWarning); attack_v19_core is canonical.

## Not established by this repository
That any mapped finding reflects a real attack. Detection logic correctness (this is a data layer).
