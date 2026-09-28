# Research Brief — Poster 08

## Repository
`github.com/poojakira/attack-v19-core` (public, default branch `main`, primary language Python). MIT • Python 3.12 • HEAD 734c633 • verified 2026-09-26

## Academic Project Title
**Version-Aware Normalization of Findings Against MITRE ATT&CK v19**

### Subtitle
Typed Data Models and Revocation-Resolving Technique Lookup for Security Tooling

## One-Sentence Contribution
A typed ATT&CK v19 data layer that transparently resolves revoked/renamed technique IDs (22 revocations, 29 total remaps) via a revocation map over SHA-256-verified STIX bundles, giving security tooling stable O(1) lookup that survives version churn.

## Problem Statement
ATT&CK v19 revoked 22 technique IDs, renamed a tactic, added TA0112, and introduced 48 techniques. A SIEM rule referencing T1562 now points at a dead ID (replaced by T1685) — the coverage dashboard shows green while a whole tactic is unmonitored. Detection tooling needs to absorb this churn safely.

## Threat Model
Chain: STALE FINDING ID -> VERSION CHANGE -> SILENT COVERAGE GAP -> NORMALIZATION BOUNDARY -> V19 REPRESENTATION.
Adversary capability: n/a — correctness risk, not an active attacker; Assumptions: official STIX bundles; SHA-256 verified; Out of scope: proving an attack occurred; detection logic itself; Residual risk: mapping ≠ evidence of compromise.

## Research / Engineering Question
> Can security tooling keep mapping findings to ATT&CK across version churn when technique IDs are revoked, renamed, or remapped?

## Objective
Determine whether typed models + a revocation map can resolve deprecated ATT&CK IDs to v19 and give O(1) lookup for tooling.

## Engineering Sub-Objectives
O1 — Pydantic models per object type
O2 — Revocation map v18→v19
O3 — O(1) indexes (id/tactic/platform)
O4 — SHA-256-verified STIX download

## Methodology
1 Download (STIX) -> 2 Verify (SHA-256) -> 3 Parse (Pydantic) -> 4 Remap (revocations) -> 5 Index (O(1)) -> 6·7 Query (CLI/layer)

## Current Verified Evidence + Claim Ledger
- **VERIFIED_CURRENT** — 108 test functions across suite — Counted def test_ in tests/ (HEAD 734c633).
- **VERIFIED_CURRENT** — v19: 22 revoked IDs, 29 total remaps, 48 new techniques — README/CHANGELOG; V19_REVOCATION_MAP resolves deprecated IDs.
- **VERIFIED_CURRENT** — SHA-256 verification of downloaded STIX bundles — README + download.py description.
- **VERIFIED_CURRENT** — O(1) in-memory indexes (id/tactic/platform/keyword) — README architecture + index.py.
- **UNSUPPORTED (disclaimed)** — ATT&CK mapping proves an attack occurred — README-consistent scope; poster states mapping != occurrence.

## Important Negative / Honest Results
See RESULTS panel: ATT&CK v19 change counts from README/CHANGELOG. Bars scaled to the largest category.

## Limitations
1. A data/normalization layer, not a detector.
2. ATT&CK mapping does not prove an attack occurred.
3. Depends on official STIX bundle availability.
4. Deprecated attack_core shim still present (v20 removal).
5. Coverage of future versions needs map updates.

## Future Work
• Automated v19→v20 revocation-map generation.
• Remove deprecated attack_core shim.
• TAXII live-sync mode.
• Confidence-scored mapping heuristics.
• Broader ecosystem adapter integration.

## Reproducibility
```
pytest tests/
python -m attack_core lookup T1685
```
Evidence: CHANGELOG.md, MIGRATION_GUIDE.md, tests/

## References
[1] MITRE ATT&CK v19 · [2] OASIS STIX 2.1 · [3] MITRE ATT&CK Navigator · [4] Pydantic · [5] MITRE ATT&CK Versioning · [6] NIST AI RMF 1.0
