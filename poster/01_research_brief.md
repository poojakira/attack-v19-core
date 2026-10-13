# Research Brief - Poster 08

> Evidence status: Refreshed against verified code snapshot `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d` and successful CI run `36783662812` on 2026-09-30.

## Repository

`github.com/poojakira/attack-v19-core` - public, default branch `main`.

## Academic Project Title

**Version-Aware Normalization of Findings Against MITRE ATT&CK v19**

### Subtitle

Typed Data Models and Revocation-Resolving Technique Lookup for Security Tooling

## One-Sentence Contribution

A typed ATT&CK v19 data layer that normalizes findings across version churn by resolving revoked/renamed technique IDs through a maintained remap table over SHA-256-verified STIX data, with indexed lookup for downstream security tooling.

## Method

1. Download/validate ATT&CK STIX data with SHA-256 verification.
2. Parse techniques/tactics/platform metadata into typed structures.
3. Resolve deprecated/revoked IDs through the v19 remap table.
4. Build in-memory indexes for ID, tactic, platform, and keyword lookup.
5. Regression-test migration and data-loader behavior across supported Python versions.

## Verified Evidence at Cited Snapshot

Cited snapshot Python 3.12 CI reports:

- **165 tests passed**.
- **63.83% statement coverage**; CI gate is 60%.
- **113 test functions across 11 test files**; parametrization expands these to 165 executed tests.
- Current repository mapping evidence retains:
  - **22 mapped release-revocation IDs**
  - **29 total remaps**
  - **46 unique entries** in the repository new-technique migration table (release-wide total not independently verified)
- Type checking, lint, dependency/security scanning, data download verification, and performance benchmark jobs succeeded.

## Claim Boundary

- ATT&CK mapping/normalization does not prove an attack occurred.
- O(1) dictionary/index lookup describes the in-memory data structure, not end-to-end system latency.
- Future ATT&CK releases require new migration/remap evidence.

## Reproducibility

```bash
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
git checkout 22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d
python -m pip install -e ".[dev]"
pytest tests/ -q --cov=attack_v19_core --cov-report=term
```

Expected cited CI evidence: **165 passed**, **63.83% coverage**.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
