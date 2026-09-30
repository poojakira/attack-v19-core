# Research Brief - Poster 08

> Evidence status: Refreshed against current code snapshot `22cc9ee3e08406a446bf500f84ea1d8fb53a6a6d` and successful CI run `36783662812` on 2026-09-30.

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

## Current Verified Evidence

Current-main Python 3.12 CI reports:

- **165 tests passed**.
- **63.83% statement coverage**; CI gate is 60%.
- **113 test functions across 11 test files**; parametrization expands these to 165 executed tests.
- Current repository mapping evidence retains:
  - **22 revoked technique IDs**
  - **29 total remaps**
  - **48 new techniques** for the documented v19 migration surface
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

Expected current CI evidence: **165 passed**, **63.83% coverage**.
