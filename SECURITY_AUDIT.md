# Security and Readiness Audit

**Reviewed:** 2026-08-10

## Decision

Retain as a supporting open-source utility. Do not present it as a standalone security product or as production-ready.

## Verified changes

- Updated official data from ATT&CK v19.1 to v19.2, released August 6, 2026.
- Computed and pinned SHA-256 hashes for all three official v19.2 raw bundles.
- Added streaming download, a 128 MiB per-file ceiling, temporary-file cleanup, and tests.
- Corrected the v19 release revocation set to 13 Enterprise plus 9 ICS mappings.
- Separated seven older compatibility aliases from the official v19 release set.
- Removed import-time nested pytest execution that prevented normal suite collection.
- Escaped STIX-controlled HTML fields and added a regression test.
- Removed the simulated/static dashboard and unsupported coverage wording.
- Removed a nonexistent PyPI installation path.
- Pinned supported direct dependencies and added a resolved lock file.

## Residual risks

- `mitreattack-python` and its transitive parsing stack process large JSON documents in memory. Resource limits belong to the consuming deployment.
- SHA-256 pinning verifies exact bytes, not semantic correctness or absence of upstream defects.
- CSV output does not neutralize spreadsheet formulas. Treat CSV as data and apply destination-specific controls before opening it in spreadsheet software.
- The legacy compatibility alias set is curated and not exhaustive across all historical ATT&CK releases.
- There is no service authentication, authorization, tenant isolation, rate limiting, observability stack, or SLO because this repository is a library.
- Release signing and publication provenance are not implemented. Source installation from a reviewed commit is the only documented distribution path.

## Evidence

- MITRE ATT&CK April 2026 v19 notes: https://attack.mitre.org/resources/updates/updates-april-2026/
- MITRE ATT&CK August 2026 v19.2 notes: https://attack.mitre.org/resources/updates/updates-august-2026/
- Official data tag: https://github.com/mitre-attack/attack-stix-data/tree/v19.2
- Retrieval date for all sources: 2026-08-10

Readiness remains **beta / not production-ready** until release provenance, broader compatibility testing, and downstream operational validation are complete.
