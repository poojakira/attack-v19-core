# Migration Guide: ATT&CK v18 to v19.2

This guide covers taxonomy and data changes used by this library. It does not prescribe detections or claim coverage.

Primary sources, retrieved 2026-08-10:

- https://attack.mitre.org/resources/updates/updates-april-2026/
- https://attack.mitre.org/resources/updates/updates-august-2026/

## 1. Pin the data release

Install this repository from a reviewed commit and run the verified downloader:

```bash
uv sync --locked --extra dev
uv run python scripts/download_attack_data.py
```

`attack-v19-core` is not published on PyPI. Do not add a package-index dependency until a signed, verifiable release channel exists.

## 2. Update tactic names

- Display TA0005 as `Stealth`.
- Add TA0112 as `Defense Impairment`.
- Do not treat a tactic name change as evidence that a detection rule covers the tactic.

## 3. Resolve revoked technique IDs

Use the exact release map when migrating v18 data:

```python
from attack_core.constants import V19_RELEASE_REVOCATION_MAP

resolved = V19_RELEASE_REVOCATION_MAP.get(source_id, source_id)
```

Use `V19_REVOCATION_MAP` only when selected older aliases must also be accepted. The broader compatibility map is finite and not a complete history of every ATT&CK revocation.

Representative v19 changes:

| Previous ID | v19 replacement |
|---|---|
| `T1562` | `T1685` |
| `T1562.003` | `T1690` |
| `T1562.004` | `T1686` |
| `T1562.009` | `T1688` |
| `T1656` | `T1684.001` |
| `T1672` | `T1684.002` |
| `T0803` | `T1691.001` |
| `T0855` | `T1692.001` |

The complete reviewed set is `V19_RELEASE_REVOCATION_MAP` and is checked by `tests/test_official_validation.py`.

## 4. Normalize sub-technique syntax

ATT&CK external IDs use dot notation, for example `T1683.001`. The library accepts slash notation at its lookup boundary and normalizes it:

```python
assert index.resolve_attack_id("T1683/001") == "T1683.001"
```

Store and emit canonical dot notation in new data.

## 5. Rebuild Navigator exports

```python
from attack_core.mapping import ATTACKMappingBuilder
from attack_core.matrix import NavigatorLayerReporter

builder = ATTACKMappingBuilder(index)
mappings = builder.build_many(source_ids, confidence=caller_supplied_confidence)
layer_json = NavigatorLayerReporter().generate("consumer-name", mappings)
```

Review every mapping. The library carries caller-supplied confidence into the export; it does not measure detection quality.

## 6. Validate the consumer

1. Run this library's suite against the pinned v19.2 bundles.
2. Run the consumer's unit and integration suites.
3. Compare pre-migration and post-migration mapping outputs.
4. Investigate dropped, duplicated, or tactic-changed mappings.
5. Retain the old commit, lock file, and bundle hashes for rollback.

## Rollback

Restore the prior library commit, dependency lock, and matching ATT&CK bundles as one unit. Do not mix an older mapping implementation with newer unreviewed bundle data.
