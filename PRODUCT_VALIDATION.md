# Product Validation

## Product boundary
Versioned MITRE ATT&CK v19 data/lookup compatibility layer for downstream detection tooling.

## Real-world validation ladder
1. Pinned local ATT&CK data structure tests.
2. Official upstream STIX validation against MITRE's published Enterprise ATT&CK bundle.
3. Revoked/deprecated technique remapping regression tests.
4. Downstream contract tests with attack-detection-engine and other consumers.
5. Release block if upstream structure changes cannot be reconciled deterministically.

## Evidence rules
This library does not detect attacks. "Coverage" means data-model/content coverage only.
