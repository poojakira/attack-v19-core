# Migration Guide: ATT&CK v18 -> v19

This guide helps downstream consumers migrate from ATT&CK v18 to v19.

## Breaking Changes Summary

| Category | v18 | v19 | Action Required |
|----------|-----|-----|-----------------|
| Tactic TA0005 | "Defense Evasion" | "Stealth" | Update display names, dashboards |
| New Tactic | N/A | TA0112 "Defense Impairment" | Add to tactic lists, Navigator layers |
| 17 Techniques | Active | Revoked | Remap rule tables (see table below) |
| 48 Techniques | N/A | New | Add to rule tables, detection coverage |

## Step 1: Update Tactic References

### Code Changes
```python
# OLD (v18)
TACTICS = ["TA0001", "TA0002", ..., "TA0005", ...]  # TA0005 = "Defense Evasion"

# NEW (v19)
TACTICS = ["TA0001", "TA0002", ..., "TA0005", "TA0112", ...]  # TA0005 = "Stealth", TA0112 = "Defense Impairment"
```

### Display Name Updates
- Any UI showing "Defense Evasion" -> Change to "Stealth"
- Add "Defense Impairment" to tactic dropdowns, filters, legends

### Navigator Layers
```json
// OLD layer (v4.5)
{
  "versions": {"attack": "18", "navigator": "4.8", "layer": "4.4"},
  "techniques": [{"techniqueID": "T1059", "tactic": "TA0002", ...}]
}

// NEW layer (v4.9) - REQUIRES tactic field per technique
{
  "versions": {"attack": "19", "navigator": "4.9", "layer": "4.5"},
  "techniques": [{"techniqueID": "T1059", "tactic": "TA0002", "score": 80, ...}]
}
```

Use the new `NavigatorLayerReporter` in `attack_core.matrix`:
```python
from attack_core.matrix import NavigatorLayerReporter
from attack_core.models import ATTACKMapping, Domain

reporter = NavigatorLayerReporter()
layer_json = reporter.generate("my_repo", mappings_list)
```

## Step 2: Remap Revoked Technique IDs

The `V19_REVOCATION_MAP` in `attack_core.constants` provides automatic remapping:

```python
from attack_core.constants import V19_REVOCATION_MAP

# Auto-remap any technique ID
def remap_technique_id(old_id: str) -> str:
    return V19_REVOCATION_MAP.get(old_id, old_id)

# Example mappings
assert remap_technique_id("T1562") == "T1685"
assert remap_technique_id("T1562.001") == "T1685"
assert remap_technique_id("T1070.001") == "T1685.005"
assert remap_technique_id("T1534") == "T1684.001"
```

### Rule Table Migration (Required)

| Old Rule Entry | New Rule Entry |
|----------------|----------------|
| `"T1562"`, `"T1562.001"` | `"T1685"` |
| `"T1562.002"` | `"T1685.001"` |
| `"T1562.006"` | `"T1685.003"` |
| `"T1089"` | `"T1685"` |
| `"T1070.001"` | `"T1685.005"` |
| `"T1070.002"` | `"T1685.006"` |
| `"T1054"` | `"T1685"` |
| `"T1534"` | `"T1684.001"` |
| `"T1566.003"` | `"T1684.002"` |

**In enricher rule tables:**
```python
# BEFORE (v18)
"defender_tampering": ["T1562", "T1562.001", "T1089"],
"log_clearing": ["T1070.001", "T1070.002"],

# AFTER (v19)
"defender_tampering": ["T1685", "T1685.001", "T1685.003", "T1687"],
"log_clearing": ["T1685.005", "T1685.006"],
```

## Step 3: Add New Technique Coverage

### Priority New Techniques (AI/ML Security)

| ID | Name | Relevance |
|----|------|-----------|
| T1682 | Query Public AI Services | CRITICAL - LAMEHUG malware uses this |
| T1683/001 | Generate Content: Written | HIGH - Phishing content generation |
| T1683/002 | Generate Content: Audio-Visual | HIGH - Deepfake generation |
| T1684/001 | Social Engineering: Impersonation | HIGH - BEC, spearphishing |
| T1684/002 | Social Engineering: Email Spoofing | HIGH - DMARC failures |
| T1685 | Disable or Modify Tools | CRITICAL - Replaces T1562 |
| T1687 | Exploitation for Defense Impairment | HIGH - New tactic technique |
| T1689 | Downgrade Attack | MEDIUM - TLS/SSL downgrades |
| T1027/018 | Invisible Unicode | MEDIUM - Code obfuscation |

### ICS-Specific New Sub-techniques

| Parent | New Sub-techniques |
|--------|-------------------|
| T1691 | /001 Command Message, /002 Reporting Message |
| T1692 | /001 Command Message, /002 Reporting Message |
| T1693 | /001 System Firmware, /002 Module Firmware |
| T1694 | /001 Default Credentials, /002 Hardcoded Credentials |
| T1695 | /001 Serial COM, /002 Ethernet, /003 Wi-Fi |
| T0843 | /001 Download All, /002 Online Edit, /003 Program Append |
| T0873 | /001 Siemens Project File Format |
| T0846 | /001 Port Scan, /002 Broadcast Discovery, /003 Multicast Discovery |

### Example: Adding T1682 Detection

```python
# In your enricher rule table
"llm_api_calls": ["T1682", "T1059.006"],

# In detection patterns (attack-detection-engine style)
{
    "rule_id": "ATK-V19-T1682-001",
    "technique_ids": ["T1682"],
    "conditions": [
        {"type": "message_contains", "keywords": ["api.openai.com", "api.anthropic.com"]},
        {"type": "field_regex", "field": "process_name", "pattern": r"(python|node|curl|wget)"}
    ]
}
```

## Step 4: Update Dependency

### Released dependency

Use the v19 package version in project metadata when your package index provides it:

```toml
[project]
dependencies = [
    "attack-v19-core>=19.1.0",
]
```

For a fully pinned release, use the same version as this repository's
`pyproject.toml`:

```toml
dependencies = [
    "attack-v19-core==19.1.0",
]
```

### Local sibling checkout

For development, install the local core checkout instead of relying on a
network download. These commands assume the consumer repository and
`attack-v19-core` are sibling directories.

```powershell
# Run from the consumer repository root.
py -m pip install -e ..\attack-v19-core
```

```bash
# Run from the consumer repository root.
python -m pip install -e ../attack-v19-core
```

## Step 5: Run Migration Tests

### 1. Validate the core package

Run this from the `attack-v19-core` repository root:

```powershell
py -m pip install -e ".[dev]"
py -m pytest -c pyproject.toml tests/test_v19_structure.py -v
```

```bash
python -m pip install -e ".[dev]"
python -m pytest -c pyproject.toml tests/test_v19_structure.py -v
```

### 2. Validate a consumer repository

Not every consumer repository has the same test layout. If the repository
contains `tests/test_attack_mapping.py`, run it from that repository root:

```powershell
py -m pytest -c pyproject.toml tests/test_attack_mapping.py -v
```

```bash
python -m pytest -c pyproject.toml tests/test_attack_mapping.py -v
```

If that file is absent, run the test command documented by that repository's
README or runbook instead of copying this command blindly.

### 3. Confirm the revocation map is available

```powershell
py -c "from attack_core.constants import V19_REVOCATION_MAP; print(f'Revocation mappings: {len(V19_REVOCATION_MAP)}')"
```

This confirms the shared mapping is installed. Checking whether a consumer's
rule table still contains revoked IDs is consumer-specific; use that
repository's mapping test or rule-table test for the final check.

## Step 6: Verify Dashboard/Alert Updates

- [ ] Tactic "Defense Evasion" renamed to "Stealth" in all dashboards
- [ ] New tactic "Defense Impairment" (TA0112) appears in tactic filters
- [ ] Alerts referencing T1562/T1562.001/T1070.001 now show T1685/T1685.005
- [ ] Navigator layers regenerated with v19 format (attack: "19", navigator: "4.9")
- [ ] New technique IDs (T1682, T1683, T1684, T1685, T1689) have coverage indicators

## Step 7: Update Documentation

- [ ] README.md: Update technique ID examples
- [ ] Architecture docs: Update tactic diagrams
- [ ] Runbook: Update technique references in response procedures

## Rollback Plan

If issues arise:
1. Restore the last known compatible `attack-v19-core` version recorded in your lockfile or release manifest.
2. Revert rule table changes.
3. Regenerate Navigator layers with the prior ATT&CK format.
4. Report issues to upstream.

## Support

- Check `CHANGELOG.md` for full change list
- Run `pytest tests/test_v19_structure.py` to validate v19 compliance
- See `attack_core.constants.V19_REVOCATION_MAP` for complete remapping