# Changelog - attack-v19-core

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-22

### Changed - ATT&CK v19 Migration (BREAKING)

#### Tactic Structure Changes
- **TA0005 renamed**: "Defense Evasion" -> "Stealth" (same ID, new name)
- **TA0112 added**: "Defense Impairment" (new tactic, split from old TA0005)
- Enterprise tactic count remains 15, but composition changed

#### Technique Revocations (17 mappings in V19_REVOCATION_MAP)
| Old ID | New ID | Notes |
|--------|--------|-------|
| T1562 | T1685 | Impair Defenses -> Disable or Modify Tools |
| T1562.001 | T1685 | Sub-technique collapsed to parent |
| T1562.002 | T1685.001 | Disable Windows Event Logging |
| T1562.006 | T1685.002 | Indicator Blocking -> Modify or Spoof Tool UI |
| T1089 | T1685 | Disable Security Tools (legacy) |
| T1070.001 | T1685.005 | Clear Windows Event Logs |
| T1070.002 | T1685.006 | Clear Linux/Mac Logs |
| T1054 | T1685 | Indicator Blocking (legacy) |
| T1534 | T1684.001 | Internal Spearphishing -> Social Engineering: Impersonation |
| T1566.003 | T1684.002 | Email Spoofing -> Social Engineering: Email Spoofing |

#### New v19 Techniques (48 IDs)
**Enterprise (12 parent + 13 sub-techniques):**
- T1682: Query Public AI Services
- T1683: Generate Content (T1683/001 Written, T1683/002 Audio-Visual)
- T1684: Social Engineering (T1684/001 Impersonation, T1684/002 Email Spoofing)
- T1685: Disable or Modify Tools (6 sub-techniques: /001-/006)
- T1686: Disable or Modify System Firewall (3 sub-techniques)
- T1687: Exploitation for Defense Impairment
- T1688: Safe Mode Boot
- T1689: Downgrade Attack
- T1690: Prevent Command History Logging
- T1027/018: Obfuscated Files: Invisible Unicode

**ICS (5 parent + 13 sub-techniques):**
- T1691: Block OT Message (2 sub-techniques)
- T1692: Unauthorized Message (2 sub-techniques)
- T1693: Modify Firmware (2 sub-techniques)
- T1694: Insecure Credentials (2 sub-techniques)
- T1695: Block Communications (3 sub-techniques)
- T0843/001-003: Program Download sub-techniques
- T0873/001: Project File Infection: Siemens
- T0846/001-003: Remote System Discovery sub-techniques

#### CTI Additions
- **Campaigns**: C0062 (AI-orchestrated), C0063 (Poland Wiper), C0060 (AkaiRyu), C0061 (Digital Eye)
- **Software**: S9035 (LAMEHUG), S9010 (GlassWorm), S9008 (Shai-Hulud), S9038 (DynoWiper), S9039 (LazyWiper), S9030 (SameCoin)

### Added
- `NavigatorLayerReporter` class generating ATT&CK Navigator v4.9 layers with TA0112 support
- `V19_REVOCATION_MAP` constant for automatic technique ID remapping
- `V19_NEW_TECHNIQUES` constant with all 48 new technique IDs and names
- `V19_NEW_SOFTWARE` and `V19_NEW_CAMPAIGNS` CTI tracking constants
- Comprehensive test suite in `tests/test_v19_structure.py` (8 tests)

### Fixed
- Null guard in `_build_mapping()` with automatic revocation remapping and warning logs
- Navigator layer output includes `tactic` field per technique (required for v19 multi-tactic techniques)

### Migration Guide for Consumers
See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for step-by-step migration instructions.

## [0.1.0] - 2026-07-21
- Initial MITRE ATT&CK v19 data models