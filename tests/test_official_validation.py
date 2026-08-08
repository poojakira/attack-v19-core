"""
Validate attack-v19-core constants against official MITRE ATT&CK v19 data.

Reference: https://attack.mitre.org/resources/updates/updates-april-2026/
ATT&CK v19 was released April 28, 2026. Official counts from the release notes:
  - Enterprise: 15 Tactics, 222 Techniques, 475 Sub-Techniques
  - TA0005 renamed from "Defense Evasion" to "Stealth"
  - TA0112 "Defense Impairment" added (split from old TA0005)
  - New Enterprise techniques: T1682-T1690, T1027.018
  - New ICS techniques: T1691-T1695, T0843.001-003, T0873.001, T0846.001-003

This file validates the library's constants against these official facts.
"""

import re

import pytest
from attack_core.constants import (
    ENTERPRISE_SUBTECHNIQUE_COUNT,
    ENTERPRISE_TACTIC_COUNT,
    ENTERPRISE_TACTICS,
    ENTERPRISE_TECHNIQUE_COUNT,
    V19_NEW_TECHNIQUES,
    V19_REVOCATION_MAP,
)

# ---------------------------------------------------------------------------
# Section 1: Tactic ID format validation
# ---------------------------------------------------------------------------


class TestTacticIDFormat:
    """Verify all tactic IDs in ENTERPRISE_TACTICS are valid (TA + 4 digits)."""

    def test_all_tactic_ids_start_with_ta(self):
        for tactic_id, name in ENTERPRISE_TACTICS:
            assert tactic_id.startswith(
                "TA"
            ), f"Tactic ID '{tactic_id}' ({name}) does not start with 'TA'"

    def test_all_tactic_ids_have_valid_format(self):
        pattern = re.compile(r"^TA\d{4}$")
        for tactic_id, name in ENTERPRISE_TACTICS:
            assert pattern.match(
                tactic_id
            ), f"Tactic ID '{tactic_id}' ({name}) does not match TAxxxx format"

    def test_tactic_count_is_15(self):
        """ATT&CK v19 has 15 Enterprise tactics (14 from v11 + TA0112 new)."""
        assert len(ENTERPRISE_TACTICS) == 15
        assert ENTERPRISE_TACTIC_COUNT == 15

    def test_known_tactic_ids_present(self):
        """Verify the 15 official Enterprise tactic IDs are all present."""
        tactic_ids = {t[0] for t in ENTERPRISE_TACTICS}
        expected_ids = {
            "TA0001",  # Initial Access
            "TA0002",  # Execution
            "TA0003",  # Persistence
            "TA0004",  # Privilege Escalation
            "TA0005",  # Stealth (renamed from Defense Evasion in v19)
            "TA0006",  # Credential Access
            "TA0007",  # Discovery
            "TA0008",  # Lateral Movement
            "TA0009",  # Collection
            "TA0010",  # Exfiltration
            "TA0011",  # Command and Control
            "TA0040",  # Impact
            "TA0042",  # Resource Development
            "TA0043",  # Reconnaissance
            "TA0112",  # Defense Impairment (NEW in v19)
        }
        assert (
            tactic_ids == expected_ids
        ), f"Missing: {expected_ids - tactic_ids}, Extra: {tactic_ids - expected_ids}"


# ---------------------------------------------------------------------------
# Section 2: Technique ID format validation
# ---------------------------------------------------------------------------


class TestTechniqueIDFormat:
    """Verify all technique IDs in V19_NEW_TECHNIQUES follow Txxxx or Txxxx.yyy format."""

    TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
    # ICS techniques use T0xxx format
    ICS_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

    def test_all_new_technique_ids_valid_format(self):
        for tech_id in V19_NEW_TECHNIQUES:
            assert self.TECHNIQUE_PATTERN.match(
                tech_id
            ), f"Technique ID '{tech_id}' does not match Txxxx or Txxxx.yyy format"

    def test_all_new_techniques_start_with_t(self):
        for tech_id in V19_NEW_TECHNIQUES:
            assert tech_id.startswith("T"), f"Technique ID '{tech_id}' does not start with 'T'"

    def test_subtechnique_parents_exist(self):
        """Every sub-technique (Txxxx.yyy) should have its parent (Txxxx) in the dict
        OR the parent should be a known pre-existing technique."""
        pre_existing_parents = {
            "T1027",
            "T0843",
            "T0873",
            "T0846",
        }  # Parents that existed before v19
        for tech_id in V19_NEW_TECHNIQUES:
            if "." in tech_id:
                parent_id = tech_id.split(".")[0]
                assert parent_id in V19_NEW_TECHNIQUES or parent_id in pre_existing_parents, (
                    f"Sub-technique '{tech_id}' has no parent '{parent_id}' "
                    f"in V19_NEW_TECHNIQUES or known pre-existing techniques"
                )


# ---------------------------------------------------------------------------
# Section 3: Revocation map integrity
# ---------------------------------------------------------------------------


class TestRevocationMapIntegrity:
    """Verify V19_REVOCATION_MAP is internally consistent."""

    def test_revoked_ids_not_in_new_techniques(self):
        """Old (revoked) IDs should NOT appear in V19_NEW_TECHNIQUES —
        they are being replaced, not added."""
        for old_id in V19_REVOCATION_MAP:
            # Identity mappings (ICS techniques that got sub-techs added) are exceptions
            if V19_REVOCATION_MAP[old_id] == old_id:
                continue
            assert (
                old_id not in V19_NEW_TECHNIQUES
            ), f"Revoked ID '{old_id}' should not appear in V19_NEW_TECHNIQUES"

    def test_replacement_ids_are_resolvable(self):
        """Replacement IDs in V19_REVOCATION_MAP should be present in
        V19_NEW_TECHNIQUES (since they are newly introduced replacements).
        Exception: identity mappings where old == new (technique kept, sub-techs added)."""
        for old_id, new_id in V19_REVOCATION_MAP.items():
            if old_id == new_id:
                # Identity mapping — the technique still exists, sub-techs were added
                continue
            assert new_id in V19_NEW_TECHNIQUES, (
                f"Replacement ID '{new_id}' (for revoked '{old_id}') "
                f"not found in V19_NEW_TECHNIQUES"
            )

    def test_revocation_map_ids_valid_format(self):
        """Both keys and values in revocation map should be valid technique IDs."""
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for old_id, new_id in V19_REVOCATION_MAP.items():
            assert pattern.match(
                old_id
            ), f"Revoked ID '{old_id}' does not match technique ID format"
            assert pattern.match(
                new_id
            ), f"Replacement ID '{new_id}' does not match technique ID format"

    def test_revocation_map_has_expected_count(self):
        """V19_REVOCATION_MAP tracks 13 remapped IDs.
        This includes both true revocations (old→new) and identity mappings
        for ICS techniques that received new sub-techniques."""
        assert (
            len(V19_REVOCATION_MAP) == 13
        ), f"Expected 13 entries in V19_REVOCATION_MAP, got {len(V19_REVOCATION_MAP)}"


# ---------------------------------------------------------------------------
# Section 4: Technique counts cross-check
# ---------------------------------------------------------------------------


class TestTechniqueCounts:
    """Cross-check technique counts against official MITRE v19 release notes.

    Official counts from https://attack.mitre.org/resources/updates/updates-april-2026/:
      Enterprise: 15 Tactics, 222 Techniques, 475 Sub-Techniques

    These are the authoritative numbers from MITRE's own release page.
    """

    def test_enterprise_technique_count_matches_official(self):
        """MITRE v19 release notes state: 222 Enterprise Techniques."""
        assert ENTERPRISE_TECHNIQUE_COUNT == 222, (
            f"Library claims {ENTERPRISE_TECHNIQUE_COUNT} techniques, "
            f"but official MITRE v19 release notes say 222"
        )

    def test_enterprise_subtechnique_count_matches_official(self):
        """MITRE v19 release notes state: 475 Enterprise Sub-Techniques."""
        assert ENTERPRISE_SUBTECHNIQUE_COUNT == 475, (
            f"Library claims {ENTERPRISE_SUBTECHNIQUE_COUNT} sub-techniques, "
            f"but official MITRE v19 release notes say 475"
        )

    def test_enterprise_tactic_count_matches_official(self):
        """MITRE v19 release notes state: 15 Enterprise Tactics."""
        assert ENTERPRISE_TACTIC_COUNT == 15, (
            f"Library claims {ENTERPRISE_TACTIC_COUNT} tactics, "
            f"but official MITRE v19 release notes say 15"
        )

    def test_new_techniques_count(self):
        """V19 added 46 new technique/sub-technique IDs per the official release notes.
        (23 Enterprise + 23 ICS, including new sub-techniques for existing ICS parents.)"""
        assert len(V19_NEW_TECHNIQUES) == 46, (
            f"Expected 46 new techniques in V19_NEW_TECHNIQUES, " f"got {len(V19_NEW_TECHNIQUES)}"
        )


# ---------------------------------------------------------------------------
# Section 5: Validate specific well-known technique IDs
# ---------------------------------------------------------------------------


class TestSpecificTechniqueIDs:
    """Validate that specific well-known technique IDs from STIX bundles
    are NOT in the new or revoked sets (they are pre-existing)."""

    def test_t1059_command_scripting_interpreter_is_preexisting(self):
        """T1059 (Command and Scripting Interpreter) has existed since ATT&CK v1.
        It should NOT appear in V19_NEW_TECHNIQUES (it's not new)."""
        assert (
            "T1059" not in V19_NEW_TECHNIQUES
        ), "T1059 is a pre-existing technique, should not be in V19_NEW_TECHNIQUES"

    def test_t1059_001_powershell_is_subtechnique_of_t1059(self):
        """T1059.001 (PowerShell) is a sub-technique of T1059.
        Verify the ID format confirms parent relationship."""
        parent = "T1059.001".split(".")[0]
        assert parent == "T1059", "T1059.001 parent should be T1059"
        # T1059.001 should not be in new techniques (it existed before v19)
        assert "T1059.001" not in V19_NEW_TECHNIQUES

    def test_t1195_supply_chain_compromise_is_preexisting(self):
        """T1195 (Supply Chain Compromise) has existed since ATT&CK v1."""
        assert (
            "T1195" not in V19_NEW_TECHNIQUES
        ), "T1195 is a pre-existing technique, should not be in V19_NEW_TECHNIQUES"
        assert "T1195" not in V19_REVOCATION_MAP, "T1195 was not revoked in v19"

    def test_t1190_exploit_public_facing_application_is_preexisting(self):
        """T1190 (Exploit Public-Facing Application) has existed since ATT&CK v1."""
        assert (
            "T1190" not in V19_NEW_TECHNIQUES
        ), "T1190 is a pre-existing technique, should not be in V19_NEW_TECHNIQUES"
        assert "T1190" not in V19_REVOCATION_MAP, "T1190 was not revoked in v19"


# ---------------------------------------------------------------------------
# Section 6: Tactic rename validation
# ---------------------------------------------------------------------------


class TestTacticRename:
    """Verify the TA0005 rename from 'Defense Evasion' to 'Stealth'.

    Confirmed by official MITRE ATT&CK v19 release notes (April 28, 2026):
    https://attack.mitre.org/resources/updates/updates-april-2026/
    'The biggest changes in ATT&CK v19 are the split of the Defense Evasion
    Tactic in Enterprise ATT&CK into the Stealth and Defense Impairment Tactics'

    NOTE: This rename is REAL and officially published by MITRE. Previous
    ATT&CK versions (v16 and earlier) used 'Defense Evasion' for TA0005.
    The v19 release (April 2026) renamed it to 'Stealth' and split out
    'Defense Impairment' as TA0112.
    """

    def test_ta0005_is_stealth(self):
        """TA0005 should be named 'Stealth' in v19 constants."""
        tactic_map = {tid: name for tid, name in ENTERPRISE_TACTICS}
        assert (
            tactic_map["TA0005"] == "Stealth"
        ), f"TA0005 should be 'Stealth' in v19, got '{tactic_map.get('TA0005')}'"

    def test_defense_evasion_not_present(self):
        """'Defense Evasion' was retired in v19 — should not appear as a tactic name."""
        tactic_names = [name for _, name in ENTERPRISE_TACTICS]
        assert (
            "Defense Evasion" not in tactic_names
        ), "'Defense Evasion' should not appear in v19 ENTERPRISE_TACTICS"

    def test_ta0112_is_defense_impairment(self):
        """TA0112 'Defense Impairment' is the new tactic split from old TA0005."""
        tactic_map = {tid: name for tid, name in ENTERPRISE_TACTICS}
        assert "TA0112" in tactic_map, "TA0112 should exist in ENTERPRISE_TACTICS"
        assert (
            tactic_map["TA0112"] == "Defense Impairment"
        ), f"TA0112 should be 'Defense Impairment', got '{tactic_map.get('TA0112')}'"


# ---------------------------------------------------------------------------
# Section 7: V19 new technique spot-checks against official release notes
# ---------------------------------------------------------------------------


class TestOfficialNewTechniques:
    """Spot-check specific new techniques confirmed in the official v19 release notes.

    These technique IDs and names are directly from:
    https://attack.mitre.org/resources/updates/updates-april-2026/#new-techniques
    """

    @pytest.mark.parametrize(
        "tech_id,expected_name_fragment",
        [
            ("T1682", "Query Public AI Services"),
            ("T1683", "Generate Content"),
            ("T1683.001", "Written Content"),
            ("T1683.002", "Audio-Visual Content"),
            ("T1684", "Social Engineering"),
            ("T1684.001", "Impersonation"),
            ("T1684.002", "Email Spoofing"),
            ("T1685", "Disable or Modify Tools"),
            ("T1685.001", "Disable or Modify Windows Event Log"),
            ("T1685.002", "Disable or Modify Cloud Log"),
            ("T1685.003", "Modify or Spoof Tool UI"),
            ("T1685.004", "Disable or Modify Linux Audit System Log"),
            ("T1685.005", "Clear Windows Event Logs"),
            ("T1685.006", "Clear Linux or Mac System Logs"),
            ("T1686", "Disable or Modify System Firewall"),
            ("T1686.001", "Cloud Firewall"),
            ("T1686.002", "Network Device Firewall"),
            ("T1686.003", "Windows Host Firewall"),
            ("T1687", "Exploitation for Defense Impairment"),
            ("T1688", "Safe Mode Boot"),
            ("T1689", "Downgrade Attack"),
            ("T1690", "Prevent Command History Logging"),
            ("T1027.018", "Invisible Unicode"),
        ],
    )
    def test_enterprise_new_technique_present(self, tech_id, expected_name_fragment):
        """Each officially documented new Enterprise technique must be in V19_NEW_TECHNIQUES."""
        assert (
            tech_id in V19_NEW_TECHNIQUES
        ), f"Official v19 technique '{tech_id}' missing from V19_NEW_TECHNIQUES"
        assert expected_name_fragment in V19_NEW_TECHNIQUES[tech_id], (
            f"Technique '{tech_id}' name should contain '{expected_name_fragment}', "
            f"got '{V19_NEW_TECHNIQUES[tech_id]}'"
        )

    @pytest.mark.parametrize(
        "tech_id,expected_name_fragment",
        [
            ("T1691", "Block Operational Technology Message"),
            ("T1691.001", "Command Message"),
            ("T1691.002", "Reporting Message"),
            ("T1692", "Unauthorized Message"),
            ("T1693", "Modify Firmware"),
            ("T1693.001", "System Firmware"),
            ("T1693.002", "Module Firmware"),
            ("T1694", "Insecure Credentials"),
            ("T1694.001", "Default Credentials"),
            ("T1694.002", "Hardcoded Credentials"),
            ("T1695", "Block Communications"),
            ("T1695.001", "Serial COM"),
            ("T1695.002", "Ethernet"),
            ("T1695.003", "Wi-Fi"),
            ("T0843.001", "Program Download"),
            ("T0843.002", "Program Download"),
            ("T0843.003", "Program Download"),
            ("T0873.001", "Project File Infection"),
            ("T0846.001", "Remote System Discovery"),
            ("T0846.002", "Remote System Discovery"),
            ("T0846.003", "Remote System Discovery"),
        ],
    )
    def test_ics_new_technique_present(self, tech_id, expected_name_fragment):
        """Each officially documented new ICS technique must be in V19_NEW_TECHNIQUES."""
        assert (
            tech_id in V19_NEW_TECHNIQUES
        ), f"Official v19 ICS technique '{tech_id}' missing from V19_NEW_TECHNIQUES"
        assert expected_name_fragment in V19_NEW_TECHNIQUES[tech_id], (
            f"ICS technique '{tech_id}' name should contain '{expected_name_fragment}', "
            f"got '{V19_NEW_TECHNIQUES[tech_id]}'"
        )


# ---------------------------------------------------------------------------
# Section 8: Data integrity — no duplicates, no empty values
# ---------------------------------------------------------------------------


class TestDataIntegrity:
    """Basic data integrity checks on constants."""

    def test_no_duplicate_tactic_ids(self):
        tactic_ids = [t[0] for t in ENTERPRISE_TACTICS]
        assert len(tactic_ids) == len(set(tactic_ids)), "Duplicate tactic IDs found"

    def test_no_duplicate_tactic_names(self):
        tactic_names = [t[1] for t in ENTERPRISE_TACTICS]
        assert len(tactic_names) == len(set(tactic_names)), "Duplicate tactic names found"

    def test_no_empty_technique_names(self):
        for tech_id, name in V19_NEW_TECHNIQUES.items():
            assert name.strip(), f"Empty name for technique '{tech_id}'"

    def test_no_empty_revocation_values(self):
        for old_id, new_id in V19_REVOCATION_MAP.items():
            assert new_id.strip(), f"Empty replacement for revoked '{old_id}'"
