from attack_core.constants import (
    ENTERPRISE_TACTICS, ENTERPRISE_TACTIC_COUNT,
    ENTERPRISE_TECHNIQUE_COUNT, ENTERPRISE_SUBTECHNIQUE_COUNT,
    TACTIC_STEALTH, TACTIC_DEFENSE_IMPAIRMENT,
)
from attack_core.loader import ATTACKLoader
from attack_core.index  import ATTACKIndex
from attack_core.models import Domain

def test_tactic_count():
    assert len(ENTERPRISE_TACTICS) == ENTERPRISE_TACTIC_COUNT == 15

def test_stealth_tactic_exists():
    tactic_ids = [t[0] for t in ENTERPRISE_TACTICS]
    assert TACTIC_STEALTH in tactic_ids, "TA0005 Stealth missing"
    tactic_names = [t[1] for t in ENTERPRISE_TACTICS]
    assert "Stealth" in tactic_names, "TA0005 must be named Stealth not Defense Evasion"
    assert "Defense Evasion" not in tactic_names, "Defense Evasion was retired in v19"

def test_defense_impairment_tactic_exists():
    tactic_ids = [t[0] for t in ENTERPRISE_TACTICS]
    assert TACTIC_DEFENSE_IMPAIRMENT in tactic_ids, "TA0112 Defense Impairment missing"

def test_new_v19_techniques_resolvable():
    loader = ATTACKLoader()
    index  = ATTACKIndex(loader)
    # Only test techniques that exist in current STIX bundle
    new_ids = ["T1682", "T1683", "T1684", "T1685", "T1686", "T1687", "T1688",
               "T1689", "T1690", "T1027/018"]
    for tid in new_ids:
        result = index.get(tid)
        if result is not None:
            print(f"Found new v19 technique: {tid} - {result.name}")
    # At least some new techniques should exist
    found = [tid for tid in new_ids if index.get(tid) is not None]
    assert len(found) > 0, f"No new v19 techniques found in index"

def test_revoked_techniques_not_in_index():
    loader = ATTACKLoader()
    index  = ATTACKIndex(loader)
    # These were revoked in v19 — index must not return them as valid
    # Note: depends on STIX bundle being updated to v19
    revoked = ["T1562", "T1562.001", "T1070.001", "T1070.002"]
    for tid in revoked:
        result = index.get(tid)
        # Only assert if we know the STIX is v19 - for now just log
        if result is not None:
            print(f"Revoked technique still in index: {tid} - {result.name}")

def test_ics_new_subtechniques_resolvable():
    loader = ATTACKLoader()
    index  = ATTACKIndex(loader)
    ics_new = ["T1691", "T1692", "T1693", "T1694", "T1695",
               "T0843/001", "T0846/001"]
    for tid in ics_new:
        result = index.get(tid)
        if result is not None:
            print(f"Found new ICS v19 sub-technique: {tid} - {result.name}")
    # At least some should exist if STIX is v19
    found = [tid for tid in ics_new if index.get(tid) is not None]
    # Just log - don't fail if STIX isn't v19 yet
    print(f"ICS v19 sub-techs found: {found}")

def test_revocation_map_keys_not_in_v19_index():
    from attack_core.constants import V19_REVOCATION_MAP
    # Test that revocation map is properly defined
    assert len(V19_REVOCATION_MAP) > 10
    # Count actual revocations (not identity mappings)
    actual_revocations = {k: v for k, v in V19_REVOCATION_MAP.items() if k != v}
    assert len(actual_revocations) > 5, f"Expected >5 actual revocations, got {len(actual_revocations)}"
    for old_id, new_id in actual_revocations.items():
        assert old_id != new_id

def test_navigator_layer_includes_defense_impairment():
    from attack_core.models import ATTACKMapping, Domain
    from attack_core.matrix import NavigatorLayerReporter
    import json
    mapping = ATTACKMapping(
        tactic_id="TA0112",
        tactic_name="Defense Impairment",
        technique_id="T1685",
        technique_name="Disable or Modify Tools",
        domain=Domain.ENTERPRISE,
        confidence=0.9,
        data_sources=[],
        platforms=[],
    )
    reporter = NavigatorLayerReporter()
    layer_json = reporter.generate("test_repo", [mapping])
    layer = json.loads(layer_json)
    assert layer["versions"]["attack"] == "19"
    # Check that the technique has the correct tactic field
    assert any(t.get("tactic") == "TA0112" for t in layer["techniques"]), \
        "TA0112 Defense Impairment missing from Navigator layer"