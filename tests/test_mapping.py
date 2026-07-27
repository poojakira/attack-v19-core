from attack_core import ATTACKIndex, ATTACKLoader
from attack_core.mapping import ATTACKMappingBuilder


def test_builder_resolves_canonical_tactic_id():
    builder = ATTACKMappingBuilder(ATTACKIndex(ATTACKLoader()))
    mapping = builder.build("T1059", 0.85)

    assert mapping is not None
    assert mapping.tactic_id == "TA0002"
    assert mapping.tactic_name == "Execution"
    assert mapping.technique_id == "T1059"
    assert mapping.subtechnique_id is None
    assert mapping.was_normalized is False
    assert mapping.was_revoked is False


def test_builder_preserves_subtechnique_parent_context():
    builder = ATTACKMappingBuilder(ATTACKIndex(ATTACKLoader()))
    mapping = builder.build("T1059.001", 0.75)

    assert mapping is not None
    assert mapping.technique_id == "T1059"
    assert mapping.technique_name == "Command and Scripting Interpreter"
    assert mapping.subtechnique_id == "T1059.001"
    assert mapping.parent_technique_id == "T1059"
    assert mapping.resolved_technique_id == "T1059.001"


def test_builder_normalizes_slash_subtechnique_ids():
    builder = ATTACKMappingBuilder(ATTACKIndex(ATTACKLoader()))
    mapping = builder.build("T1683/001", 0.65)

    assert mapping is not None
    assert mapping.technique_id == "T1683"
    assert mapping.subtechnique_id == "T1683.001"
    assert mapping.resolved_technique_id == "T1683.001"
    assert mapping.was_normalized is True


def test_builder_records_revoked_id_remap(caplog):
    builder = ATTACKMappingBuilder(ATTACKIndex(ATTACKLoader()))
    mapping = builder.build("T1562.001", 0.8)

    assert mapping is not None
    assert mapping.technique_id == "T1685"
    assert mapping.source_technique_id == "T1562.001"
    assert mapping.resolved_technique_id == "T1685"
    assert mapping.was_revoked is True
    assert "Auto-remapped to T1685" in caplog.text
