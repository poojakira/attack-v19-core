# tests/test_loader.py
from attack_core.loader import ATTACKLoader
from attack_core.models import Domain


def test_loader_loads_all_domains():
    loader = ATTACKLoader()
    assert "enterprise" in loader._raw
    assert "mobile" in loader._raw
    assert "ics" in loader._raw


def test_get_tactics_enterprise():
    loader = ATTACKLoader()
    tactics = loader.get_tactics(Domain.ENTERPRISE)
    assert len(tactics) >= 14
    tactic_ids = [t.attack_id for t in tactics]
    assert "TA0001" in tactic_ids
    assert "TA0011" in tactic_ids


def test_get_tactics_mobile():
    loader = ATTACKLoader()
    tactics = loader.get_tactics(Domain.MOBILE)
    assert len(tactics) >= 12


def test_get_tactics_ics():
    loader = ATTACKLoader()
    tactics = loader.get_tactics(Domain.ICS)
    assert len(tactics) >= 12


def test_get_techniques_enterprise():
    loader = ATTACKLoader()
    techniques = loader.get_techniques(Domain.ENTERPRISE)
    assert len(techniques) >= 200
    tech_ids = [t.attack_id for t in techniques]
    assert "T1059" in tech_ids
    assert "T1190" in tech_ids


def test_get_subtechniques_enterprise():
    loader = ATTACKLoader()
    subtechniques = loader.get_subtechniques(Domain.ENTERPRISE)
    assert len(subtechniques) >= 400
    sub_ids = [s.attack_id for s in subtechniques]
    assert "T1059.001" in sub_ids
    assert "T1566.001" in sub_ids


def test_subtechnique_has_parent_id():
    loader = ATTACKLoader()
    subtechniques = loader.get_subtechniques(Domain.ENTERPRISE)
    for sub in subtechniques:
        assert sub.parent_id != ""
        assert "." in sub.attack_id


def test_technique_has_kill_chain():
    loader = ATTACKLoader()
    techniques = loader.get_techniques(Domain.ENTERPRISE)
    for tech in techniques[:10]:
        assert isinstance(tech.kill_chain, list)


def test_get_groups_enterprise():
    loader = ATTACKLoader()
    groups = loader.get_groups(Domain.ENTERPRISE)
    assert len(groups) > 0
    assert all(g.domain == Domain.ENTERPRISE for g in groups)


def test_get_software_enterprise():
    loader = ATTACKLoader()
    software = loader.get_software(Domain.ENTERPRISE)
    assert len(software) > 0
    assert all(s.domain == Domain.ENTERPRISE for s in software)


def test_get_mitigations_enterprise():
    loader = ATTACKLoader()
    mitigations = loader.get_mitigations(Domain.ENTERPRISE)
    assert len(mitigations) > 0
    assert all(m.domain == Domain.ENTERPRISE for m in mitigations)


def test_get_data_sources_enterprise():
    loader = ATTACKLoader()
    data_sources = loader.get_data_sources(Domain.ENTERPRISE)
    assert len(data_sources) > 0
    assert all(ds.domain == Domain.ENTERPRISE for ds in data_sources)