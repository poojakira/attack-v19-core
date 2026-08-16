from attack_v19_core.constants import (
    ENTERPRISE_TECHNIQUE_COUNT,
    ENTERPRISE_SUBTECHNIQUE_COUNT,
    ENTERPRISE_TACTIC_COUNT,
)
from attack_v19_core.loader import ATTACKLoader
from attack_v19_core.index import ATTACKIndex
from attack_v19_core.models import Domain


def test_enterprise_technique_count():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    count = index.count_techniques(Domain.ENTERPRISE)
    assert (
        count == ENTERPRISE_TECHNIQUE_COUNT
    ), f"Expected {ENTERPRISE_TECHNIQUE_COUNT} techniques, got {count}"


def test_enterprise_subtechnique_count():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    count = index.count_subtechniques(Domain.ENTERPRISE)
    assert (
        count == ENTERPRISE_SUBTECHNIQUE_COUNT
    ), f"Expected {ENTERPRISE_SUBTECHNIQUE_COUNT} sub-techniques, got {count}"


def test_enterprise_tactic_count():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    tactics = [t for t in index._tactics.values() if t.domain == Domain.ENTERPRISE]
    count = len(tactics)
    assert (
        count == ENTERPRISE_TACTIC_COUNT
    ), f"Expected {ENTERPRISE_TACTIC_COUNT} tactics, got {count}"


def test_lookup_by_id():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    t = index.get("T1059")
    assert t is not None
    assert t.name == "Command and Scripting Interpreter"


def test_lookup_subtechnique():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    sub = index.get("T1059.001")
    assert sub is not None
    assert sub.is_subtechnique
    assert getattr(sub, "parent_id", None) == "T1059"


def test_by_tactic():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    # TA0001 (Initial Access) spans Enterprise, ICS, and Mobile domains
    # because ATTACKIndex merges all domains. Domain filtering is by_tactic's
    # responsibility only when a domain filter param is added.
    techs = index.by_tactic("TA0001")
    assert len(techs) > 0
    # All returned techniques must have TA0001 in their tactic phase
    assert all("initial-access" in t.tactic_ids for t in techs)


def test_by_platform():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    techs = index.by_platform("Windows")
    assert len(techs) > 0
    assert all("windows" in [p.lower() for p in t.platforms] for t in techs)


def test_search():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    results = index.search("credential")
    assert len(results) > 0
    assert any(
        "credential" in r.name.lower() or "credential" in r.description.lower()
        for r in results
    )


def test_get_subtechniques_of():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    subs = index.get_subtechniques_of("T1059")
    assert len(subs) > 0
    assert all(
        s.is_subtechnique and getattr(s, "parent_id", None) == "T1059" for s in subs
    )


def test_mobile_counts():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    m_tech = index.count_techniques(Domain.MOBILE)
    m_sub = index.count_subtechniques(Domain.MOBILE)
    assert m_tech > 0
    assert m_sub >= 0


def test_ics_counts():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    ics_tech = index.count_techniques(Domain.ICS)
    ics_sub = index.count_subtechniques(Domain.ICS)
    assert ics_tech > 0
    assert ics_sub >= 0
