# tests/test_models.py
from attack_core.constants import (
    ENTERPRISE_SUBTECHNIQUE_COUNT,
    ENTERPRISE_TACTIC_COUNT,
    ENTERPRISE_TECHNIQUE_COUNT,
)
from attack_core.index import ATTACKIndex
from attack_core.loader import ATTACKLoader
from attack_core.models import Domain


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


def test_tactic_count():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    tactics = [t for t in index._tactics.values() if t.domain == Domain.ENTERPRISE]
    assert len(tactics) == ENTERPRISE_TACTIC_COUNT


def test_mobile_domain_loads():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    count = index.count_techniques(Domain.MOBILE)
    assert count > 0


def test_ics_domain_loads():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    count = index.count_techniques(Domain.ICS)
    assert count > 0
