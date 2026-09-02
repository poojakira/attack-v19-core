# tests/conftest.py
import pytest

from attack_v19_core.loader import ATTACKLoader
from attack_v19_core.index import ATTACKIndex


@pytest.fixture(scope="session")
def loader():
    """Session-scoped ATTACKLoader.

    Building the loader re-parses ~60MB of STIX via mitreattack-python
    (~20s), so it is constructed once per test session and shared across
    all tests that only need read access to loaded data.
    """
    return ATTACKLoader()


@pytest.fixture(scope="session")
def index(loader):
    """Session-scoped ATTACKIndex built from the shared loader."""
    return ATTACKIndex(loader)
