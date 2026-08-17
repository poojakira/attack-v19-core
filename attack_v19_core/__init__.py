"""
attack-v19-core: MITRE ATT&CK v19 Data Models
Standalone importable package for ATT&CK v19 Enterprise, Mobile, and ICS domains.
"""

from .constants import (
    ENTERPRISE_TACTICS,
    ENTERPRISE_TACTIC_COUNT,
    ENTERPRISE_TECHNIQUE_COUNT,
    ENTERPRISE_SUBTECHNIQUE_COUNT,
    MOBILE_TACTIC_COUNT,
    ICS_TACTIC_COUNT,
    DOMAINS,
    PLATFORMS_ENTERPRISE,
    PLATFORMS_MOBILE,
    PLATFORMS_ICS,
)
from .models import (
    Domain,
    Tactic,
    Technique,
    SubTechnique,
    Group,
    Software,
    Mitigation,
    DataSource,
    ATTACKMapping,
)
from .loader import ATTACKLoader
from .index import ATTACKIndex
from .matrix import ATTACKMatrix
from .mapping import ATTACKMappingBuilder, NavigatorLayerReporter

__version__ = "19.2.0"
__all__ = [
    "Domain",
    "Tactic",
    "Technique",
    "SubTechnique",
    "Group",
    "Software",
    "Mitigation",
    "DataSource",
    "ATTACKMapping",
    "ATTACKMappingBuilder",
    "NavigatorLayerReporter",
    "ATTACKLoader",
    "ATTACKIndex",
    "ATTACKMatrix",
    "ENTERPRISE_TACTICS",
    "ENTERPRISE_TACTIC_COUNT",
    "ENTERPRISE_TECHNIQUE_COUNT",
    "ENTERPRISE_SUBTECHNIQUE_COUNT",
    "MOBILE_TACTIC_COUNT",
    "ICS_TACTIC_COUNT",
    "DOMAINS",
    "PLATFORMS_ENTERPRISE",
    "PLATFORMS_MOBILE",
    "PLATFORMS_ICS",
]
