"""
attack-v19-core: MITRE ATT&CK v19 Data Models
Standalone importable package for ATT&CK v19 Enterprise, Mobile, and ICS domains.
"""

from .constants import (
    DOMAINS,
    ENTERPRISE_SUBTECHNIQUE_COUNT,
    ENTERPRISE_TACTIC_COUNT,
    ENTERPRISE_TACTICS,
    ENTERPRISE_TECHNIQUE_COUNT,
    ICS_TACTIC_COUNT,
    MOBILE_TACTIC_COUNT,
    PLATFORMS_ENTERPRISE,
    PLATFORMS_ICS,
    PLATFORMS_MOBILE,
)
from .index import ATTACKIndex
from .loader import ATTACKLoader
from .mapping import ATTACKMappingBuilder, MappingResolution
from .matrix import ATTACKMatrix, NavigatorLayerReporter
from .models import (
    ATTACKMapping,
    DataSource,
    Domain,
    Group,
    Mitigation,
    Software,
    SubTechnique,
    Tactic,
    Technique,
)

import warnings
warnings.warn(
    "The 'attack_core' package is a compatibility shim for 'attack_v19_core'. "
    "It will be removed in v20.0.0. Update your imports to use 'attack_v19_core' directly. "
    "See MIGRATION_GUIDE.md for details.",
    DeprecationWarning,
    stacklevel=2,
)

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
    "MappingResolution",
    "ATTACKLoader",
    "ATTACKIndex",
    "ATTACKMatrix",
    "NavigatorLayerReporter",
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
