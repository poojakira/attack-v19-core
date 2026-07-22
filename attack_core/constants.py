"""
MITRE ATT&CK v19 canonical constants.
Counts are assertions — tests will fail if loaded data diverges.
"""

ENTERPRISE_TACTICS = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
    ("TA0042", "Resource Development"),
    ("TA0043", "Reconnaissance"),
    ("TA0101", "Pre-ATT&CK"),
]

ENTERPRISE_TACTIC_COUNT = 15
ENTERPRISE_TECHNIQUE_COUNT = 222
ENTERPRISE_SUBTECHNIQUE_COUNT = 475

MOBILE_TACTIC_COUNT = 12
ICS_TACTIC_COUNT = 12

DOMAINS = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack",
}

PLATFORMS_ENTERPRISE = [
    "Windows", "macOS", "Linux",
    "AWS", "Azure", "GCP",
    "Containers", "Network", "PRE",
    "Office 365", "Google Workspace", "SaaS",
    "IaaS",
]

PLATFORMS_MOBILE = ["Android", "iOS"]

PLATFORMS_ICS = [
    "Control Server", "Data Historian", "Engineering Workstation",
    "Field Controller/RTU/PLC/IED", "HMI", "Input/Output Server",
    "Jump Server", "Operator Workstation", "Remote Desktop Protocol",
    "Safety Instrumented System/Protection Relay", "Wireless Controller",
]