# ATT&CK v19 Data Model

This document describes the internal data model used by `attack-v19-core` to
represent MITRE ATT&CK v19 knowledge base objects. All models are defined as
Pydantic v2 `BaseModel` subclasses in `attack_core/models.py`.

---

## Overview

ATT&CK v19 organizes adversary behavior into a hierarchy:

```
Domain (Enterprise | Mobile | ICS)
  └── Tactic (14-15 per domain)
        └── Technique (parent-level, e.g. T1059)
              └── Sub-technique (e.g. T1059.001)
```

Each technique may be associated with:
- One or more **tactics** (kill chain phases)
- One or more **platforms** (OS/cloud environments)
- Zero or more **data sources** (telemetry for detection)
- Zero or more **mitigations** (defensive controls)

---

## Entity-Relationship Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ATT&CK v19 DATA MODEL                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   Domain     │         │     Tactic       │         │   Technique      │
├──────────────┤         ├──────────────────┤         ├──────────────────┤
│ ENTERPRISE   │◄────────┤ stix_id          │    ┌───►│ stix_id          │
│ MOBILE       │ domain  │ attack_id (TA*)  │    │    │ attack_id (T*)   │
│ ICS          │         │ name             │    │    │ name             │
└──────────────┘         │ description      │    │    │ description      │
                         │ domain           │    │    │ tactic_ids[]     │──┐
                         │ url              │    │    │ platforms[]      │  │
                         └──────────────────┘    │    │ data_sources[]   │  │
                                  │              │    │ mitigations[]    │  │
                                  │ 1:N          │    │ subtechniques[]  │  │
                                  │ (tactic has  │    │ kill_chain[]     │  │
                                  │  techniques) │    │ domain           │  │
                                  ▼              │    │ is_subtechnique  │  │
                         ┌──────────────────┐    │    │ url              │  │
                         │  tactic_ids[]    │────┘    └──────────────────┘  │
                         │  (kill chain     │                │              │
                         │   phase names)   │                │ parent_id    │
                         └──────────────────┘                │ 1:N          │
                                                             ▼              │
┌──────────────────┐                              ┌──────────────────┐     │
│   DataSource     │                              │  SubTechnique    │     │
├──────────────────┤                              ├──────────────────┤     │
│ stix_id          │         detects              │ stix_id          │     │
│ attack_id (DS*)  │◄────────────────────────────-│ attack_id (T*.x) │     │
│ name             │                              │ name             │     │
│ description      │                              │ parent_id        │──┐  │
│ components[]     │                              │ tactic_ids[]     │  │  │
│ techniques[]     │                              │ platforms[]      │  │  │
│ domain           │                              │ data_sources[]   │  │  │
│ url              │                              │ mitigations[]    │  │  │
└──────────────────┘                              │ kill_chain[]     │  │  │
                                                  │ domain           │  │  │
                                                  │ is_subtechnique  │  │  │
┌──────────────────┐                              │ url              │  │  │
│   Group          │                              └──────────────────┘  │  │
├──────────────────┤                                       │           │  │
│ stix_id          │         uses                          │           │  │
│ attack_id (G*)   │─────────────────────────────┐         │           │  │
│ name             │                             │         │           │  │
│ aliases[]        │                             ▼         │           │  │
│ description      │                    ┌────────────────┐ │           │  │
│ techniques[]     │────────────────────┤  Technique or  │◄┘           │  │
│ software[]       │                    │  SubTechnique  │             │  │
│ domain           │                    │  (referenced   │◄────────────┘  │
│ url              │                    │   by attack_id)│              │  │
└──────────────────┘                    └────────────────┘              │  │
                                                 ▲                     │  │
┌──────────────────┐                             │                     │  │
│   Software       │          uses               │                     │  │
├──────────────────┤─────────────────────────────┘                     │  │
│ stix_id          │                                                   │  │
│ attack_id (S*)   │                                                   │  │
│ name             │         ┌──────────────────┐                      │  │
│ software_type    │         │   Mitigation     │                      │  │
│ platforms[]      │         ├──────────────────┤       mitigates       │  │
│ techniques[]     │         │ stix_id          │──────────────────────┘  │
│ description      │         │ attack_id (M*)   │                         │
│ domain           │         │ name             │                         │
│ url              │         │ description      │                         │
└──────────────────┘         │ techniques[]     │─────────────────────────┘
                             │ domain           │  (mitigates techniques)
                             │ url              │
                             └──────────────────┘

┌──────────────────┐
│  ATTACKMapping   │  ← Reusable mapping block for detection findings
├──────────────────┤
│ tactic_id        │──► references Tactic
│ tactic_name      │
│ technique_id     │──► references Technique (parent)
│ technique_name   │
│ subtechnique_id  │──► references SubTechnique (optional)
│ subtechnique_name│
│ domain           │
│ confidence       │  [0.0 – 1.0]
│ data_sources[]   │
│ platforms[]      │
│ url              │
│ was_normalized   │  (input had formatting issues)
│ was_revoked      │  (input used deprecated ID)
└──────────────────┘
```

---

## Model Details

### Domain (Enum)

Defines the three ATT&CK matrices:

| Value        | STIX Bundle               | Description          |
|--------------|---------------------------|----------------------|
| `enterprise` | `enterprise-attack.json`  | IT/cloud networks    |
| `mobile`     | `mobile-attack.json`      | Android/iOS          |
| `ics`        | `ics-attack.json`         | Industrial control   |

### Tactic

Represents a tactical objective (kill chain phase).

| Field         | Type           | Description                                |
|---------------|----------------|--------------------------------------------|
| `stix_id`     | `str`          | STIX 2.0 identifier                        |
| `attack_id`   | `str`          | ATT&CK ID (e.g. `TA0001`)                  |
| `name`        | `str`          | Human-readable name                        |
| `description` | `str`          | Tactic description                         |
| `domain`      | `Domain`       | Which matrix this belongs to               |
| `url`         | `str | None`   | MITRE ATT&CK page URL                      |

v19 changes: TA0005 renamed "Defense Evasion" → "Stealth"; TA0112 "Defense
Impairment" added as a new tactic.

### Technique

Parent-level technique (e.g. T1059 "Command and Scripting Interpreter").

| Field            | Type              | Description                           |
|------------------|-------------------|---------------------------------------|
| `stix_id`        | `str`             | STIX 2.0 identifier                   |
| `attack_id`      | `str`             | ATT&CK ID (e.g. `T1059`)              |
| `name`           | `str`             | Technique name                         |
| `description`    | `str`             | Full description text                  |
| `tactic_ids`     | `List[str]`       | Kill chain phase names                 |
| `platforms`      | `List[str]`       | Applicable platforms                   |
| `data_sources`   | `List[str]`       | Detection telemetry sources            |
| `mitigations`    | `List[str]`       | Mitigation IDs                         |
| `subtechniques`  | `List[str]`       | Child sub-technique IDs                |
| `parent_id`      | `str | None`      | Always `None` for parent techniques    |
| `detection`      | `str | None`      | Detection guidance text                |
| `domain`         | `Domain`          | Matrix domain                          |
| `is_subtechnique`| `bool`            | Always `False`                         |
| `kill_chain`     | `List[Dict]`      | Raw STIX kill chain phase objects       |
| `url`            | `str | None`      | MITRE ATT&CK page URL                  |

### SubTechnique

Child technique (e.g. T1059.001 "PowerShell").

Inherits the same field set as Technique with these differences:
- `parent_id`: ATT&CK ID of the parent technique (e.g. `T1059`)
- `is_subtechnique`: Always `True`
- Derived from parent ID by splitting on `.` (e.g. `T1059.001` → parent `T1059`)

### Tactic–Technique Relationships

Techniques reference tactics via **kill chain phase names** (not tactic IDs
directly). The `ATTACKIndex` resolves phase names to tactic IDs:

```
Technique.tactic_ids = ["initial-access", "execution"]
                                │
                                ▼
ATTACKIndex.tactic_id_for_phase("initial-access") → "TA0001"
```

A single technique can appear under multiple tactics (many-to-many).

### Sub-technique Hierarchy

```
T1059 (parent)
  ├── T1059.001 (PowerShell)
  ├── T1059.002 (AppleScript)
  ├── T1059.003 (Windows Command Shell)
  ├── T1059.004 (Unix Shell)
  └── ...
```

- Parent ID derived by splitting `attack_id` on `.`
- `ATTACKIndex.get_subtechniques_of("T1059")` returns all children
- Sub-techniques inherit the parent's tactic mapping

### Platform Filtering

Each technique lists applicable platforms. The library defines valid platforms
per domain:

**Enterprise** (13): Windows, macOS, Linux, AWS, Azure, GCP, Containers,
Network, PRE, Office 365, Google Workspace, SaaS, IaaS

**Mobile** (2): Android, iOS

**ICS** (11): Control Server, Data Historian, Engineering Workstation,
Field Controller/RTU/PLC/IED, HMI, Input/Output Server, Jump Server,
Operator Workstation, Remote Desktop Protocol,
Safety Instrumented System/Protection Relay, Wireless Controller

Query by platform: `index.by_platform("linux")` returns all techniques
applicable to Linux (case-insensitive).

### Data Source Mapping

Data sources describe telemetry needed to detect a technique:

```
DataSource
  ├── name: "Process: Process Creation"
  ├── components: ["Sysmon Event ID 1", ...]
  └── techniques: ["T1059", "T1204", ...]
```

Techniques reference data sources as string labels in their `data_sources[]`
field (e.g. `"Process: Process Creation"`).

---

## Revocation and ID Resolution

ATT&CK v19 revoked 22 techniques (29 total remaps) and remapped them to new IDs. The library
handles this transparently via `V19_REVOCATION_MAP`:

```python
# Example revocation chain
"T1562"     → "T1685"       # Impair Defenses → Disable or Modify Tools
"T1562.001" → "T1685"       # Sub collapsed into new parent
"T1562.008" → "T1685.002"   # Disable Cloud Logs → new sub-technique
```

`ATTACKIndex.resolve_attack_id()` automatically follows the revocation map.
`ATTACKMappingBuilder.build()` logs a warning when remapping occurs and sets
`was_revoked=True` on the resulting `ATTACKMapping`.

---

## ATTACKMapping (Mapping Block)

A portable, self-contained mapping that links a detection finding to ATT&CK:

```python
ATTACKMapping(
    tactic_id="TA0005",
    tactic_name="Stealth",
    technique_id="T1685",
    technique_name="Disable or Modify Tools",
    subtechnique_id="T1685.002",
    subtechnique_name="Disable or Modify Cloud Log",
    domain=Domain.ENTERPRISE,
    confidence=0.85,
    data_sources=["Cloud Service: Cloud Service Modification"],
    platforms=["AWS", "Azure", "GCP"],
    was_revoked=True,          # input was T1562.008
    source_technique_id="T1562.008",
    resolved_technique_id="T1685.002",
)
```

---

## Index Architecture

`ATTACKIndex` builds five O(1) lookup dictionaries at construction time:

| Index                       | Key                       | Value                 |
|-----------------------------|---------------------------|-----------------------|
| `_by_id`                    | `attack_id`               | Technique/SubTechnique|
| `_by_domain_id`             | `(Domain, attack_id)`     | Technique/SubTechnique|
| `_by_tactic`                | `tactic_id`               | `List[attack_id]`     |
| `_by_platform`              | `platform` (lowercase)    | `List[attack_id]`     |
| `_subtechniques_by_parent`  | `(Domain, parent_id)`     | `List[attack_id]`     |

Construction cost: one pass over all tactics, techniques, and sub-techniques
per domain (3 domains × ~700 objects ≈ 2100 iterations). After construction,
all lookups are dictionary access — O(1).

---

## Data Flow

```
STIX JSON Bundles (enterprise-attack.json, mobile-attack.json, ics-attack.json)
        │
        ▼
  ATTACKLoader._load_all()          ← parses via mitreattack-python
        │
        ▼
  ATTACKLoader.get_techniques()     ← returns List[Technique]
  ATTACKLoader.get_subtechniques()  ← returns List[SubTechnique]
  ATTACKLoader.get_tactics()        ← returns List[Tactic]
        │
        ▼
  ATTACKIndex(loader)               ← builds O(1) lookup indexes
        │
        ▼
  ATTACKMappingBuilder(index)       ← produces ATTACKMapping objects
  ATTACKMatrix(index)               ← renders matrix as dict/JSON/CSV/HTML
```

---

## Version Guarantees

- Models track ATT&CK v19 (April 2026 release)
- `V19_REVOCATION_MAP` is exhaustive for v18→v19 transitions
- Technique/tactic counts are asserted in tests
- The library will bump major version for ATT&CK v20 breaking changes
