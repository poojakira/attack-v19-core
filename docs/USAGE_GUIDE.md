# Usage Guide

This guide covers how to use `attack-v19-core` as a library, its integration
points with other tools in the portfolio, and common query patterns.

---

## Installation

```bash
# Install the package and its dependencies
pip install -e .

# Download STIX bundles (required before first use)
python -m attack_core download

# Or set a custom data directory
export ATTACK_DATA_DIR=/path/to/stix/bundles
```

The STIX bundles are cached in `~/attack_data/` by default. Each bundle is
approximately 30 MB.

---

## Quick Start

```python
from attack_v19_core import ATTACKLoader, ATTACKIndex, ATTACKMappingBuilder
from attack_v19_core.models import Domain

# Load all three domains (Enterprise, Mobile, ICS)
loader = ATTACKLoader()

# Build the in-memory index for fast lookups
index = ATTACKIndex(loader)

# Look up a technique by ID
technique = index.get("T1059")
print(technique.name)           # "Command and Scripting Interpreter"
print(technique.platforms)      # ["Windows", "macOS", "Linux"]
print(technique.tactic_ids)     # ["execution"]

# Get sub-techniques
subs = index.get_subtechniques_of("T1059")
for s in subs:
    print(f"  {s.attack_id}: {s.name}")
```

---

## API Reference

### ATTACKLoader

Parses STIX 2.0 JSON bundles into typed Pydantic models.

```python
loader = ATTACKLoader(stix_dir=Path("~/attack_data"))
```

| Method                          | Returns              | Description                    |
|---------------------------------|----------------------|--------------------------------|
| `get_tactics(domain)`           | `List[Tactic]`       | All tactics for a domain       |
| `get_techniques(domain)`        | `List[Technique]`    | Parent techniques only         |
| `get_subtechniques(domain)`     | `List[SubTechnique]` | Sub-techniques only            |
| `get_groups(domain)`            | `List[Group]`        | Threat groups                  |
| `get_software(domain)`          | `List[Software]`     | Malware and tools              |
| `get_mitigations(domain)`       | `List[Mitigation]`   | Defensive controls             |
| `get_data_sources(domain)`      | `List[DataSource]`   | Detection telemetry sources    |

### ATTACKIndex

O(1) lookup index over all loaded techniques.

```python
index = ATTACKIndex(loader)
```

| Method                                    | Returns                    | Description                          |
|-------------------------------------------|----------------------------|--------------------------------------|
| `get(attack_id, domain=None)`             | `Technique\|SubTechnique\|None` | Lookup with revocation resolution    |
| `get_exact(attack_id, domain=None)`       | `Technique\|SubTechnique\|None` | Lookup without revocation resolution |
| `resolve_attack_id(attack_id)`            | `str`                      | Resolve revoked IDs to current       |
| `by_tactic(tactic_id)`                    | `List[TechniqueOrSub]`     | All techniques under a tactic        |
| `by_platform(platform)`                   | `List[TechniqueOrSub]`     | All techniques for a platform        |
| `get_subtechniques_of(technique_id, domain)` | `List[SubTechnique]`    | Children of a parent technique       |
| `tactic_id_for_phase(phase_name, domain)` | `str`                      | Resolve phase name to tactic ID      |
| `tactic_for_technique(technique)`         | `Tactic\|None`             | Primary tactic for a technique       |
| `parent_for(technique)`                   | `TechniqueOrSub\|None`     | Parent of a sub-technique            |
| `search(keyword)`                         | `List[TechniqueOrSub]`     | Full-text search in name/description |
| `count_techniques(domain=None)`           | `int`                      | Count parent techniques              |
| `count_subtechniques(domain=None)`        | `int`                      | Count sub-techniques                 |

### ATTACKMappingBuilder

Produces `ATTACKMapping` objects with full context for detection findings.

```python
builder = ATTACKMappingBuilder(index)
```

| Method                              | Returns                  | Description                       |
|-------------------------------------|--------------------------|-----------------------------------|
| `build(attack_id, confidence)`      | `ATTACKMapping\|None`    | Build single mapping              |
| `build_many(attack_ids, confidence)`| `List[ATTACKMapping]`    | Build mappings for multiple IDs   |
| `resolve(attack_id)`               | `MappingResolution`      | Check normalization/revocation    |

### ATTACKMatrix

Renders the ATT&CK matrix in multiple output formats.

```python
matrix = ATTACKMatrix(index)
```

| Method                    | Returns | Description                      |
|---------------------------|---------|----------------------------------|
| `to_dict(domain)`         | `Dict`  | Structured dictionary            |
| `to_json(domain, indent)` | `str`  | JSON string                      |
| `to_csv(domain)`          | `str`  | CSV with headers                 |
| `to_html(domain)`         | `str`  | HTML table with styling          |

---

## Common Query Patterns

### Find all techniques for a specific platform

```python
linux_techniques = index.by_platform("linux")
print(f"{len(linux_techniques)} techniques target Linux")
```

### Check if a technique ID is still valid in v19

```python
resolution = builder.resolve("T1562")
if resolution.was_revoked:
    print(f"T1562 was revoked → now {resolution.resolved_id}")
    # T1562 was revoked → now T1685
```

### Get the full tactic chain for a technique

```python
technique = index.get("T1059")
for phase_name in technique.tactic_ids:
    tactic_id = index.tactic_id_for_phase(phase_name)
    tactic = index._tactics.get(tactic_id)
    print(f"  {tactic.attack_id}: {tactic.name}")
```

### Search techniques by keyword

```python
results = index.search("credential")
for t in results[:5]:
    print(f"{t.attack_id}: {t.name}")
```

### Export ATT&CK Navigator layer

```python
from attack_core.matrix import NavigatorLayerReporter

reporter = NavigatorLayerReporter()
mappings = builder.build_many(["T1059", "T1053", "T1547"], confidence=0.9)
layer_json = reporter.generate("my-detection-tool", mappings)

with open("layer.json", "w") as f:
    f.write(layer_json)
```

### Filter by domain

```python
# ICS-specific techniques
ics_techniques = loader.get_techniques(Domain.ICS)
ics_subs = loader.get_subtechniques(Domain.ICS)
print(f"ICS: {len(ics_techniques)} techniques, {len(ics_subs)} sub-techniques")
```

---

## Integration with Portfolio Tools

### mcp-agent-security-gateway

The MCP Agent Security Gateway uses `attack-v19-core` to map detected tool
invocations to ATT&CK techniques. When the gateway intercepts an MCP tool
call that matches a threat pattern, it:

1. Receives a candidate technique ID from its detection rules
2. Uses `ATTACKMappingBuilder.build()` to produce a full `ATTACKMapping`
3. Embeds the mapping in its security alert payload
4. Leverages revocation resolution to handle legacy rule IDs transparently

```python
# In mcp-agent-security-gateway/src/detection/mapper.py
from attack_v19_core import ATTACKLoader, ATTACKIndex, ATTACKMappingBuilder

loader = ATTACKLoader()
index = ATTACKIndex(loader)
builder = ATTACKMappingBuilder(index)

def map_detection_to_attack(rule_technique_id: str, confidence: float):
    """Map a detection rule's technique ID to a full ATT&CK v19 mapping."""
    mapping = builder.build(rule_technique_id, confidence)
    if mapping is None:
        return None
    return {
        "attack_mapping": mapping.model_dump(),
        "tactic": mapping.tactic_name,
        "technique": mapping.technique_name,
        "severity_boost": mapping.confidence > 0.8,
    }
```

Key integration points:
- Automatic revocation handling (gateway rules may reference v18 IDs)
- Platform filtering to scope alerts to relevant infrastructure
- Confidence scoring passed through to alert prioritization
- Navigator layer export for SOC visibility dashboards

### hf-model-provenance-scanner

The HuggingFace Model Provenance Scanner maps supply chain risks found in
ML model artifacts to ATT&CK techniques. It uses `attack-v19-core` for:

1. Mapping pickle deserialization exploits → T1059 (Code Execution)
2. Mapping model poisoning indicators → T1195 (Supply Chain Compromise)
3. Mapping credential exposure in configs → T1552 (Unsecured Credentials)
4. Generating Navigator layers showing the risk surface

```python
# In hf-model-provenance-scanner/src/risk_mapper.py
from attack_v19_core import ATTACKLoader, ATTACKIndex, ATTACKMappingBuilder
from attack_v19_core.models import Domain

loader = ATTACKLoader()
index = ATTACKIndex(loader)
builder = ATTACKMappingBuilder(index)

RISK_TO_TECHNIQUE = {
    "pickle_exploit": ("T1059", 0.95),
    "supply_chain_poisoning": ("T1195", 0.90),
    "exposed_credentials": ("T1552", 0.85),
    "model_backdoor": ("T1195.003", 0.80),
    "unsafe_deserialization": ("T1059.006", 0.90),
}

def map_scan_finding(risk_type: str) -> dict | None:
    """Convert a scan finding to an ATT&CK-annotated risk report."""
    if risk_type not in RISK_TO_TECHNIQUE:
        return None
    technique_id, confidence = RISK_TO_TECHNIQUE[risk_type]
    mapping = builder.build(technique_id, confidence)
    if mapping is None:
        return None
    return {
        "risk_type": risk_type,
        "attack_technique": mapping.technique_name,
        "attack_tactic": mapping.tactic_name,
        "confidence": mapping.confidence,
        "platforms": mapping.platforms,
        "detection_guidance": mapping.data_sources,
    }
```

Key integration points:
- Maps ML-specific risks to ATT&CK technique IDs
- Produces structured reports with tactic context
- Uses data sources field to recommend detection telemetry
- Supports batch mapping via `build_many()` for full scan reports

---

## CLI Usage

The library includes a CLI for common operations:

```bash
# Download STIX bundles from MITRE
python -m attack_core download

# Validate loaded data against expected v19 counts
python -m attack_core validate

# Query a technique
python -m attack_core query T1059

# Export matrix
python -m attack_core matrix --format json --domain enterprise
```

---

## Configuration

### Environment Variables

| Variable          | Default              | Description                      |
|-------------------|----------------------|----------------------------------|
| `ATTACK_DATA_DIR` | `~/attack_data`     | Path to STIX bundle directory    |

### Required Files in ATTACK_DATA_DIR

```
~/attack_data/
  ├── enterprise-attack.json
  ├── mobile-attack.json
  └── ics-attack.json
```

---

## Error Handling

The library uses explicit error patterns:

```python
# FileNotFoundError if STIX bundles are missing
try:
    loader = ATTACKLoader()
except FileNotFoundError as e:
    print(f"Run 'python -m attack_core download' first: {e}")

# Returns None if technique not found (does not raise)
technique = index.get("T9999")
assert technique is None

# MappingBuilder returns None for unknown IDs (logs error)
mapping = builder.build("T9999", 0.5)
assert mapping is None
```

---

## Performance Characteristics

| Operation                    | Time Complexity | Notes                            |
|------------------------------|-----------------|----------------------------------|
| `ATTACKLoader()` construction | O(N)           | Parses ~2100 STIX objects        |
| `ATTACKIndex()` construction  | O(N)           | One pass to build all indexes    |
| `index.get(id)`              | O(1)            | Dictionary lookup                |
| `index.by_tactic(id)`        | O(K)            | K = techniques in that tactic    |
| `index.by_platform(p)`       | O(K)            | K = techniques for that platform |
| `index.search(keyword)`      | O(N)            | Linear scan over all techniques  |
| `builder.build(id, conf)`    | O(1)            | Lookup + object construction     |

Initial load time is dominated by `mitreattack-python` STIX parsing (~2-5
seconds). The `_RAW_CACHE` ensures subsequent `ATTACKLoader` instances in
the same process reuse parsed data.

---

## Testing

```bash
# Run full test suite
pytest tests/ -q

# Run only model tests
pytest tests/test_models.py -v

# Run integration tests (requires STIX bundles)
pytest tests/test_integration_v19_chain.py -v
```
