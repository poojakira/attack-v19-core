# Incident Runbook — attack-core

Operational procedures for responding to incidents affecting `attack-core` and its consumers.

---

## Incident 1: MITRE Releases New ATT&CK Version Breaking Consumers

### Symptoms
- Consumers report unknown technique IDs or missing mappings after upstream update.
- CI pipelines fail on STIX validation or schema changes.
- Pydantic model validation errors on newly shaped objects.

### Severity
**High** — Downstream detection/response tooling may lose coverage.

### Immediate Actions (< 1 hour)

1. **Confirm the break**: Check https://github.com/mitre-attack/attack-stix-data for a new release tag.
2. **Pin consumers to current version**: Advise consumers to pin `attack-core==<last_known_good>` in their requirements.
3. **Open a tracking issue** titled `[BREAKING] ATT&CK vXX compatibility` with:
   - List of breaking schema changes
   - Affected Pydantic models
   - Link to upstream changelog

### Resolution Steps

1. **Diff the STIX bundle**:
   ```bash
   python -m attack_core diff --old v15.1 --new v16.0
   ```
2. **Update Pydantic models** to handle new/changed fields:
   - Add `Optional` fields for new attributes.
   - Add model validators for renamed fields.
3. **Update the revocation map** if techniques were revoked or deprecated upstream.
4. **Regenerate SHA-256 hashes** for the new bundle:
   ```bash
   python -m attack_core fetch --version v16.0
   python -m attack_core verify
   ```
5. **Run the full test suite** including integration tests:
   ```bash
   pytest tests/ -x --tb=short
   ```
6. **Bump version** (minor or major depending on break severity).
7. **Publish release** — the `release.yml` workflow handles signing + PyPI.
8. **Notify consumers** via GitHub Discussions / changelog.

### Prevention
- Subscribe to MITRE ATT&CK release notifications.
- Run nightly CI against `attack-stix-data@main` to detect breaks early.
- Maintain a compatibility matrix in `docs/COMPATIBILITY.md`.

---

## Incident 2: SHA-256 Hash Mismatch on Download

### Symptoms
- `attack_core.fetch()` or `attack_core verify` raises `IntegrityError`.
- Error message: `SHA-256 mismatch: expected <hash_a>, got <hash_b>`.

### Severity
**Critical** — Possible supply-chain attack or data corruption.

### Immediate Actions (< 30 minutes)

1. **Do NOT use the downloaded bundle.** It may be tampered with.
2. **Check the source**:
   - Is the download URL correct? Verify against `attack_core.STIX_SOURCE_URL`.
   - Is there a known CDN issue? Check https://status.github.com.
3. **Compare hashes independently**:
   ```bash
   curl -sL <stix_url> | sha256sum
   # Compare against the pinned hash in attack_core/hashes.json
   ```
4. **Check for upstream legitimate update**:
   - If MITRE pushed a silent update to the same tag (rare but possible), the hash will differ.
   - Verify on the MITRE STIX data repo whether the file was re-uploaded.

### Resolution Steps

**If legitimate upstream change:**
1. Verify the new bundle content manually (spot-check techniques, validate STIX schema).
2. Update `hashes.json` with the new SHA-256.
3. Run full test suite.
4. Cut a patch release.

**If suspected tampering:**
1. **Alert the team immediately** (Slack/PagerDuty).
2. Preserve the corrupted file for forensic analysis:
   ```bash
   cp /tmp/attack_core_cache/enterprise-attack.json ./evidence/tampered_bundle_$(date +%s).json
   ```
3. Rotate any credentials used to access the download source.
4. File a security advisory on the GitHub repository.
5. Notify downstream consumers to pin to the last known-good version.
6. Contact MITRE CTID if the upstream source appears compromised.

### Prevention
- Always verify downloads with SHA-256 before loading into memory.
- Use `--verify` CLI command after any cache refresh.
- Pin to specific STIX data release tags, not `main`.

---

## Incident 3: Revocation Map Missing Entry

### Symptoms
- Consumer calls `index.get("T1234")` and receives a valid technique object, but MITRE has revoked T1234.
- Detection rules reference revoked techniques without being redirected to replacements.
- `index.revocations()` does not list a known revocation.

### Severity
**Medium** — Detection coverage may be stale but no integrity issue.

### Immediate Actions (< 2 hours)

1. **Confirm the revocation** on https://attack.mitre.org/techniques/T1234 (or via STIX bundle `x-mitre-deprecated` / revoked-by relationship).
2. **Check the STIX bundle** for the revocation relationship:
   ```python
   from attack_core import AttackIndex
   idx = AttackIndex.load()
   # Look for relationship where source_ref is T1234 and relationship_type == "revoked-by"
   ```
3. **Determine scope**: How many revocations are missing? Cross-reference the full STIX revocation list.

### Resolution Steps

1. **Update the revocation map** in `attack_core/data/revocations.json`:
   ```json
   {
     "T1234": {
       "revoked_by": "T1234.001",
       "revoked_date": "2025-04-01",
       "reason": "Merged into sub-technique"
     }
   }
   ```
2. **Add a test** for the specific revocation:
   ```python
   def test_t1234_revoked():
       assert index.is_revoked("T1234")
       assert index.revoked_by("T1234") == "T1234.001"
   ```
3. **Run the revocation completeness check**:
   ```bash
   python -m attack_core audit-revocations
   ```
4. **Patch release** with the updated map.
5. **Notify affected consumers** if they rely on the revoked technique.

### Prevention
- Nightly CI job: compare `revocations.json` against STIX bundle relationships.
- Add a `test_revocation_completeness` that fails when the map falls behind.
- Include revocation diff in release notes.

---

## Incident 4: Consumer Uses Deprecated `attack_v19_core` Package

### Symptoms
- Consumer imports `from attack_v19_core import ...` and reports missing features or stale data.
- Deprecation warnings appear in consumer logs.
- Consumer is unaware the package was renamed to `attack_core`.

### Severity
**Low** — No data integrity issue, but consumer misses updates and security patches.

### Immediate Actions

1. **Confirm the consumer's installed version**:
   ```bash
   pip show attack-v19-core
   ```
2. **Direct them to migrate**:
   ```bash
   pip uninstall attack-v19-core
   pip install attack-core
   ```

### Resolution Steps

1. **Ensure the deprecated package emits a clear warning**:
   ```python
   # attack_v19_core/__init__.py
   import warnings
   warnings.warn(
       "attack_v19_core is deprecated and will be removed in 2026. "
       "Migrate to 'attack-core': pip install attack-core",
       DeprecationWarning,
       stacklevel=2,
   )
   from attack_core import *  # Re-export for backward compat
   ```
2. **Publish a final version of `attack-v19-core`** that:
   - Depends on `attack-core` as a hard dependency.
   - Re-exports all public APIs (shim package).
   - Emits `DeprecationWarning` on every import.
3. **Update PyPI project description** for `attack-v19-core` to show:
   - "⚠️ DEPRECATED — use `attack-core` instead."
   - Link to migration guide.
4. **Add to README** migration instructions with before/after import examples.

### Migration Guide for Consumers

```diff
- from attack_v19_core import AttackIndex
+ from attack_core import AttackIndex

- pip install attack-v19-core
+ pip install attack-core
```

All public APIs remain identical. No code changes beyond the import path.

### Prevention
- Set a removal date (e.g., 2026-06-01) and automate a reminder.
- Track download stats on PyPI; if `attack-v19-core` downloads stay high, send targeted outreach.
- Include migration notice in release notes of every `attack-core` version.

---

## General Incident Response Checklist

- [ ] Incident identified and severity assigned
- [ ] Tracking issue opened with `incident` label
- [ ] Immediate mitigation applied
- [ ] Root cause identified
- [ ] Fix implemented and tested
- [ ] Release published (if code change needed)
- [ ] Consumers notified
- [ ] Post-mortem written (for High/Critical)
- [ ] Prevention measures added to CI/automation
