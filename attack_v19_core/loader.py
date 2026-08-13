"""
Loads all three ATT&CK STIX bundles from local disk or TAXII server.
Returns fully-typed model instances.
"""
import json
from pathlib import Path
from typing import Dict, List, Tuple
from mitreattack.stix20 import MitreAttackData
from .models import (
    Domain, Tactic, Technique, SubTechnique,
    Group, Software, Mitigation, DataSource
)
from .constants import DOMAINS

_DEFAULT_STIX_DIR = Path.home() / "attack_data"


class ATTACKLoader:
    def __init__(self, stix_dir: Path = _DEFAULT_STIX_DIR):
        self.stix_dir = stix_dir
        self._raw: Dict[str, MitreAttackData] = {}
        self._load_all()

    def _load_all(self):
        for domain_key, filename in [
            ("enterprise", "enterprise-attack.json"),
            ("mobile",     "mobile-attack.json"),
            ("ics",        "ics-attack.json"),
        ]:
            path = self.stix_dir / filename
            if not path.exists():
                raise FileNotFoundError(f"STIX bundle not found: {path}")
            self._raw[domain_key] = MitreAttackData(str(path))

    def get_tactics(self, domain: Domain) -> List[Tactic]:
        src = self._raw[domain.value]
        results = []
        for t in src.get_tactics(remove_revoked_deprecated=True):
            ext = t.get("external_references", [{}])[0]
            results.append(Tactic(
                stix_id=t["id"],
                attack_id=ext.get("external_id", ""),
                name=t["name"],
                description=t.get("description", ""),
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_techniques(self, domain: Domain) -> List[Technique]:
        src = self._raw[domain.value]
        results = []
        for t in src.get_techniques(remove_revoked_deprecated=True):
            if t.get("x_mitre_is_subtechnique"):
                continue
            ext = t.get("external_references", [{}])[0]
            results.append(Technique(
                stix_id=t["id"],
                attack_id=ext.get("external_id", ""),
                name=t["name"],
                description=t.get("description", ""),
                tactic_ids=[kc["phase_name"] for kc in t.get("kill_chain_phases", [])],
                platforms=t.get("x_mitre_platforms", []),
                data_sources=t.get("x_mitre_data_sources", []),
                mitigations=[],
                kill_chain=t.get("kill_chain_phases", []),
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_subtechniques(self, domain: Domain) -> List[SubTechnique]:
        src = self._raw[domain.value]
        results = []
        for t in src.get_techniques(remove_revoked_deprecated=True):
            if not t.get("x_mitre_is_subtechnique"):
                continue
            ext = t.get("external_references", [{}])[0]
            attack_id = ext.get("external_id", "")
            parent_id = attack_id.split(".")[0] if "." in attack_id else ""
            results.append(SubTechnique(
                stix_id=t["id"],
                attack_id=attack_id,
                name=t["name"],
                description=t.get("description", ""),
                parent_id=parent_id,
                tactic_ids=[kc["phase_name"] for kc in t.get("kill_chain_phases", [])],
                platforms=t.get("x_mitre_platforms", []),
                data_sources=t.get("x_mitre_data_sources", []),
                mitigations=[],
                kill_chain=t.get("kill_chain_phases", []),
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_groups(self, domain: Domain) -> List[Group]:
        src = self._raw[domain.value]
        results = []
        for g in src.get_groups(remove_revoked_deprecated=True):
            ext = g.get("external_references", [{}])[0]
            techniques = []
            for ref in g.get("object_refs", []):
                if ref.startswith("attack-pattern--"):
                    tech = src.get_object_by_stix_id(ref)
                    if tech:
                        ext_ref = tech.get("external_references", [{}])[0]
                        techniques.append(ext_ref.get("external_id", ""))
            software = []
            for ref in g.get("object_refs", []):
                if ref.startswith("malware--") or ref.startswith("tool--"):
                    sw = src.get_object_by_stix_id(ref)
                    if sw:
                        ext_ref = sw.get("external_references", [{}])[0]
                        software.append(ext_ref.get("external_id", ""))
            results.append(Group(
                stix_id=g["id"],
                attack_id=ext.get("external_id", ""),
                name=g["name"],
                aliases=g.get("aliases", []),
                description=g.get("description", ""),
                techniques=techniques,
                software=software,
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_software(self, domain: Domain) -> List[Software]:
        src = self._raw[domain.value]
        results = []
        for s in src.get_software(remove_revoked_deprecated=True):
            ext = s.get("external_references", [{}])[0]
            techniques = []
            for ref in s.get("object_refs", []):
                if ref.startswith("attack-pattern--"):
                    tech = src.get_object_by_stix_id(ref)
                    if tech:
                        ext_ref = tech.get("external_references", [{}])[0]
                        techniques.append(ext_ref.get("external_id", ""))
            results.append(Software(
                stix_id=s["id"],
                attack_id=ext.get("external_id", ""),
                name=s["name"],
                software_type=s.get("x_mitre_type", "malware"),
                platforms=s.get("x_mitre_platforms", []),
                techniques=techniques,
                description=s.get("description", ""),
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_mitigations(self, domain: Domain) -> List[Mitigation]:
        src = self._raw[domain.value]
        results = []
        for m in src.get_mitigations(remove_revoked_deprecated=True):
            ext = m.get("external_references", [{}])[0]
            techniques = []
            for ref in m.get("object_refs", []):
                if ref.startswith("attack-pattern--"):
                    tech = src.get_object_by_stix_id(ref)
                    if tech:
                        ext_ref = tech.get("external_references", [{}])[0]
                        techniques.append(ext_ref.get("external_id", ""))
            results.append(Mitigation(
                stix_id=m["id"],
                attack_id=ext.get("external_id", ""),
                name=m["name"],
                description=m.get("description", ""),
                techniques=techniques,
                domain=domain,
                url=ext.get("url"),
            ))
        return results

    def get_data_sources(self, domain: Domain) -> List[DataSource]:
        src = self._raw[domain.value]
        results = []
        # NOTE: v19 STIX data marks all x-mitre-data-source objects as revoked/deprecated.
        # Passing remove_revoked_deprecated=True returns empty list. Use False to get them.
        for ds in src.get_datasources(remove_revoked_deprecated=False):
            ext = ds.get("external_references", [{}])[0]
            components = ds.get("x_mitre_data_components", [])
            techniques = []
            for ref in ds.get("object_refs", []):
                if ref.startswith("attack-pattern--"):
                    tech = src.get_object_by_stix_id(ref)
                    if tech:
                        ext_ref = tech.get("external_references", [{}])[0]
                        techniques.append(ext_ref.get("external_id", ""))
            results.append(DataSource(
                stix_id=ds["id"],
                attack_id=ext.get("external_id", ""),
                name=ds["name"],
                description=ds.get("description", ""),
                components=components,
                techniques=techniques,
                domain=domain,
                url=ext.get("url"),
            ))
        return results