"""
In-memory indexes over all loaded techniques. O(1) lookups.
"""
from typing import Dict, List, Optional, Union
from .models import Domain, Tactic, Technique, SubTechnique
from .loader import ATTACKLoader

TechniqueOrSub = Union[Technique, SubTechnique]


class ATTACKIndex:
    def __init__(self, loader: ATTACKLoader):
        self._by_id: Dict[str, TechniqueOrSub] = {}
        self._by_tactic: Dict[str, List[str]] = {}
        self._by_platform: Dict[str, List[str]] = {}
        self._tactics: Dict[str, Tactic] = {}

        for domain in Domain:
            for tac in loader.get_tactics(domain):
                self._tactics[tac.attack_id] = tac

            for tech in loader.get_techniques(domain):
                self._by_id[tech.attack_id] = tech
                for tac_id in tech.tactic_ids:
                    self._by_tactic.setdefault(tac_id, []).append(tech.attack_id)
                for plat in tech.platforms:
                    self._by_platform.setdefault(plat.lower(), []).append(tech.attack_id)

            for sub in loader.get_subtechniques(domain):
                self._by_id[sub.attack_id] = sub

        # Build phase-name -> tactic-id mapping for by_tactic() lookups
        # ATT&CK uses phase names ('initial-access') internally, but callers
        # often query by ID ('TA0001'). Support both.
        self._phase_to_id: Dict[str, str] = {}
        self._id_to_phase: Dict[str, str] = {}
        for tac in self._tactics.values():
            # Derive phase name from tactic name (lowercase, spaces->hyphens)
            phase = tac.name.lower().replace(' ', '-')
            self._phase_to_id[phase] = tac.attack_id
            self._id_to_phase[tac.attack_id] = phase

    def get(self, attack_id: str) -> Optional[TechniqueOrSub]:
        return self._by_id.get(attack_id)

    def by_tactic(self, tactic_id: str) -> List[TechniqueOrSub]:
        """Look up techniques by tactic ID ('TA0001') or phase name ('initial-access')."""
        # Resolve ATT&CK ID to phase name if needed
        key = self._id_to_phase.get(tactic_id, tactic_id)
        return [self._by_id[tid] for tid in self._by_tactic.get(key, []) if tid in self._by_id]

    def by_platform(self, platform: str) -> List[TechniqueOrSub]:
        return [self._by_id[tid] for tid in self._by_platform.get(platform.lower(), []) if tid in self._by_id]

    def search(self, keyword: str) -> List[TechniqueOrSub]:
        kw = keyword.lower()
        return [t for t in self._by_id.values() if kw in t.name.lower() or kw in t.description.lower()]

    def count_techniques(self, domain: Optional[Domain] = None) -> int:
        return sum(1 for t in self._by_id.values()
                   if not t.is_subtechnique
                   and (domain is None or t.domain == domain))

    def count_subtechniques(self, domain: Optional[Domain] = None) -> int:
        return sum(1 for t in self._by_id.values()
                   if t.is_subtechnique
                   and (domain is None or t.domain == domain))
    def get_subtechniques_of(self, parent_attack_id: str) -> list:
        """Return all sub-techniques whose parent_id matches parent_attack_id."""
        return [
            t for t in self._by_id.values()
            if t.is_subtechnique and getattr(t, 'parent_id', '') == parent_attack_id
        ]
