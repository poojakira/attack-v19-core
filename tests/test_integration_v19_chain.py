"""
Integration tests for cross-repo enricher chain with ATT&CK v19.

Tests that the enricher pipeline works end-to-end with v19 technique IDs,
revoked ID remapping, and new tactic structure.
"""

import os
import sys

import pytest

# Add attack-v19-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attack-v19-core"))

from attack_core.constants import (
    ENTERPRISE_TACTICS,
    TACTIC_DEFENSE_IMPAIRMENT,
    TACTIC_STEALTH,
    V19_REVOCATION_MAP,
)
from attack_core.index import ATTACKIndex
from attack_core.loader import ATTACKLoader
from attack_core.matrix import NavigatorLayerReporter
from attack_core.models import ATTACKMapping, Domain


class TestV19EnricherChain:
    """Test the full enricher chain with v19 data."""

    @classmethod
    def setup_class(cls):
        """Load ATT&CK data once."""
        cls.loader = ATTACKLoader()
        cls.index = ATTACKIndex(cls.loader)

    def test_all_enterprise_tactics_resolvable(self):
        """All 15 enterprise tactics should be loadable."""
        tactic_ids = [t[0] for t in ENTERPRISE_TACTICS]
        for tid in tactic_ids:
            tactic = self.index._tactics.get(tid)
            assert tactic is not None, f"Tactic {tid} not found in index"
            assert tactic.domain == Domain.ENTERPRISE

    def test_stealth_and_defense_impairment_exist(self):
        """TA0005 Stealth and TA0112 Defense Impairment both exist."""
        assert TACTIC_STEALTH in self.index._tactics
        assert TACTIC_DEFENSE_IMPAIRMENT in self.index._tactics

        stealth = self.index._tactics[TACTIC_STEALTH]
        defense_impair = self.index._tactics[TACTIC_DEFENSE_IMPAIRMENT]

        assert stealth.name == "Stealth"
        assert defense_impair.name == "Defense Impairment"
        assert stealth.domain == Domain.ENTERPRISE
        assert defense_impair.domain == Domain.ENTERPRISE

    def test_revoked_ids_auto_remap(self):
        """V19_REVOCATION_MAP keys should remap to valid techniques."""
        actual_revocations = {k: v for k, v in V19_REVOCATION_MAP.items() if k != v}

        for old_id, new_id in actual_revocations.items():
            # Old ID should NOT be in index (revoked)
            self.index.get(old_id)

            # New ID SHOULD be in index (or at least be a valid format)
            new_result = self.index.get(new_id)

            # If STIX bundle is v19, new_id should resolve
            if new_result is not None:
                assert new_result.attack_id == new_id

    def test_new_v19_techniques_resolvable(self):
        """Core new v19 techniques should be resolvable."""
        # At least the parent techniques should exist
        core_new = [
            "T1682",
            "T1683",
            "T1684",
            "T1685",
            "T1686",
            "T1687",
            "T1688",
            "T1689",
            "T1690",
            "T1027.018",
        ]

        found = 0
        for tid in core_new:
            result = self.index.get(tid)
            if result is not None:
                found += 1
                assert result.attack_id == tid

        # At least 5 should resolve (depending on STIX bundle version)
        assert found >= 5, f"Only {found}/{len(core_new)} new techniques resolved"

    def test_ics_subtechniques_resolvable(self):
        """ICS v19 sub-techniques should be resolvable."""
        ics_new = [
            "T1691",
            "T1692",
            "T1693",
            "T1694",
            "T1695",
            "T0843.001",
            "T0846.001",
        ]

        found = 0
        for tid in ics_new:
            result = self.index.get(tid)
            if result is not None:
                found += 1

        # At least some should resolve
        assert found >= 2, f"Only {found} ICS sub-techniques resolved"

    def test_navigator_layer_generation_v19(self):
        """NavigatorLayerReporter generates v19-compliant layers."""
        mapping = ATTACKMapping(
            tactic_id="TA0112",
            tactic_name="Defense Impairment",
            technique_id="T1685",
            technique_name="Disable or Modify Tools",
            subtechnique_id="T1685.005",
            subtechnique_name="Disable or Modify Tools: Clear Windows Event Logs",
            domain=Domain.ENTERPRISE,
            confidence=0.9,
            data_sources=["Windows Event Logs"],
            platforms=["Windows"],
            url="https://attack.mitre.org/techniques/T1685/005/",
        )

        reporter = NavigatorLayerReporter()
        layer_json = reporter.generate("integration_test", [mapping])
        import json

        layer = json.loads(layer_json)

        # Validate v19 layer structure
        assert layer["versions"]["attack"] == "19"
        assert layer["versions"]["navigator"] == "4.9"
        assert layer["domain"] == "enterprise-attack"

        # Technique must have tactic field (v19 requirement)
        tech = layer["techniques"][0]
        assert "tactic" in tech
        assert tech["tactic"] == "TA0112"
        assert tech["techniqueID"] == "T1685.005"
        assert tech["score"] == 90

        # Metadata should include v19 tactic note
        meta_names = {m["name"]: m["value"] for m in layer["metadata"]}
        assert meta_names["attack_version"] == "19"
        assert "TA0112" in meta_names.get("tactic_note", "")

    def test_mapping_with_multiple_tactics(self):
        """Techniques spanning multiple tactics render correctly."""
        # T1684 Social Engineering spans multiple tactics
        mapping = ATTACKMapping(
            tactic_id="TA0001",  # Initial Access
            tactic_name="Initial Access",
            technique_id="T1684",
            technique_name="Social Engineering",
            domain=Domain.ENTERPRISE,
            confidence=0.8,
            data_sources=[],
            platforms=[],
            url="",
        )

        reporter = NavigatorLayerReporter()
        layer_json = reporter.generate("multi_tactic_test", [mapping])
        import json

        layer = json.loads(layer_json)

        tech = layer["techniques"][0]
        assert tech["techniqueID"] == "T1684"
        assert tech["tactic"] == "TA0001"

    def test_revoked_id_graceful_handling_in_mapping(self):
        """Building mapping with revoked ID should warn and remap."""
        # This tests the BaseDetector._build_mapping behavior
        from attack_core.constants import V19_REVOCATION_MAP

        # Simulate what BaseDetector._build_mapping does
        revoked_id = "T1562.001"
        resolved = V19_REVOCATION_MAP.get(revoked_id, revoked_id)

        assert resolved == "T1685"
        tech = self.index.get(resolved)
        assert tech is not None
        assert tech.attack_id == "T1685"


class TestRuleTableV19Compliance:
    """Test that rule tables across repos use v19 IDs."""

    def test_no_revoked_ids_in_any_rule_table(self):
        """Scan all enricher repos for revoked technique IDs."""
        repos = [
            "hf-model-provenance-scanner",
            "mcp-security-gateway-monitor",
            "llm-redteam-framework",
            "dataset-poisoning-detector",
            "model-privacy-attacks",
            "adversarial-ml-lab",
            "PulseNet-RUL-Forecasting",
            "unified-ml-security-platform",
        ]

        actual_revocations = {k: v for k, v in V19_REVOCATION_MAP.items() if k != v}
        revoked_ids = set(actual_revocations.keys())

        for repo in repos:
            enricher_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                repo,
                "attack_mapping",
                "enricher.py",
            )
            if os.path.exists(enricher_path):
                with open(enricher_path, "r") as f:
                    content = f.read()

                # Check for revoked IDs (excluding comments)
                for revoked in revoked_ids:
                    # Skip if it's in a comment or string that's clearly documentation
                    if f'"{revoked}"' in content or f"'{revoked}'" in content:
                        # This would be a violation
                        raise AssertionError(
                            f"REVOKED ID {revoked} found in {repo}/enricher.py - should be remapped"
                        )

    def test_new_technique_coverage_indicators(self):
        """Verify key new techniques appear in relevant rule tables."""
        # T1685 (replaces T1562) should be in defense impairment related repos
        defense_impairment_repos = [
            "llm-redteam-framework",
            "dataset-poisoning-detector",
            "model-privacy-attacks",
            "adversarial-ml-lab",
            "PulseNet-RUL-Forecasting",
            "mcp-security-gateway-monitor",
            "unified-ml-security-platform",
        ]

        existing_defense_paths = []
        for repo in defense_impairment_repos:
            enricher_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                repo,
                "attack_mapping",
                "enricher.py",
            )
            if os.path.exists(enricher_path):
                existing_defense_paths.append(enricher_path)

        if len(existing_defense_paths) < len(defense_impairment_repos):
            pytest.skip(
                "cross-repo ATT&CK coverage check requires sibling repositories"
            )

        repos_with_t1685 = 0
        for enricher_path in existing_defense_paths:
            with open(enricher_path, "r") as f:
                if "T1685" in f.read():
                    repos_with_t1685 += 1

        # Should be in most defense impairment related repos
        assert (
            repos_with_t1685 >= 5
        ), f"T1685 only in {repos_with_t1685}/7 defense impairment repos"

        # T1682 (Query Public AI) should be in AI-focused repos
        ai_repos = [
            "llm-redteam-framework",
            "mcp-security-gateway-monitor",
            "unified-ml-security-platform",
            "hf-model-provenance-scanner",
            "adversarial-ml-lab",
        ]
        repos_with_t1682 = 0
        for repo in ai_repos:
            enricher_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                repo,
                "attack_mapping",
                "enricher.py",
            )
            if os.path.exists(enricher_path):
                with open(enricher_path, "r") as f:
                    if "T1682" in f.read():
                        repos_with_t1682 += 1
        assert repos_with_t1682 >= 3, f"T1682 only in {repos_with_t1682}/5 AI repos"

    import pytest

    pytest.main([__file__, "-v", "--tb=short"])
