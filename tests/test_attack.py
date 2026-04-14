"""
Tests for src/attack/ — MITRE ATT&CK for ICS tactics, techniques, loader, mapper.

No live Neo4j required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.attack.loader import AttackLoader
from src.attack.mapper import (
    enrich_finding,
    map_all_findings,
    summary_by_tactic,
)
from src.attack.techniques import (
    SIGNAL_TO_TECHNIQUES,
    TACTIC_BY_ID,
    TACTIC_BY_NAME,
    TACTICS,
    TECHNIQUE_BY_ID,
    TECHNIQUE_BY_NAME,
    TECHNIQUES,
)


# ---------------------------------------------------------------------------
# Technique constants
# ---------------------------------------------------------------------------

class TestTechniqueConstants:
    def test_twelve_tactics_defined(self):
        assert len(TACTICS) == 12

    def test_techniques_defined(self):
        assert len(TECHNIQUES) >= 10

    def test_all_tactics_have_id_prefix_ta(self):
        for t in TACTICS:
            assert t.tactic_id.startswith("TA")

    def test_all_techniques_have_id_prefix_t(self):
        for t in TECHNIQUES:
            assert t.technique_id.startswith("T")

    def test_tactic_by_id_lookup(self):
        assert "TA0102" in TACTIC_BY_ID
        assert TACTIC_BY_ID["TA0102"].name == "Discovery"

    def test_technique_by_id_lookup(self):
        assert "T0840" in TECHNIQUE_BY_ID
        assert "Network Connection" in TECHNIQUE_BY_ID["T0840"].name

    def test_each_technique_has_valid_tactic(self):
        for tech in TECHNIQUES:
            assert tech.tactic_id in TACTIC_BY_ID, (
                f"Technique {tech.technique_id} references unknown tactic {tech.tactic_id}"
            )

    def test_signal_to_techniques_populated(self):
        assert "cross_zone_violation" in SIGNAL_TO_TECHNIQUES
        assert len(SIGNAL_TO_TECHNIQUES["cross_zone_violation"]) > 0

    def test_technique_property_returns_tactic(self):
        tech = TECHNIQUE_BY_ID["T0840"]
        tactic = tech.tactic
        assert tactic is not None
        assert tactic.tactic_id == tech.tactic_id


# ---------------------------------------------------------------------------
# AttackLoader
# ---------------------------------------------------------------------------

class TestAttackLoader:
    def _mock_session(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        return session

    def test_ensure_tactics_runs_for_each_tactic(self):
        session = self._mock_session()
        loader = AttackLoader(driver=MagicMock())
        loader.ensure_tactics(session)
        assert session.run.call_count == len(TACTICS)

    def test_ensure_techniques_runs_for_each_technique(self):
        session = self._mock_session()
        loader = AttackLoader(driver=MagicMock())
        loader.ensure_techniques(session)
        # 2 calls per technique: merge + link
        assert session.run.call_count >= len(TECHNIQUES)

    def test_ensure_all_calls_both(self):
        session = self._mock_session()
        loader = AttackLoader(driver=MagicMock())
        loader.ensure_all(session)
        # Tactics + techniques + links
        assert session.run.call_count >= len(TACTICS) + len(TECHNIQUES)

    def test_loader_survives_session_errors(self):
        session = MagicMock()
        session.run = MagicMock(side_effect=Exception("neo4j down"))
        loader = AttackLoader(driver=MagicMock())
        # Should not raise
        loader.ensure_all(session)


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class TestEnrichFinding:
    def test_cross_zone_finding_gets_techniques(self):
        finding = {
            "src_ip": "10.0.1.1", "dst_ip": "10.0.3.1",
            "src_zone": "Field", "dst_zone": "Enterprise",
            "protocol": "modbus",
        }
        enriched = enrich_finding("cross_zone_violation", finding)
        assert "technique_ids" in enriched
        assert "techniques" in enriched
        assert len(enriched["technique_ids"]) > 0

    def test_write_register_function_code_adds_techniques(self):
        finding = {
            "src_ip": "10.0.1.1",
            "function_code": "WRITE_SINGLE_REGISTER",
        }
        enriched = enrich_finding("new_edge", finding)
        # Write register signal should add more techniques
        assert len(enriched["technique_ids"]) > 0

    def test_enriched_finding_preserves_original_keys(self):
        finding = {"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1"}
        enriched = enrich_finding("new_device", finding)
        assert enriched["src_ip"] == "10.0.1.1"
        assert enriched["dst_ip"] == "10.0.2.1"

    def test_techniques_list_contains_dicts(self):
        finding = {"src_ip": "10.0.1.1"}
        enriched = enrich_finding("unknown_protocol", finding)
        for tech in enriched["techniques"]:
            assert "technique_id" in tech
            assert "name" in tech
            assert "tactic_name" in tech


class TestMapAllFindings:
    def test_maps_all_categories(self):
        findings = {
            "cross_zone_violations": [{"src_ip": "10.0.1.1"}],
            "new_devices":           [{"ip": "10.0.2.1"}],
            "new_edges":             [],
            "interval_deviation":    [],
            "unknown_protocol":      [],
        }
        result = map_all_findings(findings)
        assert set(result.keys()) == set(findings.keys())

    def test_items_are_enriched(self):
        findings = {
            "cross_zone_violations": [{"src_ip": "10.0.1.1", "protocol": "modbus"}],
        }
        result = map_all_findings(findings)
        assert "technique_ids" in result["cross_zone_violations"][0]

    def test_empty_findings_returns_empty(self):
        findings = {"cross_zone_violations": [], "new_devices": []}
        result = map_all_findings(findings)
        assert result["cross_zone_violations"] == []


class TestSummaryByTactic:
    def test_returns_dict_of_counts(self):
        findings = {
            "cross_zone_violations": [
                {"technique_ids": ["T0840"], "tactic_ids": ["TA0102"]},
            ],
        }
        summary = summary_by_tactic(findings)
        assert isinstance(summary, dict)
        assert "Discovery" in summary

    def test_counts_accumulate(self):
        findings = {
            "cross_zone_violations": [
                {"technique_ids": ["T0840"], "tactic_ids": ["TA0102"]},
                {"technique_ids": ["T0840"], "tactic_ids": ["TA0102"]},
            ],
        }
        summary = summary_by_tactic(findings)
        assert summary.get("Discovery", 0) == 2

    def test_empty_findings_returns_empty(self):
        assert summary_by_tactic({}) == {}
