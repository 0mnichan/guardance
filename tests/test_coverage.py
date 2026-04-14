"""
Tests for src/coverage/ — CoverageModel, GapDetector, SilenceDetector.

No live Neo4j required.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from src.coverage.gaps import GapDetector
from src.coverage.monitor import CoverageModel, CoverageReport, ZoneCoverage
from src.coverage.silence import SilenceDetector, _severity


# ---------------------------------------------------------------------------
# Minimal dict-like Neo4j record stub (supports dict() conversion)
# ---------------------------------------------------------------------------

class _Row:
    """Minimal Neo4j record stub that supports dict() and direct key access."""

    def __init__(self, data: dict) -> None:
        self._d = data

    def keys(self):
        return self._d.keys()

    def __getitem__(self, k):
        return self._d[k]

    def __iter__(self):
        return iter(self._d)

    def get(self, k, default=None):
        return self._d.get(k, default)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _make_single_session(value: dict | None):
    """Session whose .run().single() returns a _Row or None."""
    session = MagicMock()
    result = MagicMock()
    if value is not None:
        result.single = MagicMock(return_value=_Row(value))
    else:
        result.single = MagicMock(return_value=None)
    result.__iter__ = MagicMock(return_value=iter([]))
    session.run = MagicMock(return_value=result)
    return session


def _make_iter_session(rows: list[dict]):
    """Session whose .run() always returns the given rows as _Row objects."""
    session = MagicMock()
    recs = [_Row(r) for r in rows]
    result = MagicMock()
    result.__iter__ = MagicMock(return_value=iter(recs))
    result.single = MagicMock(return_value=recs[0] if recs else None)
    session.run = MagicMock(return_value=result)
    return session


# ---------------------------------------------------------------------------
# CoverageReport
# ---------------------------------------------------------------------------

class TestCoverageReport:
    def test_to_dict_has_required_keys(self):
        report = CoverageReport(
            total_devices=10,
            total_edges=20,
            zones=[ZoneCoverage("Control", 1, 5, 10, 3)],
            coverage_score=0.85,
        )
        d = report.to_dict()
        for key in ("total_devices", "total_edges", "zone_coverage",
                    "empty_zones", "blind_zones", "coverage_score"):
            assert key in d

    def test_zone_coverage_serialised(self):
        report = CoverageReport(
            zones=[ZoneCoverage("Control", 1, 5, 10, 3)],
        )
        d = report.to_dict()
        assert len(d["zone_coverage"]) == 1
        assert d["zone_coverage"][0]["zone"] == "Control"


# ---------------------------------------------------------------------------
# CoverageModel
# ---------------------------------------------------------------------------

class TestCoverageModel:
    def _full_mock_session(
        self,
        total_devices=10,
        total_edges=20,
        zone_rows=None,
        unzoned=0,
        protocols=None,
        asymmetric=None,
    ):
        """Build a session that returns deterministic data for all queries."""
        if zone_rows is None:
            zone_rows = [
                {"zone_name": "Control", "purdue_level": 1,
                 "device_count": 5, "outbound_edges": 10, "inbound_edges": 5},
                {"zone_name": "Field", "purdue_level": 0,
                 "device_count": 3, "outbound_edges": 0, "inbound_edges": 3},
            ]
        if protocols is None:
            protocols = [{"protocol": "modbus"}, {"protocol": "dnp3"}]
        if asymmetric is None:
            asymmetric = []

        call_count = [0]

        def _result_from_rows(rows):
            recs = [_Row(r) for r in rows]
            result = MagicMock()
            result.__iter__ = MagicMock(return_value=iter(recs))
            result.single = MagicMock(return_value=recs[0] if recs else None)
            return result

        def run_side_effect(query, **kwargs):
            c = call_count[0]
            call_count[0] += 1
            if c == 0:    # total devices
                return _result_from_rows([{"total": total_devices}])
            elif c == 1:  # total edges
                return _result_from_rows([{"total": total_edges}])
            elif c == 2:  # zone stats
                return _result_from_rows(zone_rows)
            elif c == 3:  # unzoned
                return _result_from_rows([{"total": unzoned}])
            elif c == 4:  # protocols
                return _result_from_rows(protocols)
            elif c == 5:  # asymmetric
                return _result_from_rows(asymmetric)
            return _result_from_rows([])

        session = MagicMock()
        session.run = MagicMock(side_effect=run_side_effect)
        return session

    def test_assess_returns_report(self):
        session = self._full_mock_session()
        model = CoverageModel(driver=MagicMock())
        report = model.assess(session)
        assert isinstance(report, CoverageReport)

    def test_total_devices_populated(self):
        session = self._full_mock_session(total_devices=7)
        model = CoverageModel(driver=MagicMock())
        report = model.assess(session)
        assert report.total_devices == 7

    def test_blind_zone_detected(self):
        # Field zone has devices but 0 outbound edges → blind spot
        session = self._full_mock_session(
            zone_rows=[
                {"zone_name": "Field", "purdue_level": 0,
                 "device_count": 3, "outbound_edges": 0, "inbound_edges": 0},
            ]
        )
        model = CoverageModel(driver=MagicMock())
        report = model.assess(session)
        assert "Field" in report.blind_zones

    def test_missing_expected_protocols(self):
        session = self._full_mock_session(protocols=[{"protocol": "modbus"}])
        model = CoverageModel(
            driver=MagicMock(),
            expected_protocols=["modbus", "dnp3"],
        )
        report = model.assess(session)
        assert "dnp3" in report.missing_expected

    def test_coverage_score_is_float_in_range(self):
        session = self._full_mock_session()
        model = CoverageModel(driver=MagicMock())
        report = model.assess(session)
        assert 0.0 <= report.coverage_score <= 1.0

    def test_perfect_coverage_score(self):
        # No blind zones, no unzoned, no missing protocols
        session = self._full_mock_session(
            zone_rows=[
                {"zone_name": "Control", "purdue_level": 1,
                 "device_count": 5, "outbound_edges": 10, "inbound_edges": 5},
            ],
            protocols=[{"protocol": p} for p in
                       ["modbus", "dnp3", "s7comm", "iec104", "enip", "opc-ua", "bacnet"]],
        )
        model = CoverageModel(driver=MagicMock())
        report = model.assess(session)
        assert report.coverage_score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# GapDetector
# ---------------------------------------------------------------------------

class TestGapDetector:
    def _iter_session(self, rows):
        recs = [_Row(r) for r in rows]
        result = MagicMock()
        result.__iter__ = MagicMock(return_value=iter(recs))
        session = MagicMock()
        session.run = MagicMock(return_value=result)
        return session

    def test_low_coverage_devices_returns_list(self):
        rows = [{"ip": "10.0.1.1", "out_edges": 0, "in_edges": 1, "total_edges": 1}]
        session = self._iter_session(rows)
        detector = GapDetector(driver=MagicMock())
        result = detector.low_coverage_devices(session)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.1.1"

    def test_sparse_zones_returns_list(self):
        rows = [{"zone": "Field", "purdue_level": 0,
                 "devices": 5, "edges": 1, "edge_density": 0.2}]
        session = self._iter_session(rows)
        detector = GapDetector(driver=MagicMock())
        result = detector.sparse_zones(session)
        assert len(result) == 1

    def test_find_all_gaps_combines_results(self):
        session = MagicMock()
        # Three separate results for three queries
        data = [
            [{"ip": "10.0.1.1", "out_edges": 0, "in_edges": 1, "total_edges": 1}],
            [{"zone": "Field", "purdue_level": 0, "devices": 3, "edges": 0, "edge_density": 0.0}],
            [],
        ]
        data_iter = iter(data)

        def make_result(rows):
            recs = [_Row(r) for r in rows]
            result = MagicMock()
            result.__iter__ = MagicMock(return_value=iter(recs))
            return result

        session.run = MagicMock(side_effect=lambda *a, **kw: make_result(next(data_iter)))
        detector = GapDetector(driver=MagicMock())
        gaps = detector.find_all_gaps(session)
        assert gaps["total_gaps"] == 2


# ---------------------------------------------------------------------------
# SilenceDetector
# ---------------------------------------------------------------------------

class TestSilenceDetector:
    def test_threshold_for_plc_is_five_minutes(self):
        det = SilenceDetector(driver=MagicMock())
        assert det.threshold_for_role("plc") == 5 * 60

    def test_threshold_for_engineering_is_sixty_minutes(self):
        det = SilenceDetector(driver=MagicMock())
        assert det.threshold_for_role("engineering") == 60 * 60

    def test_threshold_for_none_is_default(self):
        det = SilenceDetector(driver=MagicMock(), default_threshold_s=600)
        assert det.threshold_for_role(None) == 600

    def _silence_session(self, rows):
        recs = [_Row(r) for r in rows]
        result = MagicMock()
        result.__iter__ = MagicMock(return_value=iter(recs))
        session = MagicMock()
        session.run = MagicMock(return_value=result)
        return session

    def test_find_silent_devices_returns_flagged(self):
        now = time.time()
        # Device last_seen 20 minutes ago (> 5-min PLC threshold)
        rows = [{"ip": "10.0.1.1", "role": "plc",
                 "last_seen": now - 20 * 60, "silent_for_s": 20 * 60}]
        session = self._silence_session(rows)
        det = SilenceDetector(driver=MagicMock())
        findings = det.find_silent_devices(session, now=now)
        assert len(findings) == 1
        assert findings[0]["ip"] == "10.0.1.1"

    def test_find_silent_devices_skips_recent(self):
        now = time.time()
        # Device last_seen 1 minute ago — not silent for any role
        rows = [{"ip": "10.0.1.1", "role": "plc",
                 "last_seen": now - 60, "silent_for_s": 60}]
        session = self._silence_session(rows)
        det = SilenceDetector(driver=MagicMock())
        findings = det.find_silent_devices(session, now=now)
        assert len(findings) == 0


class TestSeverity:
    def test_low_severity(self):
        # ratio < 2.0 → low; use 1.5x threshold
        assert _severity(450, 300) == "low"

    def test_medium_severity(self):
        # ratio >= 2.0 → medium; 2x threshold
        assert _severity(600, 300) == "medium"

    def test_high_severity(self):
        # ratio >= 6.0 → high; 8x threshold
        assert _severity(2400, 300) == "high"

    def test_exact_threshold_is_low(self):
        # ratio exactly 1.0 → low
        assert _severity(300, 300) == "low"
