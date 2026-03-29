"""
Tests for src/detect/queries.py

All Neo4j interactions are mocked — no live database required.
Each test verifies:
  - The correct Cypher snippet is issued (query contains expected clauses)
  - The correct parameters are passed
  - The returned list-of-dicts matches the mocked records
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

from src.detect.queries import (
    cross_zone_violations,
    interval_deviation,
    new_devices,
    new_edges,
    unknown_protocol,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _mock_session(*rows: dict) -> MagicMock:
    """
    Build a mock Neo4j session whose .run() returns an iterable of
    MagicMock records that behave like dicts when passed to dict().
    """
    session = MagicMock()
    mock_records = []
    for row in rows:
        rec = MagicMock()
        # dict(record) calls record.keys() + record.__getitem__
        rec.keys.return_value = list(row.keys())
        rec.__iter__ = MagicMock(return_value=iter(row.items()))
        # Make dict(rec) work via the mapping protocol
        rec.__class__ = _DictLikeRecord
        rec._data = row
        mock_records.append(rec)
    session.run.return_value = iter(mock_records)
    return session


class _DictLikeRecord:
    """Minimal mapping that dict() can consume."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def keys(self):  # type: ignore[override]
        return self._data.keys()

    def __getitem__(self, key):  # type: ignore[override]
        return self._data[key]

    def __iter__(self):  # type: ignore[override]
        return iter(self._data)


def _make_record(data: dict) -> _DictLikeRecord:
    return _DictLikeRecord(data)


def _session_returning(*rows: dict) -> MagicMock:
    """Return a mock session whose .run() yields _DictLikeRecord objects."""
    session = MagicMock()
    session.run.return_value = iter(_make_record(r) for r in rows)
    return session


# ---------------------------------------------------------------------------
# 1. cross_zone_violations
# ---------------------------------------------------------------------------

class TestCrossZoneViolations:
    def test_returns_empty_when_no_violations(self) -> None:
        session = _session_returning()
        result = cross_zone_violations(session)
        assert result == []
        session.run.assert_called_once()

    def test_query_contains_abs_level_check(self) -> None:
        session = _session_returning()
        cross_zone_violations(session)
        query = session.run.call_args[0][0]
        assert "abs(z1.purdue_level - z2.purdue_level) > 1" in query

    def test_query_matches_communicates_with(self) -> None:
        session = _session_returning()
        cross_zone_violations(session)
        query = session.run.call_args[0][0]
        assert "COMMUNICATES_WITH" in query

    def test_returns_correct_dicts(self) -> None:
        row = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_zone": "field",
            "dst_zone": "enterprise",
            "src_level": 1,
            "dst_level": 4,
            "protocol": "modbus",
            "port": 502,
            "packet_count": 5,
        }
        session = _session_returning(row)
        result = cross_zone_violations(session)
        assert len(result) == 1
        assert result[0] == row

    def test_returns_multiple_violations(self) -> None:
        rows = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.5", "src_zone": "a",
             "dst_zone": "b", "src_level": 0, "dst_level": 3,
             "protocol": "dnp3", "port": 20000, "packet_count": 12},
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.6", "src_zone": "c",
             "dst_zone": "d", "src_level": 1, "dst_level": 4,
             "protocol": "modbus", "port": 502, "packet_count": 3},
        ]
        session = _session_returning(*rows)
        result = cross_zone_violations(session)
        assert len(result) == 2
        assert result[0]["src_ip"] == "10.0.0.1"
        assert result[1]["src_ip"] == "10.0.0.2"


# ---------------------------------------------------------------------------
# 2. new_devices
# ---------------------------------------------------------------------------

BASELINE_DT = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
BASELINE_EPOCH = BASELINE_DT.timestamp()


class TestNewDevices:
    def test_returns_empty_when_no_new_devices(self) -> None:
        session = _session_returning()
        result = new_devices(session, BASELINE_DT)
        assert result == []

    def test_passes_epoch_as_parameter(self) -> None:
        session = _session_returning()
        new_devices(session, BASELINE_DT)
        _, kwargs = session.run.call_args
        assert kwargs.get("baseline_end") == pytest.approx(BASELINE_EPOCH)

    def test_query_filters_first_seen_after_baseline(self) -> None:
        session = _session_returning()
        new_devices(session, BASELINE_DT)
        query = session.run.call_args[0][0]
        assert "d.first_seen > $baseline_end" in query

    def test_returns_correct_dicts(self) -> None:
        row = {
            "ip": "192.168.1.50",
            "mac": None,
            "role": None,
            "first_seen": BASELINE_EPOCH + 3600,
            "last_seen": BASELINE_EPOCH + 7200,
        }
        session = _session_returning(row)
        result = new_devices(session, BASELINE_DT)
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.50"

    def test_handles_naive_datetime_by_calling_timestamp(self) -> None:
        """new_devices must work even if a naive datetime is passed."""
        naive_dt = datetime(2024, 6, 15, 12, 0, 0)  # no tzinfo
        session = _session_returning()
        # Should not raise
        new_devices(session, naive_dt)
        _, kwargs = session.run.call_args
        assert "baseline_end" in kwargs

    def test_multiple_new_devices(self) -> None:
        rows = [
            {"ip": "10.1.1.1", "mac": None, "role": None,
             "first_seen": BASELINE_EPOCH + 100, "last_seen": BASELINE_EPOCH + 200},
            {"ip": "10.1.1.2", "mac": "de:ad:be:ef:00:01", "role": "plc",
             "first_seen": BASELINE_EPOCH + 150, "last_seen": BASELINE_EPOCH + 250},
        ]
        session = _session_returning(*rows)
        result = new_devices(session, BASELINE_DT)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 3. new_edges
# ---------------------------------------------------------------------------

class TestNewEdges:
    def test_returns_empty_when_no_new_edges(self) -> None:
        session = _session_returning()
        result = new_edges(session, BASELINE_DT)
        assert result == []

    def test_passes_epoch_as_parameter(self) -> None:
        session = _session_returning()
        new_edges(session, BASELINE_DT)
        _, kwargs = session.run.call_args
        assert kwargs.get("baseline_end") == pytest.approx(BASELINE_EPOCH)

    def test_query_filters_first_seen_after_baseline(self) -> None:
        session = _session_returning()
        new_edges(session, BASELINE_DT)
        query = session.run.call_args[0][0]
        assert "r.first_seen > $baseline_end" in query

    def test_query_targets_communicates_with(self) -> None:
        session = _session_returning()
        new_edges(session, BASELINE_DT)
        query = session.run.call_args[0][0]
        assert "COMMUNICATES_WITH" in query

    def test_returns_correct_dicts(self) -> None:
        row = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "modbus",
            "port": 502,
            "function_code": "READ_COILS",
            "first_seen": BASELINE_EPOCH + 500,
            "packet_count": 7,
        }
        session = _session_returning(row)
        result = new_edges(session, BASELINE_DT)
        assert len(result) == 1
        assert result[0]["protocol"] == "modbus"

    def test_multiple_new_edges(self) -> None:
        rows = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "protocol": "dnp3",
             "port": 20000, "function_code": "READ", "first_seen": BASELINE_EPOCH + 1,
             "packet_count": 1},
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.4", "protocol": "s7comm",
             "port": 102, "function_code": "READ_VAR", "first_seen": BASELINE_EPOCH + 2,
             "packet_count": 2},
        ]
        session = _session_returning(*rows)
        result = new_edges(session, BASELINE_DT)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 4. interval_deviation
# ---------------------------------------------------------------------------

class TestIntervalDeviation:
    def test_returns_empty_when_no_deviations(self) -> None:
        session = _session_returning()
        result = interval_deviation(session)
        assert result == []

    def test_default_bounds_passed_as_parameters(self) -> None:
        session = _session_returning()
        interval_deviation(session)
        _, kwargs = session.run.call_args
        assert kwargs["min_ms"] == pytest.approx(100.0)
        assert kwargs["max_ms"] == pytest.approx(1000.0)

    def test_custom_bounds_passed_correctly(self) -> None:
        session = _session_returning()
        interval_deviation(session, min_ms=50.0, max_ms=500.0)
        _, kwargs = session.run.call_args
        assert kwargs["min_ms"] == pytest.approx(50.0)
        assert kwargs["max_ms"] == pytest.approx(500.0)

    def test_query_checks_packet_count_gt_one(self) -> None:
        session = _session_returning()
        interval_deviation(session)
        query = session.run.call_args[0][0]
        assert "r.packet_count > 1" in query

    def test_query_uses_min_ms_and_max_ms_params(self) -> None:
        session = _session_returning()
        interval_deviation(session)
        query = session.run.call_args[0][0]
        assert "$min_ms" in query
        assert "$max_ms" in query

    def test_returns_correct_dicts(self) -> None:
        row = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "modbus",
            "port": 502,
            "function_code": "READ_COILS",
            "avg_interval_ms": 50.0,
            "packet_count": 100,
            "is_periodic": False,
        }
        session = _session_returning(row)
        result = interval_deviation(session)
        assert len(result) == 1
        assert result[0]["avg_interval_ms"] == 50.0

    def test_fast_polling_below_min(self) -> None:
        """Edge with avg_interval_ms < min_ms should be returned."""
        row = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "dnp3",
               "port": 20000, "function_code": "READ", "avg_interval_ms": 10.0,
               "packet_count": 200, "is_periodic": False}
        session = _session_returning(row)
        result = interval_deviation(session, min_ms=100.0, max_ms=1000.0)
        assert len(result) == 1
        assert result[0]["avg_interval_ms"] == 10.0

    def test_slow_polling_above_max(self) -> None:
        """Edge with avg_interval_ms > max_ms should be returned."""
        row = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "modbus",
               "port": 502, "function_code": "READ_HOLDING", "avg_interval_ms": 5000.0,
               "packet_count": 10, "is_periodic": False}
        session = _session_returning(row)
        result = interval_deviation(session, min_ms=100.0, max_ms=1000.0)
        assert len(result) == 1
        assert result[0]["avg_interval_ms"] == 5000.0


# ---------------------------------------------------------------------------
# 5. unknown_protocol
# ---------------------------------------------------------------------------

ALLOWED = ["modbus", "dnp3", "s7comm", "tcp", "udp"]


class TestUnknownProtocol:
    def test_returns_empty_when_all_known(self) -> None:
        session = _session_returning()
        result = unknown_protocol(session, ALLOWED)
        assert result == []

    def test_passes_allowed_list_as_parameter(self) -> None:
        session = _session_returning()
        unknown_protocol(session, ALLOWED)
        _, kwargs = session.run.call_args
        assert kwargs["allowed"] == ALLOWED

    def test_query_uses_not_in_allowed(self) -> None:
        session = _session_returning()
        unknown_protocol(session, ALLOWED)
        query = session.run.call_args[0][0]
        assert "NOT r.protocol IN $allowed" in query

    def test_returns_correct_dicts(self) -> None:
        row = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.6",
            "protocol": "bacnet",
            "port": 47808,
            "function_code": "flow",
            "packet_count": 3,
            "first_seen": 1_700_000_000.0,
        }
        session = _session_returning(row)
        result = unknown_protocol(session, ALLOWED)
        assert len(result) == 1
        assert result[0]["protocol"] == "bacnet"

    def test_empty_allowed_list_returns_all_edges(self) -> None:
        """If allowed is empty, every edge is unknown."""
        rows = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "modbus",
             "port": 502, "function_code": "READ_COILS", "packet_count": 10,
             "first_seen": 1_700_000_001.0},
            {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "protocol": "dnp3",
             "port": 20000, "function_code": "READ", "packet_count": 5,
             "first_seen": 1_700_000_002.0},
        ]
        session = _session_returning(*rows)
        result = unknown_protocol(session, [])
        assert len(result) == 2

    def test_multiple_unknown_protocols(self) -> None:
        rows = [
            {"src_ip": "10.0.0.7", "dst_ip": "10.0.0.8", "protocol": "iec104",
             "port": 2404, "function_code": "flow", "packet_count": 1,
             "first_seen": 1_700_000_010.0},
            {"src_ip": "10.0.0.9", "dst_ip": "10.0.0.10", "protocol": "enip",
             "port": 44818, "function_code": "flow", "packet_count": 2,
             "first_seen": 1_700_000_020.0},
        ]
        session = _session_returning(*rows)
        result = unknown_protocol(session, ALLOWED)
        assert len(result) == 2
        protocols = {r["protocol"] for r in result}
        assert protocols == {"iec104", "enip"}
