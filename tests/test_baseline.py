"""
Tests for src/baseline/ — profiles, engine, windows, snapshots.

No live Neo4j or Spark required.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch


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

import pytest

from src.baseline.engine import BaselineEngine, anomaly_score, iqr_bounds, z_score
from src.baseline.profile import BaselineStore, DeviceBaselineProfile
from src.baseline.snapshot import SnapshotManager
from src.baseline.windows import (
    SLIDING_WINDOW_S,
    TUMBLING_WINDOW_S,
    build_sliding_window,
    build_tumbling_window,
)


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

class TestZScore:
    def test_z_score_positive(self):
        assert z_score(10.0, 5.0, 2.0) == pytest.approx(2.5)

    def test_z_score_negative(self):
        assert z_score(0.0, 5.0, 2.0) == pytest.approx(-2.5)

    def test_z_score_zero_std_returns_zero(self):
        assert z_score(10.0, 5.0, 0.0) == 0.0

    def test_z_score_at_mean(self):
        assert z_score(5.0, 5.0, 2.0) == 0.0


class TestIQRBounds:
    def test_bounds_on_normal_data(self):
        values = list(range(1, 101))  # 1..100
        lower, upper = iqr_bounds(values)
        # Q1=25.75, Q3=75.25, IQR=49.5; fences outside the data range
        assert lower < 1
        assert upper > 100

    def test_too_few_values(self):
        lower, upper = iqr_bounds([1.0, 2.0])
        assert lower == 0.0
        assert upper == float("inf")

    def test_exactly_four_values(self):
        lower, upper = iqr_bounds([1.0, 2.0, 3.0, 4.0])
        assert isinstance(lower, float)
        assert isinstance(upper, float)


class TestAnomalyScore:
    def _profile(self, mean=250.0, std=25.0, intervals=None):
        p = DeviceBaselineProfile(
            ip="10.0.1.1",
            baseline_start=0.0,
            baseline_end=86400.0,
            interval_mean=mean,
            interval_std=std,
            raw_intervals=intervals or [200.0, 225.0, 250.0, 275.0, 300.0],
        )
        return p

    def test_normal_value_not_anomalous(self):
        score = anomaly_score(255.0, self._profile())
        assert not score["anomalous"]

    def test_extreme_value_is_anomalous(self):
        score = anomaly_score(1000.0, self._profile())
        assert score["z_anomalous"]

    def test_iqr_flags_outlier(self):
        # Use baseline with tight distribution, outlier at 2000ms
        profile = self._profile(
            mean=250.0, std=10.0,
            intervals=[240.0, 245.0, 250.0, 255.0, 260.0]
        )
        score = anomaly_score(2000.0, profile)
        assert score["iqr_anomalous"]

    def test_score_keys_present(self):
        score = anomaly_score(250.0, self._profile())
        for key in ("z_score", "z_anomalous", "iqr_lower", "iqr_upper",
                    "iqr_anomalous", "anomalous"):
            assert key in score


# ---------------------------------------------------------------------------
# BaselineStore
# ---------------------------------------------------------------------------

class TestBaselineStore:
    def _profile(self, ip="10.0.1.1"):
        return DeviceBaselineProfile(ip=ip, baseline_start=0.0, baseline_end=86400.0)

    def test_put_and_get(self):
        store = BaselineStore()
        p = self._profile()
        store.put(p)
        assert store.get("10.0.1.1") is p

    def test_get_nonexistent_returns_none(self):
        store = BaselineStore()
        assert store.get("99.99.99.99") is None

    def test_len(self):
        store = BaselineStore()
        store.put(self._profile("10.0.1.1"))
        store.put(self._profile("10.0.1.2"))
        assert len(store) == 2

    def test_contains(self):
        store = BaselineStore()
        store.put(self._profile())
        assert "10.0.1.1" in store
        assert "10.0.1.2" not in store

    def test_all_returns_list(self):
        store = BaselineStore()
        for i in range(3):
            store.put(self._profile(f"10.0.1.{i}"))
        assert len(store.all()) == 3


# ---------------------------------------------------------------------------
# DeviceBaselineProfile serialisation
# ---------------------------------------------------------------------------

class TestDeviceBaselineProfile:
    def test_to_dict_and_from_dict_roundtrip(self):
        p = DeviceBaselineProfile(
            ip="10.0.1.1",
            baseline_start=1700000000.0,
            baseline_end=1700086400.0,
            interval_mean=250.0,
            interval_std=15.0,
            packet_rate_mean=4.0,
            protocols=["modbus", "tcp"],
            peer_count=2,
            periodic_edge_count=1,
            total_edges=2,
        )
        d = p.to_dict()
        p2 = DeviceBaselineProfile.from_dict(d)
        assert p2.ip == p.ip
        assert p2.interval_mean == p.interval_mean
        assert p2.protocols == p.protocols


# ---------------------------------------------------------------------------
# BaselineEngine
# ---------------------------------------------------------------------------

class TestBaselineEngine:
    def _make_edge_session(self, edges):
        """Return a mock session whose .run() yields _Row records."""
        session = MagicMock()
        edge_recs = [_Row(e) for e in edges]
        edge_result = MagicMock()
        edge_result.__iter__ = MagicMock(return_value=iter(edge_recs))
        session.run = MagicMock(return_value=edge_result)
        return session

    def test_capture_device_builds_profile(self):
        now = time.time()
        edges = [
            {
                "protocol": "modbus", "avg_interval_ms": 250.0,
                "packet_count": 100, "is_periodic": True,
                "first_seen": now - 3600, "last_seen": now - 100,
                "dst_ip": "10.0.2.1",
            }
        ]
        session = self._make_edge_session(edges)
        engine = BaselineEngine(driver=MagicMock())
        profile = engine.capture_device(session, "10.0.1.1", now - 86400, now)
        assert profile is not None
        assert profile.ip == "10.0.1.1"
        assert profile.interval_mean == pytest.approx(250.0)
        assert profile.periodic_edge_count == 1

    def test_capture_device_returns_none_for_no_edges(self):
        session = self._make_edge_session([])
        engine = BaselineEngine(driver=MagicMock())
        profile = engine.capture_device(session, "10.0.1.1", 0.0, time.time())
        assert profile is None

    def test_score_device_interval_not_anomalous(self):
        engine = BaselineEngine(driver=MagicMock())
        profile = DeviceBaselineProfile(
            ip="10.0.1.1",
            baseline_start=0.0,
            baseline_end=86400.0,
            interval_mean=250.0,
            interval_std=20.0,
            raw_intervals=[230.0, 240.0, 250.0, 260.0, 270.0],
        )
        result = engine.score_device_interval(profile, 252.0)
        assert not result["anomalous"]

    def test_score_device_interval_anomalous(self):
        engine = BaselineEngine(driver=MagicMock())
        profile = DeviceBaselineProfile(
            ip="10.0.1.1",
            baseline_start=0.0,
            baseline_end=86400.0,
            interval_mean=250.0,
            interval_std=10.0,
            raw_intervals=[240.0, 245.0, 250.0, 255.0, 260.0],
        )
        result = engine.score_device_interval(profile, 5000.0)
        assert result["anomalous"]


# ---------------------------------------------------------------------------
# Windows (no Spark required — test constants only)
# ---------------------------------------------------------------------------

class TestWindowConstants:
    def test_tumbling_window_is_five_minutes(self):
        assert TUMBLING_WINDOW_S == 300

    def test_sliding_window_is_thirty_minutes(self):
        assert SLIDING_WINDOW_S == 1800

    def test_build_tumbling_returns_none_without_pyspark(self):
        # PySpark not installed — function should return None gracefully
        result = build_tumbling_window(MagicMock())
        assert result is None

    def test_build_sliding_returns_none_without_pyspark(self):
        result = build_sliding_window(MagicMock())
        assert result is None


# ---------------------------------------------------------------------------
# SnapshotManager
# ---------------------------------------------------------------------------

class TestSnapshotManager:
    def _profile(self, ip="10.0.1.1"):
        return DeviceBaselineProfile(
            ip=ip,
            baseline_start=1700000000.0,
            baseline_end=1700086400.0,
            captured_at=1700086500.0,
            interval_mean=250.0,
            interval_std=15.0,
            protocols=["modbus"],
            peer_count=1,
            periodic_edge_count=1,
            total_edges=1,
        )

    def test_save_calls_session_run(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        mgr = SnapshotManager(driver=MagicMock())
        mgr.save(session, self._profile())
        session.run.assert_called_once()

    def test_save_survives_neo4j_error(self):
        session = MagicMock()
        session.run = MagicMock(side_effect=Exception("down"))
        mgr = SnapshotManager(driver=MagicMock())
        mgr.save(session, self._profile())  # Should not raise

    def test_load_returns_none_when_no_record(self):
        session = MagicMock()
        result = MagicMock()
        result.single = MagicMock(return_value=None)
        session.run = MagicMock(return_value=result)
        mgr = SnapshotManager(driver=MagicMock())
        assert mgr.load(session, "10.0.1.1") is None

    def test_load_deserialises_profile(self):
        p = self._profile()
        session = MagicMock()
        result = MagicMock()
        result.single = MagicMock(return_value=_Row(p.to_dict()))
        session.run = MagicMock(return_value=result)
        mgr = SnapshotManager(driver=MagicMock())
        loaded = mgr.load(session, "10.0.1.1")
        assert loaded is not None
        assert loaded.ip == "10.0.1.1"
        assert loaded.interval_mean == pytest.approx(250.0)

    def test_save_all_returns_count(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        store = BaselineStore()
        for i in range(3):
            store.put(self._profile(f"10.0.1.{i}"))
        mgr = SnapshotManager(driver=MagicMock())
        count = mgr.save_all(session, store)
        assert count == 3
