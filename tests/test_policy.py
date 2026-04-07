"""
Tests for src/policy/engine.py

All OPA HTTP calls and Neo4j interactions are mocked — no live services
required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.policy.engine import OPAClient, PolicyEngine, _fetch_graph_data


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_BASELINE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _neo4j_session(edges: list[dict], devices: list[dict]) -> MagicMock:
    """
    Build a mock Neo4j session.

    First .run() call returns edge records, second returns device records.
    """
    session = MagicMock()
    edge_records = [_dict_record(e) for e in edges]
    device_records = [_dict_record(d) for d in devices]
    session.run.side_effect = [edge_records, device_records]
    return session


def _dict_record(data: dict) -> MagicMock:
    """Mock a Neo4j record that dict() can consume."""
    rec = MagicMock()
    rec.keys.return_value = list(data.keys())
    rec.__iter__ = MagicMock(return_value=iter(data.items()))

    class _R:
        def __init__(self, d):
            self._d = d
        def keys(self):
            return self._d.keys()
        def __getitem__(self, k):
            return self._d[k]
        def __iter__(self):
            return iter(self._d)
        def get(self, k, default=None):
            return self._d.get(k, default)

    return _R(data)


_SAMPLE_EDGES = [
    {
        "src_ip": "10.0.1.1",
        "dst_ip": "10.0.2.1",
        "protocol": "modbus",
        "port": 502,
        "function_code": "READ_HOLDING_REGISTERS",
        "first_seen": 1700000000.0,
        "last_seen": 1700001000.0,
        "packet_count": 100,
        "avg_interval_ms": 250.0,
        "is_periodic": True,
    }
]

_SAMPLE_DEVICES_RAW = [
    {
        "ip": "10.0.1.1",
        "mac": "aa:bb:cc:dd:ee:01",
        "role": "plc",
        "first_seen": 1699900000.0,
        "last_seen": 1700001000.0,
        "zone_name": "Field",
        "zone_level": 1,
    },
    {
        "ip": "10.0.2.1",
        "mac": "aa:bb:cc:dd:ee:02",
        "role": "hmi",
        "first_seen": 1699900000.0,
        "last_seen": 1700001000.0,
        "zone_name": "Control",
        "zone_level": 2,
    },
]


# ---------------------------------------------------------------------------
# OPAClient tests
# ---------------------------------------------------------------------------

class TestOPAClient:
    def test_is_alive_returns_true_on_200(self) -> None:
        client = OPAClient(base_url="http://localhost:8181")
        with patch.object(client._session, "get") as mock_get:
            mock_get.return_value.status_code = 200
            assert client.is_alive() is True

    def test_is_alive_returns_false_on_connection_error(self) -> None:
        from requests.exceptions import ConnectionError as CE
        client = OPAClient(base_url="http://localhost:8181")
        with patch.object(client._session, "get", side_effect=CE("refused")):
            assert client.is_alive() is False

    def test_evaluate_returns_violations(self) -> None:
        client = OPAClient()
        expected = [{"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1"}]
        with patch.object(client._session, "post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"result": expected}
            result = client.evaluate("guardance/cross_zone", {"edges": [], "devices": {}})
        assert result == expected

    def test_evaluate_returns_empty_on_null_result(self) -> None:
        client = OPAClient()
        with patch.object(client._session, "post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"result": None}
            result = client.evaluate("guardance/cross_zone", {})
        assert result == []

    def test_evaluate_returns_empty_on_http_error(self) -> None:
        from requests.exceptions import RequestException
        client = OPAClient()
        with patch.object(client._session, "post", side_effect=RequestException("timeout")):
            result = client.evaluate("guardance/cross_zone", {})
        assert result == []

    def test_evaluate_posts_correct_url(self) -> None:
        client = OPAClient(base_url="http://opa:8181")
        with patch.object(client._session, "post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"result": []}
            client.evaluate("guardance/cross_zone", {"edges": []})
        url = mock_post.call_args[0][0]
        assert url == "http://opa:8181/v1/data/guardance/cross_zone/violations"

    def test_context_manager_closes_session(self) -> None:
        client = OPAClient()
        with patch.object(client._session, "close") as mock_close:
            with client:
                pass
        mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# _fetch_graph_data tests
# ---------------------------------------------------------------------------

class TestFetchGraphData:
    def test_returns_edges_and_devices(self) -> None:
        session = _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)
        edges, devices = _fetch_graph_data(session)
        assert len(edges) == 1
        assert edges[0]["src_ip"] == "10.0.1.1"
        assert "10.0.1.1" in devices
        assert devices["10.0.1.1"]["zone"]["name"] == "Field"

    def test_device_without_zone_has_none_zone(self) -> None:
        raw_device = {
            "ip": "10.0.3.1",
            "mac": None,
            "role": None,
            "first_seen": 1700000000.0,
            "last_seen": 1700000000.0,
            "zone_name": None,
            "zone_level": None,
        }
        session = _neo4j_session([], [raw_device])
        _, devices = _fetch_graph_data(session)
        assert devices["10.0.3.1"]["zone"] is None


# ---------------------------------------------------------------------------
# PolicyEngine tests
# ---------------------------------------------------------------------------

class TestPolicyEngine:
    def _mock_opa_alive(self, engine: PolicyEngine, violations: list[dict]) -> None:
        """Patch the OPA client to be alive and return given violations."""
        engine._client.is_alive = MagicMock(return_value=True)
        engine._client.evaluate = MagicMock(return_value=violations)

    def _session(self) -> MagicMock:
        return _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)

    def test_run_all_uses_opa_when_alive(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [])
        session = _neo4j_session(
            _SAMPLE_EDGES * 5,   # called 5 times (once per policy)
            _SAMPLE_DEVICES_RAW * 5,
        )
        # Override side_effect to always return valid data
        edge_records = [_dict_record(e) for e in _SAMPLE_EDGES]
        dev_records = [_dict_record(d) for d in _SAMPLE_DEVICES_RAW]
        session.run.side_effect = None
        session.run.return_value = []

        results = engine.run_all(session, _BASELINE, ["modbus"])
        assert "cross_zone_violations" in results
        assert "new_devices" in results
        assert "new_edges" in results
        assert "interval_deviation" in results
        assert "unknown_protocol" in results

    def test_run_all_falls_back_when_opa_down(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        engine._client.is_alive = MagicMock(return_value=False)

        with patch("src.policy.engine.PolicyEngine._cypher_fallback") as mock_fb:
            mock_fb.return_value = {
                "cross_zone_violations": [],
                "new_devices": [],
                "new_edges": [],
                "interval_deviation": [],
                "unknown_protocol": [],
            }
            session = MagicMock()
            results = engine.run_all(session, _BASELINE, ["modbus"])

        mock_fb.assert_called_once()
        assert "cross_zone_violations" in results

    def test_cross_zone_violations_passes_edges_and_devices(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [{"src_ip": "10.0.1.1"}])
        session = _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)
        result = engine.cross_zone_violations(session)
        assert result == [{"src_ip": "10.0.1.1"}]
        call_args = engine._client.evaluate.call_args
        assert call_args[0][0] == "guardance/cross_zone"
        assert "edges" in call_args[0][1]
        assert "devices" in call_args[0][1]

    def test_new_devices_passes_baseline_as_epoch(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [])
        session = _neo4j_session([], _SAMPLE_DEVICES_RAW)
        engine.new_devices(session, _BASELINE)
        call_input = engine._client.evaluate.call_args[0][1]
        assert call_input["baseline_end"] == _BASELINE.timestamp()

    def test_new_edges_passes_baseline_as_epoch(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [])
        session = _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)
        engine.new_edges(session, _BASELINE)
        call_input = engine._client.evaluate.call_args[0][1]
        assert call_input["baseline_end"] == _BASELINE.timestamp()

    def test_interval_deviation_passes_bounds(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [])
        session = _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)
        engine.interval_deviation(session, min_ms=50.0, max_ms=500.0)
        call_input = engine._client.evaluate.call_args[0][1]
        assert call_input["min_ms"] == 50.0
        assert call_input["max_ms"] == 500.0

    def test_unknown_protocol_passes_allowlist(self) -> None:
        engine = PolicyEngine(client=OPAClient())
        self._mock_opa_alive(engine, [])
        session = _neo4j_session(_SAMPLE_EDGES, _SAMPLE_DEVICES_RAW)
        engine.unknown_protocol(session, ["modbus", "dnp3"])
        call_input = engine._client.evaluate.call_args[0][1]
        assert call_input["allowed"] == ["modbus", "dnp3"]

    def test_context_manager_closes_client(self) -> None:
        client = OPAClient()
        with patch.object(client, "close") as mock_close:
            with PolicyEngine(client=client):
                pass
        mock_close.assert_called_once()

    def test_cypher_fallback_calls_query_functions(self) -> None:
        session = MagicMock()
        with patch("src.detect.queries.cross_zone_violations", return_value=[]) as m1, \
             patch("src.detect.queries.new_devices", return_value=[]) as m2, \
             patch("src.detect.queries.new_edges", return_value=[]) as m3, \
             patch("src.detect.queries.interval_deviation", return_value=[]) as m4, \
             patch("src.detect.queries.unknown_protocol", return_value=[]) as m5:
            PolicyEngine._cypher_fallback(session, _BASELINE, ["modbus"], 100.0, 1000.0)
        m1.assert_called_once_with(session)
        m2.assert_called_once_with(session, _BASELINE)
        m3.assert_called_once_with(session, _BASELINE)
        m4.assert_called_once_with(session, 100.0, 1000.0)
        m5.assert_called_once_with(session, ["modbus"])
