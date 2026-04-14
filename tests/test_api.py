"""
Tests for src/api/ — auth, devices, findings endpoints, and UI routes.

Uses FastAPI's TestClient with dependency overrides to mock Neo4j.
No live Neo4j or Redpanda required.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import require_api_key
from src.api.routes.devices import get_neo4j_driver as devices_driver
from src.api.routes.findings import get_neo4j_driver as findings_driver


# ---------------------------------------------------------------------------
# Mock Neo4j helpers
# ---------------------------------------------------------------------------

class _DictRecord:
    """Minimal dict-like Neo4j record mock."""

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


def _mock_driver(query_results: list[list[dict]]) -> MagicMock:
    """
    Build a mock Neo4j driver whose session().run() returns results in order.

    Each successive call to session.run() consumes the next list in
    query_results.  When the list is exhausted, subsequent calls return [].
    """
    driver = MagicMock()
    session = MagicMock()

    ctx = driver.session.return_value
    ctx.__enter__ = MagicMock(return_value=session)
    ctx.__exit__ = MagicMock(return_value=False)

    results_iter = iter(query_results)

    def _run(query, **kwargs):
        try:
            rows = next(results_iter)
        except StopIteration:
            rows = []
        result = MagicMock()
        records = [_DictRecord(r) for r in rows]
        result.__iter__ = MagicMock(return_value=iter(records))
        result.single = MagicMock(return_value=records[0] if records else None)
        return result

    session.run.side_effect = _run
    return driver


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_DEVICES = [
    {"ip": "10.0.1.1", "mac": "aa:bb:cc:00:01", "role": "plc",
     "purdue_level": 1, "first_seen": 1700000000.0, "last_seen": 1700001000.0, "zone": "Field"},
    {"ip": "10.0.2.1", "mac": "aa:bb:cc:00:02", "role": "hmi",
     "purdue_level": 2, "first_seen": 1700000000.0, "last_seen": 1700001000.0, "zone": "Control"},
]

_EDGES = [
    {"dst_ip": "10.0.2.1", "protocol": "modbus", "port": 502,
     "function_code": "READ_HOLDING_REGISTERS", "packet_count": 100,
     "avg_interval_ms": 250.0, "is_periodic": True, "first_seen": 1700000000.0,
     "last_seen": 1700001000.0},
]


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_health_needs_no_key(self) -> None:
        with patch("src.api.auth.get_valid_keys", return_value={"secret"}):
            client = TestClient(app)
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_returns_401_when_key_missing(self) -> None:
        with patch("src.api.auth.get_valid_keys", return_value={"secret-key"}):
            client = TestClient(app)
            resp = client.get("/api/v1/devices")
        assert resp.status_code == 401

    def test_returns_403_on_wrong_key(self) -> None:
        with patch("src.api.auth.get_valid_keys", return_value={"secret-key"}):
            client = TestClient(app)
            resp = client.get("/api/v1/devices", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 403

    def test_passes_with_valid_key(self) -> None:
        driver = _mock_driver([[{"total": 0}], []])
        app.dependency_overrides[devices_driver] = lambda: driver
        app.dependency_overrides[require_api_key] = lambda: None
        client = TestClient(app)
        resp = client.get("/api/v1/devices")
        app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_no_auth_when_keys_empty(self) -> None:
        """When GUARDANCE_API_KEYS is not set, all requests pass through."""
        driver = _mock_driver([[{"total": 0}], []])
        app.dependency_overrides[devices_driver] = lambda: driver
        client = TestClient(app)
        with patch("src.api.auth.get_valid_keys", return_value=set()):
            resp = client.get("/api/v1/devices")
        app.dependency_overrides.clear()
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealth:
    def test_returns_ok(self) -> None:
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "time" in body
        assert body["version"] == "3.0.0"


# ---------------------------------------------------------------------------
# Device API tests
# ---------------------------------------------------------------------------

class TestDeviceAPI:
    def _client(self, query_results: list[list[dict]]) -> TestClient:
        driver = _mock_driver(query_results)
        app.dependency_overrides[devices_driver] = lambda: driver
        app.dependency_overrides[require_api_key] = lambda: None
        return TestClient(app)

    def teardown_method(self) -> None:
        app.dependency_overrides.clear()

    def test_list_devices_returns_items(self) -> None:
        client = self._client([[{"total": 2}], _DEVICES])
        resp = client.get("/api/v1/devices")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2
        assert body["items"][0]["ip"] == "10.0.1.1"

    def test_list_devices_empty(self) -> None:
        client = self._client([[{"total": 0}], []])
        resp = client.get("/api/v1/devices")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_list_devices_pagination_params(self) -> None:
        client = self._client([[{"total": 100}], _DEVICES])
        resp = client.get("/api/v1/devices?skip=10&limit=5")
        assert resp.status_code == 200
        body = resp.json()
        assert body["skip"] == 10
        assert body["limit"] == 5

    def test_get_device_by_ip(self) -> None:
        client = self._client([_DEVICES[:1]])
        resp = client.get("/api/v1/devices/10.0.1.1")
        assert resp.status_code == 200
        assert resp.json()["ip"] == "10.0.1.1"

    def test_get_device_not_found(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/devices/192.168.99.99")
        assert resp.status_code == 404

    def test_get_device_edges(self) -> None:
        client = self._client([_DEVICES[:1], _EDGES])
        resp = client.get("/api/v1/devices/10.0.1.1/edges")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ip"] == "10.0.1.1"
        assert len(body["edges"]) == 1
        assert body["edges"][0]["protocol"] == "modbus"

    def test_get_edges_for_unknown_device_returns_404(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/devices/99.99.99.99/edges")
        assert resp.status_code == 404

    def test_limit_validation_zero(self) -> None:
        client = self._client([])
        resp = client.get("/api/v1/devices?limit=0")
        assert resp.status_code == 422

    def test_limit_max_validation(self) -> None:
        client = self._client([])
        resp = client.get("/api/v1/devices?limit=501")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Findings API tests
# ---------------------------------------------------------------------------

class TestFindingsAPI:
    def _client(self, session_run_results: list[list[dict]]) -> TestClient:
        driver = _mock_driver(session_run_results)
        app.dependency_overrides[findings_driver] = lambda: driver
        app.dependency_overrides[require_api_key] = lambda: None
        return TestClient(app)

    def teardown_method(self) -> None:
        app.dependency_overrides.clear()

    def _empty(self) -> TestClient:
        return self._client([[], [], [], [], []])

    def test_run_all_findings_returns_all_keys(self) -> None:
        client = self._empty()
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 200
        body = resp.json()
        assert "findings" in body
        assert "total" in body
        for key in ("cross_zone_violations", "new_devices", "new_edges",
                    "interval_deviation", "unknown_protocol"):
            assert key in body["findings"]

    def test_total_sums_findings(self) -> None:
        cross_zone_row = {
            "src_ip": "10.0.1.1", "dst_ip": "10.0.3.1",
            "src_zone": "Field", "dst_zone": "Enterprise",
            "src_level": 1, "dst_level": 4, "protocol": "modbus",
            "port": 502, "packet_count": 5,
        }
        client = self._client([[cross_zone_row], [], [], [], []])
        resp = client.get("/api/v1/findings")
        assert resp.json()["total"] == 1

    def test_cross_zone_endpoint(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/findings/cross-zone")
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "count" in body

    def test_new_devices_endpoint(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/findings/new-devices")
        assert resp.status_code == 200
        body = resp.json()
        assert "baseline_end" in body
        assert "items" in body

    def test_new_edges_endpoint(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/findings/new-edges")
        assert resp.status_code == 200

    def test_interval_deviation_endpoint(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/findings/interval-deviation")
        assert resp.status_code == 200

    def test_unknown_protocol_endpoint(self) -> None:
        client = self._client([[]])
        resp = client.get("/api/v1/findings/unknown-protocol")
        assert resp.status_code == 200

    def test_baseline_hours_param(self) -> None:
        client = self._empty()
        resp = client.get("/api/v1/findings?baseline_hours=48")
        assert resp.status_code == 200

    def test_allowed_protocols_param(self) -> None:
        client = self._empty()
        resp = client.get("/api/v1/findings?allowed_protocols=modbus")
        assert resp.status_code == 200

    def test_baseline_end_in_response(self) -> None:
        client = self._empty()
        resp = client.get("/api/v1/findings")
        assert "baseline_end" in resp.json()


# ---------------------------------------------------------------------------
# UI route smoke tests
# ---------------------------------------------------------------------------

class TestUIRoutes:
    def _patch_stats(self, stats: dict):
        """Patch _get_dashboard_stats in app module."""
        return patch("src.api.app._get_dashboard_stats", return_value=stats)

    def _patch_driver(self, results: list[list[dict]]):
        """Patch _driver() used by the UI routes in app.py."""
        driver = _mock_driver(results)
        return patch("src.api.app._driver", return_value=driver)

    def _empty_stats(self) -> dict:
        return {
            "device_count": 0, "edge_count": 0,
            "cross_zone": 0, "new_devices": 0, "new_edges": 0,
            "interval_deviation": 0, "unknown_protocol": 0,
            "total_findings": 0,
        }

    def test_dashboard_returns_html(self) -> None:
        with self._patch_stats(self._empty_stats()):
            client = TestClient(app)
            resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert b"GUARDANCE" in resp.content

    def test_dashboard_shows_finding_count(self) -> None:
        stats = self._empty_stats()
        stats["total_findings"] = 3
        stats["cross_zone"] = 3
        with self._patch_stats(stats):
            client = TestClient(app)
            resp = client.get("/")
        assert b"3" in resp.content

    def test_devices_page_returns_html(self) -> None:
        with self._patch_driver([[{"total": 0}], []]):
            client = TestClient(app)
            resp = client.get("/ui/devices")
        assert resp.status_code == 200
        assert b"Devices" in resp.content

    def test_devices_page_shows_devices(self) -> None:
        with self._patch_driver([[{"total": 2}], _DEVICES]):
            client = TestClient(app)
            resp = client.get("/ui/devices")
        assert b"10.0.1.1" in resp.content

    def test_findings_page_returns_html(self) -> None:
        empty_findings = {
            "cross_zone_violations": [], "new_devices": [], "new_edges": [],
            "interval_deviation": [], "unknown_protocol": [],
        }
        with patch("src.api.app._driver") as mock_drv:
            driver = _mock_driver([[], [], [], [], []])
            mock_drv.return_value = driver
            client = TestClient(app)
            resp = client.get("/ui/findings")
        assert resp.status_code == 200
        assert b"Findings" in resp.content

    def test_openapi_schema_available(self) -> None:
        client = TestClient(app)
        resp = client.get("/api/openapi.json")
        assert resp.status_code == 200
        assert resp.json()["info"]["title"] == "Guardance"

    def test_docs_available(self) -> None:
        client = TestClient(app)
        resp = client.get("/api/docs")
        assert resp.status_code == 200
