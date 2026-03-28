"""
Tests for src/graph/writer.py

All Neo4j interactions are mocked so no live database is required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from neo4j.exceptions import Neo4jError

from src.graph.writer import GraphWriter, _UPSERT_DEVICE, _UPSERT_EDGE, create_driver
from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TS = datetime(2004, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
TS_EPOCH = TS.timestamp()


@pytest.fixture()
def modbus_event() -> ModbusEvent:
    return ModbusEvent(
        ts=TS, uid="Cabc", orig_h="10.0.0.57", orig_p=2578,
        resp_h="10.0.0.3", resp_p=502, func="READ_COILS", exception=None,
    )


@pytest.fixture()
def dnp3_event() -> Dnp3Event:
    return Dnp3Event(
        ts=TS, uid="Cdef", orig_h="192.168.1.10", orig_p=1413,
        resp_h="192.168.1.20", resp_p=20000, fc_request="READ",
        fc_reply="RESPONSE", iin=36866,
    )


@pytest.fixture()
def conn_event_with_service() -> ConnEvent:
    return ConnEvent(
        ts=TS, uid="Cghi", orig_h="10.0.0.1", orig_p=55000,
        resp_h="10.0.0.2", resp_p=502, proto="tcp", service="modbus",
        duration=0.5, orig_bytes=100, resp_bytes=200, conn_state="SF",
        local_orig=True, local_resp=True, missed_bytes=0,
        history="ShADadFf", orig_pkts=4, orig_ip_bytes=240,
        resp_pkts=3, resp_ip_bytes=180, tunnel_parents=[],
    )


@pytest.fixture()
def conn_event_no_service() -> ConnEvent:
    return ConnEvent(
        ts=TS, uid="Cjkl", orig_h="10.0.0.3", orig_p=12345,
        resp_h="10.0.0.4", resp_p=44818, proto="tcp", service=None,
        duration=None, orig_bytes=None, resp_bytes=None, conn_state="OTH",
        local_orig=None, local_resp=None, missed_bytes=0,
        history=None, orig_pkts=1, orig_ip_bytes=60,
        resp_pkts=0, resp_ip_bytes=0, tunnel_parents=None,
    )


def _make_mock_driver() -> MagicMock:
    """Return a mock Neo4j driver with a functioning session context manager."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return driver, session


# ---------------------------------------------------------------------------
# Tests — GraphWriter.ensure_constraints
# ---------------------------------------------------------------------------

class TestEnsureConstraints:
    def test_runs_all_constraint_queries(self):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ensure_constraints()
        # session.run() should be called once per constraint
        from src.graph.writer import _CONSTRAINTS
        assert session.run.call_count == len(_CONSTRAINTS)

    def test_neo4j_error_does_not_raise(self):
        driver, session = _make_mock_driver()
        session.run.side_effect = Neo4jError("already exists")
        writer = GraphWriter(driver)
        # Should not raise; errors are caught and logged
        writer.ensure_constraints()


# ---------------------------------------------------------------------------
# Tests — GraphWriter.ingest_event (Modbus)
# ---------------------------------------------------------------------------

class TestIngestModbus:
    def test_execute_write_called(self, modbus_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)
        session.execute_write.assert_called_once()

    def test_ingested_count_increments(self, modbus_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)
        assert writer.ingested_count == 1

    def test_session_opened_with_database(self, modbus_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver, database="mydb")
        writer.ingest_event(modbus_event)
        driver.session.assert_called_with(database="mydb")

    def test_neo4j_error_increments_error_count(self, modbus_event):
        driver, session = _make_mock_driver()
        session.execute_write.side_effect = Neo4jError("write failed")
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)
        assert writer.error_count == 1
        assert writer.ingested_count == 0

    def test_unexpected_exception_increments_error_count(self, modbus_event):
        driver, session = _make_mock_driver()
        session.execute_write.side_effect = RuntimeError("unexpected")
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)
        assert writer.error_count == 1


# ---------------------------------------------------------------------------
# Tests — GraphWriter.ingest_event (DNP3)
# ---------------------------------------------------------------------------

class TestIngestDnp3:
    def test_execute_write_called(self, dnp3_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_event(dnp3_event)
        session.execute_write.assert_called_once()

    def test_ingested_count_increments(self, dnp3_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_event(dnp3_event)
        assert writer.ingested_count == 1


# ---------------------------------------------------------------------------
# Tests — GraphWriter.ingest_event (ConnEvent)
# ---------------------------------------------------------------------------

class TestIngestConn:
    def test_service_label_used_when_present(self, conn_event_with_service):
        """When service='modbus', the protocol on the edge should be 'modbus'."""
        driver, session = _make_mock_driver()

        captured_params = {}

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            # Capture the params from the edge MERGE call (second run call)
            calls = fake_tx.run.call_args_list
            if len(calls) >= 3:
                edge_call = calls[2]
                captured_params.update(edge_call.kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(conn_event_with_service)
        assert captured_params.get("protocol") == "modbus"

    def test_proto_used_when_no_service(self, conn_event_no_service):
        """When service=None, fall back to proto ('tcp')."""
        driver, session = _make_mock_driver()

        captured_params = {}

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            calls = fake_tx.run.call_args_list
            if len(calls) >= 3:
                captured_params.update(calls[2].kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(conn_event_no_service)
        assert captured_params.get("protocol") == "tcp"

    def test_function_code_is_flow(self, conn_event_with_service):
        driver, session = _make_mock_driver()

        captured_params = {}

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            calls = fake_tx.run.call_args_list
            if len(calls) >= 3:
                captured_params.update(calls[2].kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(conn_event_with_service)
        assert captured_params.get("function_code") == "flow"


# ---------------------------------------------------------------------------
# Tests — transaction content (Cypher params)
# ---------------------------------------------------------------------------

class TestTransactionParams:
    """Verify that the correct parameters are passed to the Cypher queries."""

    def test_device_upsert_params(self, modbus_event):
        driver, session = _make_mock_driver()
        device_params = []

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            for c in fake_tx.run.call_args_list:
                if c.args and c.args[0] == _UPSERT_DEVICE:
                    device_params.append(c.kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)

        ips = [p["ip"] for p in device_params]
        assert "10.0.0.57" in ips
        assert "10.0.0.3" in ips
        for p in device_params:
            assert p["ts"] == pytest.approx(TS_EPOCH)

    def test_edge_upsert_params(self, modbus_event):
        driver, session = _make_mock_driver()
        edge_params = {}

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            for c in fake_tx.run.call_args_list:
                if c.args and c.args[0] == _UPSERT_EDGE:
                    edge_params.update(c.kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(modbus_event)

        assert edge_params["orig_h"] == "10.0.0.57"
        assert edge_params["resp_h"] == "10.0.0.3"
        assert edge_params["protocol"] == "modbus"
        assert edge_params["port"] == 502
        assert edge_params["function_code"] == "READ_COILS"
        assert edge_params["ts"] == pytest.approx(TS_EPOCH)

    def test_dnp3_function_code_is_fc_request(self, dnp3_event):
        driver, session = _make_mock_driver()
        edge_params = {}

        def fake_execute_write(fn):
            fake_tx = MagicMock()
            fn(fake_tx)
            for c in fake_tx.run.call_args_list:
                if c.args and c.args[0] == _UPSERT_EDGE:
                    edge_params.update(c.kwargs)

        session.execute_write.side_effect = fake_execute_write
        writer = GraphWriter(driver)
        writer.ingest_event(dnp3_event)

        assert edge_params["function_code"] == "READ"
        assert edge_params["protocol"] == "dnp3"
        assert edge_params["port"] == 20000


# ---------------------------------------------------------------------------
# Tests — ingest_batch
# ---------------------------------------------------------------------------

class TestIngestBatch:
    def test_all_events_ingested(self, modbus_event, dnp3_event):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_batch([modbus_event, dnp3_event])
        assert writer.ingested_count == 2

    def test_empty_batch(self):
        driver, session = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_batch([])
        assert writer.ingested_count == 0

    def test_partial_error_continues(self, modbus_event, dnp3_event):
        driver, session = _make_mock_driver()
        # First call raises, second succeeds
        session.execute_write.side_effect = [Neo4jError("fail"), None]
        writer = GraphWriter(driver)
        writer.ingest_batch([modbus_event, dnp3_event])
        assert writer.error_count == 1
        assert writer.ingested_count == 1


# ---------------------------------------------------------------------------
# Tests — unknown event type
# ---------------------------------------------------------------------------

class TestUnknownEventType:
    def test_unknown_type_does_not_raise(self):
        driver, _ = _make_mock_driver()
        writer = GraphWriter(driver)
        writer.ingest_event("not-an-event")  # type: ignore[arg-type]
        assert writer.ingested_count == 0
        assert writer.error_count == 0


# ---------------------------------------------------------------------------
# Tests — context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_driver_closed_on_exit(self):
        driver, _ = _make_mock_driver()
        with GraphWriter(driver):
            pass
        driver.close.assert_called_once()

    def test_driver_closed_on_exception(self):
        driver, _ = _make_mock_driver()
        with pytest.raises(ValueError):
            with GraphWriter(driver):
                raise ValueError("boom")
        driver.close.assert_called_once()


# ---------------------------------------------------------------------------
# Tests — create_driver uses env vars
# ---------------------------------------------------------------------------

class TestCreateDriver:
    def test_uses_env_uri(self, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://testhost:7687")
        monkeypatch.setenv("NEO4J_USER", "admin")
        monkeypatch.setenv("NEO4J_PASSWORD", "secret")
        with patch("src.graph.writer.GraphDatabase.driver") as mock_gd:
            create_driver()
            mock_gd.assert_called_once_with(
                "bolt://testhost:7687", auth=("admin", "secret")
            )

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://envhost:7687")
        with patch("src.graph.writer.GraphDatabase.driver") as mock_gd:
            create_driver(uri="bolt://explicit:7687", user="u", password="p")
            mock_gd.assert_called_once_with(
                "bolt://explicit:7687", auth=("u", "p")
            )
