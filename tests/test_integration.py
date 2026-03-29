"""
Integration tests for the Guardance Phase 1 pipeline.

These tests exercise the full data path from Zeek log parsing through to
detection query results, with Neo4j and Redpanda replaced by lightweight
mocks.  This avoids OOM issues: at most two small real log files are loaded.

Real log files used (both are tiny — < 60 lines each):
  data/pcaps/ICS-pcap-master/MODBUS/Modbus/modbus.log   (~52 data rows)
  data/pcaps/ICS-pcap-master/MODBUS/Modbus/conn.log     (~2 data rows)

Every other interaction with external services is synthetic / in-memory.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODBUS_LOG = (
    PROJECT_ROOT
    / "data"
    / "pcaps"
    / "ICS-pcap-master"
    / "MODBUS"
    / "Modbus"
    / "modbus.log"
)
CONN_LOG = (
    PROJECT_ROOT
    / "data"
    / "pcaps"
    / "ICS-pcap-master"
    / "MODBUS"
    / "Modbus"
    / "conn.log"
)


def _require_file(path: Path) -> None:
    """Skip test if *path* is absent (CI without test data)."""
    if not path.exists():
        pytest.skip(f"Test data not found: {path}")


# ---------------------------------------------------------------------------
# Helpers — inline synthetic Zeek logs
# ---------------------------------------------------------------------------

_MODBUS_LOG_INLINE = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tmodbus
    #open\t2024-01-01-00-00-00
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfunc\texception
    #types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring
    1704067200.000000\tABCDEF123456\t192.168.1.10\t1024\t192.168.1.20\t502\tREAD_HOLDING_REGISTERS\t-
    1704067201.000000\tABCDEF123457\t192.168.1.10\t1025\t192.168.1.20\t502\tWRITE_SINGLE_REGISTER\t-
    1704067202.000000\tABCDEF123458\t192.168.1.30\t2048\t192.168.1.20\t502\tREAD_COILS\t-
    #close\t2024-01-01-00-00-03
""")

_CONN_LOG_INLINE = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tconn
    #open\t2024-01-01-00-00-00
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
    #types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]
    1704067200.000000\tCONN000001\t192.168.1.10\t1024\t192.168.1.20\t502\ttcp\tmodbus\t1.0\t100\t200\tSF\tT\tT\t0\tShADadFf\t3\t246\t2\t252\t(empty)
    #close\t2024-01-01-00-00-01
""")


# ---------------------------------------------------------------------------
# Inline log tests (zero external I/O)
# ---------------------------------------------------------------------------

class TestZeekParserWithSyntheticLogs:
    """Parse inline Zeek log content — no file I/O, no external deps."""

    def test_parse_inline_modbus_yields_events(self, tmp_path: Path) -> None:
        from src.ingest.zeek_parser import parse_zeek_log, ModbusEvent

        log_file = tmp_path / "modbus.log"
        log_file.write_text(_MODBUS_LOG_INLINE, encoding="utf-8")

        events = list(parse_zeek_log(log_file))
        assert len(events) == 3
        assert all(isinstance(e, ModbusEvent) for e in events)

    def test_modbus_event_fields(self, tmp_path: Path) -> None:
        from src.ingest.zeek_parser import parse_zeek_log

        log_file = tmp_path / "modbus.log"
        log_file.write_text(_MODBUS_LOG_INLINE, encoding="utf-8")

        events = list(parse_zeek_log(log_file))
        first = events[0]
        assert first.orig_h == "192.168.1.10"
        assert first.resp_h == "192.168.1.20"
        assert first.resp_p == 502
        assert first.func == "READ_HOLDING_REGISTERS"
        assert first.exception is None

    def test_parse_inline_conn_yields_events(self, tmp_path: Path) -> None:
        from src.ingest.zeek_parser import parse_zeek_log, ConnEvent

        log_file = tmp_path / "conn.log"
        log_file.write_text(_CONN_LOG_INLINE, encoding="utf-8")

        events = list(parse_zeek_log(log_file))
        assert len(events) == 1
        assert isinstance(events[0], ConnEvent)

    def test_conn_event_service_field(self, tmp_path: Path) -> None:
        from src.ingest.zeek_parser import parse_zeek_log

        log_file = tmp_path / "conn.log"
        log_file.write_text(_CONN_LOG_INLINE, encoding="utf-8")

        events = list(parse_zeek_log(log_file))
        assert events[0].service == "modbus"
        assert events[0].proto == "tcp"


# ---------------------------------------------------------------------------
# Producer serialisation (no Kafka broker)
# ---------------------------------------------------------------------------

class TestProducerSerialisation:
    """Verify serialize_event / event_to_topic work on synthetic events."""

    def _make_modbus(self) -> Any:
        from src.ingest.zeek_parser import ModbusEvent

        return ModbusEvent(
            ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            uid="ABC123",
            orig_h="192.168.1.10",
            orig_p=1024,
            resp_h="192.168.1.20",
            resp_p=502,
            func="READ_HOLDING_REGISTERS",
            exception=None,
        )

    def test_serialize_event_is_valid_json(self) -> None:
        from src.ingest.producer import serialize_event

        raw = serialize_event(self._make_modbus())
        assert isinstance(raw, bytes)
        data = json.loads(raw)
        assert data["orig_h"] == "192.168.1.10"
        assert data["func"] == "READ_HOLDING_REGISTERS"

    def test_event_to_topic_modbus(self) -> None:
        from src.ingest.producer import event_to_topic

        assert event_to_topic(self._make_modbus()) == "raw.modbus"

    def test_event_to_topic_with_prefix(self) -> None:
        from src.ingest.producer import event_to_topic

        assert event_to_topic(self._make_modbus(), prefix="test.") == "test.raw.modbus"


# ---------------------------------------------------------------------------
# Consumer deserialisation (no Kafka broker)
# ---------------------------------------------------------------------------

class TestConsumerDeserialisation:
    """Round-trip: serialize → deserialize."""

    def test_modbus_round_trip(self) -> None:
        from src.ingest.zeek_parser import ModbusEvent
        from src.ingest.producer import serialize_event
        from src.graph.consumer import deserialize_message

        event = ModbusEvent(
            ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            uid="ABC123",
            orig_h="10.0.0.1",
            orig_p=1024,
            resp_h="10.0.0.2",
            resp_p=502,
            func="READ_COILS",
            exception=None,
        )
        raw = serialize_event(event)
        result = deserialize_message("raw.modbus", raw)
        assert isinstance(result, ModbusEvent)
        assert result.orig_h == "10.0.0.1"
        assert result.func == "READ_COILS"

    def test_bad_json_returns_none(self) -> None:
        from src.graph.consumer import deserialize_message

        result = deserialize_message("raw.modbus", b"not-json")
        assert result is None

    def test_unknown_topic_returns_none(self) -> None:
        from src.graph.consumer import deserialize_message

        raw = json.dumps({"ts": "2024-01-01T00:00:00+00:00", "uid": "x",
                          "orig_h": "1.2.3.4", "orig_p": 1, "resp_h": "5.6.7.8",
                          "resp_p": 502, "func": "READ_COILS", "exception": None}).encode()
        result = deserialize_message("raw.unknown", raw)
        assert result is None


# ---------------------------------------------------------------------------
# GraphWriter with mock Neo4j driver
# ---------------------------------------------------------------------------

class TestGraphWriterMocked:
    """Write events through GraphWriter with a fully mocked Neo4j driver."""

    def _make_driver_mock(self) -> MagicMock:
        """Return a mock neo4j Driver whose session() works as a context manager."""
        driver = MagicMock()
        session = MagicMock()
        driver.session.return_value.__enter__ = MagicMock(return_value=session)
        driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return driver, session

    def test_ingest_modbus_event(self) -> None:
        from src.ingest.zeek_parser import ModbusEvent
        from src.graph.writer import GraphWriter

        driver, session = self._make_driver_mock()
        writer = GraphWriter(driver)

        event = ModbusEvent(
            ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            uid="ABC",
            orig_h="10.0.0.1",
            orig_p=1024,
            resp_h="10.0.0.2",
            resp_p=502,
            func="READ_COILS",
            exception=None,
        )
        writer.ingest_event(event)
        assert writer.ingested_count == 1
        assert writer.error_count == 0

    def test_ingest_batch_counts_events(self) -> None:
        from src.ingest.zeek_parser import ModbusEvent
        from src.graph.writer import GraphWriter

        driver, _ = self._make_driver_mock()
        writer = GraphWriter(driver)

        events = [
            ModbusEvent(
                ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
                uid=f"uid{i}",
                orig_h="10.0.0.1",
                orig_p=1024 + i,
                resp_h="10.0.0.2",
                resp_p=502,
                func="READ_COILS",
                exception=None,
            )
            for i in range(5)
        ]
        writer.ingest_batch(events)
        assert writer.ingested_count == 5

    def test_neo4j_error_increments_error_count(self) -> None:
        from neo4j.exceptions import Neo4jError
        from src.ingest.zeek_parser import ModbusEvent
        from src.graph.writer import GraphWriter

        driver = MagicMock()
        session_mock = MagicMock()
        session_mock.execute_write.side_effect = Neo4jError("boom")
        driver.session.return_value.__enter__ = MagicMock(return_value=session_mock)
        driver.session.return_value.__exit__ = MagicMock(return_value=False)

        writer = GraphWriter(driver)
        event = ModbusEvent(
            ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            uid="E1",
            orig_h="10.0.0.1",
            orig_p=1024,
            resp_h="10.0.0.2",
            resp_p=502,
            func="READ_COILS",
            exception=None,
        )
        writer.ingest_event(event)
        assert writer.error_count == 1
        assert writer.ingested_count == 0


# ---------------------------------------------------------------------------
# Full pipeline end-to-end (synthetic data, mocked Neo4j)
# ---------------------------------------------------------------------------

class TestFullPipelineEndToEnd:
    """
    Parse inline Zeek events → serialize → deserialize → mock-write to Neo4j
    → run detection queries on a mock session that returns pre-canned results.
    """

    def _build_events_from_inline_log(self, tmp_path: Path) -> list:
        from src.ingest.zeek_parser import parse_zeek_log

        modbus_file = tmp_path / "modbus.log"
        modbus_file.write_text(_MODBUS_LOG_INLINE, encoding="utf-8")
        return list(parse_zeek_log(modbus_file))

    def test_parse_serialize_deserialize_cycle(self, tmp_path: Path) -> None:
        from src.ingest.producer import serialize_event, event_to_topic
        from src.graph.consumer import deserialize_message

        events = self._build_events_from_inline_log(tmp_path)
        for event in events:
            raw = serialize_event(event)
            topic = event_to_topic(event)
            recovered = deserialize_message(topic, raw)
            assert recovered is not None
            assert recovered.orig_h == event.orig_h
            assert recovered.resp_h == event.resp_h

    def test_write_all_inline_events_to_mock_neo4j(self, tmp_path: Path) -> None:
        from src.graph.writer import GraphWriter

        driver = MagicMock()
        session_mock = MagicMock()
        driver.session.return_value.__enter__ = MagicMock(return_value=session_mock)
        driver.session.return_value.__exit__ = MagicMock(return_value=False)

        writer = GraphWriter(driver)
        events = self._build_events_from_inline_log(tmp_path)
        writer.ingest_batch(events)

        assert writer.ingested_count == len(events)
        assert writer.error_count == 0

    def test_detection_queries_on_mock_session(self) -> None:
        """Run all five detection queries against pre-canned mock results."""
        from src.detect.queries import (
            cross_zone_violations,
            new_devices,
            new_edges,
            interval_deviation,
            unknown_protocol,
        )

        # Helper: build a mock session that returns one canned row per call.
        def _row(data: dict) -> MagicMock:
            class _R:
                _d = data

                def keys(self):
                    return self._d.keys()

                def __getitem__(self, k):
                    return self._d[k]

                def __iter__(self):
                    return iter(self._d)

            return _R()

        baseline = datetime(2024, 1, 1, tzinfo=timezone.utc)

        # cross_zone_violations
        session = MagicMock()
        session.run.return_value = iter([_row({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.5",
            "src_zone": "field", "dst_zone": "enterprise",
            "src_level": 1, "dst_level": 4,
            "protocol": "modbus", "port": 502, "packet_count": 3,
        })])
        findings = cross_zone_violations(session)
        assert len(findings) == 1
        assert findings[0]["src_level"] == 1

        # new_devices
        session2 = MagicMock()
        session2.run.return_value = iter([_row({
            "ip": "192.168.1.99", "mac": None, "role": None,
            "first_seen": baseline.timestamp() + 100,
            "last_seen": baseline.timestamp() + 200,
        })])
        nd = new_devices(session2, baseline)
        assert len(nd) == 1
        assert nd[0]["ip"] == "192.168.1.99"

        # new_edges
        session3 = MagicMock()
        session3.run.return_value = iter([_row({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "protocol": "modbus", "port": 502, "function_code": "READ_COILS",
            "first_seen": baseline.timestamp() + 50, "packet_count": 5,
        })])
        ne = new_edges(session3, baseline)
        assert len(ne) == 1

        # interval_deviation
        session4 = MagicMock()
        session4.run.return_value = iter([_row({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "protocol": "modbus", "port": 502, "function_code": "READ_COILS",
            "avg_interval_ms": 50.0, "packet_count": 100, "is_periodic": False,
        })])
        iv = interval_deviation(session4)
        assert len(iv) == 1
        assert iv[0]["avg_interval_ms"] == 50.0

        # unknown_protocol
        session5 = MagicMock()
        session5.run.return_value = iter([_row({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "protocol": "bacnet", "port": 47808, "function_code": "flow",
            "packet_count": 2, "first_seen": 1_700_000_000.0,
        })])
        up = unknown_protocol(session5, ["modbus", "dnp3"])
        assert len(up) == 1
        assert up[0]["protocol"] == "bacnet"


# ---------------------------------------------------------------------------
# Real log file tests (skipped if data absent)
# ---------------------------------------------------------------------------

class TestRealLogFiles:
    """
    Smoke-tests that parse real (small) Zeek logs.
    Uses at most 2 files.  Skipped if data is not present.
    """

    def test_real_modbus_log_yields_events(self) -> None:
        _require_file(MODBUS_LOG)
        from src.ingest.zeek_parser import parse_zeek_log, ModbusEvent

        events = list(parse_zeek_log(MODBUS_LOG))
        assert len(events) > 0
        assert all(isinstance(e, ModbusEvent) for e in events)

    def test_real_modbus_all_events_have_valid_ips(self) -> None:
        _require_file(MODBUS_LOG)
        from src.ingest.zeek_parser import parse_zeek_log

        for event in parse_zeek_log(MODBUS_LOG):
            assert "." in event.orig_h, f"Bad orig_h: {event.orig_h}"
            assert "." in event.resp_h, f"Bad resp_h: {event.resp_h}"

    def test_real_conn_log_yields_events(self) -> None:
        _require_file(CONN_LOG)
        from src.ingest.zeek_parser import parse_zeek_log, ConnEvent

        events = list(parse_zeek_log(CONN_LOG))
        assert len(events) > 0
        assert all(isinstance(e, ConnEvent) for e in events)

    def test_real_modbus_serialize_deserialize(self) -> None:
        _require_file(MODBUS_LOG)
        from src.ingest.zeek_parser import parse_zeek_log
        from src.ingest.producer import serialize_event, event_to_topic
        from src.graph.consumer import deserialize_message

        # Only sample the first 3 events to stay within memory budget.
        events = []
        for event in parse_zeek_log(MODBUS_LOG):
            events.append(event)
            if len(events) >= 3:
                break

        for event in events:
            raw = serialize_event(event)
            topic = event_to_topic(event)
            recovered = deserialize_message(topic, raw)
            assert recovered is not None
            assert recovered.orig_h == event.orig_h


# ---------------------------------------------------------------------------
# main.py smoke tests (no live services)
# ---------------------------------------------------------------------------

class TestMainModule:
    """Lightweight tests for src/main.py argument parsing and helpers."""

    def test_parse_args_defaults(self) -> None:
        from src.main import parse_args

        args = parse_args([])
        assert args.pcap_dir == "data/pcaps"
        assert args.log_level == "INFO"
        assert args.allowed_protocols == "modbus,dnp3,s7comm,tcp,udp"

    def test_parse_args_custom(self) -> None:
        from src.main import parse_args

        args = parse_args([
            "--pcap-dir", "/tmp/logs",
            "--neo4j-uri", "bolt://neo4j:7687",
            "--bootstrap-servers", "broker:9092",
            "--log-level", "DEBUG",
        ])
        assert args.pcap_dir == "/tmp/logs"
        assert args.neo4j_uri == "bolt://neo4j:7687"
        assert args.bootstrap_servers == "broker:9092"
        assert args.log_level == "DEBUG"

    def test_main_exits_zero_on_missing_pcap_dir(self, tmp_path: Path) -> None:
        """main() should return 0 (not crash) when pcap-dir has no logs."""
        from src.main import main

        log_file = str(tmp_path / "test.log")
        # Point at an empty directory so no events are ingested.
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        # We mock create_driver so Neo4j is never contacted.
        driver_mock = MagicMock()
        session_mock = MagicMock()
        driver_mock.session.return_value.__enter__ = MagicMock(return_value=session_mock)
        driver_mock.session.return_value.__exit__ = MagicMock(return_value=False)

        with patch("src.graph.writer.GraphDatabase.driver", return_value=driver_mock):
            rc = main([
                "--pcap-dir", str(empty_dir),
                "--log-file", log_file,
                "--log-level", "WARNING",
            ])
        assert rc == 0

    def test_log_detection_results_returns_total(self) -> None:
        from src.main import log_detection_results
        import logging

        results = {
            "cross_zone_violations": [{"src_ip": "a", "dst_ip": "b"}],
            "new_devices": [],
            "new_edges": [{"src_ip": "c"}, {"src_ip": "d"}],
            "interval_deviation": [],
            "unknown_protocol": [],
        }
        # Suppress log output during this test.
        logging.disable(logging.CRITICAL)
        try:
            total = log_detection_results(results)
        finally:
            logging.disable(logging.NOTSET)
        assert total == 3
