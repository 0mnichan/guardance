"""
Tests for src/graph/consumer.py

The Kafka Consumer and GraphWriter are both mocked so no live broker or
Neo4j instance is needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest
from confluent_kafka import KafkaError

from src.graph.consumer import (
    GraphConsumer,
    _build_consumer_config,
    _topic_list,
    deserialize_message,
)
from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TS = datetime(2004, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
TS_ISO = TS.isoformat()


def _make_msg(topic: str, value: dict, error=None) -> MagicMock:
    """Build a fake confluent-kafka Message."""
    msg = MagicMock()
    msg.topic.return_value = topic
    msg.partition.return_value = 0
    msg.offset.return_value = 0
    msg.value.return_value = json.dumps(value).encode("utf-8")
    msg.error.return_value = error
    return msg


def _make_err_msg(code: int) -> MagicMock:
    """Build a fake error Message."""
    msg = MagicMock()
    err = MagicMock()
    err.code.return_value = code
    msg.error.return_value = err
    msg.topic.return_value = "raw.modbus"
    msg.partition.return_value = 0
    msg.offset.return_value = 99
    return msg


MODBUS_PAYLOAD = {
    "ts": TS_ISO, "uid": "Cabc", "orig_h": "10.0.0.57", "orig_p": 2578,
    "resp_h": "10.0.0.3", "resp_p": 502, "func": "READ_COILS", "exception": None,
}
DNP3_PAYLOAD = {
    "ts": TS_ISO, "uid": "Cdef", "orig_h": "192.168.1.10", "orig_p": 1413,
    "resp_h": "192.168.1.20", "resp_p": 20000, "fc_request": "READ",
    "fc_reply": "RESPONSE", "iin": 36866,
}
CONN_PAYLOAD = {
    "ts": TS_ISO, "uid": "Cghi", "orig_h": "10.0.0.1", "orig_p": 55000,
    "resp_h": "10.0.0.2", "resp_p": 502, "proto": "tcp", "service": "modbus",
    "duration": 0.5, "orig_bytes": 100, "resp_bytes": 200, "conn_state": "SF",
    "local_orig": True, "local_resp": True, "missed_bytes": 0,
    "history": "ShADadFf", "orig_pkts": 4, "orig_ip_bytes": 240,
    "resp_pkts": 3, "resp_ip_bytes": 180, "tunnel_parents": [],
}


# ---------------------------------------------------------------------------
# Tests — _topic_list
# ---------------------------------------------------------------------------

class TestTopicList:
    def test_default_no_prefix(self):
        assert _topic_list() == ["raw.modbus", "raw.dnp3", "raw.conn"]

    def test_prefix_applied(self):
        assert _topic_list("dev.") == ["dev.raw.modbus", "dev.raw.dnp3", "dev.raw.conn"]


# ---------------------------------------------------------------------------
# Tests — deserialize_message
# ---------------------------------------------------------------------------

class TestDeserializeMessage:
    def test_modbus_round_trip(self):
        ev = deserialize_message(
            "raw.modbus", json.dumps(MODBUS_PAYLOAD).encode()
        )
        assert isinstance(ev, ModbusEvent)
        assert ev.orig_h == "10.0.0.57"
        assert ev.resp_p == 502
        assert ev.func == "READ_COILS"
        assert ev.exception is None
        assert ev.ts == TS

    def test_dnp3_round_trip(self):
        ev = deserialize_message(
            "raw.dnp3", json.dumps(DNP3_PAYLOAD).encode()
        )
        assert isinstance(ev, Dnp3Event)
        assert ev.fc_request == "READ"
        assert ev.iin == 36866

    def test_conn_round_trip(self):
        ev = deserialize_message(
            "raw.conn", json.dumps(CONN_PAYLOAD).encode()
        )
        assert isinstance(ev, ConnEvent)
        assert ev.proto == "tcp"
        assert ev.service == "modbus"
        assert ev.tunnel_parents == []

    def test_prefix_stripped_before_routing(self):
        ev = deserialize_message(
            "dev.raw.modbus",
            json.dumps(MODBUS_PAYLOAD).encode(),
            prefix="dev.",
        )
        assert isinstance(ev, ModbusEvent)

    def test_invalid_json_returns_none(self):
        ev = deserialize_message("raw.modbus", b"not-json")
        assert ev is None

    def test_missing_required_field_returns_none(self):
        bad = {k: v for k, v in MODBUS_PAYLOAD.items() if k != "func"}
        ev = deserialize_message("raw.modbus", json.dumps(bad).encode())
        assert ev is None

    def test_unknown_topic_returns_none(self):
        ev = deserialize_message("raw.unknown", json.dumps({"ts": TS_ISO}).encode())
        assert ev is None

    def test_ts_is_utc_datetime(self):
        ev = deserialize_message("raw.modbus", json.dumps(MODBUS_PAYLOAD).encode())
        assert isinstance(ev.ts, datetime)
        assert ev.ts.tzinfo is not None

    def test_conn_optional_fields_are_none_when_missing(self):
        minimal = {k: v for k, v in CONN_PAYLOAD.items()}
        minimal["service"] = None
        minimal["duration"] = None
        ev = deserialize_message("raw.conn", json.dumps(minimal).encode())
        assert isinstance(ev, ConnEvent)
        assert ev.service is None
        assert ev.duration is None


# ---------------------------------------------------------------------------
# Tests — GraphConsumer._handle_message
# ---------------------------------------------------------------------------

class TestHandleMessage:
    def _make_consumer(self) -> tuple[GraphConsumer, MagicMock]:
        mock_writer = MagicMock()
        mock_kafka = MagicMock()
        c = GraphConsumer(writer=mock_writer, consumer=mock_kafka, poll_timeout=0.0)
        return c, mock_writer

    def test_modbus_message_calls_ingest_event(self):
        c, writer = self._make_consumer()
        msg = _make_msg("raw.modbus", MODBUS_PAYLOAD)
        c._handle_message(msg)
        writer.ingest_event.assert_called_once()
        ev = writer.ingest_event.call_args.args[0]
        assert isinstance(ev, ModbusEvent)

    def test_dnp3_message_calls_ingest_event(self):
        c, writer = self._make_consumer()
        msg = _make_msg("raw.dnp3", DNP3_PAYLOAD)
        c._handle_message(msg)
        writer.ingest_event.assert_called_once()
        ev = writer.ingest_event.call_args.args[0]
        assert isinstance(ev, Dnp3Event)

    def test_conn_message_calls_ingest_event(self):
        c, writer = self._make_consumer()
        msg = _make_msg("raw.conn", CONN_PAYLOAD)
        c._handle_message(msg)
        writer.ingest_event.assert_called_once()
        ev = writer.ingest_event.call_args.args[0]
        assert isinstance(ev, ConnEvent)

    def test_partition_eof_not_counted_as_error(self):
        c, writer = self._make_consumer()
        msg = _make_err_msg(KafkaError._PARTITION_EOF)
        c._handle_message(msg)
        assert c.error_count == 0
        writer.ingest_event.assert_not_called()

    def test_kafka_error_increments_error_count(self):
        c, writer = self._make_consumer()
        msg = _make_err_msg(KafkaError.BROKER_NOT_AVAILABLE)
        c._handle_message(msg)
        assert c.error_count == 1
        writer.ingest_event.assert_not_called()

    def test_bad_payload_increments_error_count(self):
        c, writer = self._make_consumer()
        bad_msg = MagicMock()
        bad_msg.error.return_value = None
        bad_msg.topic.return_value = "raw.modbus"
        bad_msg.value.return_value = b"garbage"
        c._handle_message(bad_msg)
        assert c.error_count == 1

    def test_consumed_count_increments_on_success(self):
        c, writer = self._make_consumer()
        msg = _make_msg("raw.modbus", MODBUS_PAYLOAD)
        c._handle_message(msg)
        assert c.consumed_count == 1


# ---------------------------------------------------------------------------
# Tests — GraphConsumer.run (poll loop)
# ---------------------------------------------------------------------------

class TestConsumerRun:
    def test_subscribes_to_all_topics(self):
        mock_writer = MagicMock()
        mock_kafka = MagicMock()
        # Return None (no message) then stop
        call_count = 0

        def fake_poll(timeout):
            nonlocal call_count
            call_count += 1
            c.stop()  # stop after first poll
            return None

        mock_kafka.poll.side_effect = fake_poll
        c = GraphConsumer(writer=mock_writer, consumer=mock_kafka, poll_timeout=0.0)
        c.run()
        mock_kafka.subscribe.assert_called_once_with(["raw.modbus", "raw.dnp3", "raw.conn"])

    def test_consumer_closed_on_normal_exit(self):
        mock_writer = MagicMock()
        mock_kafka = MagicMock()
        mock_kafka.poll.side_effect = lambda t: (setattr(
            mock_kafka, "_stop", True
        ) or None)  # always return None

        c = GraphConsumer(writer=mock_writer, consumer=mock_kafka, poll_timeout=0.0)
        c.stop()  # pre-stopped
        c.run()
        mock_kafka.close.assert_called_once()

    def test_consumer_closed_on_kafka_exception(self):
        from confluent_kafka import KafkaException
        mock_writer = MagicMock()
        mock_kafka = MagicMock()
        mock_kafka.poll.side_effect = KafkaException("fatal")
        c = GraphConsumer(writer=mock_writer, consumer=mock_kafka, poll_timeout=0.0)
        c._running = True
        c.run()
        mock_kafka.close.assert_called_once()

    def test_processes_messages_in_run_loop(self):
        mock_writer = MagicMock()
        mock_kafka = MagicMock()
        msgs = [
            _make_msg("raw.modbus", MODBUS_PAYLOAD),
            _make_msg("raw.dnp3", DNP3_PAYLOAD),
            None,  # poll returns None → stop
        ]
        call_idx = 0

        def fake_poll(timeout):
            nonlocal call_idx
            msg = msgs[call_idx]
            call_idx += 1
            if call_idx >= len(msgs):
                c.stop()
            return msg

        mock_kafka.poll.side_effect = fake_poll
        c = GraphConsumer(writer=mock_writer, consumer=mock_kafka, poll_timeout=0.0)
        c.run()
        assert mock_writer.ingest_event.call_count == 2


# ---------------------------------------------------------------------------
# Tests — consumer configuration
# ---------------------------------------------------------------------------

class TestConsumerConfig:
    def test_default_bootstrap_servers(self, monkeypatch):
        monkeypatch.delenv("REDPANDA_BOOTSTRAP_SERVERS", raising=False)
        cfg = _build_consumer_config()
        assert cfg["bootstrap.servers"] == "localhost:9092"

    def test_custom_bootstrap_servers(self, monkeypatch):
        monkeypatch.setenv("REDPANDA_BOOTSTRAP_SERVERS", "redpanda:19092")
        cfg = _build_consumer_config()
        assert cfg["bootstrap.servers"] == "redpanda:19092"

    def test_default_group_id(self, monkeypatch):
        monkeypatch.delenv("REDPANDA_CONSUMER_GROUP", raising=False)
        cfg = _build_consumer_config()
        assert cfg["group.id"] == "guardance-graph"

    def test_group_id_override(self):
        cfg = _build_consumer_config(group_id="test-group")
        assert cfg["group.id"] == "test-group"

    def test_auto_offset_reset_default(self, monkeypatch):
        monkeypatch.delenv("REDPANDA_AUTO_OFFSET_RESET", raising=False)
        cfg = _build_consumer_config()
        assert cfg["auto.offset.reset"] == "earliest"
