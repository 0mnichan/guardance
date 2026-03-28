"""
Tests for src/ingest/producer.py

The Kafka/Redpanda producer is tested with a mocked confluent-kafka.Producer
so the tests run without a live broker.  Serialisation and topic-routing logic
are tested directly without mocking.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from src.ingest.producer import (
    ZeekEventProducer,
    _build_producer_config,
    event_to_topic,
    serialize_event,
)
from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent

# ---------------------------------------------------------------------------
# Fixtures — canonical test events
# ---------------------------------------------------------------------------

TS = datetime(2004, 8, 26, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def modbus_event() -> ModbusEvent:
    return ModbusEvent(
        ts=TS,
        uid="Cabc123",
        orig_h="10.0.0.57",
        orig_p=2578,
        resp_h="10.0.0.3",
        resp_p=502,
        func="READ_COILS",
        exception=None,
    )


@pytest.fixture()
def dnp3_event() -> Dnp3Event:
    return Dnp3Event(
        ts=TS,
        uid="Cdef456",
        orig_h="192.168.10.204",
        orig_p=1413,
        resp_h="192.168.10.140",
        resp_p=20000,
        fc_request="READ",
        fc_reply="RESPONSE",
        iin=36866,
    )


@pytest.fixture()
def conn_event() -> ConnEvent:
    return ConnEvent(
        ts=TS,
        uid="Cghi789",
        orig_h="10.0.0.1",
        orig_p=12345,
        resp_h="10.0.0.2",
        resp_p=80,
        proto="tcp",
        service=None,
        duration=1.5,
        orig_bytes=100,
        resp_bytes=200,
        conn_state="SF",
        local_orig=True,
        local_resp=True,
        missed_bytes=0,
        history="ShADadFf",
        orig_pkts=10,
        orig_ip_bytes=460,
        resp_pkts=8,
        resp_ip_bytes=380,
        tunnel_parents=[],
    )


@pytest.fixture()
def mock_producer() -> MagicMock:
    """A mock confluent-kafka Producer with a no-op flush."""
    p = MagicMock()
    p.flush.return_value = 0
    return p


# ---------------------------------------------------------------------------
# Tests — event_to_topic
# ---------------------------------------------------------------------------

class TestEventToTopic:
    def test_modbus_routes_to_raw_modbus(self, modbus_event):
        assert event_to_topic(modbus_event) == "raw.modbus"

    def test_dnp3_routes_to_raw_dnp3(self, dnp3_event):
        assert event_to_topic(dnp3_event) == "raw.dnp3"

    def test_conn_routes_to_raw_conn(self, conn_event):
        assert event_to_topic(conn_event) == "raw.conn"

    def test_prefix_prepended(self, modbus_event):
        assert event_to_topic(modbus_event, prefix="dev.") == "dev.raw.modbus"

    def test_empty_prefix_unchanged(self, dnp3_event):
        assert event_to_topic(dnp3_event, prefix="") == "raw.dnp3"

    def test_unknown_type_raises_type_error(self):
        with pytest.raises(TypeError, match="Unsupported event type"):
            event_to_topic("not-an-event")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Tests — serialize_event
# ---------------------------------------------------------------------------

class TestSerializeEvent:
    def _decode(self, event: Any) -> dict:
        raw = serialize_event(event)
        assert isinstance(raw, bytes)
        return json.loads(raw.decode("utf-8"))

    def test_modbus_fields_present(self, modbus_event):
        d = self._decode(modbus_event)
        assert d["uid"] == "Cabc123"
        assert d["orig_h"] == "10.0.0.57"
        assert d["orig_p"] == 2578
        assert d["resp_h"] == "10.0.0.3"
        assert d["resp_p"] == 502
        assert d["func"] == "READ_COILS"
        assert d["exception"] is None

    def test_datetime_serialised_as_iso(self, modbus_event):
        d = self._decode(modbus_event)
        assert d["ts"] == TS.isoformat()

    def test_dnp3_fields_present(self, dnp3_event):
        d = self._decode(dnp3_event)
        assert d["fc_request"] == "READ"
        assert d["fc_reply"] == "RESPONSE"
        assert d["iin"] == 36866

    def test_conn_fields_present(self, conn_event):
        d = self._decode(conn_event)
        assert d["proto"] == "tcp"
        assert d["service"] is None
        assert d["duration"] == pytest.approx(1.5)
        assert d["tunnel_parents"] == []
        assert d["local_orig"] is True

    def test_output_is_valid_json(self, modbus_event):
        raw = serialize_event(modbus_event)
        # Should not raise
        json.loads(raw)

    def test_none_fields_become_json_null(self, modbus_event):
        d = self._decode(modbus_event)
        assert "exception" in d
        assert d["exception"] is None

    def test_conn_with_tunnel_parents(self, conn_event):
        conn_event.tunnel_parents = ["uid1", "uid2"]
        d = self._decode(conn_event)
        assert d["tunnel_parents"] == ["uid1", "uid2"]


# ---------------------------------------------------------------------------
# Tests — ZeekEventProducer.publish  (mocked broker)
# ---------------------------------------------------------------------------

class TestZeekEventProducerPublish:
    def test_produce_called_with_correct_topic(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        mock_producer.produce.assert_called_once()
        kwargs = mock_producer.produce.call_args.kwargs
        assert kwargs["topic"] == "raw.modbus"

    def test_produce_called_with_serialised_value(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        kwargs = mock_producer.produce.call_args.kwargs
        payload = json.loads(kwargs["value"].decode("utf-8"))
        assert payload["func"] == "READ_COILS"

    def test_message_key_is_orig_resp_pair(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        kwargs = mock_producer.produce.call_args.kwargs
        assert kwargs["key"] == b"10.0.0.57:10.0.0.3"

    def test_poll_called_after_produce(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        mock_producer.poll.assert_called_with(0)

    def test_publish_all_event_types(self, modbus_event, dnp3_event, conn_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        p.publish(dnp3_event)
        p.publish(conn_event)
        assert mock_producer.produce.call_count == 3
        topics = [
            c.kwargs["topic"] for c in mock_producer.produce.call_args_list
        ]
        assert topics == ["raw.modbus", "raw.dnp3", "raw.conn"]

    def test_publish_with_topic_prefix(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer, topic_prefix="test.")
        p.publish(modbus_event)
        kwargs = mock_producer.produce.call_args.kwargs
        assert kwargs["topic"] == "test.raw.modbus"

    def test_kafka_exception_does_not_raise(self, modbus_event, mock_producer):
        from confluent_kafka import KafkaException
        mock_producer.produce.side_effect = KafkaException("broker down")
        p = ZeekEventProducer(producer=mock_producer)
        # Should not raise; error is logged
        p.publish(modbus_event)
        assert p.error_count == 1

    def test_type_error_does_not_raise(self, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        # Passing a non-event object should be caught internally
        p.publish("bad-event")  # type: ignore[arg-type]
        assert p.error_count == 1


# ---------------------------------------------------------------------------
# Tests — publish_batch
# ---------------------------------------------------------------------------

class TestPublishBatch:
    def test_all_events_published(self, modbus_event, dnp3_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish_batch([modbus_event, dnp3_event])
        assert mock_producer.produce.call_count == 2

    def test_flush_called_after_batch(self, modbus_event, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish_batch([modbus_event])
        mock_producer.flush.assert_called()

    def test_empty_batch_still_flushes(self, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.publish_batch([])
        mock_producer.flush.assert_called()


# ---------------------------------------------------------------------------
# Tests — flush and close
# ---------------------------------------------------------------------------

class TestFlushAndClose:
    def test_flush_returns_remaining_count(self, mock_producer):
        mock_producer.flush.return_value = 3
        p = ZeekEventProducer(producer=mock_producer)
        assert p.flush() == 3

    def test_close_calls_flush(self, mock_producer):
        p = ZeekEventProducer(producer=mock_producer)
        p.close()
        mock_producer.flush.assert_called()


# ---------------------------------------------------------------------------
# Tests — context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_context_manager_calls_close(self, modbus_event, mock_producer):
        with ZeekEventProducer(producer=mock_producer) as p:
            p.publish(modbus_event)
        # flush is called on exit (via close)
        mock_producer.flush.assert_called()

    def test_context_manager_flushes_on_exception(self, modbus_event, mock_producer):
        with pytest.raises(RuntimeError):
            with ZeekEventProducer(producer=mock_producer) as p:
                p.publish(modbus_event)
                raise RuntimeError("downstream error")
        mock_producer.flush.assert_called()


# ---------------------------------------------------------------------------
# Tests — delivery callback
# ---------------------------------------------------------------------------

class TestDeliveryCallback:
    def test_success_increments_published_count(self, modbus_event, mock_producer):
        # Immediately invoke the on_delivery callback with success (err=None).
        def fake_produce(**kwargs):
            cb = kwargs.get("on_delivery")
            if cb:
                fake_msg = MagicMock()
                fake_msg.topic.return_value = "raw.modbus"
                fake_msg.partition.return_value = 0
                fake_msg.offset.return_value = 42
                cb(None, fake_msg)

        mock_producer.produce.side_effect = fake_produce
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        assert p.published_count == 1
        assert p.error_count == 0

    def test_failure_increments_error_count(self, modbus_event, mock_producer):
        def fake_produce(**kwargs):
            cb = kwargs.get("on_delivery")
            if cb:
                fake_msg = MagicMock()
                fake_msg.topic.return_value = "raw.modbus"
                fake_msg.partition.return_value = 0
                cb("broker unavailable", fake_msg)

        mock_producer.produce.side_effect = fake_produce
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        assert p.error_count == 1
        assert p.published_count == 0


# ---------------------------------------------------------------------------
# Tests — config from environment
# ---------------------------------------------------------------------------

class TestProducerConfig:
    def test_default_bootstrap_servers(self, monkeypatch):
        monkeypatch.delenv("REDPANDA_BOOTSTRAP_SERVERS", raising=False)
        cfg = _build_producer_config()
        assert cfg["bootstrap.servers"] == "localhost:9092"

    def test_custom_bootstrap_servers(self, monkeypatch):
        monkeypatch.setenv("REDPANDA_BOOTSTRAP_SERVERS", "redpanda:19092")
        cfg = _build_producer_config()
        assert cfg["bootstrap.servers"] == "redpanda:19092"

    def test_custom_linger_ms(self, monkeypatch):
        monkeypatch.setenv("REDPANDA_LINGER_MS", "50")
        cfg = _build_producer_config()
        assert cfg["linger.ms"] == 50

    def test_topic_prefix_from_env(self, monkeypatch, modbus_event, mock_producer):
        monkeypatch.setenv("REDPANDA_TOPIC_PREFIX", "staging.")
        p = ZeekEventProducer(producer=mock_producer)
        p.publish(modbus_event)
        kwargs = mock_producer.produce.call_args.kwargs
        assert kwargs["topic"] == "staging.raw.modbus"
        monkeypatch.delenv("REDPANDA_TOPIC_PREFIX")
