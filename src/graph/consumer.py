"""
Redpanda/Kafka consumer for the Guardance graph pipeline.

Reads JSON messages from the raw.modbus, raw.dnp3, and raw.conn topics,
deserialises them back into ZeekEvent dataclasses, and passes each event
to a :class:`GraphWriter` for Neo4j ingestion.

Configuration (env vars):

    REDPANDA_BOOTSTRAP_SERVERS    default: "localhost:9092"
    REDPANDA_CONSUMER_GROUP       default: "guardance-graph"
    REDPANDA_AUTO_OFFSET_RESET    default: "earliest"
    REDPANDA_TOPIC_PREFIX         default: ""
    REDPANDA_POLL_TIMEOUT_S       default: "1.0"
"""

from __future__ import annotations

import json
import logging
import os
import signal
from datetime import datetime, timezone
from typing import Optional

from confluent_kafka import Consumer, KafkaError, KafkaException, Message

from src.graph.writer import GraphWriter
from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent, ZeekEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Topic → event type mapping
# ---------------------------------------------------------------------------

_BASE_TOPICS = ("raw.modbus", "raw.dnp3", "raw.conn")


def _topic_list(prefix: str = "") -> list[str]:
    """Return the list of topics to subscribe to, with optional prefix."""
    return [f"{prefix}{t}" for t in _BASE_TOPICS]


def _base_topic(full_topic: str, prefix: str) -> str:
    """Strip *prefix* from *full_topic* to get the canonical base topic name."""
    return full_topic[len(prefix):] if full_topic.startswith(prefix) else full_topic


# ---------------------------------------------------------------------------
# Deserialisation
# ---------------------------------------------------------------------------

def _parse_ts(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string produced by serialize_event."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def deserialize_message(topic: str, raw: bytes, prefix: str = "") -> Optional[ZeekEvent]:
    """
    Deserialise a raw Kafka message value into the appropriate ZeekEvent.

    Args:
        topic:  The full Kafka topic name the message was consumed from.
        raw:    Raw bytes of the message value (UTF-8 JSON).
        prefix: Topic prefix that should be stripped before lookup.

    Returns:
        A ModbusEvent, Dnp3Event, or ConnEvent, or ``None`` if the message
        cannot be parsed.  Errors are logged at WARNING level.
    """
    try:
        data: dict = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Failed to decode message from %s: %s", topic, exc)
        return None

    base = _base_topic(topic, prefix)

    try:
        if base == "raw.modbus":
            return ModbusEvent(
                ts=_parse_ts(data["ts"]),
                uid=data["uid"],
                orig_h=data["orig_h"],
                orig_p=int(data["orig_p"]),
                resp_h=data["resp_h"],
                resp_p=int(data["resp_p"]),
                func=data["func"],
                exception=data.get("exception"),
            )

        if base == "raw.dnp3":
            return Dnp3Event(
                ts=_parse_ts(data["ts"]),
                uid=data["uid"],
                orig_h=data["orig_h"],
                orig_p=int(data["orig_p"]),
                resp_h=data["resp_h"],
                resp_p=int(data["resp_p"]),
                fc_request=data["fc_request"],
                fc_reply=data.get("fc_reply"),
                iin=data.get("iin"),
            )

        if base == "raw.conn":
            return ConnEvent(
                ts=_parse_ts(data["ts"]),
                uid=data["uid"],
                orig_h=data["orig_h"],
                orig_p=int(data["orig_p"]),
                resp_h=data["resp_h"],
                resp_p=int(data["resp_p"]),
                proto=data["proto"],
                service=data.get("service"),
                duration=data.get("duration"),
                orig_bytes=data.get("orig_bytes"),
                resp_bytes=data.get("resp_bytes"),
                conn_state=data["conn_state"],
                local_orig=data.get("local_orig"),
                local_resp=data.get("local_resp"),
                missed_bytes=data.get("missed_bytes"),
                history=data.get("history"),
                orig_pkts=data.get("orig_pkts"),
                orig_ip_bytes=data.get("orig_ip_bytes"),
                resp_pkts=data.get("resp_pkts"),
                resp_ip_bytes=data.get("resp_ip_bytes"),
                tunnel_parents=data.get("tunnel_parents"),
            )

    except (KeyError, ValueError, TypeError) as exc:
        logger.warning(
            "Failed to construct event from %s message: %s — data: %r",
            base,
            exc,
            data,
        )
        return None

    logger.warning("Unrecognised base topic: %s", base)
    return None


# ---------------------------------------------------------------------------
# Consumer configuration
# ---------------------------------------------------------------------------

def _build_consumer_config(group_id: Optional[str] = None) -> dict:
    """
    Build a confluent-kafka Consumer configuration dict from env vars.

    Args:
        group_id: Override for the consumer group ID.

    Returns:
        Dict suitable for ``confluent_kafka.Consumer()``.
    """
    return {
        "bootstrap.servers": os.environ.get(
            "REDPANDA_BOOTSTRAP_SERVERS", "localhost:9092"
        ),
        "group.id": group_id
        or os.environ.get("REDPANDA_CONSUMER_GROUP", "guardance-graph"),
        "auto.offset.reset": os.environ.get(
            "REDPANDA_AUTO_OFFSET_RESET", "earliest"
        ),
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
    }


# ---------------------------------------------------------------------------
# GraphConsumer
# ---------------------------------------------------------------------------

class GraphConsumer:
    """
    Consumes Zeek events from Redpanda and writes them to Neo4j via GraphWriter.

    The consumer runs a blocking poll loop (:meth:`run`) that continues until
    :meth:`stop` is called or a fatal error occurs.  SIGINT and SIGTERM are
    handled gracefully.

    Usage::

        writer = GraphWriter(create_driver())
        writer.ensure_constraints()

        consumer = GraphConsumer(writer=writer)
        consumer.run()   # blocks; Ctrl-C to stop
    """

    def __init__(
        self,
        writer: GraphWriter,
        consumer: Optional[Consumer] = None,
        topic_prefix: str = "",
        poll_timeout: float = 0.0,
    ) -> None:
        """
        Initialise the graph consumer.

        Args:
            writer:       GraphWriter instance to send events to.
            consumer:     An existing confluent-kafka Consumer.  If ``None``,
                          one is created from env vars.
            topic_prefix: Prepended to all topic names.  Defaults to
                          ``REDPANDA_TOPIC_PREFIX`` env var.
            poll_timeout: Seconds to block in each poll call.  Defaults to
                          ``REDPANDA_POLL_TIMEOUT_S`` env var (1.0 s).
        """
        self._writer = writer
        self._prefix = topic_prefix or os.environ.get("REDPANDA_TOPIC_PREFIX", "")
        self._poll_timeout = poll_timeout or float(
            os.environ.get("REDPANDA_POLL_TIMEOUT_S", "1.0")
        )
        self._consumer: Consumer = consumer or Consumer(_build_consumer_config())
        self._running = False
        self._consumed: int = 0
        self._errors: int = 0

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        """Register SIGINT / SIGTERM handlers that call :meth:`stop`."""

        def _handle(signum, _frame):  # type: ignore[no-untyped-def]
            logger.info("Received signal %s — stopping consumer", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    def _handle_message(self, msg: Message) -> None:
        """Process a single Kafka message: deserialise and write to Neo4j."""
        if msg.error():
            err = msg.error()
            if err.code() == KafkaError._PARTITION_EOF:
                # End of partition — not an error, just informational.
                logger.debug(
                    "Reached end of %s [%d] at offset %d",
                    msg.topic(),
                    msg.partition(),
                    msg.offset(),
                )
            else:
                self._errors += 1
                logger.error("Consumer error: %s", err)
            return

        event = deserialize_message(msg.topic(), msg.value(), prefix=self._prefix)
        if event is None:
            self._errors += 1
            return

        self._writer.ingest_event(event)
        self._consumed += 1

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the consumer poll loop.

        Subscribes to all OT topics and polls continuously until
        :meth:`stop` is called.  Handles SIGINT/SIGTERM for clean shutdown.
        """
        topics = _topic_list(self._prefix)
        self._consumer.subscribe(topics)
        self._running = True
        self._install_signal_handlers()

        logger.info("Subscribed to topics: %s", topics)

        try:
            while self._running:
                msg = self._consumer.poll(self._poll_timeout)
                if msg is None:
                    continue
                self._handle_message(msg)
        except KafkaException as exc:
            logger.error("Fatal Kafka error: %s", exc)
            self._errors += 1
        finally:
            self._consumer.close()
            logger.info(
                "Consumer stopped — consumed: %d, errors: %d",
                self._consumed,
                self._errors,
            )

    def stop(self) -> None:
        """Signal the poll loop to exit after the current message."""
        self._running = False

    @property
    def consumed_count(self) -> int:
        """Total messages successfully processed."""
        return self._consumed

    @property
    def error_count(self) -> int:
        """Total messages that failed to deserialise or write."""
        return self._errors
