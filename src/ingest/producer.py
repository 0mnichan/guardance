"""
Redpanda/Kafka producer for Zeek ICSNPP events.

Serialises ModbusEvent, Dnp3Event, and ConnEvent dataclasses to JSON and
publishes them to the appropriate topics:

    raw.modbus  ← ModbusEvent
    raw.dnp3    ← Dnp3Event
    raw.conn    ← ConnEvent

Configuration (all via environment variables with sensible defaults):

    REDPANDA_BOOTSTRAP_SERVERS   default: "localhost:9092"
    REDPANDA_TOPIC_PREFIX        default: ""   (e.g. "dev." → "dev.raw.modbus")
    REDPANDA_PRODUCER_ACKS       default: "all"
    REDPANDA_LINGER_MS           default: "5"
    REDPANDA_BATCH_SIZE          default: "65536"
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

from confluent_kafka import Producer, KafkaException

from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent, ZeekEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Topic routing
# ---------------------------------------------------------------------------

_TOPIC_MAP: dict[type, str] = {
    ModbusEvent: "raw.modbus",
    Dnp3Event: "raw.dnp3",
    ConnEvent: "raw.conn",
}


def event_to_topic(event: ZeekEvent, prefix: str = "") -> str:
    """
    Return the Redpanda topic name for *event*.

    Args:
        event: A parsed Zeek event (ModbusEvent, Dnp3Event, or ConnEvent).
        prefix: Optional string prepended to the base topic name, e.g. ``"dev."``.

    Returns:
        Topic string such as ``"raw.modbus"`` or ``"dev.raw.modbus"``.

    Raises:
        TypeError: If *event* is not a recognised ZeekEvent type.
    """
    base = _TOPIC_MAP.get(type(event))
    if base is None:
        raise TypeError(f"Unsupported event type: {type(event).__name__}")
    return f"{prefix}{base}"


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def _default_json(obj: Any) -> Any:
    """JSON serialiser hook for types not handled by the stdlib encoder."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")


def serialize_event(event: ZeekEvent) -> bytes:
    """
    Serialise a ZeekEvent dataclass to UTF-8 encoded JSON bytes.

    datetime fields are converted to ISO 8601 strings.
    None fields are preserved as JSON ``null``.

    Args:
        event: A ModbusEvent, Dnp3Event, or ConnEvent instance.

    Returns:
        UTF-8 encoded JSON bytes ready for Kafka/Redpanda.
    """
    payload = dataclasses.asdict(event)
    return json.dumps(payload, default=_default_json).encode("utf-8")


# ---------------------------------------------------------------------------
# Producer configuration
# ---------------------------------------------------------------------------

def _build_producer_config() -> dict[str, Any]:
    """
    Build a confluent-kafka Producer configuration dict from environment variables.

    Returns:
        Dictionary suitable for passing to ``confluent_kafka.Producer()``.
    """
    return {
        "bootstrap.servers": os.environ.get(
            "REDPANDA_BOOTSTRAP_SERVERS", "localhost:9092"
        ),
        "acks": os.environ.get("REDPANDA_PRODUCER_ACKS", "all"),
        "linger.ms": int(os.environ.get("REDPANDA_LINGER_MS", "5")),
        "batch.size": int(os.environ.get("REDPANDA_BATCH_SIZE", "65536")),
        # Retry transient errors automatically.
        "retries": 3,
        "retry.backoff.ms": 200,
    }


# ---------------------------------------------------------------------------
# ZeekEventProducer
# ---------------------------------------------------------------------------

class ZeekEventProducer:
    """
    Publishes parsed Zeek events to Redpanda/Kafka topics.

    Each event is keyed by ``"{orig_h}:{resp_h}"`` so that traffic between
    the same two endpoints lands on the same partition (preserving order).

    Usage::

        producer = ZeekEventProducer()
        for event in parse_zeek_log(path):
            producer.publish(event)
        producer.flush()
        producer.close()

    Or as a context manager::

        with ZeekEventProducer() as p:
            for event in parse_zeek_log(path):
                p.publish(event)
    """

    def __init__(
        self,
        producer: Optional[Producer] = None,
        topic_prefix: str = "",
    ) -> None:
        """
        Initialise the producer.

        Args:
            producer: An existing confluent-kafka Producer instance.  If
                ``None`` (the default) a new one is created from environment
                variables via :func:`_build_producer_config`.
            topic_prefix: String prepended to every topic name.  Defaults to
                the ``REDPANDA_TOPIC_PREFIX`` env var, then ``""``.
        """
        self._producer: Producer = producer or Producer(_build_producer_config())
        self._prefix: str = topic_prefix or os.environ.get(
            "REDPANDA_TOPIC_PREFIX", ""
        )
        self._published: int = 0
        self._errors: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _delivery_callback(self, err: Any, msg: Any) -> None:
        """Called by confluent-kafka for each message after delivery attempt."""
        if err:
            self._errors += 1
            logger.error(
                "Delivery failure for topic %s partition %s: %s",
                msg.topic(),
                msg.partition(),
                err,
            )
        else:
            self._published += 1
            logger.debug(
                "Delivered to %s [partition %d] offset %d",
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )

    @staticmethod
    def _message_key(event: ZeekEvent) -> bytes:
        """Return a partition key derived from the source/dest IP pair."""
        return f"{event.orig_h}:{event.resp_h}".encode("utf-8")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def publish(self, event: ZeekEvent) -> None:
        """
        Enqueue *event* for delivery to its Redpanda topic.

        The call is non-blocking; use :meth:`flush` to wait for all pending
        messages.  Publish errors are caught and logged; the method does not
        raise so a single bad event cannot halt the pipeline.

        Args:
            event: A ModbusEvent, Dnp3Event, or ConnEvent to publish.
        """
        try:
            topic = event_to_topic(event, prefix=self._prefix)
            value = serialize_event(event)
            key = self._message_key(event)
            self._producer.produce(
                topic=topic,
                key=key,
                value=value,
                on_delivery=self._delivery_callback,
            )
            # Call poll(0) to trigger delivery callbacks without blocking.
            self._producer.poll(0)
        except (TypeError, KafkaException) as exc:
            self._errors += 1
            logger.error("Failed to publish event %s: %s", type(event).__name__, exc)

    def publish_batch(self, events: list[ZeekEvent]) -> None:
        """
        Publish multiple events in sequence, then flush.

        Args:
            events: List of ZeekEvent instances to publish.
        """
        for event in events:
            self.publish(event)
        self.flush()

    def flush(self, timeout: float = 30.0) -> int:
        """
        Block until all enqueued messages have been delivered or *timeout* elapses.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            Number of messages still in the local queue (0 means all delivered).
        """
        remaining = self._producer.flush(timeout)
        if remaining > 0:
            logger.warning("%d messages not delivered within %.1fs timeout", remaining, timeout)
        return remaining

    def close(self) -> None:
        """Flush and release producer resources."""
        self.flush()
        logger.info(
            "Producer closed — published: %d, errors: %d",
            self._published,
            self._errors,
        )

    @property
    def published_count(self) -> int:
        """Total number of successfully delivered messages (delivery-callback counted)."""
        return self._published

    @property
    def error_count(self) -> int:
        """Total number of delivery errors encountered."""
        return self._errors

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "ZeekEventProducer":
        """Return self to support ``with ZeekEventProducer() as p:`` usage."""
        return self

    def __exit__(self, *_: Any) -> None:
        """Flush and close on context exit regardless of exceptions."""
        self.close()
