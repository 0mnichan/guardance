"""
Neo4j graph writer for Guardance.

Translates parsed Zeek events into MERGE operations that build and maintain
the device behaviour graph defined in CLAUDE.md:

    Nodes:   Device, Zone, Protocol
    Edges:   COMMUNICATES_WITH (Device → Device)
             MEMBER_OF         (Device → Zone)

COMMUNICATES_WITH is keyed by (src_ip, dst_ip, protocol, port, function_code)
so each distinct operation type on each channel gets its own edge.  That lets
detection queries spot new function codes appearing on an established channel.

Configuration (env vars):

    NEO4J_URI       default: "bolt://localhost:7687"
    NEO4J_USER      default: "neo4j"
    NEO4J_PASSWORD  default: "neo4j"
    NEO4J_DATABASE  default: "neo4j"
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from neo4j import Driver, GraphDatabase, Session
from neo4j.exceptions import Neo4jError

from src.ingest.zeek_parser import ConnEvent, Dnp3Event, ModbusEvent, ZeekEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Driver factory
# ---------------------------------------------------------------------------

def create_driver(
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> Driver:
    """
    Create and return a Neo4j driver using environment variables as defaults.

    Args:
        uri:      Bolt URI, e.g. ``"bolt://localhost:7687"``.
        user:     Neo4j username.
        password: Neo4j password.

    Returns:
        An authenticated :class:`neo4j.Driver` instance.
    """
    return GraphDatabase.driver(
        uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(
            user or os.environ.get("NEO4J_USER", "neo4j"),
            password or os.environ.get("NEO4J_PASSWORD", "neo4j"),
        ),
    )


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

# Create uniqueness constraints on first run.
_CONSTRAINTS = [
    "CREATE CONSTRAINT device_ip IF NOT EXISTS FOR (d:Device) REQUIRE d.ip IS UNIQUE",
    "CREATE CONSTRAINT zone_name IF NOT EXISTS FOR (z:Zone) REQUIRE z.name IS UNIQUE",
    "CREATE CONSTRAINT protocol_name IF NOT EXISTS FOR (p:Protocol) REQUIRE p.name IS UNIQUE",
]

# Upsert a Device node.  Tracks first_seen / last_seen as epoch floats for
# easy arithmetic in Cypher detection queries.
_UPSERT_DEVICE = """
MERGE (d:Device {ip: $ip})
ON CREATE SET
    d.first_seen = $ts,
    d.last_seen  = $ts
ON MATCH SET
    d.last_seen  = CASE WHEN $ts > d.last_seen THEN $ts ELSE d.last_seen END
"""

# Upsert a COMMUNICATES_WITH edge between two Device nodes.
# packet_count accumulates; avg_interval_ms is recomputed each update.
_UPSERT_EDGE = """
MATCH (src:Device {ip: $orig_h})
MATCH (dst:Device {ip: $resp_h})
MERGE (src)-[r:COMMUNICATES_WITH {
    protocol:      $protocol,
    port:          $port,
    function_code: $function_code
}]->(dst)
ON CREATE SET
    r.first_seen      = $ts,
    r.last_seen       = $ts,
    r.packet_count    = 1,
    r.avg_interval_ms = 0.0,
    r.is_periodic     = false
ON MATCH SET
    r.last_seen       = CASE WHEN $ts > r.last_seen THEN $ts ELSE r.last_seen END,
    r.packet_count    = r.packet_count + 1,
    r.avg_interval_ms = CASE
        WHEN r.packet_count > 1
        THEN ((r.last_seen - r.first_seen) * 1000.0) / (r.packet_count - 1)
        ELSE 0.0
    END,
    r.is_periodic     = CASE
        WHEN r.packet_count > 1
             AND ((r.last_seen - r.first_seen) * 1000.0) / (r.packet_count - 1)
                 BETWEEN 100.0 AND 1000.0
        THEN true
        ELSE false
    END
"""


# ---------------------------------------------------------------------------
# GraphWriter
# ---------------------------------------------------------------------------

class GraphWriter:
    """
    Writes Zeek events into the Guardance Neo4j graph.

    Intended to be used as a long-lived object (one per consumer process).
    Each :meth:`ingest_event` call opens a managed transaction, MERGEs the
    two Device nodes, then MERGEs the COMMUNICATES_WITH edge.

    Usage::

        driver = create_driver()
        writer = GraphWriter(driver)
        writer.ensure_constraints()
        writer.ingest_event(some_modbus_event)
        driver.close()

    Or as a context manager::

        with GraphWriter(create_driver()) as w:
            w.ensure_constraints()
            for event in events:
                w.ingest_event(event)
    """

    def __init__(self, driver: Driver, database: Optional[str] = None) -> None:
        """
        Initialise the writer.

        Args:
            driver:   An authenticated Neo4j driver.
            database: Target database name.  Defaults to the
                      ``NEO4J_DATABASE`` env var, then ``"neo4j"``.
        """
        self._driver = driver
        self._database: str = database or os.environ.get("NEO4J_DATABASE", "neo4j")
        self._ingested: int = 0
        self._errors: int = 0

    # ------------------------------------------------------------------
    # Schema setup
    # ------------------------------------------------------------------

    def ensure_constraints(self) -> None:
        """
        Create Neo4j uniqueness constraints required by the schema.

        Safe to call on every startup; uses ``IF NOT EXISTS`` so it is
        idempotent.
        """
        with self._driver.session(database=self._database) as session:
            for cql in _CONSTRAINTS:
                try:
                    session.run(cql)
                except Neo4jError as exc:
                    logger.error("Failed to create constraint: %s — %s", cql, exc)

    # ------------------------------------------------------------------
    # Internal transaction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ts_epoch(ts: datetime) -> float:
        """Convert a datetime to a Unix epoch float (seconds)."""
        return ts.timestamp()

    def _write_device_and_edge(
        self,
        session: Session,
        orig_h: str,
        resp_h: str,
        protocol: str,
        port: int,
        function_code: str,
        ts: datetime,
    ) -> None:
        """
        Upsert both Device nodes and the COMMUNICATES_WITH edge in one session.

        Runs as a single write transaction so partial failures are rolled back.
        """
        ts_epoch = self._ts_epoch(ts)

        def _tx(tx):  # type: ignore[no-untyped-def]
            tx.run(_UPSERT_DEVICE, ip=orig_h, ts=ts_epoch)
            tx.run(_UPSERT_DEVICE, ip=resp_h, ts=ts_epoch)
            tx.run(
                _UPSERT_EDGE,
                orig_h=orig_h,
                resp_h=resp_h,
                protocol=protocol,
                port=port,
                function_code=function_code,
                ts=ts_epoch,
            )

        session.execute_write(_tx)

    # ------------------------------------------------------------------
    # Per-event-type ingestion
    # ------------------------------------------------------------------

    def _ingest_modbus(self, event: ModbusEvent) -> None:
        """Write a ModbusEvent to the graph."""
        with self._driver.session(database=self._database) as session:
            self._write_device_and_edge(
                session,
                orig_h=event.orig_h,
                resp_h=event.resp_h,
                protocol="modbus",
                port=event.resp_p,
                function_code=event.func,
                ts=event.ts,
            )

    def _ingest_dnp3(self, event: Dnp3Event) -> None:
        """Write a Dnp3Event to the graph."""
        # Use fc_request as the function code; fc_reply is the outstation response.
        with self._driver.session(database=self._database) as session:
            self._write_device_and_edge(
                session,
                orig_h=event.orig_h,
                resp_h=event.resp_h,
                protocol="dnp3",
                port=event.resp_p,
                function_code=event.fc_request,
                ts=event.ts,
            )

    def _ingest_conn(self, event: ConnEvent) -> None:
        """
        Write a ConnEvent to the graph.

        conn.log records all TCP/UDP flows.  We use the service label if
        available (e.g. ``"modbus"``, ``"dnp3"``), otherwise the protocol
        field (``"tcp"`` / ``"udp"``).  function_code is set to
        ``"flow"`` since conn.log has no application-layer detail.
        """
        protocol = event.service if event.service else event.proto
        with self._driver.session(database=self._database) as session:
            self._write_device_and_edge(
                session,
                orig_h=event.orig_h,
                resp_h=event.resp_h,
                protocol=protocol,
                port=event.resp_p,
                function_code="flow",
                ts=event.ts,
            )

    # ------------------------------------------------------------------
    # Public ingestion interface
    # ------------------------------------------------------------------

    def ingest_event(self, event: ZeekEvent) -> None:
        """
        Write a single Zeek event to the graph.

        Dispatches to the appropriate per-type handler.  Neo4j errors are
        caught and logged; the method never raises so a bad event cannot
        halt the consumer.

        Args:
            event: A ModbusEvent, Dnp3Event, or ConnEvent.
        """
        try:
            if isinstance(event, ModbusEvent):
                self._ingest_modbus(event)
            elif isinstance(event, Dnp3Event):
                self._ingest_dnp3(event)
            elif isinstance(event, ConnEvent):
                self._ingest_conn(event)
            else:
                logger.warning("Unknown event type: %s", type(event).__name__)
                return
            self._ingested += 1
        except Neo4jError as exc:
            self._errors += 1
            logger.error("Neo4j write failed for %s: %s", type(event).__name__, exc)
        except Exception as exc:  # pylint: disable=broad-except
            self._errors += 1
            logger.error(
                "Unexpected error ingesting %s: %s", type(event).__name__, exc
            )

    def ingest_batch(self, events: list[ZeekEvent]) -> None:
        """
        Ingest a list of events, logging a summary on completion.

        Args:
            events: List of ZeekEvent instances to write.
        """
        for event in events:
            self.ingest_event(event)
        logger.info(
            "Batch complete — ingested: %d, errors: %d",
            self._ingested,
            self._errors,
        )

    @property
    def ingested_count(self) -> int:
        """Total events successfully written to Neo4j."""
        return self._ingested

    @property
    def error_count(self) -> int:
        """Total events that failed to write."""
        return self._errors

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "GraphWriter":
        """Return self for ``with GraphWriter(...) as w:`` usage."""
        return self

    def __exit__(self, *_) -> None:  # type: ignore[no-untyped-def]
        """Close the underlying driver on context exit."""
        self._driver.close()
