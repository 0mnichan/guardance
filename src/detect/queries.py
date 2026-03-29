"""
Detection queries for Guardance.

Each function runs a Cypher query against a live Neo4j session and returns
a list of dicts representing the matching rows.  The queries correspond to
the five detection categories defined in CLAUDE.md:

1. Cross-zone violations      — devices in zones with |level_diff| > 1 communicating
2. New device detection       — Device.first_seen > baseline_end
3. New edge detection         — COMMUNICATES_WITH.first_seen > baseline_end
4. Polling interval deviation — avg_interval_ms outside [min_ms, max_ms]
5. Unknown protocol           — protocol not in an allowed list on a Device edge

All functions accept a :class:`neo4j.Session` (or any object with a
``.run(query, **params)`` method) so they are trivially mockable in tests.

Timestamps stored in Neo4j are Unix epoch floats (seconds, as written by
GraphWriter).  The ``baseline_end`` parameter is converted to epoch before
the query so callers can pass plain :class:`datetime` objects.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Record = dict[str, Any]


# ---------------------------------------------------------------------------
# 1. Cross-zone violations
# ---------------------------------------------------------------------------

_CROSS_ZONE_QUERY = """
MATCH (d1:Device)-[r:COMMUNICATES_WITH]->(d2:Device)
MATCH (d1)-[:MEMBER_OF]->(z1:Zone)
MATCH (d2)-[:MEMBER_OF]->(z2:Zone)
WHERE abs(z1.purdue_level - z2.purdue_level) > 1
RETURN
    d1.ip          AS src_ip,
    d2.ip          AS dst_ip,
    z1.name        AS src_zone,
    z2.name        AS dst_zone,
    z1.purdue_level AS src_level,
    z2.purdue_level AS dst_level,
    r.protocol     AS protocol,
    r.port         AS port,
    r.packet_count AS packet_count
ORDER BY abs(z1.purdue_level - z2.purdue_level) DESC
"""


def cross_zone_violations(session: Any) -> list[Record]:
    """
    Return all device pairs communicating across non-adjacent Purdue levels.

    A violation is defined as ``abs(src_zone.purdue_level - dst_zone.purdue_level) > 1``.
    Both devices must have a MEMBER_OF edge to a Zone node; pairs with no zone
    assignment are excluded.

    Args:
        session: An active ``neo4j.Session`` (or compatible mock).

    Returns:
        List of dicts with keys: src_ip, dst_ip, src_zone, dst_zone,
        src_level, dst_level, protocol, port, packet_count.
    """
    logger.debug("Running cross_zone_violations query")
    result = session.run(_CROSS_ZONE_QUERY)
    rows = [dict(record) for record in result]
    logger.info("cross_zone_violations: %d findings", len(rows))
    return rows


# ---------------------------------------------------------------------------
# 2. New device detection
# ---------------------------------------------------------------------------

_NEW_DEVICES_QUERY = """
MATCH (d:Device)
WHERE d.first_seen > $baseline_end
RETURN
    d.ip         AS ip,
    d.mac        AS mac,
    d.role       AS role,
    d.first_seen AS first_seen,
    d.last_seen  AS last_seen
ORDER BY d.first_seen ASC
"""


def new_devices(session: Any, baseline_end: datetime) -> list[Record]:
    """
    Return devices first seen after the baseline period ended.

    Args:
        session:      An active ``neo4j.Session`` (or compatible mock).
        baseline_end: Cutoff timestamp; devices with ``first_seen`` strictly
                      after this are considered new.

    Returns:
        List of dicts with keys: ip, mac, role, first_seen, last_seen.
        Timestamp fields are Unix epoch floats as stored in Neo4j.
    """
    epoch = baseline_end.timestamp()
    logger.debug("Running new_devices query (baseline_end=%s, epoch=%.3f)", baseline_end, epoch)
    result = session.run(_NEW_DEVICES_QUERY, baseline_end=epoch)
    rows = [dict(record) for record in result]
    logger.info("new_devices: %d findings (baseline_end=%s)", len(rows), baseline_end)
    return rows


# ---------------------------------------------------------------------------
# 3. New edge detection
# ---------------------------------------------------------------------------

_NEW_EDGES_QUERY = """
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE r.first_seen > $baseline_end
RETURN
    src.ip         AS src_ip,
    dst.ip         AS dst_ip,
    r.protocol     AS protocol,
    r.port         AS port,
    r.function_code AS function_code,
    r.first_seen   AS first_seen,
    r.packet_count AS packet_count
ORDER BY r.first_seen ASC
"""


def new_edges(session: Any, baseline_end: datetime) -> list[Record]:
    """
    Return communication edges (COMMUNICATES_WITH) first observed after the
    baseline period ended.

    Args:
        session:      An active ``neo4j.Session`` (or compatible mock).
        baseline_end: Cutoff timestamp; edges with ``first_seen`` strictly
                      after this are considered new.

    Returns:
        List of dicts with keys: src_ip, dst_ip, protocol, port,
        function_code, first_seen, packet_count.
    """
    epoch = baseline_end.timestamp()
    logger.debug("Running new_edges query (baseline_end=%s, epoch=%.3f)", baseline_end, epoch)
    result = session.run(_NEW_EDGES_QUERY, baseline_end=epoch)
    rows = [dict(record) for record in result]
    logger.info("new_edges: %d findings (baseline_end=%s)", len(rows), baseline_end)
    return rows


# ---------------------------------------------------------------------------
# 4. Polling interval deviation
# ---------------------------------------------------------------------------

_INTERVAL_DEVIATION_QUERY = """
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE r.packet_count > 1
  AND (r.avg_interval_ms < $min_ms OR r.avg_interval_ms > $max_ms)
RETURN
    src.ip            AS src_ip,
    dst.ip            AS dst_ip,
    r.protocol        AS protocol,
    r.port            AS port,
    r.function_code   AS function_code,
    r.avg_interval_ms AS avg_interval_ms,
    r.packet_count    AS packet_count,
    r.is_periodic     AS is_periodic
ORDER BY r.avg_interval_ms ASC
"""


def interval_deviation(
    session: Any,
    min_ms: float = 100.0,
    max_ms: float = 1000.0,
) -> list[Record]:
    """
    Return edges whose polling interval falls outside the expected range.

    Only edges with more than one observed packet (so an interval can be
    computed) are considered.  The ``avg_interval_ms`` field on the
    COMMUNICATES_WITH relationship is compared against ``[min_ms, max_ms]``.

    Args:
        session: An active ``neo4j.Session`` (or compatible mock).
        min_ms:  Lower bound of the acceptable interval in milliseconds.
                 Default 100 ms.
        max_ms:  Upper bound of the acceptable interval in milliseconds.
                 Default 1000 ms.

    Returns:
        List of dicts with keys: src_ip, dst_ip, protocol, port,
        function_code, avg_interval_ms, packet_count, is_periodic.
    """
    logger.debug(
        "Running interval_deviation query (min_ms=%.1f, max_ms=%.1f)", min_ms, max_ms
    )
    result = session.run(_INTERVAL_DEVIATION_QUERY, min_ms=min_ms, max_ms=max_ms)
    rows = [dict(record) for record in result]
    logger.info("interval_deviation: %d findings", len(rows))
    return rows


# ---------------------------------------------------------------------------
# 5. Unknown protocol
# ---------------------------------------------------------------------------

_UNKNOWN_PROTOCOL_QUERY = """
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE NOT r.protocol IN $allowed
RETURN
    src.ip          AS src_ip,
    dst.ip          AS dst_ip,
    r.protocol      AS protocol,
    r.port          AS port,
    r.function_code AS function_code,
    r.packet_count  AS packet_count,
    r.first_seen    AS first_seen
ORDER BY r.first_seen ASC
"""


def unknown_protocol(session: Any, allowed: list[str]) -> list[Record]:
    """
    Return edges using a protocol not in the allowed list.

    In OT networks the set of legitimate protocols is small and known in
    advance (Modbus, DNP3, S7, etc.).  Any edge with a protocol outside
    that set warrants investigation.

    Args:
        session: An active ``neo4j.Session`` (or compatible mock).
        allowed: List of protocol name strings considered legitimate,
                 e.g. ``["modbus", "dnp3", "s7comm", "tcp", "udp"]``.

    Returns:
        List of dicts with keys: src_ip, dst_ip, protocol, port,
        function_code, packet_count, first_seen.
    """
    logger.debug("Running unknown_protocol query (allowed=%s)", allowed)
    result = session.run(_UNKNOWN_PROTOCOL_QUERY, allowed=allowed)
    rows = [dict(record) for record in result]
    logger.info("unknown_protocol: %d findings", len(rows))
    return rows
