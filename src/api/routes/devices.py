"""
Device endpoints for the Guardance web API.

Provides read access to the Neo4j Device graph for listing, filtering,
and inspecting individual devices.

All endpoints require a valid API key via the ``X-API-Key`` header when
``GUARDANCE_API_KEYS`` is configured.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.auth import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["devices"])

# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_LIST_DEVICES = """
MATCH (d:Device)
OPTIONAL MATCH (d)-[:MEMBER_OF]->(z:Zone)
RETURN
    d.ip           AS ip,
    d.mac          AS mac,
    d.role         AS role,
    d.purdue_level AS purdue_level,
    d.first_seen   AS first_seen,
    d.last_seen    AS last_seen,
    z.name         AS zone
ORDER BY d.ip
SKIP $skip LIMIT $limit
"""

_COUNT_DEVICES = "MATCH (d:Device) RETURN count(d) AS total"

_GET_DEVICE = """
MATCH (d:Device {ip: $ip})
OPTIONAL MATCH (d)-[:MEMBER_OF]->(z:Zone)
RETURN
    d.ip           AS ip,
    d.mac          AS mac,
    d.role         AS role,
    d.purdue_level AS purdue_level,
    d.first_seen   AS first_seen,
    d.last_seen    AS last_seen,
    z.name         AS zone
"""

_DEVICE_EDGES = """
MATCH (d:Device {ip: $ip})-[r:COMMUNICATES_WITH]->(dst:Device)
RETURN
    dst.ip          AS dst_ip,
    r.protocol      AS protocol,
    r.port          AS port,
    r.function_code AS function_code,
    r.packet_count  AS packet_count,
    r.avg_interval_ms AS avg_interval_ms,
    r.is_periodic   AS is_periodic,
    r.first_seen    AS first_seen,
    r.last_seen     AS last_seen
ORDER BY r.packet_count DESC
"""


# ---------------------------------------------------------------------------
# Driver dependency
# ---------------------------------------------------------------------------

def get_neo4j_driver() -> Any:
    """
    FastAPI dependency that returns an authenticated Neo4j driver.

    Override this in tests via ``app.dependency_overrides``.
    """
    from src.graph.writer import create_driver
    return create_driver()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", summary="List all devices")
async def list_devices(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=500, description="Maximum records to return"),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Return a paginated list of all Device nodes.

    Args:
        skip:   Records to skip (for pagination).
        limit:  Maximum number of records to return (1–500).
        driver: Injected Neo4j driver.

    Returns:
        Dict with ``total``, ``skip``, ``limit``, and ``items`` list.
    """
    try:
        with driver.session() as session:
            total_rec = session.run(_COUNT_DEVICES).single()
            total = total_rec["total"] if total_rec else 0
            records = session.run(_LIST_DEVICES, skip=skip, limit=limit)
            items = [dict(r) for r in records]
    finally:
        driver.close()

    return {"total": total, "skip": skip, "limit": limit, "items": items}


@router.get("/{ip}", summary="Get a device by IP")
async def get_device(
    ip: str,
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Return a single Device node by IP address.

    Args:
        ip:     IPv4 or IPv6 address of the device.
        driver: Injected Neo4j driver.

    Returns:
        Device property dict.

    Raises:
        404: If no device with that IP exists.
    """
    try:
        with driver.session() as session:
            record = session.run(_GET_DEVICE, ip=ip).single()
    finally:
        driver.close()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {ip!r} not found",
        )
    return dict(record)


@router.get("/{ip}/edges", summary="Get outbound edges for a device")
async def get_device_edges(
    ip: str,
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Return all outbound COMMUNICATES_WITH edges for a device.

    Args:
        ip:     Source device IP address.
        driver: Injected Neo4j driver.

    Returns:
        Dict with ``ip`` and ``edges`` list.

    Raises:
        404: If no device with that IP exists.
    """
    try:
        with driver.session() as session:
            check = session.run(_GET_DEVICE, ip=ip).single()
            if check is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Device {ip!r} not found",
                )
            edges = [dict(r) for r in session.run(_DEVICE_EDGES, ip=ip)]
    finally:
        driver.close()

    return {"ip": ip, "edges": edges}
