"""
Findings endpoints for the Guardance web API.

Runs the five detection queries on demand and returns their results.
Findings can also be retrieved per-category with optional parameters.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from src.api.auth import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


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

@router.get("", summary="Run all detection queries")
async def run_all_findings(
    baseline_hours: float = Query(
        24.0,
        ge=0.0,
        description="Hours before now to use as the baseline cutoff",
    ),
    allowed_protocols: str = Query(
        "modbus,dnp3,s7comm,tcp,udp",
        description="Comma-separated protocol allowlist",
    ),
    min_interval_ms: float = Query(100.0, ge=0.0, description="Minimum polling interval (ms)"),
    max_interval_ms: float = Query(1000.0, ge=0.0, description="Maximum polling interval (ms)"),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Run all five detection queries and return a summary of findings.

    Args:
        baseline_hours:    Hours before now to treat as the baseline cutoff.
        allowed_protocols: Comma-separated list of allowed protocol names.
        min_interval_ms:   Lower bound for the acceptable polling window (ms).
        max_interval_ms:   Upper bound for the acceptable polling window (ms).
        driver:            Injected Neo4j driver.

    Returns:
        Dict with a ``findings`` key per query name, and a ``total`` count.
    """
    from src.detect.queries import (
        cross_zone_violations,
        interval_deviation,
        new_devices,
        new_edges,
        unknown_protocol,
    )

    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=baseline_hours)
    allowed = [p.strip() for p in allowed_protocols.split(",") if p.strip()]

    try:
        with driver.session() as session:
            results = {
                "cross_zone_violations": cross_zone_violations(session),
                "new_devices":           new_devices(session, baseline_end),
                "new_edges":             new_edges(session, baseline_end),
                "interval_deviation":    interval_deviation(session, min_interval_ms, max_interval_ms),
                "unknown_protocol":      unknown_protocol(session, allowed),
            }
    finally:
        driver.close()

    total = sum(len(v) for v in results.values())
    logger.info("Findings API: %d total findings", total)
    return {"total": total, "baseline_end": baseline_end.isoformat(), "findings": results}


@router.get("/cross-zone", summary="Cross-zone violations")
async def get_cross_zone(
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """Return devices communicating across non-adjacent Purdue levels."""
    from src.detect.queries import cross_zone_violations
    try:
        with driver.session() as session:
            results = cross_zone_violations(session)
    finally:
        driver.close()
    return {"count": len(results), "items": results}


@router.get("/new-devices", summary="New devices since baseline")
async def get_new_devices(
    baseline_hours: float = Query(24.0, ge=0.0),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """Return devices first seen after the baseline period."""
    from src.detect.queries import new_devices
    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=baseline_hours)
    try:
        with driver.session() as session:
            results = new_devices(session, baseline_end)
    finally:
        driver.close()
    return {"baseline_end": baseline_end.isoformat(), "count": len(results), "items": results}


@router.get("/new-edges", summary="New communication edges since baseline")
async def get_new_edges(
    baseline_hours: float = Query(24.0, ge=0.0),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """Return COMMUNICATES_WITH edges first seen after the baseline period."""
    from src.detect.queries import new_edges
    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=baseline_hours)
    try:
        with driver.session() as session:
            results = new_edges(session, baseline_end)
    finally:
        driver.close()
    return {"baseline_end": baseline_end.isoformat(), "count": len(results), "items": results}


@router.get("/interval-deviation", summary="Polling interval anomalies")
async def get_interval_deviation(
    min_ms: float = Query(100.0, ge=0.0),
    max_ms: float = Query(1000.0, ge=0.0),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """Return edges with avg_interval_ms outside the expected window."""
    from src.detect.queries import interval_deviation
    try:
        with driver.session() as session:
            results = interval_deviation(session, min_ms, max_ms)
    finally:
        driver.close()
    return {"min_ms": min_ms, "max_ms": max_ms, "count": len(results), "items": results}


@router.get("/unknown-protocol", summary="Unknown protocol detections")
async def get_unknown_protocol(
    allowed: str = Query("modbus,dnp3,s7comm,tcp,udp"),
    _key: Optional[str] = Depends(require_api_key),
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """Return edges using protocols not in the allowlist."""
    from src.detect.queries import unknown_protocol
    allowed_list = [p.strip() for p in allowed.split(",") if p.strip()]
    try:
        with driver.session() as session:
            results = unknown_protocol(session, allowed_list)
    finally:
        driver.close()
    return {"allowed": allowed_list, "count": len(results), "items": results}
