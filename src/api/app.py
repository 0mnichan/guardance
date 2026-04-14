"""
Guardance FastAPI web application.

Provides a JSON REST API and a lightweight Jinja2 HTML dashboard for
monitoring the OT/ICS device graph and reviewing detection findings.

Endpoints
---------
API (JSON):
    GET  /api/v1/devices               List all Device nodes (paginated)
    GET  /api/v1/devices/{ip}          Get a single Device by IP
    GET  /api/v1/devices/{ip}/edges    Get outbound edges for a device
    GET  /api/v1/findings              Run all detection queries
    GET  /api/v1/findings/cross-zone   Cross-zone violations
    GET  /api/v1/findings/new-devices  New devices since baseline
    GET  /api/v1/findings/new-edges    New edges since baseline
    GET  /api/v1/findings/interval-deviation  Polling interval anomalies
    GET  /api/v1/findings/unknown-protocol    Unknown protocols
    GET  /health                        Health check (no auth required)

UI (HTML):
    GET  /                              Dashboard
    GET  /ui/devices                    Device table
    GET  /ui/devices/{ip}               Device detail / edges
    GET  /ui/findings                   Findings triage

Configuration (env vars):
    NEO4J_URI           default: "bolt://localhost:7687"
    NEO4J_USER          default: "neo4j"
    NEO4J_PASSWORD      default: "neo4j"
    GUARDANCE_API_KEYS  Comma-separated API key strings
    GUARDANCE_HOST      default: "0.0.0.0"
    GUARDANCE_PORT      default: "8000"

Usage::

    uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.api.auth import require_api_key
from src.api.routes import devices as devices_router
from src.api.routes import findings as findings_router
from src.api.routes import intelligence as intelligence_router
from src.api.routes.devices import get_neo4j_driver as _devices_driver_dep
from src.api.routes.findings import get_neo4j_driver as _findings_driver_dep

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Guardance",
    description="Passive OT/ICS network security monitor",
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Register API routers
app.include_router(devices_router.router, prefix="/api/v1")
app.include_router(findings_router.router, prefix="/api/v1")
app.include_router(intelligence_router.router, prefix="/api/v1")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["health"], summary="Health check")
async def health() -> dict:
    """
    Return service health status.  Does not require authentication.

    Returns:
        Dict with ``status: "ok"`` and current server time.
    """
    return {
        "status": "ok",
        "time": datetime.now(tz=timezone.utc).isoformat(),
        "version": "3.0.0",
    }


# ---------------------------------------------------------------------------
# Neo4j helpers (shared by UI routes)
# ---------------------------------------------------------------------------

def _driver() -> Any:
    """Return a Neo4j driver from environment variables."""
    from src.graph.writer import create_driver
    return create_driver()


_STATS_QUERY = """
MATCH (d:Device) WITH count(d) AS device_count
MATCH ()-[r:COMMUNICATES_WITH]->() WITH device_count, count(r) AS edge_count
RETURN device_count, edge_count
"""

_STATS_QUERY_DEVICES_ONLY = "MATCH (d:Device) RETURN count(d) AS device_count"
_STATS_QUERY_EDGES_ONLY = "MATCH ()-[r:COMMUNICATES_WITH]->() RETURN count(r) AS edge_count"


def _get_dashboard_stats() -> dict:
    """
    Query Neo4j for dashboard statistics.

    Returns:
        Dict with device_count, edge_count, cross_zone, new_devices,
        new_edges, interval_deviation, unknown_protocol, total_findings.
    """
    from src.detect.queries import (
        cross_zone_violations,
        interval_deviation,
        new_devices,
        new_edges,
        unknown_protocol,
    )

    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    allowed = ["modbus", "dnp3", "s7comm", "tcp", "udp"]

    driver = _driver()
    try:
        with driver.session() as session:
            dev_count_rec = session.run(_STATS_QUERY_DEVICES_ONLY).single()
            device_count = dev_count_rec["device_count"] if dev_count_rec else 0

            edge_count_rec = session.run(_STATS_QUERY_EDGES_ONLY).single()
            edge_count = edge_count_rec["edge_count"] if edge_count_rec else 0

            cz  = len(cross_zone_violations(session))
            nd  = len(new_devices(session, baseline_end))
            ne  = len(new_edges(session, baseline_end))
            iv  = len(interval_deviation(session))
            up  = len(unknown_protocol(session, allowed))
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Failed to fetch dashboard stats: %s", exc)
        device_count = edge_count = cz = nd = ne = iv = up = 0

    finally:
        driver.close()

    total = cz + nd + ne + iv + up
    return {
        "device_count":       device_count,
        "edge_count":         edge_count,
        "cross_zone":         cz,
        "new_devices":        nd,
        "new_edges":          ne,
        "interval_deviation": iv,
        "unknown_protocol":   up,
        "total_findings":     total,
    }


# ---------------------------------------------------------------------------
# UI routes (HTML)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    """Render the dashboard with detection summary statistics."""
    stats = _get_dashboard_stats()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"stats": stats},
    )


@app.get("/ui/devices", response_class=HTMLResponse, include_in_schema=False)
async def ui_devices(
    request: Request,
    skip: int = 0,
    limit: int = 100,
) -> HTMLResponse:
    """Render the device list page."""
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
    _COUNT = "MATCH (d:Device) RETURN count(d) AS total"

    driver = _driver()
    try:
        with driver.session() as session:
            total = (session.run(_COUNT).single() or {}).get("total", 0)
            devices = [dict(r) for r in session.run(_LIST_DEVICES, skip=skip, limit=limit)]
    except Exception as exc:
        logger.error("Failed to fetch devices for UI: %s", exc)
        total, devices = 0, []
    finally:
        driver.close()

    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        context={"devices": devices, "total": total, "skip": skip, "limit": limit},
    )


@app.get("/ui/devices/{ip}", response_class=HTMLResponse, include_in_schema=False)
async def ui_device_detail(request: Request, ip: str) -> HTMLResponse:
    """Render the device detail page showing outbound edges."""
    _GET_DEVICE = """
    MATCH (d:Device {ip: $ip})
    OPTIONAL MATCH (d)-[:MEMBER_OF]->(z:Zone)
    RETURN d.ip AS ip, d.mac AS mac, d.role AS role,
           d.purdue_level AS purdue_level,
           d.first_seen AS first_seen, d.last_seen AS last_seen,
           z.name AS zone
    """
    _GET_EDGES = """
    MATCH (d:Device {ip: $ip})-[r:COMMUNICATES_WITH]->(dst:Device)
    RETURN dst.ip AS dst_ip, r.protocol AS protocol, r.port AS port,
           r.function_code AS function_code, r.packet_count AS packet_count,
           r.avg_interval_ms AS avg_interval_ms, r.is_periodic AS is_periodic,
           r.first_seen AS first_seen
    ORDER BY r.packet_count DESC
    """

    driver = _driver()
    try:
        with driver.session() as session:
            rec = session.run(_GET_DEVICE, ip=ip).single()
            if rec is None:
                raise HTTPException(status_code=404, detail=f"Device {ip!r} not found")
            device = dict(rec)
            edges = [dict(r) for r in session.run(_GET_EDGES, ip=ip)]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch device detail for %s: %s", ip, exc)
        device, edges = {"ip": ip}, []
    finally:
        driver.close()

    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        context={
            "device": device,
            "devices": edges,
            "total": len(edges),
            "skip": 0,
            "limit": len(edges),
            "detail_mode": True,
        },
    )


@app.get("/ui/findings", response_class=HTMLResponse, include_in_schema=False)
async def ui_findings(request: Request) -> HTMLResponse:
    """Render the findings triage page."""
    from src.detect.queries import (
        cross_zone_violations,
        interval_deviation,
        new_devices,
        new_edges,
        unknown_protocol,
    )

    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    allowed = ["modbus", "dnp3", "s7comm", "tcp", "udp"]

    driver = _driver()
    try:
        with driver.session() as session:
            findings = {
                "cross_zone_violations": cross_zone_violations(session),
                "new_devices":           new_devices(session, baseline_end),
                "new_edges":             new_edges(session, baseline_end),
                "interval_deviation":    interval_deviation(session),
                "unknown_protocol":      unknown_protocol(session, allowed),
            }
    except Exception as exc:
        logger.error("Failed to fetch findings for UI: %s", exc)
        findings = {
            "cross_zone_violations": [],
            "new_devices": [],
            "new_edges": [],
            "interval_deviation": [],
            "unknown_protocol": [],
        }
    finally:
        driver.close()

    total = sum(len(v) for v in findings.values())
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={"findings": findings, "total": total, "baseline_end": baseline_end.isoformat()},
    )


# ---------------------------------------------------------------------------
# Entry point for direct execution
# ---------------------------------------------------------------------------

def serve(host: Optional[str] = None, port: Optional[int] = None) -> None:
    """
    Start the Uvicorn ASGI server.

    Args:
        host: Bind address (default: ``GUARDANCE_HOST`` env var, then ``0.0.0.0``).
        port: Port number (default: ``GUARDANCE_PORT`` env var, then ``8000``).
    """
    import uvicorn

    _host = host or os.environ.get("GUARDANCE_HOST", "0.0.0.0")
    _port = port or int(os.environ.get("GUARDANCE_PORT", "8000"))
    logger.info("Starting Guardance web UI on %s:%d", _host, _port)
    uvicorn.run("src.api.app:app", host=_host, port=_port, reload=False)


if __name__ == "__main__":
    serve()
