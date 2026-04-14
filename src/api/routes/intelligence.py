"""
Phase 3 intelligence API endpoints for Guardance.

Endpoints:
    GET /api/v1/intelligence/coverage        — Coverage model assessment
    GET /api/v1/intelligence/silence         — Silent device detection
    GET /api/v1/intelligence/gaps            — Monitoring gaps
    GET /api/v1/intelligence/roles           — Device role inference results
    GET /api/v1/intelligence/attack-map      — ATT&CK-enriched findings
    GET /api/v1/intelligence/procid          — ProcID process deviation findings
    GET /api/v1/intelligence/baseline/{ip}   — Baseline profile for a device
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/intelligence",
    tags=["intelligence"],
    dependencies=[Depends(require_api_key)],
)


# ---------------------------------------------------------------------------
# Driver dependency
# ---------------------------------------------------------------------------

def get_neo4j_driver() -> Any:
    """Return a Neo4j driver from environment variables."""
    from src.graph.writer import create_driver
    return create_driver()


# ---------------------------------------------------------------------------
# Coverage endpoints
# ---------------------------------------------------------------------------

@router.get("/coverage", summary="Network coverage assessment")
async def coverage(driver: Any = Depends(get_neo4j_driver)) -> dict:
    """
    Run a full coverage assessment of the monitored OT network.

    Returns a coverage score (0.0–1.0) plus lists of blind zones,
    unzoned devices, and missing expected protocols.
    """
    from src.coverage.monitor import CoverageModel

    model = CoverageModel(driver)
    try:
        with driver.session() as session:
            report = model.assess(session)
    except Exception as exc:
        logger.error("Coverage assessment failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    return report.to_dict()


@router.get("/silence", summary="Silent device detection")
async def silence(
    threshold_minutes: Optional[int] = None,
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Return devices that have not communicated within their silence threshold.

    Uses role-specific thresholds (PLCs: 5 min, HMIs: 15 min, etc.) unless
    ``threshold_minutes`` overrides all thresholds.
    """
    from src.coverage.silence import SilenceDetector

    override_s = threshold_minutes * 60 if threshold_minutes else None
    detector = SilenceDetector(driver)
    try:
        with driver.session() as session:
            findings = detector.find_silent_devices(session, override_threshold_s=override_s)
    except Exception as exc:
        logger.error("Silence detection failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    return {"items": findings, "count": len(findings)}


@router.get("/gaps", summary="Monitoring gap detection")
async def gaps(driver: Any = Depends(get_neo4j_driver)) -> dict:
    """
    Identify monitoring gaps: low-coverage devices, sparse zones, and
    unconduit cross-zone communication paths.
    """
    from src.coverage.gaps import GapDetector

    detector = GapDetector(driver)
    try:
        with driver.session() as session:
            result = detector.find_all_gaps(session)
    except Exception as exc:
        logger.error("Gap detection failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    return result


# ---------------------------------------------------------------------------
# Role inference endpoint
# ---------------------------------------------------------------------------

@router.get("/roles", summary="Device role inference")
async def roles(driver: Any = Depends(get_neo4j_driver)) -> dict:
    """
    Run role inference across all Device nodes and return results.

    Devices that already have a manually-assigned role are skipped.
    """
    from src.roles.classifier import RoleClassifier, run_role_inference

    clf = RoleClassifier()
    try:
        with driver.session() as session:
            results = run_role_inference(session, clf)
    except Exception as exc:
        logger.error("Role inference failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    return {"items": results, "count": len(results)}


# ---------------------------------------------------------------------------
# ATT&CK enrichment endpoint
# ---------------------------------------------------------------------------

@router.get("/attack-map", summary="ATT&CK-enriched findings")
async def attack_map(
    baseline_hours: int = 24,
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Run all detection queries and enrich each finding with MITRE ATT&CK
    for ICS technique and tactic references.
    """
    from src.attack.mapper import map_all_findings, summary_by_tactic
    from src.detect.queries import (
        cross_zone_violations,
        interval_deviation,
        new_devices,
        new_edges,
        unknown_protocol,
    )

    baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=baseline_hours)
    allowed = ["modbus", "dnp3", "s7comm", "tcp", "udp"]

    try:
        with driver.session() as session:
            raw_findings = {
                "cross_zone_violations": cross_zone_violations(session),
                "new_devices":           new_devices(session, baseline_end),
                "new_edges":             new_edges(session, baseline_end),
                "interval_deviation":    interval_deviation(session),
                "unknown_protocol":      unknown_protocol(session, allowed),
            }
    except Exception as exc:
        logger.error("ATT&CK map query failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    enriched = map_all_findings(raw_findings)
    tactic_summary = summary_by_tactic(enriched)
    total = sum(len(v) for v in enriched.values())

    return {
        "findings": enriched,
        "tactic_summary": tactic_summary,
        "total": total,
    }


# ---------------------------------------------------------------------------
# ProcID endpoint
# ---------------------------------------------------------------------------

@router.get("/procid", summary="Process signature deviation findings")
async def procid(driver: Any = Depends(get_neo4j_driver)) -> dict:
    """
    Run ProcID process signature matching across all devices and return
    deviation findings where a device's behavior deviates from its expected
    process signature.
    """
    from src.procid.matcher import ProcessMatcher
    from src.procid.scorer import ProcessDeviationScorer

    matcher = ProcessMatcher(driver)
    scorer = ProcessDeviationScorer()
    try:
        with driver.session() as session:
            findings = scorer.run_all(session, matcher)
    except Exception as exc:
        logger.error("ProcID scoring failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    return {"items": findings, "count": len(findings)}


# ---------------------------------------------------------------------------
# Baseline profile endpoint
# ---------------------------------------------------------------------------

@router.get("/baseline/{ip}", summary="Baseline profile for a device")
async def baseline_profile(
    ip: str,
    driver: Any = Depends(get_neo4j_driver),
) -> dict:
    """
    Return the most recent behavioral baseline profile for a device.

    Returns 404 if no baseline has been captured for the device yet.
    """
    from src.baseline.snapshot import SnapshotManager

    mgr = SnapshotManager(driver)
    try:
        with driver.session() as session:
            profile = mgr.load(session, ip)
    except Exception as exc:
        logger.error("Baseline load failed for %s: %s", ip, exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        driver.close()

    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=f"No baseline profile found for device {ip!r}",
        )
    return profile.to_dict()
