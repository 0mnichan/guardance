"""
Behavioral Baseline Engine for Guardance.

Captures per-device behavioral baselines from the Neo4j graph and scores
live observations against them using z-score and IQR-based anomaly detection.

Anomaly scoring
---------------
Z-score:
    z = (x - mean) / std
    |z| > 3.0 → anomalous (three-sigma rule)

IQR:
    Q1, Q3 = 25th and 75th percentile of baseline values
    IQR = Q3 - Q1
    lower = Q1 - 1.5 * IQR
    upper = Q3 + 1.5 * IQR
    Values outside [lower, upper] are flagged as anomalous.

Both methods are computed; the result dict reports both scores so
operators can apply whichever threshold suits their environment.
"""

from __future__ import annotations

import logging
import math
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np

from src.baseline.profile import BaselineStore, DeviceBaselineProfile

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_EDGES_IN_WINDOW = """
MATCH (src:Device {ip: $ip})-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE r.first_seen >= $window_start AND r.last_seen <= $window_end
RETURN
    r.protocol        AS protocol,
    r.avg_interval_ms AS avg_interval_ms,
    r.packet_count    AS packet_count,
    r.is_periodic     AS is_periodic,
    r.first_seen      AS first_seen,
    r.last_seen       AS last_seen,
    dst.ip            AS dst_ip
"""

_ALL_DEVICE_IPS = "MATCH (d:Device) RETURN d.ip AS ip"


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def z_score(value: float, mean: float, std: float) -> float:
    """
    Compute the z-score of a value against a baseline distribution.

    Args:
        value: The observed value.
        mean:  Baseline mean.
        std:   Baseline standard deviation.

    Returns:
        z-score (signed).  Returns 0.0 if std is effectively zero.
    """
    if std < 1e-9:
        return 0.0
    return (value - mean) / std


def iqr_bounds(values: list[float]) -> tuple[float, float]:
    """
    Compute Tukey IQR fence bounds for a list of baseline values.

    Args:
        values: List of baseline measurement floats.

    Returns:
        Tuple of (lower_bound, upper_bound).  Both are 0.0 if the list
        has fewer than 4 elements.
    """
    if len(values) < 4:
        return 0.0, float("inf")
    arr = np.array(values, dtype=float)
    q1, q3 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
    iqr = q3 - q1
    return q1 - 1.5 * iqr, q3 + 1.5 * iqr


def anomaly_score(value: float, profile: DeviceBaselineProfile) -> dict:
    """
    Score a single observation against a device baseline profile.

    Args:
        value:   The observed metric value (e.g. current avg_interval_ms).
        profile: The baseline profile for the device.

    Returns:
        Dict with keys:
            z_score        — signed z-score
            z_anomalous    — True if |z| > 3.0
            iqr_lower      — IQR lower fence
            iqr_upper      — IQR upper fence
            iqr_anomalous  — True if value outside IQR fences
            anomalous      — True if either method flags it
    """
    z = z_score(
        value,
        profile.interval_mean if profile.interval_mean is not None else 0.0,
        profile.interval_std,
    )
    lower, upper = iqr_bounds(profile.raw_intervals)
    z_anom = abs(z) > 3.0
    iqr_anom = (len(profile.raw_intervals) >= 4) and (value < lower or value > upper)

    return {
        "z_score":       z,
        "z_anomalous":   z_anom,
        "iqr_lower":     lower,
        "iqr_upper":     upper,
        "iqr_anomalous": iqr_anom,
        "anomalous":     z_anom or iqr_anom,
    }


# ---------------------------------------------------------------------------
# BaselineEngine
# ---------------------------------------------------------------------------

class BaselineEngine:
    """
    Captures and manages per-device behavioral baselines from Neo4j.

    Usage::

        engine = BaselineEngine(driver)
        with driver.session() as session:
            engine.capture_all(session, window_hours=24)
        profile = engine.store.get("10.0.1.1")
        score = engine.score_device_interval(profile, observed_ms=450.0)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the engine.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver
        self.store = BaselineStore()

    # ------------------------------------------------------------------
    # Baseline capture
    # ------------------------------------------------------------------

    def capture_device(
        self,
        session: Any,
        ip: str,
        window_start: float,
        window_end: float,
    ) -> DeviceBaselineProfile | None:
        """
        Build a baseline profile for one device from graph data.

        Args:
            session:      An active Neo4j session.
            ip:           Device IP address.
            window_start: Unix epoch start of the baseline window.
            window_end:   Unix epoch end of the baseline window.

        Returns:
            :class:`DeviceBaselineProfile` or None if no edges exist.
        """
        result = session.run(
            _EDGES_IN_WINDOW,
            ip=ip,
            window_start=window_start,
            window_end=window_end,
        )
        edges = [dict(r) for r in result]
        if not edges:
            logger.debug("No edges for device %s in baseline window", ip)
            return None

        protocols: set[str] = set()
        peers: set[str] = set()
        intervals: list[float] = []
        packet_rates: list[float] = []
        periodic_count = 0

        for e in edges:
            if e.get("protocol"):
                protocols.add(e["protocol"])
            if e.get("dst_ip"):
                peers.add(e["dst_ip"])
            if e.get("is_periodic") and e.get("avg_interval_ms"):
                intervals.append(float(e["avg_interval_ms"]))
                periodic_count += 1
            # Compute packet rate (packets/minute) for the edge window
            duration_s = (e.get("last_seen") or 0) - (e.get("first_seen") or 0)
            if duration_s > 0 and e.get("packet_count"):
                rate = float(e["packet_count"]) / (duration_s / 60.0)
                packet_rates.append(rate)

        interval_mean: float | None = None
        interval_std: float = 0.0
        if intervals:
            arr = np.array(intervals, dtype=float)
            interval_mean = float(arr.mean())
            interval_std = float(arr.std()) if len(arr) > 1 else 0.0

        pr_mean = 0.0
        pr_std = 0.0
        if packet_rates:
            arr_pr = np.array(packet_rates, dtype=float)
            pr_mean = float(arr_pr.mean())
            pr_std = float(arr_pr.std()) if len(arr_pr) > 1 else 0.0

        profile = DeviceBaselineProfile(
            ip=ip,
            baseline_start=window_start,
            baseline_end=window_end,
            captured_at=time.time(),
            interval_mean=interval_mean,
            interval_std=interval_std,
            packet_rate_mean=pr_mean,
            packet_rate_std=pr_std,
            protocols=sorted(protocols),
            peer_count=len(peers),
            periodic_edge_count=periodic_count,
            total_edges=len(edges),
            raw_intervals=intervals,
            raw_packet_rates=packet_rates,
        )
        self.store.put(profile)
        logger.debug(
            "Captured baseline for %s: %d edges, interval_mean=%.1f",
            ip, len(edges), interval_mean or 0,
        )
        return profile

    def capture_all(
        self,
        session: Any,
        window_hours: float = 24.0,
    ) -> int:
        """
        Capture baselines for every Device node in the graph.

        Args:
            session:      An active Neo4j session.
            window_hours: How many hours back from now to use as the
                          baseline window.

        Returns:
            Number of profiles captured.
        """
        now = time.time()
        window_start = now - window_hours * 3600.0
        window_end = now

        ips_result = session.run(_ALL_DEVICE_IPS)
        ips = [r["ip"] for r in ips_result]
        captured = 0
        for ip in ips:
            profile = self.capture_device(session, ip, window_start, window_end)
            if profile is not None:
                captured += 1

        logger.info(
            "Baseline capture complete: %d/%d devices profiled (%.1fh window)",
            captured, len(ips), window_hours,
        )
        return captured

    # ------------------------------------------------------------------
    # Anomaly scoring
    # ------------------------------------------------------------------

    def score_device_interval(
        self,
        profile: DeviceBaselineProfile,
        observed_ms: float,
    ) -> dict:
        """
        Score an observed polling interval against a device's baseline.

        Args:
            profile:     The device's baseline profile.
            observed_ms: Current observed avg_interval_ms.

        Returns:
            Anomaly score dict from :func:`anomaly_score`.
        """
        return anomaly_score(observed_ms, profile)

    def score_all_devices(self, session: Any) -> list[dict]:
        """
        Score all devices in the graph whose baseline profiles exist.

        Queries current avg_interval_ms from Neo4j and compares against
        stored baseline profiles.

        Args:
            session: An active Neo4j session.

        Returns:
            List of dicts: ip, observed_ms, plus anomaly score fields.
        """
        _CURRENT_INTERVALS = """
        MATCH (d:Device)-[r:COMMUNICATES_WITH]->()
        WHERE r.is_periodic = true
        RETURN d.ip AS ip, avg(r.avg_interval_ms) AS avg_ms
        """
        result = session.run(_CURRENT_INTERVALS)
        rows = []
        for rec in result:
            ip = rec["ip"]
            observed = float(rec["avg_ms"] or 0)
            profile = self.store.get(ip)
            if profile is None:
                continue
            score = self.score_device_interval(profile, observed)
            score["ip"] = ip
            score["observed_ms"] = observed
            score["baseline_mean"] = profile.interval_mean
            rows.append(score)

        anomalous = [r for r in rows if r["anomalous"]]
        logger.info(
            "Interval scoring: %d devices scored, %d anomalous",
            len(rows), len(anomalous),
        )
        return rows
