"""
Unexpected silence detection for Guardance.

In OT networks, silence is anomalous.  A PLC that stopped sending
Modbus polls is not idle — something is wrong.  A field sensor that
hasn't updated in 10 minutes is either failed or being suppressed.

Silence detection queries Neo4j for devices whose ``last_seen``
timestamp is older than a configurable threshold relative to the
current time.  The threshold is configurable per device role:

    plc / rtu        — 5 minutes (should poll constantly)
    hmi              — 15 minutes (human-driven)
    engineering      — 60 minutes (periodic access)
    historian / scada — 10 minutes (should be continuous)
    default          — 10 minutes

Devices are considered "expected to communicate" if they have at least
one COMMUNICATES_WITH edge.  Devices with no edges are not flagged —
they may simply have never been observed (coverage gap, not silence).
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Role → silence threshold (seconds)
# ---------------------------------------------------------------------------

_ROLE_THRESHOLDS: dict[str, float] = {
    "plc":         5  * 60,   # 5 minutes
    "rtu":         5  * 60,
    "hmi":         15 * 60,   # 15 minutes
    "scada":       10 * 60,   # 10 minutes
    "historian":   10 * 60,
    "engineering": 60 * 60,   # 60 minutes
    "field_device": 5 * 60,
    "gateway":     10 * 60,
}

_DEFAULT_THRESHOLD_S = 10 * 60   # 10 minutes


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_SILENT_DEVICES = """
MATCH (d:Device)
WHERE d.last_seen IS NOT NULL
  AND d.last_seen < $cutoff
  AND EXISTS { MATCH (d)-[:COMMUNICATES_WITH]->() }
RETURN
    d.ip        AS ip,
    d.role      AS role,
    d.last_seen AS last_seen,
    ($now - d.last_seen) AS silent_for_s
ORDER BY d.last_seen ASC
"""

_DEVICE_LAST_SEEN = """
MATCH (d:Device {ip: $ip})
RETURN d.last_seen AS last_seen, d.role AS role
"""


# ---------------------------------------------------------------------------
# SilenceDetector
# ---------------------------------------------------------------------------

class SilenceDetector:
    """
    Detects devices that have gone unexpectedly silent.

    Usage::

        detector = SilenceDetector(driver)
        with driver.session() as session:
            silent = detector.find_silent_devices(session)
    """

    def __init__(
        self,
        driver: Any,
        default_threshold_s: float = _DEFAULT_THRESHOLD_S,
        role_thresholds: dict[str, float] | None = None,
    ) -> None:
        """
        Initialise the detector.

        Args:
            driver:              An authenticated Neo4j driver instance.
            default_threshold_s: Default silence threshold in seconds.
            role_thresholds:     Per-role thresholds in seconds.  Merged
                                 with :data:`_ROLE_THRESHOLDS`.
        """
        self._driver = driver
        self._default_s = default_threshold_s
        self._thresholds = dict(_ROLE_THRESHOLDS)
        if role_thresholds:
            self._thresholds.update(role_thresholds)

    def threshold_for_role(self, role: str | None) -> float:
        """
        Return the silence threshold (seconds) for a device role.

        Args:
            role: Device role string, or None.

        Returns:
            Threshold in seconds.
        """
        if not role:
            return self._default_s
        return self._thresholds.get(role.lower(), self._default_s)

    def find_silent_devices(
        self,
        session: Any,
        now: float | None = None,
        override_threshold_s: float | None = None,
    ) -> list[dict]:
        """
        Return devices that have not communicated within their silence window.

        Devices are only considered if they have at least one outbound edge
        (i.e., they are expected to communicate).

        Args:
            session:              An active Neo4j session.
            now:                  Current time as Unix epoch (defaults to
                                  ``time.time()``).
            override_threshold_s: If set, use this threshold for all roles
                                  instead of per-role defaults.

        Returns:
            List of dicts: ip, role, last_seen, silent_for_s, threshold_s,
            severity.
        """
        if now is None:
            now = time.time()

        # Use the minimum role threshold as the query cutoff so we fetch
        # all candidates; then filter per-role in Python.
        if override_threshold_s is not None:
            cutoff = now - override_threshold_s
        else:
            min_threshold = min(self._thresholds.values(), default=self._default_s)
            cutoff = now - min_threshold

        result = session.run(_SILENT_DEVICES, cutoff=cutoff, now=now)
        candidates = [dict(r) for r in result]

        findings = []
        for c in candidates:
            role = c.get("role")
            threshold = override_threshold_s or self.threshold_for_role(role)
            silent_s = float(c.get("silent_for_s") or 0)
            if silent_s >= threshold:
                c["threshold_s"] = threshold
                c["severity"] = _severity(silent_s, threshold)
                findings.append(c)

        logger.info(
            "Silence detection: %d candidates checked, %d silent devices found",
            len(candidates), len(findings),
        )
        return findings

    def is_device_silent(
        self,
        session: Any,
        ip: str,
        now: float | None = None,
    ) -> bool:
        """
        Check whether a single device is currently silent.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.
            now:     Current time as Unix epoch (defaults to ``time.time()``).

        Returns:
            True if the device is silent beyond its role threshold.
        """
        if now is None:
            now = time.time()
        result = session.run(_DEVICE_LAST_SEEN, ip=ip)
        rec = result.single()
        if rec is None:
            return False
        last_seen = float(rec["last_seen"] or 0)
        role = rec["role"]
        threshold = self.threshold_for_role(role)
        return (now - last_seen) >= threshold


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------

def _severity(silent_s: float, threshold_s: float) -> str:
    """
    Classify silence severity based on how far beyond the threshold it is.

    Args:
        silent_s:    How long the device has been silent (seconds).
        threshold_s: The configured threshold (seconds).

    Returns:
        "low", "medium", or "high".
    """
    ratio = silent_s / max(threshold_s, 1.0)
    if ratio >= 6.0:
        return "high"
    if ratio >= 2.0:
        return "medium"
    return "low"
