"""
Baseline snapshot persistence for Guardance.

Saves and loads :class:`~src.baseline.profile.DeviceBaselineProfile` objects
to/from Neo4j as DeviceBaseline nodes, enabling baseline state to survive
process restarts.

Neo4j schema additions:
    Node: DeviceBaseline {ip, captured_at, baseline_start, baseline_end,
                          interval_mean, interval_std, packet_rate_mean,
                          packet_rate_std, protocols, peer_count,
                          periodic_edge_count, total_edges}
    Relationship: (Device)-[:HAS_BASELINE]->(DeviceBaseline)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.baseline.profile import BaselineStore, DeviceBaselineProfile

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_MERGE_BASELINE = """
MATCH (d:Device {ip: $ip})
MERGE (d)-[:HAS_BASELINE]->(b:DeviceBaseline {ip: $ip})
SET
    b.captured_at         = $captured_at,
    b.baseline_start      = $baseline_start,
    b.baseline_end        = $baseline_end,
    b.interval_mean       = $interval_mean,
    b.interval_std        = $interval_std,
    b.packet_rate_mean    = $packet_rate_mean,
    b.packet_rate_std     = $packet_rate_std,
    b.protocols           = $protocols,
    b.peer_count          = $peer_count,
    b.periodic_edge_count = $periodic_edge_count,
    b.total_edges         = $total_edges
"""

_LOAD_BASELINE = """
MATCH (d:Device {ip: $ip})-[:HAS_BASELINE]->(b:DeviceBaseline)
RETURN
    b.ip                  AS ip,
    b.captured_at         AS captured_at,
    b.baseline_start      AS baseline_start,
    b.baseline_end        AS baseline_end,
    b.interval_mean       AS interval_mean,
    b.interval_std        AS interval_std,
    b.packet_rate_mean    AS packet_rate_mean,
    b.packet_rate_std     AS packet_rate_std,
    b.protocols           AS protocols,
    b.peer_count          AS peer_count,
    b.periodic_edge_count AS periodic_edge_count,
    b.total_edges         AS total_edges
ORDER BY b.captured_at DESC
LIMIT 1
"""

_LOAD_ALL_BASELINES = """
MATCH (d:Device)-[:HAS_BASELINE]->(b:DeviceBaseline)
RETURN
    b.ip                  AS ip,
    b.captured_at         AS captured_at,
    b.baseline_start      AS baseline_start,
    b.baseline_end        AS baseline_end,
    b.interval_mean       AS interval_mean,
    b.interval_std        AS interval_std,
    b.packet_rate_mean    AS packet_rate_mean,
    b.packet_rate_std     AS packet_rate_std,
    b.protocols           AS protocols,
    b.peer_count          AS peer_count,
    b.periodic_edge_count AS periodic_edge_count,
    b.total_edges         AS total_edges
ORDER BY b.ip, b.captured_at DESC
"""

_BASELINE_AGE = """
MATCH (d:Device {ip: $ip})-[:HAS_BASELINE]->(b:DeviceBaseline)
RETURN b.captured_at AS captured_at
ORDER BY b.captured_at DESC
LIMIT 1
"""


# ---------------------------------------------------------------------------
# SnapshotManager
# ---------------------------------------------------------------------------

class SnapshotManager:
    """
    Persists and loads baseline snapshots from Neo4j.

    Usage::

        mgr = SnapshotManager(driver)
        with driver.session() as session:
            # Save a profile
            mgr.save(session, profile)
            # Load it back
            loaded = mgr.load(session, "10.0.1.1")
            # Populate a store
            store = mgr.load_all_into_store(session)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the manager.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def save(self, session: Any, profile: DeviceBaselineProfile) -> None:
        """
        Persist a baseline profile to Neo4j.

        Creates or updates a DeviceBaseline node attached to the Device node
        via a HAS_BASELINE relationship.

        Args:
            session: An active Neo4j session.
            profile: The profile to persist.
        """
        try:
            session.run(
                _MERGE_BASELINE,
                ip=profile.ip,
                captured_at=profile.captured_at,
                baseline_start=profile.baseline_start,
                baseline_end=profile.baseline_end,
                interval_mean=profile.interval_mean,
                interval_std=profile.interval_std,
                packet_rate_mean=profile.packet_rate_mean,
                packet_rate_std=profile.packet_rate_std,
                protocols=profile.protocols,
                peer_count=profile.peer_count,
                periodic_edge_count=profile.periodic_edge_count,
                total_edges=profile.total_edges,
            )
            logger.debug("Saved baseline snapshot for %s", profile.ip)
        except Exception as exc:
            logger.error("Failed to save baseline for %s: %s", profile.ip, exc)

    def save_all(self, session: Any, store: BaselineStore) -> int:
        """
        Persist all profiles in a :class:`BaselineStore` to Neo4j.

        Args:
            session: An active Neo4j session.
            store:   The in-memory store to persist.

        Returns:
            Number of profiles saved.
        """
        count = 0
        for profile in store.all():
            self.save(session, profile)
            count += 1
        logger.info("Saved %d baseline snapshots to Neo4j", count)
        return count

    def load(self, session: Any, ip: str) -> DeviceBaselineProfile | None:
        """
        Load the most recent baseline snapshot for a device from Neo4j.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            :class:`DeviceBaselineProfile` or None if not found.
        """
        try:
            result = session.run(_LOAD_BASELINE, ip=ip)
            rec = result.single()
            if rec is None:
                return None
            return DeviceBaselineProfile.from_dict(dict(rec))
        except Exception as exc:
            logger.error("Failed to load baseline for %s: %s", ip, exc)
            return None

    def load_all_into_store(self, session: Any) -> BaselineStore:
        """
        Load all persisted baselines from Neo4j into a new BaselineStore.

        Args:
            session: An active Neo4j session.

        Returns:
            A populated :class:`BaselineStore`.
        """
        store = BaselineStore()
        try:
            result = session.run(_LOAD_ALL_BASELINES)
            seen: set[str] = set()
            for rec in result:
                d = dict(rec)
                ip = d["ip"]
                # Take the most recent per device (already ORDER BY captured_at DESC)
                if ip not in seen:
                    profile = DeviceBaselineProfile.from_dict(d)
                    store.put(profile)
                    seen.add(ip)
            logger.info("Loaded %d baseline snapshots from Neo4j", len(store))
        except Exception as exc:
            logger.error("Failed to load baselines from Neo4j: %s", exc)
        return store

    def baseline_age_seconds(self, session: Any, ip: str) -> float | None:
        """
        Return the age (in seconds) of the most recent baseline for a device.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            Age in seconds, or None if no baseline exists.
        """
        try:
            result = session.run(_BASELINE_AGE, ip=ip)
            rec = result.single()
            if rec is None:
                return None
            return time.time() - float(rec["captured_at"])
        except Exception as exc:
            logger.error("Failed to get baseline age for %s: %s", ip, exc)
            return None
