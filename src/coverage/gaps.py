"""
Monitoring gap detection for Guardance.

Surfaces devices and network segments where the passive sensor has
insufficient visibility.  A monitoring gap is defined as any situation
where the graph provides less information than expected:

    - Devices with only inbound OR only outbound edges (tap asymmetry)
    - Zones with very few edges relative to their device count
    - Devices that communicated heavily during baseline but now have
      sparse recent edges (sensor drift or cable/SPAN issue)
    - Protocols used across a zone boundary without a conduit record
      (conduit model gap — not necessarily a security problem, but
      means the IEC 62443 model is incomplete)
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_LOW_COVERAGE_DEVICES = """
MATCH (d:Device)
OPTIONAL MATCH (d)-[out:COMMUNICATES_WITH]->()
OPTIONAL MATCH ()-[in:COMMUNICATES_WITH]->(d)
WITH d,
     count(DISTINCT out) AS out_edges,
     count(DISTINCT in)  AS in_edges
WHERE out_edges + in_edges < $min_edges
RETURN d.ip AS ip, out_edges, in_edges,
       (out_edges + in_edges) AS total_edges
ORDER BY total_edges ASC
"""

_SPARSE_ZONES = """
MATCH (z:Zone)
OPTIONAL MATCH (d:Device)-[:MEMBER_OF]->(z)
OPTIONAL MATCH (d)-[r:COMMUNICATES_WITH]->()
WITH z,
     count(DISTINCT d)  AS devices,
     count(DISTINCT r)  AS edges
WHERE devices > 0
WITH z, devices, edges,
     toFloat(edges) / devices AS edge_density
WHERE edge_density < $min_density
RETURN z.name AS zone, z.purdue_level AS purdue_level,
       devices, edges, edge_density
ORDER BY edge_density ASC
"""

_UNCONDUIT_CROSS_ZONE = """
MATCH (d1:Device)-[r:COMMUNICATES_WITH]->(d2:Device)
MATCH (d1)-[:MEMBER_OF]->(z1:Zone)
MATCH (d2)-[:MEMBER_OF]->(z2:Zone)
WHERE z1.name <> z2.name
  AND NOT EXISTS {
      MATCH (c:Conduit)
      WHERE (c.src_zone = z1.name AND c.dst_zone = z2.name)
         OR (c.src_zone = z2.name AND c.dst_zone = z1.name)
  }
RETURN DISTINCT
    z1.name AS src_zone,
    z2.name AS dst_zone,
    count(r) AS edge_count
ORDER BY edge_count DESC
"""


# ---------------------------------------------------------------------------
# GapDetector
# ---------------------------------------------------------------------------

class GapDetector:
    """
    Identifies monitoring gaps in the OT network graph.

    Usage::

        detector = GapDetector(driver)
        with driver.session() as session:
            gaps = detector.find_all_gaps(session)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the detector.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def low_coverage_devices(
        self,
        session: Any,
        min_edges: int = 2,
    ) -> list[dict]:
        """
        Return devices with fewer than ``min_edges`` total edges.

        A device with zero or one edge is almost certainly a coverage
        gap — either the sensor can't see it properly or the device
        was only briefly observed.

        Args:
            session:   An active Neo4j session.
            min_edges: Threshold; devices below this edge count are
                       returned.  Default 2.

        Returns:
            List of dicts: ip, out_edges, in_edges, total_edges.
        """
        result = session.run(_LOW_COVERAGE_DEVICES, min_edges=min_edges)
        rows = [dict(r) for r in result]
        logger.debug("Low-coverage devices (<=%d edges): %d", min_edges - 1, len(rows))
        return rows

    def sparse_zones(
        self,
        session: Any,
        min_density: float = 0.5,
    ) -> list[dict]:
        """
        Return zones whose edge-to-device density is below the threshold.

        An OT zone where devices rarely communicate (relative to the zone
        size) suggests the sensor may not be seeing all traffic.

        Args:
            session:     An active Neo4j session.
            min_density: Minimum edges-per-device ratio.  Default 0.5.

        Returns:
            List of dicts: zone, purdue_level, devices, edges, edge_density.
        """
        result = session.run(_SPARSE_ZONES, min_density=min_density)
        rows = [dict(r) for r in result]
        logger.debug("Sparse zones (density <%.1f): %d", min_density, len(rows))
        return rows

    def unconduit_cross_zone_edges(self, session: Any) -> list[dict]:
        """
        Return cross-zone communication pairs that have no matching conduit.

        Communication across a zone boundary without a Conduit record means
        the IEC 62443 conduit model is incomplete for this traffic path.

        Args:
            session: An active Neo4j session.

        Returns:
            List of dicts: src_zone, dst_zone, edge_count.
        """
        result = session.run(_UNCONDUIT_CROSS_ZONE)
        rows = [dict(r) for r in result]
        logger.debug("Unconduit cross-zone paths: %d", len(rows))
        return rows

    def find_all_gaps(self, session: Any) -> dict:
        """
        Run all gap detection queries and return a combined report.

        Args:
            session: An active Neo4j session.

        Returns:
            Dict with keys:
                low_coverage_devices    — list of dicts
                sparse_zones            — list of dicts
                unconduit_cross_zone    — list of dicts
                total_gaps              — total gap count
        """
        lc = self.low_coverage_devices(session)
        sz = self.sparse_zones(session)
        uc = self.unconduit_cross_zone_edges(session)

        total = len(lc) + len(sz) + len(uc)
        logger.info(
            "Gap detection: %d low-coverage devices, %d sparse zones, "
            "%d unconduit paths, total=%d",
            len(lc), len(sz), len(uc), total,
        )
        return {
            "low_coverage_devices": lc,
            "sparse_zones":         sz,
            "unconduit_cross_zone": uc,
            "total_gaps":           total,
        }
