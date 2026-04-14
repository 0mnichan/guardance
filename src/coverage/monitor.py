"""
Coverage Model for Guardance.

Models what the passive sensor is actually observing versus what it
*should* be observing based on the known network topology.

Coverage blindness arises when:
    - A device is present (reachable at the IP layer) but never appears
      in Zeek logs because it communicates on a segment the sensor
      cannot see.
    - A protocol is in use on the network but not parsed (e.g. PROFIBUS
      on a serial segment that has no TAP).
    - A zone has devices but zero communication edges — the sensor may
      not be positioned on that segment.

The CoverageReport captures:
    - Total devices seen vs. expected zones populated
    - Per-zone device count and edge count
    - Zones with zero edges (potential blind spots)
    - Protocols expected but not seen
    - Devices with only one direction of traffic (asymmetric tap)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CoverageReport dataclass
# ---------------------------------------------------------------------------

@dataclass
class ZoneCoverage:
    """Coverage statistics for a single Purdue zone."""

    zone_name: str
    purdue_level: int
    device_count: int = 0
    outbound_edge_count: int = 0
    inbound_edge_count: int = 0
    has_blind_spot: bool = False  # True if devices exist but no edges


@dataclass
class CoverageReport:
    """
    Full coverage assessment of the monitored network.

    Attributes:
        total_devices:          Total Device nodes in graph.
        total_edges:            Total COMMUNICATES_WITH relationships.
        zones:                  Per-zone coverage stats.
        empty_zones:            Zone names with no devices assigned.
        blind_zones:            Zone names with devices but no edges.
        unzoned_device_count:   Devices with no MEMBER_OF zone link.
        observed_protocols:     Protocols seen in COMMUNICATES_WITH edges.
        missing_expected:       Expected OT protocols not yet seen.
        asymmetric_devices:     IPs that only send OR only receive (never both).
        coverage_score:         0.0–1.0 aggregate coverage quality score.
    """

    total_devices: int = 0
    total_edges: int = 0
    zones: list[ZoneCoverage] = field(default_factory=list)
    empty_zones: list[str] = field(default_factory=list)
    blind_zones: list[str] = field(default_factory=list)
    unzoned_device_count: int = 0
    observed_protocols: list[str] = field(default_factory=list)
    missing_expected: list[str] = field(default_factory=list)
    asymmetric_devices: list[str] = field(default_factory=list)
    coverage_score: float = 0.0

    def to_dict(self) -> dict:
        """Serialise the report to a plain dict for API output."""
        return {
            "total_devices":        self.total_devices,
            "total_edges":          self.total_edges,
            "zone_coverage":        [
                {
                    "zone": z.zone_name,
                    "purdue_level": z.purdue_level,
                    "devices": z.device_count,
                    "edges": z.outbound_edge_count,
                    "blind_spot": z.has_blind_spot,
                }
                for z in self.zones
            ],
            "empty_zones":          self.empty_zones,
            "blind_zones":          self.blind_zones,
            "unzoned_device_count": self.unzoned_device_count,
            "observed_protocols":   self.observed_protocols,
            "missing_expected":     self.missing_expected,
            "asymmetric_devices":   self.asymmetric_devices,
            "coverage_score":       round(self.coverage_score, 3),
        }


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_TOTAL_DEVICES = "MATCH (d:Device) RETURN count(d) AS total"
_TOTAL_EDGES   = "MATCH ()-[r:COMMUNICATES_WITH]->() RETURN count(r) AS total"

_ZONE_STATS = """
MATCH (z:Zone)
OPTIONAL MATCH (d:Device)-[:MEMBER_OF]->(z)
OPTIONAL MATCH (d)-[out:COMMUNICATES_WITH]->()
OPTIONAL MATCH ()-[in:COMMUNICATES_WITH]->(d)
RETURN
    z.name         AS zone_name,
    z.purdue_level AS purdue_level,
    count(DISTINCT d) AS device_count,
    count(DISTINCT out) AS outbound_edges,
    count(DISTINCT in)  AS inbound_edges
ORDER BY z.purdue_level
"""

_UNZONED_DEVICES = """
MATCH (d:Device) WHERE NOT (d)-[:MEMBER_OF]->(:Zone)
RETURN count(d) AS total
"""

_OBSERVED_PROTOCOLS = """
MATCH ()-[r:COMMUNICATES_WITH]->()
RETURN DISTINCT r.protocol AS protocol
ORDER BY protocol
"""

_ASYMMETRIC_DEVICES = """
MATCH (d:Device)
WITH d,
     size([(d)-[:COMMUNICATES_WITH]->() | 1]) AS sent,
     size([()-[:COMMUNICATES_WITH]->(d) | 1]) AS recv
WHERE (sent > 0 AND recv = 0) OR (sent = 0 AND recv > 0)
RETURN d.ip AS ip, sent, recv
"""


# ---------------------------------------------------------------------------
# CoverageModel
# ---------------------------------------------------------------------------

# Protocols expected in a typical OT network
_EXPECTED_PROTOCOLS = [
    "modbus", "dnp3", "s7comm", "iec104", "enip",
    "opc-ua", "bacnet",
]


class CoverageModel:
    """
    Assesses passive monitoring coverage of the OT network.

    Usage::

        model = CoverageModel(driver)
        with driver.session() as session:
            report = model.assess(session)
        print(report.coverage_score)
    """

    def __init__(
        self,
        driver: Any,
        expected_protocols: list[str] | None = None,
    ) -> None:
        """
        Initialise the model.

        Args:
            driver:             An authenticated Neo4j driver instance.
            expected_protocols: Protocols that should appear in a fully
                                monitored OT network.  Defaults to
                                :data:`_EXPECTED_PROTOCOLS`.
        """
        self._driver = driver
        self._expected = expected_protocols or _EXPECTED_PROTOCOLS

    def assess(self, session: Any) -> CoverageReport:
        """
        Run a full coverage assessment against the current graph state.

        Args:
            session: An active Neo4j session.

        Returns:
            :class:`CoverageReport` with all metrics populated.
        """
        report = CoverageReport()

        # Total counts
        dev_rec = session.run(_TOTAL_DEVICES).single()
        report.total_devices = int((dev_rec or {}).get("total", 0))

        edge_rec = session.run(_TOTAL_EDGES).single()
        report.total_edges = int((edge_rec or {}).get("total", 0))

        # Zone stats
        zone_result = session.run(_ZONE_STATS)
        for rec in zone_result:
            zc = ZoneCoverage(
                zone_name=rec["zone_name"],
                purdue_level=int(rec["purdue_level"] or 0),
                device_count=int(rec["device_count"] or 0),
                outbound_edge_count=int(rec["outbound_edges"] or 0),
                inbound_edge_count=int(rec["inbound_edges"] or 0),
            )
            zc.has_blind_spot = (zc.device_count > 0 and zc.outbound_edge_count == 0)
            report.zones.append(zc)
            if zc.device_count == 0:
                report.empty_zones.append(zc.zone_name)
            elif zc.has_blind_spot:
                report.blind_zones.append(zc.zone_name)

        # Unzoned devices
        unzoned_rec = session.run(_UNZONED_DEVICES).single()
        report.unzoned_device_count = int((unzoned_rec or {}).get("total", 0))

        # Observed protocols
        proto_result = session.run(_OBSERVED_PROTOCOLS)
        report.observed_protocols = [
            r["protocol"] for r in proto_result if r["protocol"]
        ]

        # Missing expected protocols
        observed_lower = {p.lower() for p in report.observed_protocols}
        report.missing_expected = [
            p for p in self._expected if p.lower() not in observed_lower
        ]

        # Asymmetric devices
        asym_result = session.run(_ASYMMETRIC_DEVICES)
        report.asymmetric_devices = [r["ip"] for r in asym_result]

        # Coverage score
        report.coverage_score = self._compute_score(report)

        logger.info(
            "Coverage assessment: %d devices, %d edges, score=%.2f, "
            "blind_zones=%d, unzoned=%d",
            report.total_devices,
            report.total_edges,
            report.coverage_score,
            len(report.blind_zones),
            report.unzoned_device_count,
        )
        return report

    @staticmethod
    def _compute_score(report: CoverageReport) -> float:
        """
        Compute a 0.0–1.0 coverage quality score.

        Penalties:
            - Each blind zone: -0.10
            - Each empty zone (out of 6): -0.05
            - Unzoned devices > 0: -0.15
            - Each missing expected protocol: -0.05

        Returns:
            Score clamped to [0.0, 1.0].
        """
        score = 1.0
        score -= len(report.blind_zones) * 0.10
        score -= len(report.empty_zones) * 0.05
        if report.unzoned_device_count > 0:
            score -= 0.15
        score -= len(report.missing_expected) * 0.05
        return max(0.0, min(1.0, score))
