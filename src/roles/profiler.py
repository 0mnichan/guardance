"""
Graph behavioral profiling for device role inference.

Queries Neo4j to build a rich behavioral profile for each Device node.
The profile captures:

    - Which protocols the device uses (and on which ports)
    - The function codes it issues
    - Whether it predominantly initiates or receives connections
    - Its communication partner count (fan-out)
    - Its average polling interval and packet rate
    - Zone membership

These features feed the fingerprinting rules and ML classifier.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Device profile dataclass
# ---------------------------------------------------------------------------

@dataclass
class DeviceProfile:
    """
    Behavioral profile of a single Device node.

    Attributes:
        ip:                  Device IP address.
        protocols:           Set of protocols observed in outbound edges.
        ports:               Set of ports observed in outbound edges.
        function_codes:      Set of function codes observed in outbound edges.
        connections_out:     Number of distinct outbound neighbors.
        connections_in:      Number of distinct inbound neighbors.
        total_packets_sent:  Sum of packet_count across all outbound edges.
        total_packets_recv:  Sum of packet_count across all inbound edges.
        avg_interval_ms:     Mean avg_interval_ms across outbound edges,
                             or None if no periodic edges exist.
        is_periodic:         True if any outbound edge is flagged periodic.
        zone:                Zone name from MEMBER_OF, or None.
        purdue_level:        Purdue level of the zone, or None.
        role:                Existing role label on the Device node, or None.
    """

    ip: str
    protocols: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    function_codes: set[str] = field(default_factory=set)
    connections_out: int = 0
    connections_in: int = 0
    total_packets_sent: int = 0
    total_packets_recv: int = 0
    avg_interval_ms: float | None = None
    is_periodic: bool = False
    zone: str | None = None
    purdue_level: int | None = None
    role: str | None = None

    def to_feature_vector(self) -> list[float]:
        """
        Return a numeric feature vector for ML classification.

        Features (11 dimensions):
            0  — connections_out
            1  — connections_in
            2  — total_packets_sent (log-scaled)
            3  — total_packets_recv (log-scaled)
            4  — avg_interval_ms (0 if None)
            5  — is_periodic (0/1)
            6  — uses_modbus (0/1)
            7  — uses_dnp3 (0/1)
            8  — uses_s7comm (0/1)
            9  — uses_opc (0/1)
            10 — fan_out_ratio (out / max(out+in, 1))
        """
        import math

        protocols_lower = {p.lower() for p in self.protocols}

        sent = math.log1p(self.total_packets_sent)
        recv = math.log1p(self.total_packets_recv)
        interval = self.avg_interval_ms if self.avg_interval_ms is not None else 0.0
        total_conn = max(self.connections_out + self.connections_in, 1)
        fan_out = self.connections_out / total_conn

        return [
            float(self.connections_out),
            float(self.connections_in),
            sent,
            recv,
            interval,
            1.0 if self.is_periodic else 0.0,
            1.0 if "modbus" in protocols_lower else 0.0,
            1.0 if "dnp3" in protocols_lower else 0.0,
            1.0 if "s7comm" in protocols_lower else 0.0,
            1.0 if any("opc" in p for p in protocols_lower) else 0.0,
            fan_out,
        ]


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_PROFILE_QUERY = """
MATCH (d:Device {ip: $ip})
OPTIONAL MATCH (d)-[:MEMBER_OF]->(z:Zone)
OPTIONAL MATCH (d)-[out_r:COMMUNICATES_WITH]->(dst:Device)
OPTIONAL MATCH (src:Device)-[in_r:COMMUNICATES_WITH]->(d)
RETURN
    d.ip           AS ip,
    d.role         AS role,
    z.name         AS zone,
    z.purdue_level AS purdue_level,
    collect(DISTINCT {
        protocol:      out_r.protocol,
        port:          out_r.port,
        function_code: out_r.function_code,
        packet_count:  out_r.packet_count,
        avg_interval:  out_r.avg_interval_ms,
        is_periodic:   out_r.is_periodic
    }) AS out_edges,
    collect(DISTINCT {
        packet_count: in_r.packet_count
    }) AS in_edges
"""

_ALL_IPS_QUERY = "MATCH (d:Device) RETURN d.ip AS ip"


# ---------------------------------------------------------------------------
# GraphProfiler
# ---------------------------------------------------------------------------

class GraphProfiler:
    """
    Builds :class:`DeviceProfile` objects from Neo4j graph data.

    Usage::

        profiler = GraphProfiler(driver)
        with driver.session() as session:
            profile = profiler.build_profile(session, "10.0.1.1")
            all_profiles = profiler.build_all_profiles(session)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the profiler.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def build_profile(self, session: Any, ip: str) -> DeviceProfile | None:
        """
        Build a behavioral profile for a single device.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            :class:`DeviceProfile` or None if the device doesn't exist.
        """
        result = session.run(_PROFILE_QUERY, ip=ip)
        rec = result.single()
        if rec is None:
            return None

        out_edges: list[dict] = [e for e in (rec["out_edges"] or []) if e.get("protocol")]
        in_edges: list[dict] = [e for e in (rec["in_edges"] or []) if e.get("packet_count")]

        protocols: set[str] = set()
        ports: set[int] = set()
        function_codes: set[str] = set()
        total_sent = 0
        intervals: list[float] = []
        any_periodic = False

        for e in out_edges:
            if e.get("protocol"):
                protocols.add(e["protocol"])
            if e.get("port") is not None:
                ports.add(int(e["port"]))
            if e.get("function_code"):
                function_codes.add(e["function_code"])
            total_sent += int(e.get("packet_count") or 0)
            if e.get("avg_interval") and e["avg_interval"] > 0:
                intervals.append(float(e["avg_interval"]))
            if e.get("is_periodic"):
                any_periodic = True

        total_recv = sum(int(e.get("packet_count") or 0) for e in in_edges)
        avg_interval = sum(intervals) / len(intervals) if intervals else None

        return DeviceProfile(
            ip=ip,
            protocols=protocols,
            ports=ports,
            function_codes=function_codes,
            connections_out=len(out_edges),
            connections_in=len(in_edges),
            total_packets_sent=total_sent,
            total_packets_recv=total_recv,
            avg_interval_ms=avg_interval,
            is_periodic=any_periodic,
            zone=rec["zone"],
            purdue_level=rec["purdue_level"],
            role=rec["role"],
        )

    def build_all_profiles(self, session: Any) -> list[DeviceProfile]:
        """
        Build behavioral profiles for every Device in the graph.

        Args:
            session: An active Neo4j session.

        Returns:
            List of :class:`DeviceProfile` instances (one per Device node).
        """
        ips_result = session.run(_ALL_IPS_QUERY)
        ips = [r["ip"] for r in ips_result]
        profiles = []
        for ip in ips:
            profile = self.build_profile(session, ip)
            if profile is not None:
                profiles.append(profile)
        logger.info("Built %d device profiles", len(profiles))
        return profiles
