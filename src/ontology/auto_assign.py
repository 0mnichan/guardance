"""
Auto-zone assignment for Guardance.

Infers the Purdue Model zone for a device based on the protocols it
uses and the ports it communicates on.  Assignment rules reflect
well-known OT protocol usage patterns:

    Purdue 0 (Field)       — passive field bus protocols (PROFIBUS, HART,
                             Foundation Fieldbus)
    Purdue 1 (Control)     — Modbus/502, DNP3/20000, S7/102, IEC104/2404,
                             EtherNet/IP/44818
    Purdue 2 (Supervisory) — OPC-DA/DCOM, OPC-UA/4840, BACnet/47808,
                             SCADA polling patterns
    Purdue 3 (Operations)  — HTTPS/443, SQL/1433, historian protocols,
                             engineering workstation traffic
    Purdue 4 (Business)    — SMB/445, HTTP/80, generic business traffic
    Purdue 5 (Enterprise)  — Internet-routable, DNS/53, NTP/123

When multiple rules match, the lowest (most OT-centric) level wins.
"""

from __future__ import annotations

import logging
from typing import Any

from src.ontology.zones import LEVEL_TO_ZONE, PurdueZone, ZoneManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol and port → Purdue level mapping
# ---------------------------------------------------------------------------

# (protocol_lower, port) → purdue_level.  Port=None means any port.
_PORT_RULES: list[tuple[str | None, int | None, int]] = [
    # Level 1 — Process control field protocols
    ("modbus",    502,   1),
    ("modbus",    None,  1),
    ("dnp3",      20000, 1),
    ("dnp3",      None,  1),
    ("s7comm",    102,   1),
    ("s7comm",    None,  1),
    ("iec104",    2404,  1),
    ("enip",      44818, 1),
    ("ethernet/ip", 44818, 1),
    # Level 2 — Supervisory
    ("opc-da",    None,  2),
    ("opc-ua",    4840,  2),
    ("opc-ua",    None,  2),
    ("bacnet",    47808, 2),
    ("bacnet",    None,  2),
    # Level 3 — Operations
    ("historian", None,  3),
    ("mssql",     1433,  3),
    ("sql",       1433,  3),
    # Level 4 — Business
    ("smb",       445,   4),
    ("cifs",      445,   4),
    ("rdp",       3389,  4),
    # Level 5 — Enterprise
    ("dns",       53,    5),
    ("ntp",       123,   5),
    ("http",      80,    5),
    ("https",     443,   5),
]

# Protocol name → minimum purdue level (used when no port match found)
_PROTOCOL_FALLBACK: dict[str, int] = {
    "modbus":      1,
    "dnp3":        1,
    "s7comm":      1,
    "iec104":      1,
    "enip":        1,
    "opc-ua":      2,
    "opc-da":      2,
    "bacnet":      2,
    "mssql":       3,
    "sql":         3,
    "historian":   3,
    "smb":         4,
    "rdp":         4,
    "http":        5,
    "https":       5,
    "dns":         5,
    "ntp":         5,
}


# ---------------------------------------------------------------------------
# Inference function
# ---------------------------------------------------------------------------

def infer_purdue_level(
    protocols_ports: list[tuple[str, int]],
) -> int:
    """
    Infer the most appropriate Purdue level for a device.

    Applies port-based rules first, then protocol-only fallback.
    The *lowest* (most OT-centric) level that any rule fires on is
    returned.  If no rule matches, Level 3 (Operations) is assumed as
    a conservative default.

    Args:
        protocols_ports: List of (protocol, port) tuples observed for
                         the device, e.g. ``[("modbus", 502), ("tcp", 80)]``.

    Returns:
        Purdue level integer (0–5).
    """
    # None = no rule matched yet; default to 3 only when nothing fires.
    # This prevents level-5 protocols (https) being overridden by the
    # level-3 default via min().
    best_level: int | None = None

    for proto_raw, port in protocols_ports:
        proto = proto_raw.lower()

        # Exact (protocol, port) match
        for rule_proto, rule_port, rule_level in _PORT_RULES:
            if rule_proto is None:
                continue
            if proto == rule_proto and rule_port is not None and port == rule_port:
                best_level = rule_level if best_level is None else min(best_level, rule_level)

        # Protocol-only fallback
        if proto in _PROTOCOL_FALLBACK:
            fb = _PROTOCOL_FALLBACK[proto]
            best_level = fb if best_level is None else min(best_level, fb)

    # Default to Operations (3) when no rule matched
    return best_level if best_level is not None else 3


def infer_zone(protocols_ports: list[tuple[str, int]]) -> PurdueZone:
    """
    Return the PurdueZone inferred from a device's protocol/port set.

    Args:
        protocols_ports: List of (protocol, port) tuples.

    Returns:
        PurdueZone with the inferred level.
    """
    level = infer_purdue_level(protocols_ports)
    return LEVEL_TO_ZONE[level]


# ---------------------------------------------------------------------------
# AutoZoneAssigner
# ---------------------------------------------------------------------------

_DEVICES_WITHOUT_ZONE = """
MATCH (d:Device)
WHERE NOT (d)-[:MEMBER_OF]->(:Zone)
RETURN d.ip AS ip
"""

_DEVICE_PROTOCOLS = """
MATCH (d:Device {ip: $ip})-[r:COMMUNICATES_WITH]->()
RETURN r.protocol AS protocol, r.port AS port
"""


class AutoZoneAssigner:
    """
    Queries Neo4j for un-zoned devices and assigns them a Purdue zone
    based on their observed communication protocols and ports.

    Usage::

        assigner = AutoZoneAssigner(driver)
        with driver.session() as session:
            assigned = assigner.assign_all(session)
        print(f"Auto-assigned {assigned} devices")
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the assigner.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver
        self._zone_manager = ZoneManager(driver)

    def assign_device(self, session: Any, ip: str) -> PurdueZone | None:
        """
        Infer and assign a Purdue zone for a single device.

        Queries the device's outbound COMMUNICATES_WITH edges to collect
        protocol/port pairs, infers the zone, then creates the MEMBER_OF
        relationship.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            The assigned PurdueZone, or None if the device has no edges.
        """
        result = session.run(_DEVICE_PROTOCOLS, ip=ip)
        pairs: list[tuple[str, int]] = []
        for rec in result:
            proto = rec["protocol"] or "tcp"
            port = rec["port"] or 0
            pairs.append((proto, port))

        if not pairs:
            logger.debug("Device %s has no edges — skipping auto-zone", ip)
            return None

        zone = infer_zone(pairs)
        self._zone_manager.assign_device_zone(session, ip=ip, zone_name=zone.name)
        logger.info(
            "Auto-assigned device %s → zone %s (Level %d)",
            ip, zone.name, zone.purdue_level,
        )
        return zone

    def assign_all(self, session: Any) -> int:
        """
        Auto-assign zones to all devices that currently lack one.

        Args:
            session: An active Neo4j session.

        Returns:
            Number of devices that received a zone assignment.
        """
        result = session.run(_DEVICES_WITHOUT_ZONE)
        unzoned = [r["ip"] for r in result]
        logger.info("Found %d un-zoned devices", len(unzoned))

        assigned = 0
        for ip in unzoned:
            zone = self.assign_device(session, ip)
            if zone is not None:
                assigned += 1

        logger.info("Auto-assigned %d/%d un-zoned devices", assigned, len(unzoned))
        return assigned
