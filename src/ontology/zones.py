"""
Purdue Model zone definitions and Neo4j management.

The Purdue Reference Model (IEC/ISA 62443-3-3) partitions OT networks into
six levels:

    Level 0 — Field devices       (sensors, actuators)
    Level 1 — Process control     (PLCs, RTUs, DCS)
    Level 2 — Supervisory control (HMI, SCADA)
    Level 3 — Manufacturing ops   (historians, MES, engineering WS)
    Level 4 — Business logistics  (ERP, business LAN)
    Level 5 — Enterprise / cloud  (internet, DMZ)

Each Zone node carries a target security level (sl_t) per IEC 62443-3-2.
The sl_t values here represent a baseline recommendation; operators may
raise them for critical infrastructure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PurdueZone:
    """Immutable description of a Purdue Model zone."""

    name: str
    purdue_level: int
    description: str
    sl_t: int  # IEC 62443 target security level (1–4)


PURDUE_ZONES: list[PurdueZone] = [
    PurdueZone(
        name="Field",
        purdue_level=0,
        description="Physical process: sensors, actuators, drives",
        sl_t=2,
    ),
    PurdueZone(
        name="Control",
        purdue_level=1,
        description="Process control: PLCs, RTUs, DCS controllers",
        sl_t=3,
    ),
    PurdueZone(
        name="Supervisory",
        purdue_level=2,
        description="Supervisory control: HMI, SCADA servers",
        sl_t=3,
    ),
    PurdueZone(
        name="Operations",
        purdue_level=3,
        description="Manufacturing operations: historian, MES, engineering workstations",
        sl_t=2,
    ),
    PurdueZone(
        name="Business",
        purdue_level=4,
        description="Business logistics: ERP, business LAN",
        sl_t=1,
    ),
    PurdueZone(
        name="Enterprise",
        purdue_level=5,
        description="Enterprise / internet-facing: DMZ, cloud connectivity",
        sl_t=1,
    ),
]

# Lookup: level → PurdueZone
LEVEL_TO_ZONE: dict[int, PurdueZone] = {z.purdue_level: z for z in PURDUE_ZONES}
NAME_TO_ZONE: dict[str, PurdueZone] = {z.name: z for z in PURDUE_ZONES}


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_ENSURE_ZONE_CONSTRAINT = (
    "CREATE CONSTRAINT zone_name IF NOT EXISTS FOR (z:Zone) REQUIRE z.name IS UNIQUE"
)

_MERGE_ZONE = """
MERGE (z:Zone {name: $name})
ON CREATE SET
    z.purdue_level = $purdue_level,
    z.description  = $description,
    z.sl_t         = $sl_t
ON MATCH SET
    z.purdue_level = $purdue_level,
    z.sl_t         = CASE WHEN z.sl_t IS NULL THEN $sl_t ELSE z.sl_t END
"""

_ASSIGN_DEVICE_ZONE = """
MATCH (d:Device {ip: $ip})
MATCH (z:Zone {name: $zone_name})
MERGE (d)-[:MEMBER_OF]->(z)
"""

_GET_DEVICE_ZONE = """
MATCH (d:Device {ip: $ip})-[:MEMBER_OF]->(z:Zone)
RETURN z.name AS name, z.purdue_level AS purdue_level
"""

_DEVICES_WITHOUT_ZONE = """
MATCH (d:Device)
WHERE NOT (d)-[:MEMBER_OF]->(:Zone)
RETURN d.ip AS ip
"""


# ---------------------------------------------------------------------------
# ZoneManager
# ---------------------------------------------------------------------------

class ZoneManager:
    """
    Manages Zone nodes in Neo4j representing the Purdue Model hierarchy.

    Usage::

        manager = ZoneManager(driver)
        manager.ensure_zones(session)
        manager.assign_device_zone(session, ip="10.0.1.1", zone_name="Control")
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the manager.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def ensure_zones(self, session: Any) -> None:
        """
        MERGE all six Purdue Model Zone nodes into Neo4j.

        Safe to call on every startup — idempotent.

        Args:
            session: An active Neo4j session.
        """
        try:
            session.run(_ENSURE_ZONE_CONSTRAINT)
        except Exception as exc:
            logger.debug("Zone constraint already exists or couldn't create: %s", exc)

        for zone in PURDUE_ZONES:
            try:
                session.run(
                    _MERGE_ZONE,
                    name=zone.name,
                    purdue_level=zone.purdue_level,
                    description=zone.description,
                    sl_t=zone.sl_t,
                )
                logger.debug("Ensured zone: %s (Level %d)", zone.name, zone.purdue_level)
            except Exception as exc:
                logger.error("Failed to ensure zone %s: %s", zone.name, exc)

        logger.info("Ensured %d Purdue zones in Neo4j", len(PURDUE_ZONES))

    def assign_device_zone(
        self, session: Any, ip: str, zone_name: str
    ) -> None:
        """
        Create a MEMBER_OF relationship from a Device to a Zone.

        If the device or zone does not exist the query silently does nothing.

        Args:
            session:   An active Neo4j session.
            ip:        Device IP address.
            zone_name: Target zone name (must match a Zone node's ``name``).
        """
        try:
            session.run(_ASSIGN_DEVICE_ZONE, ip=ip, zone_name=zone_name)
            logger.debug("Assigned device %s → zone %s", ip, zone_name)
        except Exception as exc:
            logger.error("Failed to assign device %s to zone %s: %s", ip, zone_name, exc)

    def get_device_zone(self, session: Any, ip: str) -> PurdueZone | None:
        """
        Return the PurdueZone for a device, or None if not yet assigned.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            PurdueZone instance or None.
        """
        result = session.run(_GET_DEVICE_ZONE, ip=ip)
        rec = result.single()
        if rec is None:
            return None
        return NAME_TO_ZONE.get(rec["name"])

    def devices_without_zone(self, session: Any) -> list[str]:
        """
        Return IP addresses of Device nodes with no MEMBER_OF zone assignment.

        Args:
            session: An active Neo4j session.

        Returns:
            List of IP address strings.
        """
        result = session.run(_DEVICES_WITHOUT_ZONE)
        return [r["ip"] for r in result]
