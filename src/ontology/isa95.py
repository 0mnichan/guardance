"""
ISA-95 equipment hierarchy model for Guardance.

ISA-95 (ANSI/ISA-95 / IEC 62264) defines a hierarchical model of
manufacturing equipment that maps cleanly onto OT network topology:

    Enterprise
    └── Site
        └── Area
            └── WorkCenter
                └── WorkUnit
                    └── Equipment Module
                        └── Control Module

Guardance models the three middle layers most relevant to network
segmentation:

    Area       — A functional zone within a site (e.g. "Reactor Building",
                 "Utilities")
    WorkCenter — A collection of work units performing a related process
                 (e.g. "Distillation Train 1")
    WorkUnit   — An individual unit or machine (maps closely to a Device
                 or a small subnet)

Each WorkUnit can be linked to Device nodes via PART_OF relationships
and to a Zone via MEMBER_OF, enabling cross-framework queries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data definitions
# ---------------------------------------------------------------------------

@dataclass
class Area:
    """ISA-95 Area — top-level functional grouping within a site."""

    name: str
    description: str = ""
    purdue_level: int = 3  # Typically Operations or Supervisory


@dataclass
class WorkCenter:
    """ISA-95 WorkCenter — collection of related WorkUnits."""

    name: str
    area_name: str
    description: str = ""


@dataclass
class WorkUnit:
    """ISA-95 WorkUnit — individual unit or machine; maps to device subnet."""

    name: str
    work_center_name: str
    description: str = ""
    device_ips: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_MERGE_AREA = """
MERGE (a:Area {name: $name})
ON CREATE SET a.description = $description, a.purdue_level = $purdue_level
"""

_MERGE_WORK_CENTER = """
MERGE (wc:WorkCenter {name: $name})
ON CREATE SET wc.description = $description
WITH wc
MATCH (a:Area {name: $area_name})
MERGE (wc)-[:PART_OF]->(a)
"""

_MERGE_WORK_UNIT = """
MERGE (wu:WorkUnit {name: $name})
ON CREATE SET wu.description = $description
WITH wu
MATCH (wc:WorkCenter {name: $work_center_name})
MERGE (wu)-[:PART_OF]->(wc)
"""

_LINK_DEVICE_TO_WORK_UNIT = """
MATCH (d:Device {ip: $ip})
MATCH (wu:WorkUnit {name: $work_unit_name})
MERGE (d)-[:PART_OF]->(wu)
"""

_GET_WORK_UNIT_FOR_DEVICE = """
MATCH (d:Device {ip: $ip})-[:PART_OF]->(wu:WorkUnit)
OPTIONAL MATCH (wu)-[:PART_OF]->(wc:WorkCenter)
OPTIONAL MATCH (wc)-[:PART_OF]->(a:Area)
RETURN wu.name AS work_unit, wc.name AS work_center, a.name AS area
"""


# ---------------------------------------------------------------------------
# ISA95Manager
# ---------------------------------------------------------------------------

class ISA95Manager:
    """
    Manages ISA-95 hierarchy nodes (Area, WorkCenter, WorkUnit) in Neo4j.

    Usage::

        manager = ISA95Manager(driver)
        area = Area(name="Utilities", description="Site utilities block")
        wc   = WorkCenter(name="Cooling Tower 1", area_name="Utilities")
        wu   = WorkUnit(name="CT1-PLC", work_center_name="Cooling Tower 1")
        with driver.session() as session:
            manager.ensure_area(session, area)
            manager.ensure_work_center(session, wc)
            manager.ensure_work_unit(session, wu)
            manager.link_device(session, ip="10.0.1.1", work_unit_name="CT1-PLC")
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the manager.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def ensure_area(self, session: Any, area: Area) -> None:
        """
        MERGE an Area node into Neo4j.

        Args:
            session: An active Neo4j session.
            area:    Area definition to persist.
        """
        try:
            session.run(
                _MERGE_AREA,
                name=area.name,
                description=area.description,
                purdue_level=area.purdue_level,
            )
            logger.debug("Ensured area: %s", area.name)
        except Exception as exc:
            logger.error("Failed to ensure area %s: %s", area.name, exc)

    def ensure_work_center(self, session: Any, wc: WorkCenter) -> None:
        """
        MERGE a WorkCenter node and link it to its parent Area.

        Args:
            session: An active Neo4j session.
            wc:      WorkCenter definition to persist.
        """
        try:
            session.run(
                _MERGE_WORK_CENTER,
                name=wc.name,
                description=wc.description,
                area_name=wc.area_name,
            )
            logger.debug("Ensured work center: %s", wc.name)
        except Exception as exc:
            logger.error("Failed to ensure work center %s: %s", wc.name, exc)

    def ensure_work_unit(self, session: Any, wu: WorkUnit) -> None:
        """
        MERGE a WorkUnit node, link it to its parent WorkCenter, and
        optionally link it to Device nodes.

        Args:
            session: An active Neo4j session.
            wu:      WorkUnit definition to persist.
        """
        try:
            session.run(
                _MERGE_WORK_UNIT,
                name=wu.name,
                description=wu.description,
                work_center_name=wu.work_center_name,
            )
            for ip in wu.device_ips:
                self.link_device(session, ip=ip, work_unit_name=wu.name)
            logger.debug(
                "Ensured work unit: %s (devices: %d)", wu.name, len(wu.device_ips)
            )
        except Exception as exc:
            logger.error("Failed to ensure work unit %s: %s", wu.name, exc)

    def link_device(
        self, session: Any, ip: str, work_unit_name: str
    ) -> None:
        """
        Create a PART_OF relationship from a Device to a WorkUnit.

        Args:
            session:        An active Neo4j session.
            ip:             Device IP address.
            work_unit_name: Target WorkUnit name.
        """
        try:
            session.run(
                _LINK_DEVICE_TO_WORK_UNIT,
                ip=ip,
                work_unit_name=work_unit_name,
            )
            logger.debug("Linked device %s → WorkUnit %s", ip, work_unit_name)
        except Exception as exc:
            logger.error(
                "Failed to link device %s to work unit %s: %s",
                ip, work_unit_name, exc,
            )

    def get_hierarchy_for_device(
        self, session: Any, ip: str
    ) -> dict | None:
        """
        Return the ISA-95 hierarchy context for a device.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            Dict with work_unit, work_center, area keys, or None if not
            linked to the ISA-95 hierarchy.
        """
        result = session.run(_GET_WORK_UNIT_FOR_DEVICE, ip=ip)
        rec = result.single()
        return dict(rec) if rec else None
