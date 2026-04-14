"""
IEC 62443 Zone and Conduit model for Guardance.

IEC 62443-3-2 defines the Security Zone and Conduit methodology:

    Zone    — A grouping of logical or physical assets that share
              the same security requirements and are protected by
              a common security boundary.

    Conduit — A communication channel or pathway between two zones.
              Each conduit has an achievable security level (sl_a)
              and a target security level (sl_t).  When sl_a < sl_t
              the conduit is a risk.

Security levels:
    SL 0 — No specific requirements
    SL 1 — Protection against casual or coincidental violation
    SL 2 — Protection against intentional violation using simple means
    SL 3 — Protection against sophisticated attack using IACS-specific skills
    SL 4 — Protection against state-sponsored attacks

This module manages Conduit nodes in Neo4j and exposes helpers to assess
whether a conduit's achievable level meets the target.
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
class Conduit:
    """
    Represents an IEC 62443 conduit between two security zones.

    Attributes:
        name:               Unique conduit identifier, e.g. ``"Field-Control"``.
        src_zone:           Source zone name.
        dst_zone:           Destination zone name.
        sl_t:               Target security level (1–4).
        sl_a:               Achievable security level (1–4).
        allowed_protocols:  List of protocol names permitted on this conduit.
        bidirectional:      Whether traffic flows both ways.
    """

    name: str
    src_zone: str
    dst_zone: str
    sl_t: int = 2
    sl_a: int = 2
    allowed_protocols: list[str] = field(default_factory=list)
    bidirectional: bool = True

    @property
    def is_compliant(self) -> bool:
        """Return True if the achievable SL meets or exceeds the target SL."""
        return self.sl_a >= self.sl_t


# Standard conduit definitions for a typical OT network
DEFAULT_CONDUITS: list[Conduit] = [
    Conduit(
        name="Field-Control",
        src_zone="Field",
        dst_zone="Control",
        sl_t=3,
        sl_a=2,
        allowed_protocols=["modbus", "dnp3", "s7comm", "profibus"],
    ),
    Conduit(
        name="Control-Supervisory",
        src_zone="Control",
        dst_zone="Supervisory",
        sl_t=3,
        sl_a=3,
        allowed_protocols=["modbus", "dnp3", "opc-da", "opc-ua"],
    ),
    Conduit(
        name="Supervisory-Operations",
        src_zone="Supervisory",
        dst_zone="Operations",
        sl_t=2,
        sl_a=2,
        allowed_protocols=["opc-ua", "https", "historian"],
    ),
    Conduit(
        name="Operations-Business",
        src_zone="Operations",
        dst_zone="Business",
        sl_t=2,
        sl_a=2,
        allowed_protocols=["https", "sql"],
    ),
    Conduit(
        name="Business-Enterprise",
        src_zone="Business",
        dst_zone="Enterprise",
        sl_t=1,
        sl_a=2,
        allowed_protocols=["https"],
    ),
]

CONDUIT_BY_NAME: dict[str, Conduit] = {c.name: c for c in DEFAULT_CONDUITS}


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_MERGE_CONDUIT = """
MERGE (c:Conduit {name: $name})
ON CREATE SET
    c.src_zone           = $src_zone,
    c.dst_zone           = $dst_zone,
    c.sl_t               = $sl_t,
    c.sl_a               = $sl_a,
    c.allowed_protocols  = $allowed_protocols,
    c.bidirectional      = $bidirectional
ON MATCH SET
    c.sl_t = $sl_t,
    c.sl_a = $sl_a
"""

_LINK_CONDUIT_ZONES = """
MATCH (c:Conduit {name: $name})
MATCH (src:Zone {name: $src_zone})
MATCH (dst:Zone {name: $dst_zone})
MERGE (c)-[:CONNECTS]->(src)
MERGE (c)-[:CONNECTS]->(dst)
"""

_GET_CONDUIT_FOR_ZONES = """
MATCH (c:Conduit)
WHERE (c.src_zone = $z1 AND c.dst_zone = $z2)
   OR (c.bidirectional = true AND c.src_zone = $z2 AND c.dst_zone = $z1)
RETURN c.name AS name, c.sl_t AS sl_t, c.sl_a AS sl_a,
       c.allowed_protocols AS allowed_protocols
LIMIT 1
"""

_NON_COMPLIANT_CONDUITS = """
MATCH (c:Conduit)
WHERE c.sl_a < c.sl_t
RETURN c.name AS name, c.src_zone AS src_zone, c.dst_zone AS dst_zone,
       c.sl_t AS sl_t, c.sl_a AS sl_a
ORDER BY (c.sl_t - c.sl_a) DESC
"""


# ---------------------------------------------------------------------------
# ConduitManager
# ---------------------------------------------------------------------------

class ConduitManager:
    """
    Manages IEC 62443 Conduit nodes in Neo4j.

    Usage::

        manager = ConduitManager(driver)
        manager.ensure_conduits(session)
        gaps = manager.non_compliant_conduits(session)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the manager.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def ensure_conduits(
        self,
        session: Any,
        conduits: list[Conduit] | None = None,
    ) -> None:
        """
        MERGE conduit nodes into Neo4j and link them to Zone nodes.

        Args:
            session:  An active Neo4j session.
            conduits: Conduit definitions to persist.  Defaults to
                      :data:`DEFAULT_CONDUITS`.
        """
        if conduits is None:
            conduits = DEFAULT_CONDUITS

        for conduit in conduits:
            try:
                session.run(
                    _MERGE_CONDUIT,
                    name=conduit.name,
                    src_zone=conduit.src_zone,
                    dst_zone=conduit.dst_zone,
                    sl_t=conduit.sl_t,
                    sl_a=conduit.sl_a,
                    allowed_protocols=conduit.allowed_protocols,
                    bidirectional=conduit.bidirectional,
                )
                # Best-effort zone linking (zones may not exist yet)
                try:
                    session.run(
                        _LINK_CONDUIT_ZONES,
                        name=conduit.name,
                        src_zone=conduit.src_zone,
                        dst_zone=conduit.dst_zone,
                    )
                except Exception:
                    pass
                logger.debug(
                    "Ensured conduit: %s (%s → %s)",
                    conduit.name, conduit.src_zone, conduit.dst_zone,
                )
            except Exception as exc:
                logger.error("Failed to ensure conduit %s: %s", conduit.name, exc)

        logger.info("Ensured %d IEC 62443 conduits", len(conduits))

    def get_conduit_for_zones(
        self, session: Any, zone1: str, zone2: str
    ) -> dict | None:
        """
        Return the conduit record connecting two named zones, or None.

        Args:
            session: An active Neo4j session.
            zone1:   First zone name.
            zone2:   Second zone name.

        Returns:
            Dict with name, sl_t, sl_a, allowed_protocols, or None.
        """
        result = session.run(_GET_CONDUIT_FOR_ZONES, z1=zone1, z2=zone2)
        rec = result.single()
        return dict(rec) if rec else None

    def non_compliant_conduits(self, session: Any) -> list[dict]:
        """
        Return conduits where the achievable SL is below the target SL.

        Args:
            session: An active Neo4j session.

        Returns:
            List of dicts: name, src_zone, dst_zone, sl_t, sl_a.
        """
        result = session.run(_NON_COMPLIANT_CONDUITS)
        rows = [dict(r) for r in result]
        logger.info("Non-compliant conduits: %d", len(rows))
        return rows

    def assess_protocol_on_conduit(
        self, conduit_name: str, protocol: str
    ) -> bool:
        """
        Check whether a protocol is permitted on a named conduit.

        Uses the in-memory DEFAULT_CONDUITS definition; does not query Neo4j.

        Args:
            conduit_name: Conduit name from DEFAULT_CONDUITS.
            protocol:     Protocol string (case-insensitive).

        Returns:
            True if the protocol is allowed, False otherwise.
        """
        conduit = CONDUIT_BY_NAME.get(conduit_name)
        if conduit is None:
            return False
        return protocol.lower() in [p.lower() for p in conduit.allowed_protocols]
