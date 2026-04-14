"""
ATT&CK for ICS — Neo4j loader.

Persists Tactic and Technique nodes into Neo4j, linking each Technique
to its parent Tactic via a PART_OF relationship.  Safe to call on every
startup (idempotent).
"""

from __future__ import annotations

import logging
from typing import Any

from src.attack.techniques import TACTICS, TECHNIQUES, Tactic, Technique

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_MERGE_TACTIC = """
MERGE (t:Tactic {tactic_id: $tactic_id})
ON CREATE SET t.name = $name, t.description = $description
ON MATCH SET  t.name = $name
"""

_MERGE_TECHNIQUE = """
MERGE (t:Technique {technique_id: $technique_id})
ON CREATE SET
    t.name              = $name,
    t.tactic_id         = $tactic_id,
    t.description       = $description,
    t.detection_signals = $detection_signals
ON MATCH SET
    t.name = $name
"""

_LINK_TECHNIQUE_TACTIC = """
MATCH (tech:Technique {technique_id: $technique_id})
MATCH (tact:Tactic    {tactic_id:    $tactic_id})
MERGE (tech)-[:PART_OF]->(tact)
"""


# ---------------------------------------------------------------------------
# AttackLoader
# ---------------------------------------------------------------------------

class AttackLoader:
    """
    Loads MITRE ATT&CK for ICS data into Neo4j.

    Usage::

        loader = AttackLoader(driver)
        with driver.session() as session:
            loader.ensure_all(session)
    """

    def __init__(self, driver: Any) -> None:
        """
        Initialise the loader.

        Args:
            driver: An authenticated Neo4j driver instance.
        """
        self._driver = driver

    def ensure_tactics(self, session: Any) -> None:
        """
        MERGE all 12 ATT&CK for ICS Tactic nodes into Neo4j.

        Args:
            session: An active Neo4j session.
        """
        for tactic in TACTICS:
            try:
                session.run(
                    _MERGE_TACTIC,
                    tactic_id=tactic.tactic_id,
                    name=tactic.name,
                    description=tactic.description,
                )
                logger.debug("Ensured tactic: %s %s", tactic.tactic_id, tactic.name)
            except Exception as exc:
                logger.error("Failed to ensure tactic %s: %s", tactic.tactic_id, exc)

        logger.info("Ensured %d ATT&CK tactics", len(TACTICS))

    def ensure_techniques(self, session: Any) -> None:
        """
        MERGE all Technique nodes and link them to their parent Tactics.

        Args:
            session: An active Neo4j session.
        """
        for tech in TECHNIQUES:
            try:
                session.run(
                    _MERGE_TECHNIQUE,
                    technique_id=tech.technique_id,
                    name=tech.name,
                    tactic_id=tech.tactic_id,
                    description=tech.description,
                    detection_signals=tech.detection_signals,
                )
                try:
                    session.run(
                        _LINK_TECHNIQUE_TACTIC,
                        technique_id=tech.technique_id,
                        tactic_id=tech.tactic_id,
                    )
                except Exception:
                    pass  # tactic may not exist yet; link on ensure_all
                logger.debug("Ensured technique: %s %s", tech.technique_id, tech.name)
            except Exception as exc:
                logger.error("Failed to ensure technique %s: %s", tech.technique_id, exc)

        logger.info("Ensured %d ATT&CK techniques", len(TECHNIQUES))

    def ensure_all(self, session: Any) -> None:
        """
        MERGE tactics first, then techniques (so links can be created).

        Args:
            session: An active Neo4j session.
        """
        self.ensure_tactics(session)
        self.ensure_techniques(session)
        logger.info(
            "ATT&CK for ICS loaded: %d tactics, %d techniques",
            len(TACTICS),
            len(TECHNIQUES),
        )
