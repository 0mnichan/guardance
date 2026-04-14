"""
Process signature matching via Neo4j Cypher path traversal.

For each device, the matcher queries its outbound COMMUNICATES_WITH edges
(ordered by first_seen) and attempts to match each registered
:class:`~src.procid.signatures.ProcessSignature` against the observed
sequence of (protocol, function_code) pairs.

Two match modes are supported:

    exact  — The full sequence must match in order.
    partial — At least 60% of steps must match (for degraded/incomplete traces).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.procid.signatures import SIGNATURES, ProcessSignature

logger = logging.getLogger(__name__)

# Minimum score to count as a partial match
_PARTIAL_THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# Match result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MatchResult:
    """
    Result of matching one device against one signature.

    Attributes:
        ip:             Device IP address.
        signature_name: Name of the matched signature.
        full_match:     True if all steps matched.
        score:          Fraction of steps matched (0.0–1.0).
        observed:       The actual (protocol, function_code) sequence queried.
    """

    ip: str
    signature_name: str
    full_match: bool
    score: float
    observed: list[tuple[str, str]]


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_DEVICE_EDGE_SEQUENCE = """
MATCH (d:Device {ip: $ip})-[r:COMMUNICATES_WITH]->()
WHERE r.function_code IS NOT NULL
RETURN r.protocol AS protocol, r.function_code AS function_code,
       r.first_seen AS first_seen, r.packet_count AS packet_count
ORDER BY r.first_seen ASC
"""

_ALL_IPS = "MATCH (d:Device) RETURN d.ip AS ip"


# ---------------------------------------------------------------------------
# ProcessMatcher
# ---------------------------------------------------------------------------

class ProcessMatcher:
    """
    Queries Neo4j to retrieve device communication sequences and matches
    them against registered process signatures.

    Usage::

        matcher = ProcessMatcher(driver, signatures=SIGNATURES)
        with driver.session() as session:
            results = matcher.match_device(session, "10.0.1.1")
            all_results = matcher.match_all_devices(session)
    """

    def __init__(
        self,
        driver: Any,
        signatures: list[ProcessSignature] | None = None,
    ) -> None:
        """
        Initialise the matcher.

        Args:
            driver:     An authenticated Neo4j driver instance.
            signatures: Signatures to match against.  Defaults to
                        :data:`~src.procid.signatures.SIGNATURES`.
        """
        self._driver = driver
        self._signatures = signatures if signatures is not None else SIGNATURES

    def _get_sequence(self, session: Any, ip: str) -> list[tuple[str, str]]:
        """
        Query the ordered communication sequence for a device.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.

        Returns:
            Ordered list of (protocol, function_code) tuples.
        """
        result = session.run(_DEVICE_EDGE_SEQUENCE, ip=ip)
        return [
            (r["protocol"] or "unknown", r["function_code"] or "")
            for r in result
        ]

    def match_device(
        self,
        session: Any,
        ip: str,
        partial: bool = True,
    ) -> list[MatchResult]:
        """
        Match all registered signatures against a single device.

        Args:
            session: An active Neo4j session.
            ip:      Device IP address.
            partial: If True, also return partial matches (score ≥ 0.6).

        Returns:
            List of :class:`MatchResult` sorted by score descending.
        """
        sequence = self._get_sequence(session, ip)
        if not sequence:
            logger.debug("Device %s has no function-code edges — skipping match", ip)
            return []

        results: list[MatchResult] = []
        for sig in self._signatures:
            full_match, score = sig.matches_sequence(sequence)
            if full_match or (partial and score >= _PARTIAL_THRESHOLD):
                results.append(MatchResult(
                    ip=ip,
                    signature_name=sig.name,
                    full_match=full_match,
                    score=score,
                    observed=sequence,
                ))

        results.sort(key=lambda r: r.score, reverse=True)
        logger.debug(
            "Device %s: %d signature matches (from %d observations)",
            ip, len(results), len(sequence),
        )
        return results

    def match_all_devices(
        self,
        session: Any,
        partial: bool = True,
    ) -> dict[str, list[MatchResult]]:
        """
        Match signatures against every device in the graph.

        Args:
            session: An active Neo4j session.
            partial: If True, also include partial matches.

        Returns:
            Dict mapping device IP → list of :class:`MatchResult`.
        """
        ips_result = session.run(_ALL_IPS)
        ips = [r["ip"] for r in ips_result]

        output: dict[str, list[MatchResult]] = {}
        total_matches = 0
        for ip in ips:
            matches = self.match_device(session, ip, partial=partial)
            if matches:
                output[ip] = matches
                total_matches += len(matches)

        logger.info(
            "ProcID matching: %d devices scanned, %d signature matches",
            len(ips), total_matches,
        )
        return output
