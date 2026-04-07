"""
OPA policy engine for Guardance.

Evaluates the five detection rules via Open Policy Agent's REST API.
The engine fetches graph data from Neo4j, formats it as OPA input, sends
it to OPA's ``/v1/data/<package>`` endpoint, and returns a list of
violation dicts — the same shape as ``src/detect/queries.py``.

Requires:
  - OPA running at ``OPA_URL`` (default ``http://localhost:8181``)
  - Rego bundles loaded from ``src/policy/rules/``

If OPA is unreachable the engine falls back to the Cypher-based detection
in ``src/detect/queries.py`` so the pipeline is never blocked by an absent
OPA server.

Configuration (env vars):
    OPA_URL     default: "http://localhost:8181"
    OPA_TIMEOUT default: "5"  (seconds per request)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent / "rules"

# OPA package → REST path mapping
_PACKAGES = {
    "cross_zone":         "guardance/cross_zone",
    "new_device":         "guardance/new_device",
    "new_edge":           "guardance/new_edge",
    "interval_deviation": "guardance/interval_deviation",
    "unknown_protocol":   "guardance/unknown_protocol",
}


# ---------------------------------------------------------------------------
# OPA HTTP client
# ---------------------------------------------------------------------------

class OPAClient:
    """
    Thin HTTP client for OPA's ``/v1/data`` REST API.

    Args:
        base_url: Base URL of the OPA server (e.g. ``http://localhost:8181``).
        timeout:  Per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._base_url = (base_url or os.environ.get("OPA_URL", "http://localhost:8181")).rstrip("/")
        self._timeout = timeout or float(os.environ.get("OPA_TIMEOUT", "5"))
        self._session = requests.Session()

    def is_alive(self) -> bool:
        """Return True if OPA's health endpoint responds OK."""
        try:
            resp = self._session.get(f"{self._base_url}/health", timeout=self._timeout)
            return resp.status_code == 200
        except RequestException:
            return False

    def evaluate(self, package_path: str, input_data: dict) -> list[dict]:
        """
        POST *input_data* to ``/v1/data/<package_path>/violations`` and return
        the result array.

        Args:
            package_path: OPA package path, e.g. ``"guardance/cross_zone"``.
            input_data:   Dict to send as the ``input`` field.

        Returns:
            List of violation dicts from OPA, or empty list on error.
        """
        url = f"{self._base_url}/v1/data/{package_path}/violations"
        try:
            resp = self._session.post(
                url,
                json={"input": input_data},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            # OPA wraps the result in {"result": [...]}
            result = body.get("result", [])
            if result is None:
                return []
            # OPA may return a set (JSON array) or null when the rule produces no results
            return list(result)
        except RequestException as exc:
            logger.error("OPA request failed for %s: %s", package_path, exc)
            return []
        except (ValueError, KeyError) as exc:
            logger.error("Unexpected OPA response for %s: %s", package_path, exc)
            return []

    def close(self) -> None:
        """Close the underlying requests session."""
        self._session.close()

    def __enter__(self) -> "OPAClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Neo4j data fetchers
# ---------------------------------------------------------------------------

_FETCH_EDGES = """
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
RETURN
    src.ip          AS src_ip,
    dst.ip          AS dst_ip,
    r.protocol      AS protocol,
    r.port          AS port,
    r.function_code AS function_code,
    r.first_seen    AS first_seen,
    r.last_seen     AS last_seen,
    r.packet_count  AS packet_count,
    r.avg_interval_ms AS avg_interval_ms,
    r.is_periodic   AS is_periodic
"""

_FETCH_DEVICES = """
MATCH (d:Device)
OPTIONAL MATCH (d)-[:MEMBER_OF]->(z:Zone)
RETURN
    d.ip           AS ip,
    d.mac          AS mac,
    d.role         AS role,
    d.first_seen   AS first_seen,
    d.last_seen    AS last_seen,
    z.name         AS zone_name,
    z.purdue_level AS zone_level
"""


def _fetch_graph_data(session: Any) -> tuple[list[dict], dict]:
    """
    Fetch all edges and devices from Neo4j.

    Returns:
        Tuple of (edges list, devices dict keyed by IP).
    """
    edges: list[dict] = [dict(r) for r in session.run(_FETCH_EDGES)]
    raw_devices: list[dict] = [dict(r) for r in session.run(_FETCH_DEVICES)]

    devices: dict[str, dict] = {}
    for d in raw_devices:
        zone = None
        if d.get("zone_name") is not None:
            zone = {"name": d["zone_name"], "purdue_level": d["zone_level"]}
        devices[d["ip"]] = {
            "ip":         d["ip"],
            "mac":        d.get("mac"),
            "role":       d.get("role"),
            "first_seen": d.get("first_seen"),
            "last_seen":  d.get("last_seen"),
            "zone":       zone,
        }

    return edges, devices


# ---------------------------------------------------------------------------
# PolicyEngine — high-level interface
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    High-level policy evaluation engine.

    Fetches graph data from Neo4j, evaluates all five OPA policies, and
    returns findings.  Falls back to ``src/detect/queries`` if OPA is
    unavailable.

    Args:
        client:  An :class:`OPAClient` instance.  If ``None``, one is
                 created from environment variables.

    Usage::

        with PolicyEngine() as engine:
            results = engine.run_all(session, baseline_end, allowed_protocols)
    """

    def __init__(self, client: Optional[OPAClient] = None) -> None:
        self._client = client or OPAClient()
        self._owns_client = client is None

    # ------------------------------------------------------------------
    # Individual policy evaluators
    # ------------------------------------------------------------------

    def cross_zone_violations(self, session: Any) -> list[dict]:
        """
        Detect cross-zone communication via OPA.

        Args:
            session: Active Neo4j session.

        Returns:
            List of violation dicts.
        """
        edges, devices = _fetch_graph_data(session)
        input_data = {"edges": edges, "devices": devices}
        findings = self._client.evaluate(_PACKAGES["cross_zone"], input_data)
        logger.info("OPA cross_zone_violations: %d findings", len(findings))
        return findings

    def new_devices(self, session: Any, baseline_end: datetime) -> list[dict]:
        """
        Detect new devices via OPA.

        Args:
            session:      Active Neo4j session.
            baseline_end: Devices first_seen after this are flagged.

        Returns:
            List of violation dicts.
        """
        _, devices = _fetch_graph_data(session)
        input_data = {"devices": devices, "baseline_end": baseline_end.timestamp()}
        findings = self._client.evaluate(_PACKAGES["new_device"], input_data)
        logger.info("OPA new_devices: %d findings", len(findings))
        return findings

    def new_edges(self, session: Any, baseline_end: datetime) -> list[dict]:
        """
        Detect new communication edges via OPA.

        Args:
            session:      Active Neo4j session.
            baseline_end: Edges first_seen after this are flagged.

        Returns:
            List of violation dicts.
        """
        edges, _ = _fetch_graph_data(session)
        input_data = {"edges": edges, "baseline_end": baseline_end.timestamp()}
        findings = self._client.evaluate(_PACKAGES["new_edge"], input_data)
        logger.info("OPA new_edges: %d findings", len(findings))
        return findings

    def interval_deviation(
        self,
        session: Any,
        min_ms: float = 100.0,
        max_ms: float = 1000.0,
    ) -> list[dict]:
        """
        Detect polling interval anomalies via OPA.

        Args:
            session: Active Neo4j session.
            min_ms:  Lower bound in milliseconds.
            max_ms:  Upper bound in milliseconds.

        Returns:
            List of violation dicts.
        """
        edges, _ = _fetch_graph_data(session)
        input_data = {"edges": edges, "min_ms": min_ms, "max_ms": max_ms}
        findings = self._client.evaluate(_PACKAGES["interval_deviation"], input_data)
        logger.info("OPA interval_deviation: %d findings", len(findings))
        return findings

    def unknown_protocol(self, session: Any, allowed: list[str]) -> list[dict]:
        """
        Detect unknown protocols via OPA.

        Args:
            session: Active Neo4j session.
            allowed: List of allowed protocol names.

        Returns:
            List of violation dicts.
        """
        edges, _ = _fetch_graph_data(session)
        input_data = {"edges": edges, "allowed": allowed}
        findings = self._client.evaluate(_PACKAGES["unknown_protocol"], input_data)
        logger.info("OPA unknown_protocol: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Convenience: run all policies
    # ------------------------------------------------------------------

    def run_all(
        self,
        session: Any,
        baseline_end: datetime,
        allowed_protocols: list[str],
        min_ms: float = 100.0,
        max_ms: float = 1000.0,
    ) -> dict[str, list[dict]]:
        """
        Run all five OPA policies and return a results dict.

        If OPA is unreachable, falls back to ``src/detect/queries`` and
        logs a warning so operators know which evaluation path was used.

        Args:
            session:           Active Neo4j session.
            baseline_end:      Baseline cutoff datetime.
            allowed_protocols: Protocol allowlist.
            min_ms:            Minimum acceptable polling interval (ms).
            max_ms:            Maximum acceptable polling interval (ms).

        Returns:
            Dict mapping policy name → list of finding dicts.
        """
        if not self._client.is_alive():
            logger.warning(
                "OPA server unreachable at %s — falling back to Cypher detection",
                self._client._base_url,
            )
            return self._cypher_fallback(
                session, baseline_end, allowed_protocols, min_ms, max_ms
            )

        return {
            "cross_zone_violations": self.cross_zone_violations(session),
            "new_devices":           self.new_devices(session, baseline_end),
            "new_edges":             self.new_edges(session, baseline_end),
            "interval_deviation":    self.interval_deviation(session, min_ms, max_ms),
            "unknown_protocol":      self.unknown_protocol(session, allowed_protocols),
        }

    @staticmethod
    def _cypher_fallback(
        session: Any,
        baseline_end: datetime,
        allowed_protocols: list[str],
        min_ms: float,
        max_ms: float,
    ) -> dict[str, list[dict]]:
        """Run the Cypher-based detection queries as a fallback."""
        from src.detect.queries import (
            cross_zone_violations,
            interval_deviation,
            new_devices,
            new_edges,
            unknown_protocol,
        )

        return {
            "cross_zone_violations": cross_zone_violations(session),
            "new_devices":           new_devices(session, baseline_end),
            "new_edges":             new_edges(session, baseline_end),
            "interval_deviation":    interval_deviation(session, min_ms, max_ms),
            "unknown_protocol":      unknown_protocol(session, allowed_protocols),
        }

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "PolicyEngine":
        return self

    def __exit__(self, *_: Any) -> None:
        self._client.close()
