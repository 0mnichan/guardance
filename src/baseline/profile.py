"""
Per-device behavioral baseline profiles for Guardance.

A baseline profile captures the "normal" communication pattern for a
device during a known-good observation window.  Subsequent observations
are scored against this baseline to detect anomalies.

Stored fields mirror the COMMUNICATES_WITH edge attributes plus derived
statistics.  Profiles are held in memory and optionally persisted to
Neo4j as DeviceBaseline nodes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DeviceBaselineProfile
# ---------------------------------------------------------------------------

@dataclass
class DeviceBaselineProfile:
    """
    Statistical summary of a device's communication behaviour during a
    baseline observation window.

    Attributes:
        ip:                    Device IP address.
        baseline_start:        Unix epoch start of the observation window.
        baseline_end:          Unix epoch end of the observation window.
        captured_at:           Unix epoch when the profile was computed.
        interval_mean:         Mean polling interval across all outbound
                               periodic edges (ms).  None if no periodic edges.
        interval_std:          Std dev of polling intervals (ms).
        packet_rate_mean:      Mean packets-per-minute for outbound edges.
        packet_rate_std:       Std dev of packet rate.
        protocols:             Sorted list of observed protocols.
        peer_count:            Number of distinct communication peers.
        periodic_edge_count:   Number of outbound edges flagged is_periodic.
        total_edges:           Total outbound edges observed.
        raw_intervals:         Individual avg_interval_ms values (for IQR).
        raw_packet_rates:      Individual packet rates (packets/minute).
    """

    ip: str
    baseline_start: float
    baseline_end: float
    captured_at: float = field(default_factory=time.time)
    interval_mean: float | None = None
    interval_std: float = 0.0
    packet_rate_mean: float = 0.0
    packet_rate_std: float = 0.0
    protocols: list[str] = field(default_factory=list)
    peer_count: int = 0
    periodic_edge_count: int = 0
    total_edges: int = 0
    raw_intervals: list[float] = field(default_factory=list)
    raw_packet_rates: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to a plain dict (for Neo4j persistence or API output)."""
        return {
            "ip":                  self.ip,
            "baseline_start":      self.baseline_start,
            "baseline_end":        self.baseline_end,
            "captured_at":         self.captured_at,
            "interval_mean":       self.interval_mean,
            "interval_std":        self.interval_std,
            "packet_rate_mean":    self.packet_rate_mean,
            "packet_rate_std":     self.packet_rate_std,
            "protocols":           self.protocols,
            "peer_count":          self.peer_count,
            "periodic_edge_count": self.periodic_edge_count,
            "total_edges":         self.total_edges,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceBaselineProfile":
        """Deserialise from a plain dict (e.g. from Neo4j)."""
        return cls(
            ip=d["ip"],
            baseline_start=float(d.get("baseline_start", 0)),
            baseline_end=float(d.get("baseline_end", 0)),
            captured_at=float(d.get("captured_at", time.time())),
            interval_mean=d.get("interval_mean"),
            interval_std=float(d.get("interval_std", 0)),
            packet_rate_mean=float(d.get("packet_rate_mean", 0)),
            packet_rate_std=float(d.get("packet_rate_std", 0)),
            protocols=list(d.get("protocols") or []),
            peer_count=int(d.get("peer_count", 0)),
            periodic_edge_count=int(d.get("periodic_edge_count", 0)),
            total_edges=int(d.get("total_edges", 0)),
        )


# ---------------------------------------------------------------------------
# BaselineStore (in-memory)
# ---------------------------------------------------------------------------

class BaselineStore:
    """
    In-memory store of :class:`DeviceBaselineProfile` objects, keyed by IP.

    Acts as a fast lookup layer in front of Neo4j persistence.

    Usage::

        store = BaselineStore()
        store.put(profile)
        profile = store.get("10.0.1.1")
        all_profiles = store.all()
    """

    def __init__(self) -> None:
        """Initialise an empty store."""
        self._profiles: dict[str, DeviceBaselineProfile] = {}

    def put(self, profile: DeviceBaselineProfile) -> None:
        """
        Insert or replace the profile for a device.

        Args:
            profile: The profile to store.
        """
        self._profiles[profile.ip] = profile

    def get(self, ip: str) -> DeviceBaselineProfile | None:
        """
        Retrieve the profile for a device IP, or None.

        Args:
            ip: Device IP address.

        Returns:
            :class:`DeviceBaselineProfile` or None.
        """
        return self._profiles.get(ip)

    def all(self) -> list[DeviceBaselineProfile]:
        """Return all profiles in the store."""
        return list(self._profiles.values())

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, ip: str) -> bool:
        return ip in self._profiles
