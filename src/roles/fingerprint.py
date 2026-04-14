"""
Protocol fingerprinting for OT device role inference.

Maps (protocol, port, function_code) observations to candidate device roles
using a rule-based approach.  Rules are ordered by specificity; the first
match wins.

Roles follow the ISA-99 / IEC 62443 taxonomy:
    plc          — Programmable Logic Controller
    rtu          — Remote Terminal Unit
    hmi          — Human-Machine Interface
    engineering  — Engineering Workstation
    historian    — Data historian / time-series server
    scada        — SCADA server / master station
    field_device — Sensor, actuator, transmitter
    gateway      — Protocol gateway / router
    unknown      — Could not determine role
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Role constants
# ---------------------------------------------------------------------------

ROLE_PLC = "plc"
ROLE_RTU = "rtu"
ROLE_HMI = "hmi"
ROLE_ENGINEERING = "engineering"
ROLE_HISTORIAN = "historian"
ROLE_SCADA = "scada"
ROLE_FIELD_DEVICE = "field_device"
ROLE_GATEWAY = "gateway"
ROLE_UNKNOWN = "unknown"

ALL_ROLES = [
    ROLE_PLC, ROLE_RTU, ROLE_HMI, ROLE_ENGINEERING,
    ROLE_HISTORIAN, ROLE_SCADA, ROLE_FIELD_DEVICE, ROLE_GATEWAY, ROLE_UNKNOWN,
]


# ---------------------------------------------------------------------------
# Fingerprint rule definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FingerprintRule:
    """A single fingerprinting rule mapping observations to a role."""

    role: str
    protocol: str | None = None    # None = match any protocol
    port: int | None = None        # None = match any port
    function_code: str | None = None  # None = match any function code
    is_server: bool | None = None  # None = don't filter on direction
    confidence: float = 0.7


# Rules ordered from most-specific to least-specific.
FINGERPRINT_RULES: list[FingerprintRule] = [
    # S7 CPU — always a PLC
    FingerprintRule(role=ROLE_PLC, protocol="s7comm", port=102, confidence=0.95),

    # Modbus server (responds on 502) — typically PLC or RTU
    FingerprintRule(role=ROLE_PLC, protocol="modbus", port=502,
                    function_code="READ_HOLDING_REGISTERS", confidence=0.85),
    FingerprintRule(role=ROLE_PLC, protocol="modbus", port=502,
                    function_code="WRITE_SINGLE_REGISTER", confidence=0.85),
    FingerprintRule(role=ROLE_PLC, protocol="modbus", port=502, confidence=0.75),

    # DNP3 outstation — RTU in distribution, PLC in process
    FingerprintRule(role=ROLE_RTU, protocol="dnp3", port=20000, confidence=0.85),
    FingerprintRule(role=ROLE_RTU, protocol="dnp3", confidence=0.75),

    # IEC 104 outstation
    FingerprintRule(role=ROLE_RTU, protocol="iec104", port=2404, confidence=0.85),

    # EtherNet/IP — PLC (Allen-Bradley)
    FingerprintRule(role=ROLE_PLC, protocol="enip", port=44818, confidence=0.85),
    FingerprintRule(role=ROLE_PLC, protocol="ethernet/ip", confidence=0.80),

    # BACnet — field device or controller
    FingerprintRule(role=ROLE_FIELD_DEVICE, protocol="bacnet", port=47808, confidence=0.75),

    # OPC-UA server — SCADA or historian
    FingerprintRule(role=ROLE_SCADA, protocol="opc-ua", port=4840, confidence=0.80),
    FingerprintRule(role=ROLE_HISTORIAN, protocol="historian", confidence=0.90),

    # SQL traffic — historian or engineering WS
    FingerprintRule(role=ROLE_HISTORIAN, protocol="mssql", port=1433, confidence=0.75),
    FingerprintRule(role=ROLE_HISTORIAN, protocol="sql", port=1433, confidence=0.70),

    # RDP — engineering workstation (remote access pattern)
    FingerprintRule(role=ROLE_ENGINEERING, protocol="rdp", port=3389, confidence=0.75),

    # HTTP/HTTPS — HMI web panel or engineering WS
    FingerprintRule(role=ROLE_HMI, protocol="http", port=80, confidence=0.60),
    FingerprintRule(role=ROLE_HMI, protocol="https", port=443, confidence=0.60),
]


# ---------------------------------------------------------------------------
# ProtocolFingerprinter
# ---------------------------------------------------------------------------

@dataclass
class FingerprintResult:
    """Result of a fingerprinting attempt."""

    role: str
    confidence: float
    matched_rule: FingerprintRule | None = None


class ProtocolFingerprinter:
    """
    Infers a device's role from its observed protocol/port/function_code set.

    Applies FINGERPRINT_RULES in order; the first matching rule determines
    the role.  If no rule matches, returns ROLE_UNKNOWN with confidence 0.0.

    Usage::

        fingerprinter = ProtocolFingerprinter()
        obs = [("modbus", 502, "READ_HOLDING_REGISTERS")]
        result = fingerprinter.infer(obs)
        print(result.role, result.confidence)   # plc  0.85
    """

    def __init__(self, rules: list[FingerprintRule] | None = None) -> None:
        """
        Initialise with an optional custom rule list.

        Args:
            rules: Custom fingerprint rules.  Defaults to
                   :data:`FINGERPRINT_RULES`.
        """
        self._rules = rules if rules is not None else FINGERPRINT_RULES

    def infer(
        self,
        observations: list[tuple[str, int, str | None]],
    ) -> FingerprintResult:
        """
        Infer a device role from a list of (protocol, port, function_code) tuples.

        The highest-confidence matching rule across all observations wins.

        Args:
            observations: List of ``(protocol, port, function_code)`` tuples.
                          ``function_code`` may be None.

        Returns:
            :class:`FingerprintResult` with the inferred role and confidence.
        """
        best: FingerprintResult = FingerprintResult(
            role=ROLE_UNKNOWN, confidence=0.0
        )

        for rule in self._rules:
            for proto_raw, port, func in observations:
                proto = proto_raw.lower()

                # Filter on protocol
                if rule.protocol is not None and proto != rule.protocol.lower():
                    continue
                # Filter on port
                if rule.port is not None and port != rule.port:
                    continue
                # Filter on function code
                if rule.function_code is not None:
                    if func is None or func.upper() != rule.function_code.upper():
                        continue

                # Rule matched
                if rule.confidence > best.confidence:
                    best = FingerprintResult(
                        role=rule.role,
                        confidence=rule.confidence,
                        matched_rule=rule,
                    )

        logger.debug(
            "Fingerprint result: role=%s confidence=%.2f (from %d observations)",
            best.role, best.confidence, len(observations),
        )
        return best

    def infer_from_records(self, records: list[dict]) -> FingerprintResult:
        """
        Infer role from a list of dicts with 'protocol', 'port', 'function_code' keys.

        Convenience wrapper around :meth:`infer`.

        Args:
            records: List of dicts, each with at least ``protocol`` and ``port``.
                     ``function_code`` is optional.

        Returns:
            :class:`FingerprintResult`.
        """
        observations = [
            (
                r.get("protocol", "tcp"),
                int(r.get("port") or 0),
                r.get("function_code"),
            )
            for r in records
        ]
        return self.infer(observations)
