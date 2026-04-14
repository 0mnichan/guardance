"""
MITRE ATT&CK for ICS — tactic and technique definitions.

ATT&CK for ICS (https://attack.mitre.org/matrices/ics/) covers adversary
behavior in industrial control systems.  This module defines the 12 tactics
and a representative set of techniques relevant to OT network monitoring.

Techniques are keyed by their ATT&CK ID (e.g. "T0801").  Each technique
maps to exactly one tactic.  The ``detection_signals`` list describes what
Guardance observables correlate with the technique.

Reference:
    MITRE ATT&CK for ICS v13 (https://attack.mitre.org/matrices/ics/)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Tactic definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Tactic:
    """A MITRE ATT&CK for ICS tactic."""

    tactic_id: str
    name: str
    description: str


TACTICS: list[Tactic] = [
    Tactic("TA0108", "Initial Access",
           "Gain initial foothold into ICS environment"),
    Tactic("TA0104", "Execution",
           "Execute adversary-controlled code on ICS devices"),
    Tactic("TA0110", "Persistence",
           "Maintain foothold after process restarts or device reboots"),
    Tactic("TA0111", "Privilege Escalation",
           "Gain higher-level permissions in the ICS environment"),
    Tactic("TA0103", "Evasion",
           "Avoid detection by security tools or operators"),
    Tactic("TA0102", "Discovery",
           "Enumerate ICS assets, topology, and operational state"),
    Tactic("TA0109", "Lateral Movement",
           "Move through the ICS network to reach target assets"),
    Tactic("TA0100", "Collection",
           "Gather operational data for use in attacks"),
    Tactic("TA0101", "Command and Control",
           "Communicate with compromised ICS assets"),
    Tactic("TA0107", "Inhibit Response Function",
           "Prevent safety systems or protective functions from operating"),
    Tactic("TA0106", "Impair Process Control",
           "Manipulate, disable, or damage physical processes"),
    Tactic("TA0105", "Impact",
           "Manipulate, interrupt, or destroy physical systems"),
]

TACTIC_BY_ID: dict[str, Tactic] = {t.tactic_id: t for t in TACTICS}
TACTIC_BY_NAME: dict[str, Tactic] = {t.name: t for t in TACTICS}


# ---------------------------------------------------------------------------
# Technique definitions
# ---------------------------------------------------------------------------

@dataclass
class Technique:
    """A MITRE ATT&CK for ICS technique."""

    technique_id: str
    name: str
    tactic_id: str
    description: str
    detection_signals: list[str] = field(default_factory=list)

    @property
    def tactic(self) -> Tactic | None:
        """Return the parent Tactic, or None if not found."""
        return TACTIC_BY_ID.get(self.tactic_id)


TECHNIQUES: list[Technique] = [
    # -----------------------------------------------------------------------
    # Discovery
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0840",
        name="Network Connection Enumeration",
        tactic_id="TA0102",
        description="Enumerate network connections and active sessions on ICS devices.",
        detection_signals=["cross_zone_violation", "new_edge", "port_scan"],
    ),
    Technique(
        technique_id="T0846",
        name="Remote System Discovery",
        tactic_id="TA0102",
        description="Discover remote systems and their roles in the ICS network.",
        detection_signals=["new_device", "new_edge", "broadcast_traffic"],
    ),
    Technique(
        technique_id="T0888",
        name="Remote System Information Discovery",
        tactic_id="TA0102",
        description="Collect information about remote systems via ICS protocols.",
        detection_signals=["new_edge", "unknown_protocol", "function_code_enumeration"],
    ),
    # -----------------------------------------------------------------------
    # Lateral Movement
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0812",
        name="Default Credentials",
        tactic_id="TA0109",
        description="Use default vendor credentials to authenticate to ICS devices.",
        detection_signals=["new_edge", "cross_zone_violation"],
    ),
    Technique(
        technique_id="T0866",
        name="Exploitation of Remote Services",
        tactic_id="TA0109",
        description="Exploit vulnerabilities in remote services on ICS devices.",
        detection_signals=["cross_zone_violation", "new_edge", "unusual_function_code"],
    ),
    # -----------------------------------------------------------------------
    # Collection
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0802",
        name="Automated Collection",
        tactic_id="TA0100",
        description="Automated collection of OT data using ICS protocol commands.",
        detection_signals=["interval_deviation", "new_edge", "high_packet_rate"],
    ),
    Technique(
        technique_id="T0811",
        name="Data from Information Repositories",
        tactic_id="TA0100",
        description="Collect data from historian, MES, or SCADA databases.",
        detection_signals=["new_edge", "sql_traffic", "historian_query"],
    ),
    # -----------------------------------------------------------------------
    # Inhibit Response Function
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0803",
        name="Block Command Message",
        tactic_id="TA0107",
        description="Block or drop ICS command messages to inhibit control.",
        detection_signals=["silence_detection", "missing_poll"],
    ),
    Technique(
        technique_id="T0835",
        name="Manipulate I/O Image",
        tactic_id="TA0107",
        description="Manipulate the I/O image in a PLC to prevent safety response.",
        detection_signals=["unusual_function_code", "write_coil", "interval_deviation"],
    ),
    # -----------------------------------------------------------------------
    # Impair Process Control
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0836",
        name="Modify Parameter",
        tactic_id="TA0106",
        description="Modify a device parameter to alter process behaviour.",
        detection_signals=["unusual_function_code", "write_register", "new_edge"],
    ),
    Technique(
        technique_id="T0855",
        name="Unauthorized Command Message",
        tactic_id="TA0106",
        description="Send unauthorized command messages to ICS devices.",
        detection_signals=["cross_zone_violation", "unusual_function_code", "new_edge"],
    ),
    Technique(
        technique_id="T0858",
        name="Change Credential",
        tactic_id="TA0106",
        description="Change credentials on ICS devices to maintain access.",
        detection_signals=["new_edge", "unusual_function_code"],
    ),
    # -----------------------------------------------------------------------
    # Impact
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0826",
        name="Loss of Availability",
        tactic_id="TA0105",
        description="Cause loss of availability of ICS devices or processes.",
        detection_signals=["silence_detection", "interval_deviation"],
    ),
    Technique(
        technique_id="T0828",
        name="Loss of Productivity and Revenue",
        tactic_id="TA0105",
        description="Cause disruptions that result in production downtime.",
        detection_signals=["silence_detection", "interval_deviation", "process_deviation"],
    ),
    Technique(
        technique_id="T0831",
        name="Manipulation of Control",
        tactic_id="TA0105",
        description="Cause controllers to respond in unexpected ways.",
        detection_signals=["unusual_function_code", "interval_deviation", "write_register"],
    ),
    # -----------------------------------------------------------------------
    # Evasion
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0820",
        name="Rootkit",
        tactic_id="TA0103",
        description="Use rootkits to hide presence on ICS devices.",
        detection_signals=["silence_detection", "unexpected_traffic_pattern"],
    ),
    Technique(
        technique_id="T0849",
        name="Masquerading",
        tactic_id="TA0103",
        description="Disguise malicious activity as legitimate ICS traffic.",
        detection_signals=["interval_deviation", "unknown_protocol"],
    ),
    # -----------------------------------------------------------------------
    # Command and Control
    # -----------------------------------------------------------------------
    Technique(
        technique_id="T0869",
        name="Standard Application Layer Protocol",
        tactic_id="TA0101",
        description="Use ICS protocol channels for C2 communications.",
        detection_signals=["cross_zone_violation", "unknown_protocol", "new_edge"],
    ),
]

TECHNIQUE_BY_ID: dict[str, Technique] = {t.technique_id: t for t in TECHNIQUES}
TECHNIQUE_BY_NAME: dict[str, Technique] = {t.name: t for t in TECHNIQUES}

# Signal → technique IDs mapping (precomputed for mapper)
SIGNAL_TO_TECHNIQUES: dict[str, list[str]] = {}
for _tech in TECHNIQUES:
    for _sig in _tech.detection_signals:
        SIGNAL_TO_TECHNIQUES.setdefault(_sig, []).append(_tech.technique_id)
