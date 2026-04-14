"""
Process signature definitions for Guardance ProcID.

A process signature describes the expected sequence of protocol operations
that constitute a known-good OT process.  In OT networks, entire processes
are enumerable: a PLC performing a Modbus poll cycle does it identically
every 250ms for years.  Any deviation is immediately significant.

Each signature consists of:
    name        — Human-readable process name
    description — What the process does operationally
    steps       — Ordered list of expected communication steps, each with:
                  source_role    — Role of the originating device
                  dest_role      — Role of the destination device
                  protocol       — Expected protocol
                  function_codes — Set of acceptable function codes
                  max_interval_ms — Maximum expected gap between steps

Matching strategy:
    The matcher queries COMMUNICATES_WITH chains in Neo4j and checks
    whether the observed sequence of (protocol, function_code) pairs
    on a path matches any registered signature.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Step and Signature dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessStep:
    """One step in a process signature."""

    protocol: str
    function_codes: frozenset[str]
    source_role: str | None = None    # None = any role
    dest_role: str | None = None      # None = any role
    max_interval_ms: float = 5000.0   # 5 seconds default tolerance

    @classmethod
    def of(
        cls,
        protocol: str,
        function_codes: list[str],
        source_role: str | None = None,
        dest_role: str | None = None,
        max_interval_ms: float = 5000.0,
    ) -> "ProcessStep":
        """Convenience constructor accepting a plain list of function codes."""
        return cls(
            protocol=protocol,
            function_codes=frozenset(fc.upper() for fc in function_codes),
            source_role=source_role,
            dest_role=dest_role,
            max_interval_ms=max_interval_ms,
        )

    def matches(self, protocol: str, function_code: str) -> bool:
        """
        Return True if an observed (protocol, function_code) pair satisfies
        this step.

        Args:
            protocol:      Observed protocol string.
            function_code: Observed function code string.

        Returns:
            True if both match this step's constraints.
        """
        if protocol.lower() != self.protocol.lower():
            return False
        fc_upper = (function_code or "").upper()
        # Empty function_codes set means accept any
        if not self.function_codes:
            return True
        return fc_upper in self.function_codes


@dataclass
class ProcessSignature:
    """
    A named sequence of expected process steps.

    Attributes:
        name:        Unique process name.
        description: Human-readable description of the process.
        steps:       Ordered list of :class:`ProcessStep` objects.
        tags:        Optional list of classification tags.
    """

    name: str
    description: str
    steps: list[ProcessStep]
    tags: list[str] = field(default_factory=list)

    @property
    def step_count(self) -> int:
        """Number of steps in this signature."""
        return len(self.steps)

    def matches_sequence(
        self, observed: list[tuple[str, str]]
    ) -> tuple[bool, float]:
        """
        Check whether an observed sequence of (protocol, function_code) pairs
        matches this signature.

        Uses a greedy left-to-right matching strategy.

        Args:
            observed: List of (protocol, function_code) tuples in order.

        Returns:
            Tuple of (matched: bool, score: float).
            score = matched_steps / total_steps (0.0–1.0).
        """
        if not self.steps or not observed:
            return False, 0.0

        matched = 0
        obs_idx = 0

        for step in self.steps:
            # Scan forward in observations for this step
            while obs_idx < len(observed):
                proto, fc = observed[obs_idx]
                obs_idx += 1
                if step.matches(proto, fc):
                    matched += 1
                    break

        score = matched / len(self.steps)
        full_match = matched == len(self.steps)
        return full_match, score


# ---------------------------------------------------------------------------
# Predefined signatures
# ---------------------------------------------------------------------------

SIGNATURES: list[ProcessSignature] = [
    # 1. Modbus Poll Cycle
    #    HMI/SCADA → PLC: read coils, read holding registers
    ProcessSignature(
        name="ModbusPollCycle",
        description=(
            "Standard Modbus polling: master reads discrete inputs/coils "
            "then holding registers from a PLC outstation."
        ),
        steps=[
            ProcessStep.of(
                protocol="modbus",
                function_codes=["READ_COILS", "READ_DISCRETE_INPUTS"],
                source_role="hmi",
                dest_role="plc",
                max_interval_ms=2000,
            ),
            ProcessStep.of(
                protocol="modbus",
                function_codes=["READ_HOLDING_REGISTERS", "READ_INPUT_REGISTERS"],
                source_role="hmi",
                dest_role="plc",
                max_interval_ms=2000,
            ),
        ],
        tags=["modbus", "poll", "plc"],
    ),

    # 2. DNP3 Integrity Poll
    #    SCADA master polls outstation for Class 0 (static) + Class 1/2/3
    ProcessSignature(
        name="DNP3IntegrityPoll",
        description=(
            "DNP3 integrity poll sequence: master requests Class 0 static "
            "data followed by Class 1/2/3 event data from RTU outstation."
        ),
        steps=[
            ProcessStep.of(
                protocol="dnp3",
                function_codes=["READ"],
                source_role="scada",
                dest_role="rtu",
                max_interval_ms=5000,
            ),
            ProcessStep.of(
                protocol="dnp3",
                function_codes=["RESPONSE"],
                source_role="rtu",
                dest_role="scada",
                max_interval_ms=5000,
            ),
        ],
        tags=["dnp3", "poll", "rtu"],
    ),

    # 3. S7 Program Read
    #    Engineering WS reads CPU state then downloads data block
    ProcessSignature(
        name="S7ProgramRead",
        description=(
            "S7comm program read: engineering workstation reads CPU state "
            "and then fetches a data block from the PLC."
        ),
        steps=[
            ProcessStep.of(
                protocol="s7comm",
                function_codes=["CPU_SERVICES", "SETUP_COMMUNICATION"],
                source_role="engineering",
                dest_role="plc",
                max_interval_ms=10000,
            ),
            ProcessStep.of(
                protocol="s7comm",
                function_codes=["READ_VAR", "REQUEST_DOWNLOAD"],
                source_role="engineering",
                dest_role="plc",
                max_interval_ms=10000,
            ),
        ],
        tags=["s7comm", "engineering", "plc"],
    ),

    # 4. EtherNet/IP Tag Read
    #    HMI opens a CIP connection then reads tag data
    ProcessSignature(
        name="EIPTagRead",
        description=(
            "EtherNet/IP tag read: HMI establishes a CIP connection via "
            "Forward Open then reads tag values from PLC."
        ),
        steps=[
            ProcessStep.of(
                protocol="enip",
                function_codes=["FORWARD_OPEN", "REGISTER_SESSION"],
                source_role="hmi",
                dest_role="plc",
                max_interval_ms=3000,
            ),
            ProcessStep.of(
                protocol="enip",
                function_codes=["GET_ATTRIBUTE_ALL", "GET_ATTRIBUTE_SINGLE", "READ_TAG"],
                source_role="hmi",
                dest_role="plc",
                max_interval_ms=3000,
            ),
        ],
        tags=["enip", "cip", "plc"],
    ),
]

SIGNATURE_BY_NAME: dict[str, ProcessSignature] = {s.name: s for s in SIGNATURES}
