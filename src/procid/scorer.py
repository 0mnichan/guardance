"""
Process deviation scoring for Guardance ProcID.

Given a set of :class:`~src.procid.matcher.MatchResult` objects and their
expected signatures, compute a deviation score for each device indicating
how far its current behavior has drifted from the expected process.

Deviation score: 1.0 - match_score
    0.0 → perfect match (no deviation)
    0.4 → partial match (40% deviation from expected process)
    1.0 → no match at all (complete deviation or unknown process)

Results with deviation > 0.3 are flagged as findings and can be enriched
with ATT&CK technique references via the mapper.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.procid.matcher import MatchResult, ProcessMatcher
from src.procid.signatures import SIGNATURES, SIGNATURE_BY_NAME

logger = logging.getLogger(__name__)

# Deviation above this threshold is reported as a finding
_DEVIATION_THRESHOLD = 0.3


# ---------------------------------------------------------------------------
# DeviationResult
# ---------------------------------------------------------------------------

@dataclass
class DeviationResult:
    """
    Deviation assessment for one device against one signature.

    Attributes:
        ip:             Device IP address.
        signature_name: Expected process signature name.
        expected_steps: Number of steps in the expected signature.
        matched_steps:  Number of steps that matched.
        score:          Match score (0.0–1.0).
        deviation:      1.0 - score (0.0 = no deviation, 1.0 = total deviation).
        flagged:        True if deviation > threshold (0.3).
        detail:         Human-readable summary.
    """

    ip: str
    signature_name: str
    expected_steps: int
    matched_steps: int
    score: float
    deviation: float
    flagged: bool
    detail: str

    def to_dict(self) -> dict:
        """Serialise to a plain dict for API or findings output."""
        return {
            "ip":             self.ip,
            "signature_name": self.signature_name,
            "expected_steps": self.expected_steps,
            "matched_steps":  self.matched_steps,
            "score":          self.score,
            "deviation":      self.deviation,
            "flagged":        self.flagged,
            "detail":         self.detail,
        }


# ---------------------------------------------------------------------------
# ProcessDeviationScorer
# ---------------------------------------------------------------------------

class ProcessDeviationScorer:
    """
    Scores process deviations by comparing match results against their
    expected signatures.

    Usage::

        scorer = ProcessDeviationScorer()
        results = scorer.score_device_matches(ip, match_results)
        findings = scorer.run_all(session, matcher)
    """

    def __init__(self, deviation_threshold: float = _DEVIATION_THRESHOLD) -> None:
        """
        Initialise the scorer.

        Args:
            deviation_threshold: Deviation above this value is flagged.
                                 Default 0.3 (30% of steps missing/wrong).
        """
        self._threshold = deviation_threshold

    def score_match(self, match: MatchResult) -> DeviationResult:
        """
        Compute a deviation result from a single match result.

        Args:
            match: A :class:`MatchResult` from the ProcessMatcher.

        Returns:
            :class:`DeviationResult`.
        """
        sig = SIGNATURE_BY_NAME.get(match.signature_name)
        expected_steps = sig.step_count if sig else 0
        matched_steps = round(match.score * expected_steps) if expected_steps else 0
        deviation = 1.0 - match.score
        flagged = deviation > self._threshold

        if match.full_match:
            detail = f"Full match: all {expected_steps} steps matched."
        elif flagged:
            detail = (
                f"Partial match: {matched_steps}/{expected_steps} steps matched "
                f"(deviation={deviation:.0%})."
            )
        else:
            detail = (
                f"Acceptable match: {matched_steps}/{expected_steps} steps "
                f"(deviation={deviation:.0%})."
            )

        return DeviationResult(
            ip=match.ip,
            signature_name=match.signature_name,
            expected_steps=expected_steps,
            matched_steps=matched_steps,
            score=match.score,
            deviation=deviation,
            flagged=flagged,
            detail=detail,
        )

    def score_device_matches(
        self,
        ip: str,
        matches: list[MatchResult],
    ) -> list[DeviationResult]:
        """
        Score all match results for a single device.

        Args:
            ip:      Device IP address (informational).
            matches: List of MatchResult for this device.

        Returns:
            List of :class:`DeviationResult`, flagged ones first.
        """
        results = [self.score_match(m) for m in matches]
        results.sort(key=lambda r: r.deviation, reverse=True)
        return results

    def run_all(
        self,
        session: Any,
        matcher: ProcessMatcher | None = None,
    ) -> list[dict]:
        """
        Run ProcID matching and deviation scoring across all devices.

        Args:
            session: An active Neo4j session.
            matcher: A :class:`ProcessMatcher` to use.  Created with default
                     signatures if None.

        Returns:
            List of deviation finding dicts (only flagged results), each
            with keys from :meth:`DeviationResult.to_dict`.
        """
        if matcher is None:
            matcher = ProcessMatcher(None)  # session-based, no driver needed

        all_matches = matcher.match_all_devices(session, partial=True)
        findings: list[dict] = []

        for ip, matches in all_matches.items():
            device_results = self.score_device_matches(ip, matches)
            for result in device_results:
                if result.flagged:
                    findings.append(result.to_dict())

        logger.info(
            "ProcID scoring: %d devices with matches, %d flagged deviations",
            len(all_matches), len(findings),
        )
        return findings
