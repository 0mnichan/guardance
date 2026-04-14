"""
Tests for src/procid/ — process signatures, matcher, scorer.

No live Neo4j required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.procid.matcher import MatchResult, ProcessMatcher
from src.procid.scorer import DeviationResult, ProcessDeviationScorer
from src.procid.signatures import (
    SIGNATURE_BY_NAME,
    SIGNATURES,
    ProcessSignature,
    ProcessStep,
)


# ---------------------------------------------------------------------------
# ProcessStep
# ---------------------------------------------------------------------------

class TestProcessStep:
    def test_matches_protocol_and_function_code(self):
        step = ProcessStep.of("modbus", ["READ_HOLDING_REGISTERS"])
        assert step.matches("modbus", "READ_HOLDING_REGISTERS")

    def test_case_insensitive_function_code(self):
        step = ProcessStep.of("modbus", ["read_holding_registers"])
        assert step.matches("modbus", "READ_HOLDING_REGISTERS")

    def test_wrong_protocol_fails(self):
        step = ProcessStep.of("modbus", ["READ_HOLDING_REGISTERS"])
        assert not step.matches("dnp3", "READ_HOLDING_REGISTERS")

    def test_wrong_function_code_fails(self):
        step = ProcessStep.of("modbus", ["READ_HOLDING_REGISTERS"])
        assert not step.matches("modbus", "WRITE_SINGLE_REGISTER")

    def test_empty_function_codes_accepts_any(self):
        step = ProcessStep.of("modbus", [])
        assert step.matches("modbus", "ANY_CODE")

    def test_none_function_code_with_empty_rule(self):
        step = ProcessStep.of("modbus", [])
        assert step.matches("modbus", "")


# ---------------------------------------------------------------------------
# ProcessSignature.matches_sequence
# ---------------------------------------------------------------------------

class TestProcessSignatureMatchesSequence:
    def test_full_match(self):
        sig = SIGNATURE_BY_NAME["ModbusPollCycle"]
        observed = [
            ("modbus", "READ_COILS"),
            ("modbus", "READ_HOLDING_REGISTERS"),
        ]
        full, score = sig.matches_sequence(observed)
        assert full
        assert score == pytest.approx(1.0)

    def test_partial_match_one_of_two(self):
        sig = SIGNATURE_BY_NAME["ModbusPollCycle"]
        observed = [("modbus", "READ_COILS")]
        full, score = sig.matches_sequence(observed)
        assert not full
        assert score == pytest.approx(0.5)

    def test_no_match(self):
        sig = SIGNATURE_BY_NAME["ModbusPollCycle"]
        observed = [("dnp3", "READ"), ("dnp3", "RESPONSE")]
        full, score = sig.matches_sequence(observed)
        assert not full
        assert score == pytest.approx(0.0)

    def test_empty_sequence_returns_no_match(self):
        sig = SIGNATURE_BY_NAME["ModbusPollCycle"]
        full, score = sig.matches_sequence([])
        assert not full
        assert score == pytest.approx(0.0)

    def test_dnp3_integrity_poll_full_match(self):
        sig = SIGNATURE_BY_NAME["DNP3IntegrityPoll"]
        observed = [("dnp3", "READ"), ("dnp3", "RESPONSE")]
        full, score = sig.matches_sequence(observed)
        assert full

    def test_extra_steps_still_matches(self):
        sig = SIGNATURE_BY_NAME["ModbusPollCycle"]
        # Extra steps before/after should still allow a full match
        observed = [
            ("tcp", "flow"),
            ("modbus", "READ_COILS"),
            ("tcp", "flow"),
            ("modbus", "READ_HOLDING_REGISTERS"),
            ("tcp", "flow"),
        ]
        full, score = sig.matches_sequence(observed)
        assert full


# ---------------------------------------------------------------------------
# Signature catalogue
# ---------------------------------------------------------------------------

class TestSignatureCatalogue:
    def test_four_signatures_defined(self):
        assert len(SIGNATURES) == 4

    def test_modbus_poll_cycle_exists(self):
        assert "ModbusPollCycle" in SIGNATURE_BY_NAME

    def test_dnp3_integrity_poll_exists(self):
        assert "DNP3IntegrityPoll" in SIGNATURE_BY_NAME

    def test_s7_program_read_exists(self):
        assert "S7ProgramRead" in SIGNATURE_BY_NAME

    def test_eip_tag_read_exists(self):
        assert "EIPTagRead" in SIGNATURE_BY_NAME

    def test_all_signatures_have_steps(self):
        for sig in SIGNATURES:
            assert sig.step_count >= 2


# ---------------------------------------------------------------------------
# ProcessMatcher
# ---------------------------------------------------------------------------

class TestProcessMatcher:
    def _session_with_sequence(self, rows):
        """Build a session whose .run() yields the given list of dicts."""
        session = MagicMock()
        recs = []
        for row in rows:
            rec = MagicMock()
            rec.__getitem__ = lambda s, k, _r=row: _r[k]
            recs.append(rec)
        result = MagicMock()
        result.__iter__ = MagicMock(return_value=iter(recs))
        session.run = MagicMock(return_value=result)
        return session

    def test_match_device_full_match(self):
        session = self._session_with_sequence([
            {"protocol": "modbus", "function_code": "READ_COILS"},
            {"protocol": "modbus", "function_code": "READ_HOLDING_REGISTERS"},
        ])
        matcher = ProcessMatcher(driver=MagicMock())
        results = matcher.match_device(session, "10.0.1.1")
        full_matches = [r for r in results if r.full_match]
        assert len(full_matches) >= 1
        assert full_matches[0].signature_name == "ModbusPollCycle"

    def test_match_device_partial_match_included(self):
        session = self._session_with_sequence([
            {"protocol": "modbus", "function_code": "READ_COILS"},
            # Missing second step
        ])
        matcher = ProcessMatcher(driver=MagicMock())
        results = matcher.match_device(session, "10.0.1.1", partial=True)
        # 50% match is below 0.6 threshold → no result
        assert all(r.score >= 0.6 for r in results)

    def test_match_device_empty_sequence_returns_empty(self):
        session = self._session_with_sequence([])
        matcher = ProcessMatcher(driver=MagicMock())
        results = matcher.match_device(session, "10.0.1.1")
        assert results == []

    def test_match_all_devices(self):
        # Session: first call returns IPs, subsequent calls return sequences
        session = MagicMock()
        ip_rec = MagicMock()
        ip_rec.__getitem__ = lambda s, k: {"ip": "10.0.1.1"}[k]

        ip_result = MagicMock()
        ip_result.__iter__ = MagicMock(return_value=iter([ip_rec]))

        seq_result = MagicMock()
        seq_recs = []
        for fc in ["READ_COILS", "READ_HOLDING_REGISTERS"]:
            r = MagicMock()
            r.__getitem__ = lambda s, k, _fc=fc: {"protocol": "modbus", "function_code": _fc}[k]
            seq_recs.append(r)
        seq_result.__iter__ = MagicMock(return_value=iter(seq_recs))

        session.run = MagicMock(side_effect=[ip_result, seq_result])
        matcher = ProcessMatcher(driver=MagicMock())
        results = matcher.match_all_devices(session)
        assert "10.0.1.1" in results


# ---------------------------------------------------------------------------
# ProcessDeviationScorer
# ---------------------------------------------------------------------------

class TestProcessDeviationScorer:
    def _match(self, full=True, score=1.0, sig_name="ModbusPollCycle"):
        return MatchResult(
            ip="10.0.1.1",
            signature_name=sig_name,
            full_match=full,
            score=score,
            observed=[],
        )

    def test_full_match_deviation_is_zero(self):
        scorer = ProcessDeviationScorer()
        result = scorer.score_match(self._match(full=True, score=1.0))
        assert result.deviation == pytest.approx(0.0)
        assert not result.flagged

    def test_partial_match_flagged(self):
        scorer = ProcessDeviationScorer(deviation_threshold=0.3)
        result = scorer.score_match(self._match(full=False, score=0.5))
        assert result.deviation == pytest.approx(0.5)
        assert result.flagged

    def test_score_device_matches_sorts_by_deviation(self):
        scorer = ProcessDeviationScorer()
        matches = [
            self._match(full=True, score=1.0),
            self._match(full=False, score=0.5),
        ]
        results = scorer.score_device_matches("10.0.1.1", matches)
        # Highest deviation first
        assert results[0].deviation >= results[-1].deviation

    def test_deviation_result_to_dict(self):
        scorer = ProcessDeviationScorer()
        result = scorer.score_match(self._match(full=True, score=1.0))
        d = result.to_dict()
        for key in ("ip", "signature_name", "expected_steps", "matched_steps",
                    "score", "deviation", "flagged", "detail"):
            assert key in d

    def test_full_match_detail_mentions_all_steps(self):
        scorer = ProcessDeviationScorer()
        result = scorer.score_match(self._match(full=True, score=1.0))
        assert "Full match" in result.detail
