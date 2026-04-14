"""
Tests for src/roles/ — fingerprinting, graph profiling, SVM classifier.

No live Neo4j required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.roles.classifier import RoleClassifier, write_role_to_graph
from src.roles.fingerprint import (
    FINGERPRINT_RULES,
    ROLE_ENGINEERING,
    ROLE_HMI,
    ROLE_PLC,
    ROLE_RTU,
    ROLE_SCADA,
    ROLE_UNKNOWN,
    FingerprintResult,
    ProtocolFingerprinter,
)
from src.roles.profiler import DeviceProfile, GraphProfiler


# ---------------------------------------------------------------------------
# ProtocolFingerprinter
# ---------------------------------------------------------------------------

class TestProtocolFingerprinter:
    def _fp(self):
        return ProtocolFingerprinter()

    def test_modbus_502_is_plc(self):
        fp = self._fp()
        result = fp.infer([("modbus", 502, "READ_HOLDING_REGISTERS")])
        assert result.role == ROLE_PLC
        assert result.confidence >= 0.8

    def test_s7comm_102_is_plc(self):
        fp = self._fp()
        result = fp.infer([("s7comm", 102, None)])
        assert result.role == ROLE_PLC
        assert result.confidence >= 0.9

    def test_dnp3_is_rtu(self):
        fp = self._fp()
        result = fp.infer([("dnp3", 20000, None)])
        assert result.role == ROLE_RTU

    def test_opc_ua_is_scada(self):
        fp = self._fp()
        result = fp.infer([("opc-ua", 4840, None)])
        assert result.role == ROLE_SCADA

    def test_rdp_is_engineering(self):
        fp = self._fp()
        result = fp.infer([("rdp", 3389, None)])
        assert result.role == ROLE_ENGINEERING

    def test_no_observations_returns_unknown(self):
        fp = self._fp()
        result = fp.infer([])
        assert result.role == ROLE_UNKNOWN
        assert result.confidence == 0.0

    def test_highest_confidence_wins(self):
        fp = self._fp()
        # s7comm (0.95) + http (0.60) → s7comm wins
        result = fp.infer([("s7comm", 102, None), ("http", 80, None)])
        assert result.role == ROLE_PLC
        assert result.confidence == 0.95

    def test_infer_from_records(self):
        fp = self._fp()
        records = [
            {"protocol": "modbus", "port": 502, "function_code": "READ_HOLDING_REGISTERS"},
        ]
        result = fp.infer_from_records(records)
        assert result.role == ROLE_PLC

    def test_case_insensitive_protocol(self):
        fp = self._fp()
        result = fp.infer([("MODBUS", 502, None)])
        assert result.role == ROLE_PLC

    def test_unknown_protocol_returns_unknown(self):
        fp = self._fp()
        result = fp.infer([("propietaryX", 9999, None)])
        assert result.role == ROLE_UNKNOWN


# ---------------------------------------------------------------------------
# DeviceProfile
# ---------------------------------------------------------------------------

class TestDeviceProfile:
    def _profile(self, **kwargs) -> DeviceProfile:
        defaults = dict(
            ip="10.0.1.1",
            protocols={"modbus"},
            ports={502},
            function_codes={"READ_HOLDING_REGISTERS"},
            connections_out=2,
            connections_in=0,
            total_packets_sent=1000,
            total_packets_recv=0,
            avg_interval_ms=250.0,
            is_periodic=True,
        )
        defaults.update(kwargs)
        return DeviceProfile(**defaults)

    def test_feature_vector_has_11_dimensions(self):
        p = self._profile()
        fv = p.to_feature_vector()
        assert len(fv) == 11

    def test_modbus_flag_is_1(self):
        p = self._profile(protocols={"modbus"})
        fv = p.to_feature_vector()
        assert fv[6] == 1.0   # uses_modbus

    def test_dnp3_flag(self):
        p = self._profile(protocols={"dnp3"})
        fv = p.to_feature_vector()
        assert fv[7] == 1.0

    def test_fan_out_ratio(self):
        p = self._profile(connections_out=3, connections_in=1)
        fv = p.to_feature_vector()
        assert abs(fv[10] - 0.75) < 1e-6

    def test_is_periodic_flag(self):
        p = self._profile(is_periodic=True)
        fv = p.to_feature_vector()
        assert fv[5] == 1.0


# ---------------------------------------------------------------------------
# GraphProfiler
# ---------------------------------------------------------------------------

class TestGraphProfiler:
    def _mock_session_profile(self):
        """Session whose .run() returns a record matching _PROFILE_QUERY."""
        session = MagicMock()
        result = MagicMock()
        rec = MagicMock()
        rec.__getitem__ = lambda s, k: {
            "ip":          "10.0.1.1",
            "role":        None,
            "zone":        "Control",
            "purdue_level": 1,
            "out_edges": [
                {
                    "protocol": "modbus", "port": 502,
                    "function_code": "READ_HOLDING_REGISTERS",
                    "packet_count": 500, "avg_interval": 250.0,
                    "is_periodic": True,
                }
            ],
            "in_edges": [],
        }[k]
        result.single = MagicMock(return_value=rec)
        result.__iter__ = MagicMock(return_value=iter([]))
        session.run = MagicMock(return_value=result)
        return session

    def test_build_profile_returns_device_profile(self):
        session = self._mock_session_profile()
        profiler = GraphProfiler(driver=MagicMock())
        profile = profiler.build_profile(session, "10.0.1.1")
        assert profile is not None
        assert profile.ip == "10.0.1.1"
        assert "modbus" in profile.protocols

    def test_build_profile_none_when_no_record(self):
        session = MagicMock()
        result = MagicMock()
        result.single = MagicMock(return_value=None)
        session.run = MagicMock(return_value=result)
        profiler = GraphProfiler(driver=MagicMock())
        assert profiler.build_profile(session, "10.0.1.1") is None


# ---------------------------------------------------------------------------
# RoleClassifier
# ---------------------------------------------------------------------------

class TestRoleClassifier:
    def _plc_profile(self):
        return DeviceProfile(
            ip="10.0.1.1",
            protocols={"modbus"},
            ports={502},
            connections_out=1,
            connections_in=0,
            total_packets_sent=500,
        )

    def test_predict_falls_back_to_fingerprint_when_untrained(self):
        clf = RoleClassifier()
        profile = self._plc_profile()
        role, confidence = clf.predict(profile)
        # Fingerprint should identify modbus as PLC
        assert role == ROLE_PLC
        assert confidence > 0.0

    def test_fit_trains_with_enough_data(self):
        clf = RoleClassifier()
        profiles_labels = [
            (DeviceProfile(ip=f"10.0.1.{i}", protocols={"modbus"}, ports={502}), "plc")
            for i in range(3)
        ] + [
            (DeviceProfile(ip=f"10.0.2.{i}", protocols={"rdp"}, ports={3389}), "engineering")
            for i in range(3)
        ]
        clf.fit(profiles_labels)
        # After fit with sklearn, is_trained should be True
        assert clf._is_trained

    def test_fit_skips_with_only_one_example(self):
        clf = RoleClassifier()
        clf.fit([(DeviceProfile(ip="10.0.1.1", protocols={"modbus"}, ports={502}), "plc")])
        assert not clf._is_trained

    def test_predict_after_train(self):
        clf = RoleClassifier()
        profiles_labels = [
            (DeviceProfile(ip=f"10.0.1.{i}", protocols={"modbus"}, ports={502},
                           connections_out=2, is_periodic=True), "plc")
            for i in range(5)
        ] + [
            (DeviceProfile(ip=f"10.0.2.{i}", protocols={"rdp"}, ports={3389},
                           connections_in=1), "engineering")
            for i in range(5)
        ]
        clf.fit(profiles_labels)
        role, conf = clf.predict(
            DeviceProfile(ip="10.0.1.99", protocols={"modbus"}, ports={502},
                          connections_out=2, is_periodic=True)
        )
        assert role in ("plc", "engineering")
        assert 0.0 < conf <= 0.99


# ---------------------------------------------------------------------------
# write_role_to_graph
# ---------------------------------------------------------------------------

class TestWriteRoleToGraph:
    def test_calls_session_run(self):
        session = MagicMock()
        session.run = MagicMock()
        write_role_to_graph(session, "10.0.1.1", "plc", 0.9, 1)
        session.run.assert_called_once()

    def test_does_not_raise_on_neo4j_error(self):
        session = MagicMock()
        session.run = MagicMock(side_effect=Exception("neo4j down"))
        # Should not raise
        write_role_to_graph(session, "10.0.1.1", "plc", 0.9, 1)
