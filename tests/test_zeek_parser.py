"""
Tests for src/ingest/zeek_parser.py

Uses real Zeek ICSNPP log files from data/pcaps/ICS-pcap-master/.
All file paths are resolved relative to the project root so the tests can
be run from any working directory.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ingest.zeek_parser import (
    ConnEvent,
    Dnp3Event,
    ModbusEvent,
    parse_log_directory,
    parse_zeek_log,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_ROOT = PROJECT_ROOT / "data" / "pcaps" / "ICS-pcap-master"

# Specific real log files used by the tests
MODBUS_LOG = PCAP_ROOT / "MODBUS" / "MODBUS-TestDataPart1" / "modbus.log"
DNP3_LOG = PCAP_ROOT / "Additional Captures" / "4SICS-GeekLounge-151022" / "dnp3.log"
CONN_LOG = PCAP_ROOT / "ETHERCAT" / "ethercat" / "conn.log"

# A directory that has all three log types
MULTI_LOG_DIR = PCAP_ROOT / "Additional Captures" / "4SICS-GeekLounge-151022"


def _write_temp_log(tmp_path: Path, content: str, name: str = "modbus.log") -> Path:
    """Write *content* to a temp file and return its Path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Fixtures / skip guards
# ---------------------------------------------------------------------------

def _require_file(path: Path) -> None:
    """Skip the test if *path* does not exist (data not present in env)."""
    if not path.exists():
        pytest.skip(f"Test data not found: {path}")


# ---------------------------------------------------------------------------
# Tests — modbus.log (real data)
# ---------------------------------------------------------------------------

class TestModbusRealData:
    def test_yields_modbus_events(self):
        _require_file(MODBUS_LOG)
        events = list(parse_zeek_log(MODBUS_LOG))
        assert len(events) > 0, "Expected at least one ModbusEvent"

    def test_all_events_are_modbus_type(self):
        _require_file(MODBUS_LOG)
        for ev in parse_zeek_log(MODBUS_LOG):
            assert isinstance(ev, ModbusEvent), f"Unexpected type: {type(ev)}"

    def test_timestamp_is_utc_datetime(self):
        _require_file(MODBUS_LOG)
        ev = next(parse_zeek_log(MODBUS_LOG))
        assert isinstance(ev.ts, datetime)
        assert ev.ts.tzinfo == timezone.utc

    def test_ports_are_integers(self):
        _require_file(MODBUS_LOG)
        for ev in parse_zeek_log(MODBUS_LOG):
            assert isinstance(ev.orig_p, int)
            assert isinstance(ev.resp_p, int)

    def test_modbus_standard_port(self):
        """Real Modbus traffic typically uses port 502."""
        _require_file(MODBUS_LOG)
        ports = {ev.resp_p for ev in parse_zeek_log(MODBUS_LOG)}
        assert 502 in ports

    def test_func_is_non_empty_string(self):
        _require_file(MODBUS_LOG)
        for ev in parse_zeek_log(MODBUS_LOG):
            assert isinstance(ev.func, str)
            assert ev.func != ""

    def test_exception_is_none_or_string(self):
        _require_file(MODBUS_LOG)
        for ev in parse_zeek_log(MODBUS_LOG):
            assert ev.exception is None or isinstance(ev.exception, str)


# ---------------------------------------------------------------------------
# Tests — dnp3.log (real data)
# ---------------------------------------------------------------------------

class TestDnp3RealData:
    def test_yields_dnp3_events(self):
        _require_file(DNP3_LOG)
        events = list(parse_zeek_log(DNP3_LOG))
        assert len(events) > 0

    def test_all_events_are_dnp3_type(self):
        _require_file(DNP3_LOG)
        for ev in parse_zeek_log(DNP3_LOG):
            assert isinstance(ev, Dnp3Event)

    def test_timestamp_is_utc_datetime(self):
        _require_file(DNP3_LOG)
        ev = next(parse_zeek_log(DNP3_LOG))
        assert isinstance(ev.ts, datetime)
        assert ev.ts.tzinfo == timezone.utc

    def test_fc_request_is_non_empty_string(self):
        _require_file(DNP3_LOG)
        for ev in parse_zeek_log(DNP3_LOG):
            assert isinstance(ev.fc_request, str)
            assert ev.fc_request != ""

    def test_fc_reply_is_none_or_string(self):
        _require_file(DNP3_LOG)
        for ev in parse_zeek_log(DNP3_LOG):
            assert ev.fc_reply is None or isinstance(ev.fc_reply, str)

    def test_iin_is_none_or_int(self):
        _require_file(DNP3_LOG)
        for ev in parse_zeek_log(DNP3_LOG):
            assert ev.iin is None or isinstance(ev.iin, int)

    def test_dnp3_standard_port(self):
        _require_file(DNP3_LOG)
        ports = {ev.resp_p for ev in parse_zeek_log(DNP3_LOG)}
        assert 20000 in ports


# ---------------------------------------------------------------------------
# Tests — conn.log (real data)
# ---------------------------------------------------------------------------

class TestConnRealData:
    def test_yields_conn_events(self):
        _require_file(CONN_LOG)
        # conn.log can be large; just grab first 50.
        events = []
        for ev in parse_zeek_log(CONN_LOG):
            events.append(ev)
            if len(events) >= 50:
                break
        assert len(events) > 0

    def test_all_events_are_conn_type(self):
        _require_file(CONN_LOG)
        for i, ev in enumerate(parse_zeek_log(CONN_LOG)):
            assert isinstance(ev, ConnEvent)
            if i >= 49:
                break

    def test_timestamp_is_utc_datetime(self):
        _require_file(CONN_LOG)
        ev = next(parse_zeek_log(CONN_LOG))
        assert isinstance(ev.ts, datetime)
        assert ev.ts.tzinfo == timezone.utc

    def test_proto_is_string(self):
        _require_file(CONN_LOG)
        for i, ev in enumerate(parse_zeek_log(CONN_LOG)):
            assert isinstance(ev.proto, str)
            if i >= 49:
                break

    def test_tunnel_parents_is_none_or_list(self):
        _require_file(CONN_LOG)
        for i, ev in enumerate(parse_zeek_log(CONN_LOG)):
            assert ev.tunnel_parents is None or isinstance(ev.tunnel_parents, list)
            if i >= 49:
                break

    def test_numeric_fields_types(self):
        _require_file(CONN_LOG)
        for i, ev in enumerate(parse_zeek_log(CONN_LOG)):
            assert ev.orig_bytes is None or isinstance(ev.orig_bytes, int)
            assert ev.resp_bytes is None or isinstance(ev.resp_bytes, int)
            assert ev.duration is None or isinstance(ev.duration, float)
            if i >= 49:
                break


# ---------------------------------------------------------------------------
# Tests — directory scanner
# ---------------------------------------------------------------------------

class TestParseLogDirectory:
    def test_scans_modbus_from_directory(self):
        _require_file(MODBUS_LOG)
        modbus_dir = MODBUS_LOG.parent
        events = list(parse_log_directory(modbus_dir, log_names=("modbus.log",)))
        assert any(isinstance(ev, ModbusEvent) for ev in events)

    def test_multi_log_directory_yields_multiple_types(self):
        """Directory containing both modbus.log and dnp3.log yields both event types."""
        _require_file(MULTI_LOG_DIR / "modbus.log")
        _require_file(MULTI_LOG_DIR / "dnp3.log")
        events = list(
            parse_log_directory(
                MULTI_LOG_DIR, log_names=("modbus.log", "dnp3.log")
            )
        )
        types = {type(ev) for ev in events}
        # Both types should appear in the output
        assert ModbusEvent in types or Dnp3Event in types

    def test_nonexistent_directory_emits_no_events(self):
        events = list(parse_log_directory(Path("/nonexistent/path/xyz")))
        assert events == []

    def test_empty_directory_emits_no_events(self, tmp_path):
        events = list(parse_log_directory(tmp_path))
        assert events == []


# ---------------------------------------------------------------------------
# Tests — synthetic logs (error handling)
# ---------------------------------------------------------------------------

class TestSyntheticModbusLog:
    """Tests that use hand-crafted log content to exercise specific behaviours."""

    HEADER = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tmodbus\n"
        "#open\t2024-01-01-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfunc\texception\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\n"
    )

    def test_basic_parse(self, tmp_path):
        content = (
            self.HEADER
            + "1093521704.839184\tCndlS1\t10.0.0.57\t2578\t10.0.0.3\t502\tDIAGNOSTICS\t-\n"
            + "#close\t2024-01-01-00-00-01\n"
        )
        log = _write_temp_log(tmp_path, content)
        events = list(parse_zeek_log(log))
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, ModbusEvent)
        assert ev.orig_h == "10.0.0.57"
        assert ev.orig_p == 2578
        assert ev.resp_h == "10.0.0.3"
        assert ev.resp_p == 502
        assert ev.func == "DIAGNOSTICS"
        assert ev.exception is None  # '-' → None
        assert ev.ts == datetime.fromtimestamp(1093521704.839184, tz=timezone.utc)

    def test_exception_field_set(self, tmp_path):
        content = (
            self.HEADER
            + "1093521704.0\tCabc\t10.0.0.1\t1024\t10.0.0.2\t502\tREAD_COILS\tILLEGAL_FUNCTION\n"
        )
        log = _write_temp_log(tmp_path, content)
        ev = next(parse_zeek_log(log))
        assert ev.exception == "ILLEGAL_FUNCTION"

    def test_malformed_line_skipped(self, tmp_path):
        """A line with the wrong number of fields should be skipped, not raise."""
        content = (
            self.HEADER
            + "1093521704.0\tCabc\t10.0.0.1\t1024\t10.0.0.2\n"  # too few fields
            + "1093521705.0\tCdef\t10.0.0.3\t1025\t10.0.0.4\t503\tWRITE_COIL\t-\n"
        )
        log = _write_temp_log(tmp_path, content)
        events = list(parse_zeek_log(log))
        # Bad line skipped; good line parsed
        assert len(events) == 1
        assert events[0].uid == "Cdef"

    def test_stop_at_close(self, tmp_path):
        """Lines after #close should not be parsed."""
        content = (
            self.HEADER
            + "1093521704.0\tCabc\t10.0.0.1\t1024\t10.0.0.2\t502\tDIAGNOSTICS\t-\n"
            + "#close\t2024-01-01-00-00-01\n"
            + "9999999999.0\tCxxx\t1.2.3.4\t9\t5.6.7.8\t502\tREAD_COILS\t-\n"
        )
        log = _write_temp_log(tmp_path, content)
        events = list(parse_zeek_log(log))
        assert len(events) == 1
        assert events[0].uid == "Cabc"

    def test_empty_file_yields_nothing(self, tmp_path):
        log = _write_temp_log(tmp_path, "")
        events = list(parse_zeek_log(log))
        assert events == []

    def test_nonexistent_file_yields_nothing(self, tmp_path):
        events = list(parse_zeek_log(tmp_path / "missing.log"))
        assert events == []

    def test_multiple_records(self, tmp_path):
        rows = "\n".join(
            f"109352170{i}.0\tC{i}\t10.0.0.{i}\t100{i}\t10.0.0.9\t502\tREAD_COILS\t-"
            for i in range(5)
        )
        content = self.HEADER + rows + "\n"
        log = _write_temp_log(tmp_path, content)
        events = list(parse_zeek_log(log))
        assert len(events) == 5


class TestSyntheticDnp3Log:
    HEADER = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tdnp3\n"
        "#open\t2024-01-01-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfc_request\tfc_reply\tiin\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tcount\n"
    )

    def test_basic_parse(self, tmp_path):
        content = (
            self.HEADER
            + "1252963725.960421\tCMraN\t192.168.10.204\t1413\t192.168.10.140\t20000\tREAD\tRESPONSE\t36866\n"
        )
        log = _write_temp_log(tmp_path, content, name="dnp3.log")
        ev = next(parse_zeek_log(log))
        assert isinstance(ev, Dnp3Event)
        assert ev.fc_request == "READ"
        assert ev.fc_reply == "RESPONSE"
        assert ev.iin == 36866
        assert ev.resp_p == 20000

    def test_unset_fc_reply(self, tmp_path):
        content = (
            self.HEADER
            + "1252963725.0\tCabc\t127.0.0.1\t1000\t127.0.0.1\t20000\tWRITE\t-\t-\n"
        )
        log = _write_temp_log(tmp_path, content, name="dnp3.log")
        ev = next(parse_zeek_log(log))
        assert ev.fc_reply is None
        assert ev.iin is None


class TestSyntheticConnLog:
    HEADER = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2024-01-01-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
        "\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory"
        "\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval"
        "\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n"
    )

    def _row(self, **overrides) -> str:
        defaults = dict(
            ts="1189592335.298447",
            uid="CCIdK5",
            orig_h="10.0.0.1",
            orig_p="12345",
            resp_h="10.0.0.2",
            resp_p="80",
            proto="tcp",
            service="-",
            duration="1.5",
            orig_bytes="100",
            resp_bytes="200",
            conn_state="SF",
            local_orig="T",
            local_resp="T",
            missed_bytes="0",
            history="ShADadFf",
            orig_pkts="10",
            orig_ip_bytes="460",
            resp_pkts="8",
            resp_ip_bytes="380",
            tunnel_parents="(empty)",
        )
        defaults.update(overrides)
        return "\t".join(defaults[k] for k in [
            "ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
        ])

    def test_basic_parse(self, tmp_path):
        content = self.HEADER + self._row() + "\n"
        log = _write_temp_log(tmp_path, content, name="conn.log")
        ev = next(parse_zeek_log(log))
        assert isinstance(ev, ConnEvent)
        assert ev.proto == "tcp"
        assert ev.orig_bytes == 100
        assert ev.duration == pytest.approx(1.5)
        assert ev.local_orig is True
        assert ev.tunnel_parents == []

    def test_unset_service(self, tmp_path):
        content = self.HEADER + self._row(service="-") + "\n"
        log = _write_temp_log(tmp_path, content, name="conn.log")
        ev = next(parse_zeek_log(log))
        assert ev.service is None

    def test_tunnel_parents_populated(self, tmp_path):
        content = self.HEADER + self._row(tunnel_parents="uid1,uid2") + "\n"
        log = _write_temp_log(tmp_path, content, name="conn.log")
        ev = next(parse_zeek_log(log))
        assert ev.tunnel_parents == ["uid1", "uid2"]

    def test_bool_fields(self, tmp_path):
        content = self.HEADER + self._row(local_orig="F", local_resp="-") + "\n"
        log = _write_temp_log(tmp_path, content, name="conn.log")
        ev = next(parse_zeek_log(log))
        assert ev.local_orig is False
        assert ev.local_resp is None


class TestUnsupportedLogType:
    def test_unknown_log_type_yields_nothing(self, tmp_path):
        content = (
            "#separator \\x09\n"
            "#path\thttp\n"
            "#fields\tts\tuid\n"
            "#types\ttime\tstring\n"
            "1234567890.0\tCabc\n"
        )
        log = _write_temp_log(tmp_path, content, name="http.log")
        events = list(parse_zeek_log(log))
        assert events == []
