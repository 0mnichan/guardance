"""
Tests for src/ontology/ — Purdue zones, IEC 62443 conduits, ISA-95, auto-zone assignment.

Uses mock Neo4j sessions throughout.  No live database required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from src.ontology.auto_assign import (
    AutoZoneAssigner,
    infer_purdue_level,
    infer_zone,
)
from src.ontology.iec62443 import (
    Conduit,
    ConduitManager,
    DEFAULT_CONDUITS,
)
from src.ontology.isa95 import Area, ISA95Manager, WorkCenter, WorkUnit
from src.ontology.zones import (
    LEVEL_TO_ZONE,
    NAME_TO_ZONE,
    PURDUE_ZONES,
    ZoneManager,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_session(single_return=None, iter_returns=None):
    """Build a minimal mock Neo4j session."""
    session = MagicMock()
    result = MagicMock()

    if iter_returns is not None:
        records = [MagicMock(**{"__getitem__": lambda s, k: row[k]}) for row in iter_returns]
        for row, rec in zip(iter_returns, records):
            rec.__getitem__ = lambda s, k, _row=row: _row[k]
        result.__iter__ = MagicMock(return_value=iter(records))
    else:
        result.__iter__ = MagicMock(return_value=iter([]))

    if single_return is not None:
        mock_rec = MagicMock()
        mock_rec.__getitem__ = lambda s, k: single_return[k]
        mock_rec.get = lambda k, d=None: single_return.get(k, d)
        result.single = MagicMock(return_value=mock_rec)
    else:
        result.single = MagicMock(return_value=None)

    session.run = MagicMock(return_value=result)
    return session


# ---------------------------------------------------------------------------
# Zone constants
# ---------------------------------------------------------------------------

class TestPurdueZones:
    def test_six_zones_defined(self):
        assert len(PURDUE_ZONES) == 6

    def test_levels_zero_to_five(self):
        levels = [z.purdue_level for z in PURDUE_ZONES]
        assert sorted(levels) == list(range(6))

    def test_level_to_zone_lookup(self):
        for level in range(6):
            assert level in LEVEL_TO_ZONE

    def test_name_to_zone_lookup(self):
        assert "Control" in NAME_TO_ZONE
        assert NAME_TO_ZONE["Control"].purdue_level == 1

    def test_sl_t_values_in_range(self):
        for zone in PURDUE_ZONES:
            assert 1 <= zone.sl_t <= 4

    def test_field_zone_is_level_0(self):
        assert LEVEL_TO_ZONE[0].name == "Field"

    def test_enterprise_zone_is_level_5(self):
        assert LEVEL_TO_ZONE[5].name == "Enterprise"


# ---------------------------------------------------------------------------
# ZoneManager
# ---------------------------------------------------------------------------

class TestZoneManager:
    def test_ensure_zones_runs_six_merges(self):
        session = _mock_session()
        mgr = ZoneManager(driver=MagicMock())
        mgr.ensure_zones(session)
        # 1 constraint + 6 zone merges
        assert session.run.call_count == 7

    def test_assign_device_zone_calls_run(self):
        session = _mock_session()
        mgr = ZoneManager(driver=MagicMock())
        mgr.assign_device_zone(session, ip="10.0.1.1", zone_name="Control")
        session.run.assert_called_once()

    def test_get_device_zone_returns_none_when_no_record(self):
        session = _mock_session(single_return=None)
        mgr = ZoneManager(driver=MagicMock())
        result = mgr.get_device_zone(session, "10.0.1.1")
        assert result is None

    def test_get_device_zone_returns_purdue_zone(self):
        session = _mock_session(single_return={"name": "Control", "purdue_level": 1})
        mgr = ZoneManager(driver=MagicMock())
        result = mgr.get_device_zone(session, "10.0.1.1")
        assert result is not None
        assert result.name == "Control"

    def test_devices_without_zone_returns_ips(self):
        rows = [{"ip": "10.0.1.1"}, {"ip": "10.0.1.2"}]
        session = MagicMock()
        recs = []
        for row in rows:
            r = MagicMock()
            r.__getitem__ = lambda s, k, _row=row: _row[k]
            recs.append(r)
        result = MagicMock()
        result.__iter__ = MagicMock(return_value=iter(recs))
        session.run = MagicMock(return_value=result)
        mgr = ZoneManager(driver=MagicMock())
        ips = mgr.devices_without_zone(session)
        assert ips == ["10.0.1.1", "10.0.1.2"]


# ---------------------------------------------------------------------------
# IEC 62443 ConduitManager
# ---------------------------------------------------------------------------

class TestConduitManager:
    def test_five_default_conduits(self):
        assert len(DEFAULT_CONDUITS) == 5

    def test_conduit_is_compliant_when_sl_a_ge_sl_t(self):
        c = Conduit("test", "Field", "Control", sl_t=2, sl_a=3)
        assert c.is_compliant

    def test_conduit_not_compliant_when_sl_a_lt_sl_t(self):
        c = Conduit("test", "Field", "Control", sl_t=3, sl_a=2)
        assert not c.is_compliant

    def test_ensure_conduits_calls_run_per_conduit(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        mgr = ConduitManager(driver=MagicMock())
        mgr.ensure_conduits(session)
        # 2 run calls per conduit (merge + link)
        assert session.run.call_count >= len(DEFAULT_CONDUITS)

    def test_assess_protocol_on_conduit_true(self):
        mgr = ConduitManager(driver=MagicMock())
        assert mgr.assess_protocol_on_conduit("Field-Control", "modbus") is True

    def test_assess_protocol_on_conduit_false(self):
        mgr = ConduitManager(driver=MagicMock())
        assert mgr.assess_protocol_on_conduit("Business-Enterprise", "modbus") is False

    def test_assess_unknown_conduit_returns_false(self):
        mgr = ConduitManager(driver=MagicMock())
        assert mgr.assess_protocol_on_conduit("nonexistent", "modbus") is False


# ---------------------------------------------------------------------------
# ISA-95 Manager
# ---------------------------------------------------------------------------

class TestISA95Manager:
    def test_ensure_area_calls_run(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        mgr = ISA95Manager(driver=MagicMock())
        area = Area(name="Utilities", description="Utility block", purdue_level=3)
        mgr.ensure_area(session, area)
        session.run.assert_called_once()

    def test_ensure_work_center_calls_run(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        mgr = ISA95Manager(driver=MagicMock())
        wc = WorkCenter(name="CoolingTower1", area_name="Utilities")
        mgr.ensure_work_center(session, wc)
        session.run.assert_called_once()

    def test_ensure_work_unit_links_devices(self):
        session = MagicMock()
        session.run = MagicMock(return_value=MagicMock())
        mgr = ISA95Manager(driver=MagicMock())
        wu = WorkUnit(
            name="CT1-PLC",
            work_center_name="CoolingTower1",
            device_ips=["10.0.1.1", "10.0.1.2"],
        )
        mgr.ensure_work_unit(session, wu)
        # 1 merge WU + 2 device links
        assert session.run.call_count == 3

    def test_get_hierarchy_returns_none_when_not_linked(self):
        session = _mock_session(single_return=None)
        mgr = ISA95Manager(driver=MagicMock())
        result = mgr.get_hierarchy_for_device(session, "10.0.1.1")
        assert result is None


# ---------------------------------------------------------------------------
# Auto-zone assignment
# ---------------------------------------------------------------------------

class TestInferPurdueLevel:
    def test_modbus_502_is_level_1(self):
        assert infer_purdue_level([("modbus", 502)]) == 1

    def test_dnp3_is_level_1(self):
        assert infer_purdue_level([("dnp3", 20000)]) == 1

    def test_opc_ua_is_level_2(self):
        assert infer_purdue_level([("opc-ua", 4840)]) == 2

    def test_https_is_level_5(self):
        assert infer_purdue_level([("https", 443)]) == 5

    def test_mixed_picks_lowest(self):
        # Modbus (1) + HTTPS (5) → should pick 1
        assert infer_purdue_level([("modbus", 502), ("https", 443)]) == 1

    def test_empty_defaults_to_3(self):
        assert infer_purdue_level([]) == 3

    def test_unknown_protocol_defaults_to_3(self):
        assert infer_purdue_level([("proprietary_x", 9999)]) == 3


class TestInferZone:
    def test_returns_purdue_zone(self):
        zone = infer_zone([("modbus", 502)])
        assert zone.purdue_level == 1
        assert zone.name == "Control"


class TestAutoZoneAssigner:
    def _make_session_with_edges(self, edges):
        session = MagicMock()
        results = []
        for e in edges:
            rec = MagicMock()
            rec.__getitem__ = lambda s, k, _e=e: _e[k]
            results.append(rec)

        result = MagicMock()
        result.__iter__ = MagicMock(return_value=iter(results))
        session.run = MagicMock(return_value=result)
        return session

    def test_assign_device_calls_zone_manager(self):
        session = self._make_session_with_edges([
            {"protocol": "modbus", "port": 502},
        ])
        driver = MagicMock()
        # ZoneManager.assign_device_zone should be called
        with patch("src.ontology.auto_assign.ZoneManager") as MockZM:
            mock_zm = MockZM.return_value
            assigner = AutoZoneAssigner(driver)
            zone = assigner.assign_device(session, "10.0.1.1")
        assert zone is not None
        assert zone.purdue_level == 1
        mock_zm.assign_device_zone.assert_called_once()

    def test_assign_device_returns_none_for_no_edges(self):
        session = self._make_session_with_edges([])
        driver = MagicMock()
        assigner = AutoZoneAssigner(driver)
        with patch("src.ontology.auto_assign.ZoneManager"):
            result = assigner.assign_device(session, "10.0.1.1")
        assert result is None
