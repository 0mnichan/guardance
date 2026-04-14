"""
MITRE ATT&CK for ICS anomaly mapper.

Maps Guardance detection findings to ATT&CK for ICS techniques by
matching the finding type (and optionally its attributes) against the
``detection_signals`` on each Technique.

Each finding dict is enriched with:
    technique_ids  — list of matching ATT&CK technique IDs
    tactic_ids     — list of parent tactic IDs (deduped)
    techniques     — list of dicts with technique_id, name, tactic_name

Mapping strategy
----------------
The primary signal is derived from the finding category:

    cross_zone_violation  → cross_zone_violation signal
    new_device            → new_device signal
    new_edge              → new_edge signal
    interval_deviation    → interval_deviation signal
    unknown_protocol      → unknown_protocol signal
    silence               → silence_detection signal
    process_deviation     → process_deviation signal

Secondary signals are derived from finding attributes where possible
(e.g. an unusual function code adds the ``unusual_function_code`` signal).
"""

from __future__ import annotations

import logging
from typing import Any

from src.attack.techniques import (
    SIGNAL_TO_TECHNIQUES,
    TACTIC_BY_ID,
    TECHNIQUE_BY_ID,
    Technique,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signal derivation
# ---------------------------------------------------------------------------

# Write function codes that suggest manipulation
_WRITE_FUNCTION_CODES = {
    "WRITE_SINGLE_COIL", "WRITE_MULTIPLE_COILS",
    "WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS",
    "WRITE_FILE_RECORD", "MASK_WRITE_REGISTER",
    "READ_WRITE_MULTIPLE_REGISTERS",
    # DNP3
    "DIRECT_OPERATE", "SELECT", "DIRECT_OPERATE_NO_ACK",
    "FREEZE", "FREEZE_CLEAR",
}


def _signals_for_finding(category: str, finding: dict) -> list[str]:
    """
    Derive a list of detection signal strings from a finding dict.

    Args:
        category: The finding category string (e.g. ``"cross_zone_violation"``).
        finding:  The finding dict from a detection query.

    Returns:
        List of signal strings to look up in SIGNAL_TO_TECHNIQUES.
    """
    signals: list[str] = [category]

    func = (finding.get("function_code") or "").upper()
    if func in _WRITE_FUNCTION_CODES:
        signals.append("write_register")
        signals.append("unusual_function_code")

    if finding.get("avg_interval_ms") is not None:
        signals.append("interval_deviation")

    return signals


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich_finding(category: str, finding: dict) -> dict:
    """
    Enrich a single finding dict with ATT&CK technique references.

    Args:
        category: Finding category (e.g. ``"cross_zone_violation"``).
        finding:  The finding dict from a Guardance detection query.

    Returns:
        A new dict (copy of finding) with added keys:
        ``technique_ids``, ``tactic_ids``, ``techniques``.
    """
    signals = _signals_for_finding(category, finding)

    tech_ids: list[str] = []
    for sig in signals:
        for tid in SIGNAL_TO_TECHNIQUES.get(sig, []):
            if tid not in tech_ids:
                tech_ids.append(tid)

    tactic_ids: list[str] = []
    techniques: list[dict] = []
    for tid in tech_ids:
        tech = TECHNIQUE_BY_ID.get(tid)
        if tech is None:
            continue
        tactic = TACTIC_BY_ID.get(tech.tactic_id)
        tactic_name = tactic.name if tactic else "Unknown"
        if tech.tactic_id not in tactic_ids:
            tactic_ids.append(tech.tactic_id)
        techniques.append({
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactic_id": tech.tactic_id,
            "tactic_name": tactic_name,
        })

    enriched = dict(finding)
    enriched["technique_ids"] = tech_ids
    enriched["tactic_ids"] = tactic_ids
    enriched["techniques"] = techniques
    return enriched


def map_all_findings(findings: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """
    Enrich all findings in a Guardance findings dict with ATT&CK references.

    Args:
        findings: Dict mapping category name → list of finding dicts,
                  as returned by :func:`src.policy.engine.PolicyEngine.run_all`.

    Returns:
        New dict with same structure but each finding enriched with
        ``technique_ids``, ``tactic_ids``, and ``techniques``.
    """
    # Category → signal name mapping
    category_to_signal = {
        "cross_zone_violations": "cross_zone_violation",
        "new_devices":           "new_device",
        "new_edges":             "new_edge",
        "interval_deviation":    "interval_deviation",
        "unknown_protocol":      "unknown_protocol",
        "silence":               "silence_detection",
        "process_deviation":     "process_deviation",
    }

    result: dict[str, list[dict]] = {}
    for category, items in findings.items():
        signal = category_to_signal.get(category, category)
        result[category] = [enrich_finding(signal, item) for item in items]
        logger.debug(
            "ATT&CK mapped %d findings in category %s", len(items), category
        )

    total = sum(len(v) for v in result.values())
    logger.info("ATT&CK enrichment complete: %d findings mapped", total)
    return result


def summary_by_tactic(enriched_findings: dict[str, list[dict]]) -> dict[str, int]:
    """
    Produce a count of findings per ATT&CK tactic.

    Args:
        enriched_findings: Output of :func:`map_all_findings`.

    Returns:
        Dict mapping tactic name → finding count (findings may be
        counted under multiple tactics).
    """
    counts: dict[str, int] = {}
    for items in enriched_findings.values():
        for finding in items:
            for tactic_id in finding.get("tactic_ids", []):
                tactic = TACTIC_BY_ID.get(tactic_id)
                name = tactic.name if tactic else tactic_id
                counts[name] = counts.get(name, 0) + 1
    return counts
