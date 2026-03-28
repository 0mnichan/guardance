"""
Zeek ICSNPP log parser.

Reads Zeek log files (modbus.log, dnp3.log, conn.log) from a directory,
parses each line into a typed Python dataclass, and yields structured events.

Zeek log format:
  - Lines beginning with '#' are metadata (separator, fields, types, etc.)
  - Data lines are separated by the declared separator (almost always TAB)
  - Unset fields are represented by '#unset_field' sentinel (typically '-')
  - Empty set/vector fields are represented by '#empty_field' sentinel (typically '(empty)')
  - '#close' marks the end of the file; lines after it are ignored
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataclasses — one per log type
# ---------------------------------------------------------------------------

@dataclass
class ModbusEvent:
    """A single parsed record from a Zeek modbus.log file."""

    ts: datetime
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    func: str
    exception: Optional[str]


@dataclass
class Dnp3Event:
    """A single parsed record from a Zeek dnp3.log file."""

    ts: datetime
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    fc_request: str
    fc_reply: Optional[str]
    iin: Optional[int]


@dataclass
class ConnEvent:
    """A single parsed record from a Zeek conn.log file."""

    ts: datetime
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: Optional[str]
    duration: Optional[float]
    orig_bytes: Optional[int]
    resp_bytes: Optional[int]
    conn_state: str
    local_orig: Optional[bool]
    local_resp: Optional[bool]
    missed_bytes: Optional[int]
    history: Optional[str]
    orig_pkts: Optional[int]
    orig_ip_bytes: Optional[int]
    resp_pkts: Optional[int]
    resp_ip_bytes: Optional[int]
    tunnel_parents: Optional[list[str]]


# Union of all event types yielded by this module.
ZeekEvent = Union[ModbusEvent, Dnp3Event, ConnEvent]


# ---------------------------------------------------------------------------
# Low-level log reader
# ---------------------------------------------------------------------------

class _ZeekLogHeader:
    """Metadata parsed from a Zeek log file's header section."""

    __slots__ = (
        "separator",
        "set_separator",
        "empty_field",
        "unset_field",
        "path",
        "fields",
        "types",
    )

    def __init__(self) -> None:
        self.separator: str = "\t"
        self.set_separator: str = ","
        self.empty_field: str = "(empty)"
        self.unset_field: str = "-"
        self.path: str = ""
        self.fields: list[str] = []
        self.types: list[str] = []


def _parse_separator(raw: str) -> str:
    """Decode a Zeek separator declaration (e.g. '\\x09') into a Python string."""
    try:
        return raw.encode("utf-8").decode("unicode_escape")
    except Exception:
        return raw


def _read_header(lines: list[str]) -> tuple[_ZeekLogHeader, int]:
    """
    Parse Zeek log header directives from *lines*.

    Returns the populated header object and the index of the first data line
    (i.e. the first line that does not start with '#').
    """
    header = _ZeekLogHeader()
    idx = 0
    for idx, line in enumerate(lines):
        line = line.rstrip("\n")
        if not line.startswith("#"):
            break
        if line.startswith("#separator"):
            raw = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else "\t"
            header.separator = _parse_separator(raw)
        elif line.startswith("#set_separator"):
            parts = line.split(header.separator, 1)
            if len(parts) > 1:
                header.set_separator = parts[1]
        elif line.startswith("#empty_field"):
            parts = line.split(header.separator, 1)
            if len(parts) > 1:
                header.empty_field = parts[1]
        elif line.startswith("#unset_field"):
            parts = line.split(header.separator, 1)
            if len(parts) > 1:
                header.unset_field = parts[1]
        elif line.startswith("#path"):
            parts = line.split(header.separator, 1)
            if len(parts) > 1:
                header.path = parts[1]
        elif line.startswith("#fields"):
            parts = line.split(header.separator)
            header.fields = parts[1:]  # drop '#fields' prefix
        elif line.startswith("#types"):
            parts = line.split(header.separator)
            header.types = parts[1:]  # drop '#types' prefix
        # '#open', '#close', '#empty', '#empty_field' — skip
    else:
        # All lines were headers; no data lines present.
        idx = len(lines)
    return header, idx


# ---------------------------------------------------------------------------
# Type coercion helpers
# ---------------------------------------------------------------------------

def _to_optional_str(value: str, unset: str) -> Optional[str]:
    """Return None when *value* is the Zeek unset sentinel, else return *value*."""
    return None if value == unset else value


def _to_ts(value: str) -> datetime:
    """Convert a Zeek epoch timestamp string to a UTC-aware datetime."""
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _to_int(value: str, unset: str) -> Optional[int]:
    """Parse an integer field; return None for unset/empty."""
    if value in (unset, ""):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _to_float(value: str, unset: str) -> Optional[float]:
    """Parse a float field; return None for unset/empty."""
    if value in (unset, ""):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _to_bool(value: str, unset: str) -> Optional[bool]:
    """Parse a Zeek boolean field (T/F); return None for unset."""
    if value == unset:
        return None
    return value == "T"


def _to_set(value: str, unset: str, empty: str, sep: str) -> Optional[list[str]]:
    """Parse a Zeek set/vector field into a list of strings."""
    if value == unset:
        return None
    if value == empty:
        return []
    return value.split(sep)


# ---------------------------------------------------------------------------
# Per-log-type parsers
# ---------------------------------------------------------------------------

def _parse_modbus_record(
    fields: list[str],
    values: list[str],
    unset: str,
) -> ModbusEvent:
    """Build a ModbusEvent from a list of field values."""
    fmap = dict(zip(fields, values))
    return ModbusEvent(
        ts=_to_ts(fmap["ts"]),
        uid=fmap["uid"],
        orig_h=fmap["id.orig_h"],
        orig_p=int(fmap["id.orig_p"]),
        resp_h=fmap["id.resp_h"],
        resp_p=int(fmap["id.resp_p"]),
        func=fmap["func"],
        exception=_to_optional_str(fmap["exception"], unset),
    )


def _parse_dnp3_record(
    fields: list[str],
    values: list[str],
    unset: str,
) -> Dnp3Event:
    """Build a Dnp3Event from a list of field values."""
    fmap = dict(zip(fields, values))
    return Dnp3Event(
        ts=_to_ts(fmap["ts"]),
        uid=fmap["uid"],
        orig_h=fmap["id.orig_h"],
        orig_p=int(fmap["id.orig_p"]),
        resp_h=fmap["id.resp_h"],
        resp_p=int(fmap["id.resp_p"]),
        fc_request=fmap["fc_request"],
        fc_reply=_to_optional_str(fmap["fc_reply"], unset),
        iin=_to_int(fmap["iin"], unset),
    )


def _parse_conn_record(
    fields: list[str],
    values: list[str],
    unset: str,
    empty: str,
    set_sep: str,
) -> ConnEvent:
    """Build a ConnEvent from a list of field values."""
    fmap = dict(zip(fields, values))
    return ConnEvent(
        ts=_to_ts(fmap["ts"]),
        uid=fmap["uid"],
        orig_h=fmap["id.orig_h"],
        orig_p=int(fmap["id.orig_p"]),
        resp_h=fmap["id.resp_h"],
        resp_p=int(fmap["id.resp_p"]),
        proto=fmap["proto"],
        service=_to_optional_str(fmap["service"], unset),
        duration=_to_float(fmap["duration"], unset),
        orig_bytes=_to_int(fmap["orig_bytes"], unset),
        resp_bytes=_to_int(fmap["resp_bytes"], unset),
        conn_state=fmap["conn_state"],
        local_orig=_to_bool(fmap["local_orig"], unset),
        local_resp=_to_bool(fmap["local_resp"], unset),
        missed_bytes=_to_int(fmap["missed_bytes"], unset),
        history=_to_optional_str(fmap["history"], unset),
        orig_pkts=_to_int(fmap["orig_pkts"], unset),
        orig_ip_bytes=_to_int(fmap["orig_ip_bytes"], unset),
        resp_pkts=_to_int(fmap["resp_pkts"], unset),
        resp_ip_bytes=_to_int(fmap["resp_ip_bytes"], unset),
        tunnel_parents=_to_set(fmap["tunnel_parents"], unset, empty, set_sep),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_zeek_log(path: Path) -> Generator[ZeekEvent, None, None]:
    """
    Parse a single Zeek log file and yield typed event dataclasses.

    Supports modbus.log, dnp3.log, and conn.log (identified by the #path
    directive inside the file).  Unrecognised log types are skipped with a
    warning.  Malformed data lines are logged at WARNING level and skipped;
    the generator continues with the next line.

    Args:
        path: Absolute or relative path to the Zeek log file.

    Yields:
        ModbusEvent, Dnp3Event, or ConnEvent instances.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error("Cannot open %s: %s", path, exc)
        return

    lines = text.splitlines()
    if not lines:
        logger.warning("Empty log file: %s", path)
        return

    header, data_start = _read_header(lines)

    if not header.fields:
        logger.warning("No #fields directive found in %s", path)
        return

    log_type = header.path
    if log_type not in ("modbus", "dnp3", "conn"):
        logger.debug("Skipping unsupported log type '%s' in %s", log_type, path)
        return

    unset = header.unset_field
    empty = header.empty_field
    set_sep = header.set_separator
    sep = header.separator
    fields = header.fields

    for lineno, line in enumerate(lines[data_start:], start=data_start + 1):
        line = line.rstrip("\n")

        # '#close' marks the end of the log — stop processing.
        if line.startswith("#close"):
            break

        # Skip any remaining metadata or blank lines inside the data section.
        if line.startswith("#") or not line.strip():
            continue

        values = line.split(sep)

        if len(values) != len(fields):
            logger.warning(
                "%s:%d — field count mismatch (expected %d, got %d): %r",
                path,
                lineno,
                len(fields),
                len(values),
                line,
            )
            continue

        try:
            if log_type == "modbus":
                yield _parse_modbus_record(fields, values, unset)
            elif log_type == "dnp3":
                yield _parse_dnp3_record(fields, values, unset)
            elif log_type == "conn":
                yield _parse_conn_record(fields, values, unset, empty, set_sep)
        except (KeyError, ValueError, IndexError) as exc:
            logger.warning(
                "%s:%d — failed to parse record: %s — line: %r",
                path,
                lineno,
                exc,
                line,
            )


def parse_log_directory(
    directory: Path,
    log_names: tuple[str, ...] = ("modbus.log", "dnp3.log", "conn.log"),
) -> Generator[ZeekEvent, None, None]:
    """
    Recursively scan *directory* for Zeek log files and yield parsed events.

    Only files whose names match *log_names* are processed.  Events from all
    matching files are yielded in the order they are discovered (filesystem
    order within each directory level, directories visited depth-first).

    Args:
        directory: Root directory to scan.
        log_names: Tuple of filenames to look for (e.g. ``("modbus.log",)``).

    Yields:
        ModbusEvent, Dnp3Event, or ConnEvent instances.
    """
    directory = Path(directory)
    if not directory.is_dir():
        logger.error("Not a directory: %s", directory)
        return

    for log_name in log_names:
        for log_path in sorted(directory.rglob(log_name)):
            logger.debug("Parsing %s", log_path)
            yield from parse_zeek_log(log_path)
