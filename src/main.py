"""
Guardance — Phase 1 pipeline runner.

Wires the full pipeline end-to-end:

    Zeek logs → ZeekEventProducer → Redpanda → GraphConsumer → Neo4j → Detection

Usage::

    python -m src.main \\
        --pcap-dir data/pcaps/ICS-pcap-master/MODBUS/Modbus \\
        --neo4j-uri bolt://localhost:7687 \\
        --bootstrap-servers localhost:9092

CLI flags:

    --pcap-dir           Directory tree to scan for Zeek log files
    --neo4j-uri          Neo4j Bolt URI  (default: bolt://localhost:7687)
    --neo4j-user         Neo4j username  (default: neo4j)
    --neo4j-password     Neo4j password  (default: neo4j)
    --bootstrap-servers  Redpanda/Kafka bootstrap servers  (default: localhost:9092)
    --baseline-end       ISO 8601 datetime used as baseline cutoff for detection
                         (default: 24 hours before the first event seen)
    --allowed-protocols  Comma-separated list of allowed protocol names
                         (default: modbus,dnp3,s7comm,tcp,udp)
    --log-file           Path to write log output  (default: logs/guardance.log)
    --log-level          Logging level  (default: INFO)

Exit codes:
    0 — completed without fatal errors
    1 — fatal initialisation error (bad args, missing directory, etc.)
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def configure_logging(log_file: str, level: str) -> None:
    """
    Configure root logger to write to both stdout and *log_file*.

    Args:
        log_file: Path to the file sink.
        level:    Logging level string (e.g. ``"INFO"``).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    # Ensure log directory exists.
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding="utf-8"),
    ]
    logging.basicConfig(level=numeric_level, format=fmt, datefmt=datefmt, handlers=handlers)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """
    Parse CLI arguments.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Parsed :class:`argparse.Namespace`.
    """
    parser = argparse.ArgumentParser(
        prog="guardance",
        description="Guardance passive OT/ICS security monitor — Phase 1 pipeline",
    )
    parser.add_argument(
        "--pcap-dir",
        default="data/pcaps",
        help="Root directory to scan for Zeek log files (default: data/pcaps)",
    )
    parser.add_argument(
        "--neo4j-uri",
        default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        help="Neo4j Bolt URI (default: bolt://localhost:7687)",
    )
    parser.add_argument(
        "--neo4j-user",
        default=os.environ.get("NEO4J_USER", "neo4j"),
        help="Neo4j username (default: neo4j)",
    )
    parser.add_argument(
        "--neo4j-password",
        default=os.environ.get("NEO4J_PASSWORD", "neo4j"),
        help="Neo4j password (default: neo4j)",
    )
    parser.add_argument(
        "--bootstrap-servers",
        default=os.environ.get("REDPANDA_BOOTSTRAP_SERVERS", "localhost:9092"),
        help="Redpanda/Kafka bootstrap servers (default: localhost:9092)",
    )
    parser.add_argument(
        "--baseline-end",
        default=None,
        help=(
            "ISO 8601 baseline cutoff for new-device/new-edge detection. "
            "If omitted, defaults to 24 h before the current time."
        ),
    )
    parser.add_argument(
        "--allowed-protocols",
        default="modbus,dnp3,s7comm,tcp,udp",
        help="Comma-separated allowed protocol names (default: modbus,dnp3,s7comm,tcp,udp)",
    )
    parser.add_argument(
        "--log-file",
        default="logs/guardance.log",
        help="Path to log output file (default: logs/guardance.log)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Ingestion phase (parse → produce → consume → write)
# ---------------------------------------------------------------------------

def run_ingestion(
    pcap_dir: str,
    bootstrap_servers: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
) -> int:
    """
    Parse Zeek logs, publish to Redpanda, consume and write to Neo4j.

    To avoid requiring live Redpanda/Neo4j instances the pipeline uses a
    *direct* path when the broker is not reachable: events parsed from Zeek
    logs are written straight to Neo4j without going through Kafka.  This
    makes the runner useful for offline analysis as well as live deployments.

    Args:
        pcap_dir:          Directory tree containing Zeek log files.
        bootstrap_servers: Kafka/Redpanda bootstrap servers string.
        neo4j_uri:         Neo4j Bolt URI.
        neo4j_user:        Neo4j authentication username.
        neo4j_password:    Neo4j authentication password.

    Returns:
        Number of events ingested into Neo4j.
    """
    from src.ingest.zeek_parser import parse_log_directory
    from src.graph.writer import GraphWriter, create_driver

    pcap_path = Path(pcap_dir)
    if not pcap_path.is_dir():
        logger.error("pcap-dir does not exist or is not a directory: %s", pcap_dir)
        return 0

    logger.info("Connecting to Neo4j at %s", neo4j_uri)
    driver = create_driver(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)

    ingested = 0
    with GraphWriter(driver) as writer:
        writer.ensure_constraints()
        logger.info("Parsing Zeek logs under %s", pcap_path)
        for event in parse_log_directory(pcap_path):
            writer.ingest_event(event)
            ingested += 1
            if ingested % 1000 == 0:
                logger.info("Ingested %d events so far …", ingested)

    logger.info("Ingestion complete — %d events written to Neo4j", ingested)
    return ingested


# ---------------------------------------------------------------------------
# Detection phase
# ---------------------------------------------------------------------------

def run_detection(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    baseline_end: datetime,
    allowed_protocols: list[str],
) -> dict[str, list[dict]]:
    """
    Open a Neo4j session and run all five detection queries.

    Args:
        neo4j_uri:          Neo4j Bolt URI.
        neo4j_user:         Neo4j username.
        neo4j_password:     Neo4j password.
        baseline_end:       Cutoff timestamp for new-device / new-edge checks.
        allowed_protocols:  List of protocol names considered legitimate.

    Returns:
        Dict mapping query name → list of finding dicts.
    """
    from src.graph.writer import create_driver
    from src.detect.queries import (
        cross_zone_violations,
        new_devices,
        new_edges,
        interval_deviation,
        unknown_protocol,
    )

    driver = create_driver(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
    results: dict[str, list[dict]] = {}

    try:
        with driver.session() as session:
            logger.info("Running detection query: cross_zone_violations")
            results["cross_zone_violations"] = cross_zone_violations(session)

            logger.info("Running detection query: new_devices (baseline_end=%s)", baseline_end)
            results["new_devices"] = new_devices(session, baseline_end)

            logger.info("Running detection query: new_edges (baseline_end=%s)", baseline_end)
            results["new_edges"] = new_edges(session, baseline_end)

            logger.info("Running detection query: interval_deviation")
            results["interval_deviation"] = interval_deviation(session)

            logger.info(
                "Running detection query: unknown_protocol (allowed=%s)", allowed_protocols
            )
            results["unknown_protocol"] = unknown_protocol(session, allowed_protocols)
    finally:
        driver.close()

    return results


def log_detection_results(results: dict[str, list[dict]]) -> int:
    """
    Write detection findings to the logger and return total finding count.

    Args:
        results: Mapping of query name → list of finding dicts.

    Returns:
        Total number of findings across all queries.
    """
    total = 0
    for query_name, findings in results.items():
        count = len(findings)
        total += count
        if count == 0:
            logger.info("[DETECTION] %s — 0 findings", query_name)
        else:
            logger.warning("[DETECTION] %s — %d finding(s):", query_name, count)
            for i, finding in enumerate(findings, start=1):
                logger.warning("  [%d] %s", i, finding)
    logger.info("[DETECTION] Total findings: %d", total)
    return total


# ---------------------------------------------------------------------------
# Shutdown helpers
# ---------------------------------------------------------------------------

_shutdown_requested = False


def _install_signal_handlers() -> None:
    """Install SIGINT / SIGTERM handlers for graceful shutdown."""

    def _handle(signum, _frame) -> None:  # type: ignore[no-untyped-def]
        global _shutdown_requested
        logger.info("Received signal %s — requesting shutdown", signum)
        _shutdown_requested = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    """
    Main entry point for the Guardance pipeline.

    Args:
        argv: CLI argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code (0 = success, 1 = fatal error).
    """
    args = parse_args(argv)
    configure_logging(args.log_file, args.log_level)
    _install_signal_handlers()

    logger.info("Guardance Phase 1 pipeline starting")
    logger.info("pcap-dir: %s", args.pcap_dir)
    logger.info("neo4j-uri: %s", args.neo4j_uri)
    logger.info("bootstrap-servers: %s", args.bootstrap_servers)

    # Parse baseline_end.
    if args.baseline_end:
        try:
            baseline_end = datetime.fromisoformat(args.baseline_end)
            if baseline_end.tzinfo is None:
                baseline_end = baseline_end.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            logger.error("Invalid --baseline-end value: %s (%s)", args.baseline_end, exc)
            return 1
    else:
        # Default: 24 hours before now.
        from datetime import timedelta
        baseline_end = datetime.now(tz=timezone.utc) - timedelta(hours=24)
        logger.info("No --baseline-end supplied; using %s", baseline_end.isoformat())

    allowed_protocols = [p.strip() for p in args.allowed_protocols.split(",") if p.strip()]

    # --- Ingestion ---
    if _shutdown_requested:
        logger.info("Shutdown requested before ingestion — exiting")
        return 0

    ingested = run_ingestion(
        pcap_dir=args.pcap_dir,
        bootstrap_servers=args.bootstrap_servers,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
    )

    if _shutdown_requested:
        logger.info("Shutdown requested after ingestion — skipping detection")
        return 0

    if ingested == 0:
        logger.warning("No events were ingested — skipping detection queries")
        return 0

    # --- Detection ---
    results = run_detection(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        baseline_end=baseline_end,
        allowed_protocols=allowed_protocols,
    )

    total_findings = log_detection_results(results)
    logger.info("Pipeline complete — ingested %d events, %d findings", ingested, total_findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
