# Guardance

Passive OT/ICS network security monitor.

Guardance ingests real OT protocol traffic, builds a Neo4j graph of device
behaviour, and detects anomalies using Cypher queries. OT networks are one of
the few environments where normal behaviour is genuinely enumerable — a PLC
polling a field sensor does the same thing every 250 ms for years. Guardance
models that reality completely: any deviation is immediately visible.

**Detection inevitability.**

---

## Table of Contents

- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Project Layout](#project-layout)
- [Pipeline Components](#pipeline-components)
- [Neo4j Schema Reference](#neo4j-schema-reference)
- [Detection Queries](#detection-queries)
- [How to Extend Detection Queries](#how-to-extend-detection-queries)
- [Configuration Reference](#configuration-reference)
- [Running Tests](#running-tests)
- [Roadmap](#roadmap)
- [License](#license)

---

## How it works

OT/ICS networks have a property that IT networks do not: their normal
behaviour is almost perfectly deterministic. A Modbus master polls its
slaves every 250 ms, on the same ports, using the same function codes, for
years at a time. That property makes a graph-based baseline trivially
complete — you simply observe the network for a window of time and record
every device, every communication channel, and every polling interval. From
that point forward, anything that deviates from the baseline is a finding.

The five detection categories are:

| # | Condition | Signal |
|---|-----------|--------|
| 1 | Two devices in zones more than one Purdue level apart communicate | Lateral movement / misconfiguration |
| 2 | A device appears that was not seen during the baseline period | Rogue device / new install |
| 3 | A communication channel appears that did not exist during baseline | Reconnaissance / new attack path |
| 4 | A polling interval falls outside the expected 100–1000 ms window | Replay attack / timing manipulation |
| 5 | A protocol appears on a channel that is not in the OT allowlist | IT protocol on OT segment / exfiltration |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Data Sources                                │
│  PCAPs  ──►  Zeek + ICSNPP  ──►  modbus.log / dnp3.log / conn.log   │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ parse_zeek_log() / parse_log_directory()
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Ingest Layer  (src/ingest/)                     │
│                                                                     │
│  zeek_parser.py  ──►  ModbusEvent / Dnp3Event / ConnEvent           │
│         │                                                           │
│         ▼                                                           │
│  ZeekEventProducer  ──►  Redpanda topics                            │
│      raw.modbus  /  raw.dnp3  /  raw.conn                           │
│                                                                     │
│  Messages are JSON, partitioned by src_ip:dst_ip for ordering.      │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ JSON over Kafka protocol
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Graph Layer  (src/graph/)                       │
│                                                                     │
│  GraphConsumer  ──►  deserialize_message()  ──►  GraphWriter        │
│                                                      │              │
│  GraphWriter issues MERGE operations — each event    │              │
│  upserts two Device nodes and one COMMUNICATES_WITH  │              │
│  edge, accumulating packet_count and recomputing     │              │
│  avg_interval_ms on every update.                    │              │
│                                                      ▼              │
│                         Neo4j 5.x Community                         │
│                                                                     │
│  ┌──────────────┐   COMMUNICATES_WITH   ┌────────────────────────┐  │
│  │  Device      │ ──────────────────►  │  Device                 │  │
│  │  {ip, mac,   │                       │  {ip, mac, role,       │  │
│  │   role,      │                       │   purdue_level,        │  │
│  │   purdue_lvl}│                       │   first_seen,          │  │
│  └──────┬───────┘                       │   last_seen}           │  │
│         │ MEMBER_OF                     └────────────────────────┘  │
│         ▼                                                           │
│  ┌──────────────┐                                                   │
│  │  Zone        │                                                   │
│  │  {name,      │                                                   │
│  │   purdue_lvl}│                                                   │
│  └──────────────┘                                                   │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Detection Layer  (src/detect/)                    │
│                                                                     │
│  1. cross_zone_violations  — Purdue level jump > 1                  │
│  2. new_devices            — first_seen > baseline_end              │
│  3. new_edges              — relationship first_seen > baseline_end │
│  4. interval_deviation     — avg_interval_ms outside [100, 1000] ms │
│  5. unknown_protocol       — protocol not in allowlist              │
│                                                                     │
│  Each query returns list[dict]. Findings are logged at WARNING.     │
└─────────────────────────────────────────────────────────────────────┘
```

### Direct ingestion path

When Redpanda is not available (e.g. offline analysis), `src/main.py`
skips the broker entirely and writes Zeek events straight to Neo4j:

```
Zeek logs ──► zeek_parser ──► GraphWriter ──► Neo4j
```

This makes the runner useful for ad-hoc forensic analysis of PCAPs without
requiring any message broker infrastructure.

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Runtime |
| Neo4j Community | 5.x | Graph database |
| Redpanda or Kafka | any recent | Message broker (optional for offline mode) |
| Zeek + ICSNPP | current | Protocol parsing from PCAPs |

Python packages:

```
neo4j
confluent-kafka
pytest
```

---

## Installation

```bash
git clone <repo>
cd guardance
pip install neo4j confluent-kafka pytest
```

Zeek with ICSNPP plugins must be installed separately and available on your
`PATH` to generate `.log` files from PCAPs. Guardance consumes the log files
that Zeek produces; it does not invoke Zeek itself.

ICSNPP plugins needed for full protocol coverage:

- [icsnpp-modbus](https://github.com/cisagov/icsnpp-modbus)
- [icsnpp-dnp3](https://github.com/cisagov/icsnpp-dnp3)
- [icsnpp-s7comm](https://github.com/cisagov/icsnpp-s7comm)

---

## How to Run

### Prerequisites

Start Neo4j and Redpanda before running the pipeline. Guardance does not
manage these services.

```bash
# Neo4j default: bolt://localhost:7687
# Redpanda default: localhost:9092
```

### Full pipeline

```bash
python -m src.main \
    --pcap-dir data/pcaps/ICS-pcap-master/MODBUS/Modbus \
    --neo4j-uri bolt://localhost:7687 \
    --bootstrap-servers localhost:9092
```

The pipeline will:
1. Recursively scan `--pcap-dir` for `modbus.log`, `dnp3.log`, and `conn.log`
2. Parse every log file into typed Python dataclasses
3. Write parsed events directly to Neo4j (upsert Device nodes + COMMUNICATES_WITH edges)
4. Run all five detection queries against the populated graph
5. Log all findings to stdout and `logs/guardance.log`

Progress is logged every 1,000 events. The pipeline exits cleanly on
`SIGINT` (Ctrl-C) or `SIGTERM` — whichever phase is active at that moment
is allowed to finish before shutdown.

### Offline mode (no Redpanda)

Omit `--bootstrap-servers` or point it at an unreachable address. The
pipeline automatically falls back to the direct Zeek → Neo4j path.

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--pcap-dir` | `data/pcaps` | Directory tree containing Zeek log files |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `neo4j` | Neo4j password |
| `--bootstrap-servers` | `localhost:9092` | Redpanda/Kafka bootstrap servers |
| `--baseline-end` | 24 h ago | ISO 8601 cutoff for new-device/edge detection |
| `--allowed-protocols` | `modbus,dnp3,s7comm,tcp,udp` | Comma-separated protocol allowlist |
| `--log-file` | `logs/guardance.log` | Log output file |
| `--log-level` | `INFO` | Verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

All flags can also be set via environment variables (see
[Configuration Reference](#configuration-reference)).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pipeline completed without fatal errors |
| `1` | Fatal initialisation error (bad args, missing directory, etc.) |

---

## Project Layout

```
guardance/
├── src/
│   ├── ingest/
│   │   ├── zeek_parser.py     # Zeek log → typed Python dataclasses
│   │   └── producer.py        # Dataclasses → Redpanda/Kafka topics
│   ├── graph/
│   │   ├── writer.py          # ZeekEvent → Neo4j MERGE operations
│   │   └── consumer.py        # Redpanda topics → GraphWriter
│   ├── detect/
│   │   └── queries.py         # Five Cypher detection functions
│   └── main.py                # Pipeline runner (CLI entry point)
├── tests/
│   ├── test_zeek_parser.py    # Parser unit tests
│   ├── test_producer.py       # Producer unit tests
│   ├── test_writer.py         # GraphWriter unit tests
│   ├── test_consumer.py       # GraphConsumer unit tests
│   ├── test_queries.py        # Detection query unit tests
│   └── test_integration.py   # End-to-end pipeline tests
├── data/
│   └── pcaps/                 # OT capture data (not committed to git)
├── logs/                      # Runtime log output (auto-created)
└── CLAUDE.md                  # Build instructions
```

---

## Pipeline Components

### `src/ingest/zeek_parser.py`

Reads Zeek log files and yields typed Python dataclasses. Handles the full
Zeek log format including header directives (`#separator`, `#fields`,
`#types`, `#unset_field`, `#empty_field`, `#close`).

**Supported log types:**

| Log file | Dataclass | Key fields |
|----------|-----------|------------|
| `modbus.log` | `ModbusEvent` | `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`, `func`, `exception` |
| `dnp3.log` | `Dnp3Event` | `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`, `fc_request`, `fc_reply`, `iin` |
| `conn.log` | `ConnEvent` | `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`, `proto`, `service`, `duration`, `conn_state`, and 12 more |

Malformed log lines are logged at `WARNING` and skipped; the generator
continues with the next line. Files with an unrecognised `#path` directive
are silently skipped with a `DEBUG` log. The directory scanner
(`parse_log_directory`) recurses depth-first and sorts files within each
directory for deterministic ordering.

### `src/ingest/producer.py`

Publishes parsed `ZeekEvent` dataclasses to Redpanda/Kafka as JSON. Events
are serialised with ISO 8601 timestamps and routed to one of three topics
based on event type. Kafka partition keys are derived from `src_ip:dst_ip`
so that all messages on a given channel land on the same partition and
arrive in order.

**Topics:**

| Topic | Event type |
|-------|------------|
| `raw.modbus` | `ModbusEvent` |
| `raw.dnp3` | `Dnp3Event` |
| `raw.conn` | `ConnEvent` |

### `src/graph/writer.py`

Translates `ZeekEvent` dataclasses into Neo4j `MERGE` operations. Each
`ingest_event` call:

1. Upserts the source `Device` node (sets `first_seen` on create, updates
   `last_seen` on match)
2. Upserts the destination `Device` node (same)
3. Upserts the `COMMUNICATES_WITH` edge keyed by
   `(src_ip, dst_ip, protocol, port, function_code)` — increments
   `packet_count` and recomputes `avg_interval_ms` on every update

The edge key includes `function_code` so that a new Modbus function code
appearing on an established channel creates a new edge rather than silently
merging into an existing one. This makes new-edge detection sensitive to
function-code-level changes.

`is_periodic` is recomputed on every edge update: it is `true` when
`avg_interval_ms` is between 100 ms and 1000 ms (configurable via the
detection query layer).

`GraphWriter` can be used as a context manager — the underlying Neo4j driver
is closed automatically on exit.

### `src/graph/consumer.py`

Subscribes to Redpanda topics and feeds messages into `GraphWriter`. Runs a
blocking poll loop until `stop()` is called. `SIGINT` and `SIGTERM` are
caught for graceful shutdown. Deserialisation errors are logged and counted
but never propagate — a bad message cannot stop the consumer.

### `src/detect/queries.py`

Five detection functions, each accepting a `neo4j.Session` and returning
`list[dict]`. All Cypher is defined as module-level string constants so it
can be reviewed and tested independently of the Python wrapping code. See
[Detection Queries](#detection-queries) for the full specification.

### `src/main.py`

Top-level pipeline runner. Parses CLI arguments, configures logging (dual
stdout + file sink), installs signal handlers, runs the ingestion phase,
then runs the detection phase. Detection findings are logged at `WARNING`
level with full detail; clean runs are logged at `INFO`.

---

## Neo4j Schema Reference

### Constraints

Guardance creates the following uniqueness constraints on first run (via
`GraphWriter.ensure_constraints()`). All use `IF NOT EXISTS` so they are
safe to call on every startup.

| Constraint | Property |
|------------|----------|
| `device_ip` | `Device.ip` |
| `zone_name` | `Zone.name` |
| `protocol_name` | `Protocol.name` |

### Nodes

| Label | Properties | Notes |
|-------|------------|-------|
| `Device` | `ip` (unique), `mac`, `role`, `purdue_level`, `first_seen`, `last_seen` | Core node; `first_seen`/`last_seen` are Unix epoch floats |
| `Zone` | `name` (unique), `purdue_level`, `sl_t` | Purdue model level (0–5); `sl_t` = security level target |
| `Protocol` | `name` (unique), `port` | Reference node; not yet populated by the ingest pipeline |

### Relationships

| Type | Direction | Properties | Notes |
|------|-----------|------------|-------|
| `COMMUNICATES_WITH` | Device → Device | `protocol`, `port`, `function_code`, `first_seen`, `last_seen`, `packet_count`, `avg_interval_ms`, `is_periodic` | One edge per unique (src, dst, protocol, port, function_code) tuple |
| `MEMBER_OF` | Device → Zone | — | Assigned externally or via enrichment |

### Timestamp storage

All timestamps are stored as **Unix epoch floats (seconds)** rather than
Neo4j `datetime` values. This allows efficient arithmetic directly in
Cypher, e.g.:

```cypher
WHERE d.first_seen > $baseline_end   // both are epoch floats
WHERE (r.last_seen - r.first_seen) * 1000.0 / r.packet_count BETWEEN 100 AND 1000
```

---

## Detection Queries

All queries live in `src/detect/queries.py` and accept a `neo4j.Session`
(or any object with a `.run(query, **params)` method, making them trivially
mockable in tests).

### 1. `cross_zone_violations(session)`

```cypher
MATCH (d1:Device)-[r:COMMUNICATES_WITH]->(d2:Device)
MATCH (d1)-[:MEMBER_OF]->(z1:Zone)
MATCH (d2)-[:MEMBER_OF]->(z2:Zone)
WHERE abs(z1.purdue_level - z2.purdue_level) > 1
RETURN d1.ip, d2.ip, z1.name, z2.name, z1.purdue_level, z2.purdue_level,
       r.protocol, r.port, r.packet_count
ORDER BY abs(z1.purdue_level - z2.purdue_level) DESC
```

Returns device pairs communicating across non-adjacent Purdue levels.
Only devices with a `MEMBER_OF` edge to a Zone are considered; unzoned
devices are excluded.

**Returns:** `src_ip`, `dst_ip`, `src_zone`, `dst_zone`, `src_level`,
`dst_level`, `protocol`, `port`, `packet_count`

---

### 2. `new_devices(session, baseline_end: datetime)`

```cypher
MATCH (d:Device)
WHERE d.first_seen > $baseline_end
RETURN d.ip, d.mac, d.role, d.first_seen, d.last_seen
ORDER BY d.first_seen ASC
```

Returns devices whose `first_seen` timestamp is strictly after `baseline_end`.
`baseline_end` is a Python `datetime`; the function converts it to an epoch
float before passing it to Cypher.

**Returns:** `ip`, `mac`, `role`, `first_seen`, `last_seen`

---

### 3. `new_edges(session, baseline_end: datetime)`

```cypher
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE r.first_seen > $baseline_end
RETURN src.ip, dst.ip, r.protocol, r.port, r.function_code,
       r.first_seen, r.packet_count
ORDER BY r.first_seen ASC
```

Returns communication edges first observed after the baseline period.

**Returns:** `src_ip`, `dst_ip`, `protocol`, `port`, `function_code`,
`first_seen`, `packet_count`

---

### 4. `interval_deviation(session, min_ms=100.0, max_ms=1000.0)`

```cypher
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE r.packet_count > 1
  AND (r.avg_interval_ms < $min_ms OR r.avg_interval_ms > $max_ms)
RETURN src.ip, dst.ip, r.protocol, r.port, r.function_code,
       r.avg_interval_ms, r.packet_count, r.is_periodic
ORDER BY r.avg_interval_ms ASC
```

Returns edges whose computed polling interval falls outside `[min_ms,
max_ms]`. Only edges with more than one packet are considered (a single
packet has no interval). The default window of 100–1000 ms covers typical
OT polling rates; adjust for your environment.

**Returns:** `src_ip`, `dst_ip`, `protocol`, `port`, `function_code`,
`avg_interval_ms`, `packet_count`, `is_periodic`

---

### 5. `unknown_protocol(session, allowed: list[str])`

```cypher
MATCH (src:Device)-[r:COMMUNICATES_WITH]->(dst:Device)
WHERE NOT r.protocol IN $allowed
RETURN src.ip, dst.ip, r.protocol, r.port, r.function_code,
       r.packet_count, r.first_seen
ORDER BY r.first_seen ASC
```

Returns edges using a protocol not present in `allowed`. The default
allowlist (`modbus`, `dnp3`, `s7comm`, `tcp`, `udp`) covers typical OT
segments; shrink it for stricter environments.

**Returns:** `src_ip`, `dst_ip`, `protocol`, `port`, `function_code`,
`packet_count`, `first_seen`

---

## How to Extend Detection Queries

All detection logic lives in `src/detect/queries.py`. Each function follows
the same pattern: a module-level Cypher string constant and a typed Python
wrapper that accepts a session and returns `list[dict]`.

**Step 1 — Write the Cypher:**

```python
_DEVICES_WITHOUT_ZONE = """
MATCH (d:Device)
WHERE NOT (d)-[:MEMBER_OF]->(:Zone)
RETURN d.ip AS ip, d.first_seen AS first_seen
ORDER BY d.first_seen ASC
"""
```

**Step 2 — Wrap it in a typed function:**

```python
def devices_without_zone(session: Any) -> list[dict]:
    """Return Device nodes not assigned to any Zone."""
    logger.debug("Running devices_without_zone query")
    result = session.run(_DEVICES_WITHOUT_ZONE)
    rows = [dict(record) for record in result]
    logger.info("devices_without_zone: %d findings", len(rows))
    return rows
```

**Step 3 — Call it from `src/main.py`:**

In `run_detection()`, add:

```python
results["devices_without_zone"] = devices_without_zone(session)
```

**Step 4 — Add tests:**

In `tests/test_queries.py`, use the `_session_returning()` helper to mock
the Neo4j session:

```python
def test_devices_without_zone_returns_results():
    session = _session_returning([{"ip": "10.0.0.5", "first_seen": 1700000000.0}])
    results = devices_without_zone(session)
    assert len(results) == 1
    assert results[0]["ip"] == "10.0.0.5"
```

---

## Configuration Reference

All CLI flags have environment variable equivalents. Environment variables
are read when the flag is not explicitly set on the command line.

| Environment variable | Corresponding flag | Default |
|---------------------|--------------------|---------|
| `NEO4J_URI` | `--neo4j-uri` | `bolt://localhost:7687` |
| `NEO4J_USER` | `--neo4j-user` | `neo4j` |
| `NEO4J_PASSWORD` | `--neo4j-password` | `neo4j` |
| `NEO4J_DATABASE` | — | `neo4j` |
| `REDPANDA_BOOTSTRAP_SERVERS` | `--bootstrap-servers` | `localhost:9092` |
| `REDPANDA_TOPIC_PREFIX` | — | `""` (empty) |
| `REDPANDA_CONSUMER_GROUP` | — | `guardance-graph` |
| `REDPANDA_AUTO_OFFSET_RESET` | — | `earliest` |
| `REDPANDA_POLL_TIMEOUT_S` | — | `1.0` |

`REDPANDA_TOPIC_PREFIX` is prepended to all topic names, useful for
multi-tenant Redpanda clusters (e.g. `REDPANDA_TOPIC_PREFIX=prod.` gives
`prod.raw.modbus`).

---

## Running Tests

```bash
pytest tests/ -v
```

All tests mock both Neo4j and Redpanda — no live services are required.

Real PCAP log files under `data/pcaps/ICS-pcap-master/` are used for
smoke-tests in `test_integration.py`. Those tests are automatically skipped
if the directory is absent, so the test suite is fully portable.

### Test coverage by module

| Test file | What it covers |
|-----------|----------------|
| `test_zeek_parser.py` | Header parsing, field mapping, type coercion, malformed lines, empty files, multi-file directory scan |
| `test_producer.py` | JSON serialisation, topic routing, partition key derivation, delivery callbacks, error handling |
| `test_writer.py` | Device node upsert, edge upsert, packet count accumulation, `avg_interval_ms` computation, `is_periodic` flag, constraint creation |
| `test_consumer.py` | Message deserialisation round-trips, unknown topic handling, `PARTITION_EOF` handling, signal-driven shutdown |
| `test_queries.py` | All five detection functions with mocked sessions, parameter binding, empty-result cases |
| `test_integration.py` | Full pipeline with real PCAP data, mocked Neo4j + Redpanda, end-to-end event count assertions, detection query output validation |

---

## Roadmap

Phase 1 (this repository) is complete. Planned Phase 2 additions:

- **OPA policy enforcement** — move detection rules into Rego policies for
  runtime-configurable allowlists and cross-zone rules
- **Spark integration** — streaming aggregation for high-volume segments
- **Web UI** — graph visualisation and finding triage dashboard
- **Docker Compose** — single-command stack bring-up
- **Authentication** — API keys and role-based access for the UI

---

## License

MIT
