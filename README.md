# Guardance

Passive OT/ICS network security monitor.

Guardance ingests real OT protocol traffic, builds a Neo4j graph of device
behaviour, and detects anomalies using Cypher queries.  OT networks are one of
the few environments where normal behaviour is genuinely enumerable — a PLC
polling a field sensor does the same thing every 250 ms for years.  Guardance
models that reality completely: any deviation is immediately visible.

**Detection inevitability.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Data Sources                                │
│  PCAPs  ──►  Zeek + ICSNPP  ──►  modbus.log / dnp3.log / conn.log  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ parse_zeek_log()
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Ingest Layer  (src/ingest/)                     │
│  ZeekEventProducer  ──►  Redpanda topics                            │
│      raw.modbus  /  raw.dnp3  /  raw.conn                           │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ JSON messages
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Graph Layer  (src/graph/)                       │
│  GraphConsumer  ──►  deserialize_message()  ──►  GraphWriter        │
│                                                      │              │
│                            Neo4j 5.x Community       │              │
│  ┌──────────────┐   COMMUNICATES_WITH   ┌────────────▼───────────┐  │
│  │  Device      │ ──────────────────►  │  Device                │  │
│  │  {ip, mac,   │                       │  {ip, mac, role,       │  │
│  │   role,      │                       │   purdue_level,        │  │
│  │   purdue_lvl}│                       │   first_seen,          │  │
│  └──────┬───────┘                       │   last_seen}           │  │
│         │ MEMBER_OF                     └────────────────────────┘  │
│         ▼                                                            │
│  ┌──────────────┐                                                    │
│  │  Zone        │                                                    │
│  │  {name,      │                                                    │
│  │   purdue_lvl}│                                                    │
│  └──────────────┘                                                    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Detection Layer  (src/detect/)                    │
│  1. cross_zone_violations  — Purdue level jump > 1                  │
│  2. new_devices            — first_seen > baseline_end              │
│  3. new_edges              — relationship first_seen > baseline_end │
│  4. interval_deviation     — avg_interval_ms outside [100, 1000] ms │
│  5. unknown_protocol       — protocol not in allowlist              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Requirements

- Python 3.11+
- Neo4j 5.x Community (running on `bolt://localhost:7687`)
- Redpanda or Kafka (running on `localhost:9092`)
- Zeek with ICSNPP plugins (for producing `.log` files from PCAPs)

Python packages:

```
pip install neo4j confluent-kafka pytest
```

---

## Installation

```bash
git clone <repo>
cd guardance_v1
pip install neo4j confluent-kafka pytest
```

---

## How to Run

### Full pipeline

```bash
python -m src.main \
    --pcap-dir data/pcaps/ICS-pcap-master/MODBUS/Modbus \
    --neo4j-uri bolt://localhost:7687 \
    --bootstrap-servers localhost:9092
```

All flags and their defaults:

| Flag | Default | Description |
|------|---------|-------------|
| `--pcap-dir` | `data/pcaps` | Directory tree containing Zeek log files |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `neo4j` | Neo4j password |
| `--bootstrap-servers` | `localhost:9092` | Redpanda/Kafka bootstrap servers |
| `--baseline-end` | 24 h ago | ISO 8601 cutoff for new-device/edge detection |
| `--allowed-protocols` | `modbus,dnp3,s7comm,tcp,udp` | Comma-separated allowlist |
| `--log-file` | `logs/guardance.log` | Log output file |
| `--log-level` | `INFO` | Verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

Environment variable equivalents: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`,
`REDPANDA_BOOTSTRAP_SERVERS`, `REDPANDA_TOPIC_PREFIX`.

### Run tests

```bash
pytest tests/ -v
```

Tests mock both Neo4j and Redpanda — no live services required.  Real PCAP log
files under `data/pcaps/ICS-pcap-master/` are used only for smoke-tests and
are skipped automatically if absent.

---

## Project Layout

```
guardance_v1/
├── src/
│   ├── ingest/
│   │   ├── zeek_parser.py     # Zeek log → Python dataclasses
│   │   └── producer.py        # Dataclasses → Redpanda topics
│   ├── graph/
│   │   ├── writer.py          # ZeekEvent → Neo4j MERGE operations
│   │   └── consumer.py        # Redpanda topics → GraphWriter
│   ├── detect/
│   │   └── queries.py         # Five Cypher detection functions
│   └── main.py                # Pipeline runner (CLI entry point)
├── tests/
│   ├── test_zeek_parser.py
│   ├── test_producer.py
│   ├── test_writer.py
│   ├── test_consumer.py
│   ├── test_queries.py
│   └── test_integration.py
├── data/
│   └── pcaps/                 # OT capture data (not committed)
├── logs/                      # Runtime log output
└── CLAUDE.md                  # Build instructions
```

---

## How to Extend Detection Queries

All detection logic lives in `src/detect/queries.py`.  Each function accepts a
`neo4j.Session` and returns `list[dict]`.

To add a new query:

1. Write the Cypher in a module-level string constant:

```python
_MY_QUERY = """
MATCH (d:Device)
WHERE d.purdue_level IS NULL
RETURN d.ip AS ip
"""
```

2. Wrap it in a typed function:

```python
def devices_without_zone(session: Any) -> list[dict]:
    """Return devices not assigned to any Zone."""
    result = session.run(_MY_QUERY)
    return [dict(record) for record in result]
```

3. Call it from `src/main.py`'s `run_detection()` alongside the existing queries.

4. Add tests in `tests/test_queries.py` using `_session_returning()`.

---

## Neo4j Schema Reference

### Nodes

| Label | Key properties |
|-------|----------------|
| `Device` | `ip` (unique), `mac`, `role`, `purdue_level`, `first_seen`, `last_seen` |
| `Zone` | `name` (unique), `purdue_level`, `sl_t` |
| `Protocol` | `name` (unique), `port` |

### Relationships

| Type | From → To | Key properties |
|------|-----------|----------------|
| `COMMUNICATES_WITH` | Device → Device | `protocol`, `port`, `function_code`, `first_seen`, `last_seen`, `packet_count`, `avg_interval_ms`, `is_periodic` |
| `MEMBER_OF` | Device → Zone | — |

Timestamps are stored as Unix epoch floats (seconds) for efficient Cypher arithmetic.

---

## License

MIT