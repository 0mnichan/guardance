cat > CLAUDE.md << 'EOF'
# Guardance — Passive OT/ICS Network Security Monitor

## What this is
Guardance is a passive OT/ICS network security monitoring platform.
It ingests real OT protocol traffic, builds a Neo4j graph of device
behavior, and detects anomalies using Cypher queries and OPA policies.

## Core thesis
OT networks are one of the few environments where normal behavior is
genuinely enumerable. A PLC polling a field sensor does the same thing
every 250ms for years. Guardance models that reality completely —
any deviation is immediately visible. Detection inevitability.

## The pipeline (build in this order)
PCAP → Zeek/ICSNPP → Kafka/Redpanda → Python consumers → Neo4j → Detection

## Phase 1 goal (what to build now)
A working pipeline that:
1. Reads OT PCAPs through Zeek with ICSNPP plugins
2. Parses modbus.log, dnp3.log, s7comm.log, conn.log
3. Ingests parsed events into Redpanda topics (raw.modbus, raw.dnp3, raw.s7)
4. Python consumer reads from topics and populates Neo4j graph
5. Neo4j schema: Device nodes, Zone nodes, COMMUNICATES_WITH edges
6. Basic Cypher detection queries run on the populated graph

## Neo4j schema
Nodes:
- Device {ip, mac, role, purdue_level, first_seen, last_seen}
- Zone {name, purdue_level, sl_t}
- Protocol {name, port}

Relationships:
- COMMUNICATES_WITH {protocol, port, function_code, first_seen,
  last_seen, packet_count, avg_interval_ms, is_periodic}
- MEMBER_OF (Device → Zone)

## Detection queries to implement
1. Cross-zone violations (abs(z1.level - z2.level) > 1)
2. New device detection (first_seen > baseline_end)
3. New edge detection (relationship first_seen > baseline_end)
4. Polling interval deviation (avg_interval_ms outside 100-1000ms)
5. Unknown protocol on OT device

## Stack
- Zeek + ICSNPP: protocol parsing
- Redpanda: message broker (Kafka-compatible)
- Python: consumers, enrichment, graph population
- Neo4j 5.x Community: graph database
- OPA: policy enforcement (Phase 2)

## PCAPs available at
data/pcaps/ — real OT captures including Modbus, DNP3, S7

## What NOT to build
- No web UI yet
- No authentication yet  
- No OPA yet (Phase 2)
- No Spark yet (Phase 2)
- No Docker (run locally for now)

## Code style
- Python only, no JS
- Type hints everywhere
- Every function has a docstring
- Logging over print statements
- Config via environment variables or config.yaml
- Tests for every module in tests/

## Run tests after every major component
Use pytest. Tests should use real PCAP data from data/pcaps/

## The standard
This is a real security product, not a demo. Code quality matters.
Error handling matters. If Zeek produces a malformed log line,
the pipeline should log it and continue, not crash.
EOF
