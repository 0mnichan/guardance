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
data/pcaps/ICS-pcap-master/ — real OT captures including Modbus, S7, DNP3, EIP, BACnet, IEC104, HART including Modbus, DNP3, S7

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

## Continuation Instructions
All Step 1-4 code exists and 106 tests pass. Continue from Step 5.

Step 5: Build src/detect/queries.py
- Five Cypher detection queries as Python functions using neo4j driver
- cross_zone_violations(), new_devices(), new_edges(), interval_deviation(), unknown_protocol()
- Each returns a list of dicts from Neo4j
- Tests in tests/test_queries.py using a mock Neo4j driver

Step 6: Build src/main.py
- Wires the full pipeline end to end
- Reads PCAPs from data/pcaps/, runs through zeek_parser
- Feeds producer into Redpanda
- Consumer writes to Neo4j
- Runs detection queries and logs results

Do NOT start Neo4j or Redpanda — assume they are already running.
Do NOT install system packages.
Only work inside ~/Desktop/guardance_v1/

## Continuation — Morning Session
Steps 1-4 complete, 72 tests passing (38 parser + 34 producer).
Writer and consumer code exists but needs Neo4j/Redpanda to test.

Continue with Step 5 ONLY:

Build src/detect/queries.py
- Five detection functions using the neo4j Python driver
- cross_zone_violations(session) 
- new_devices(session, baseline_end: datetime)
- new_edges(session, baseline_end: datetime)
- interval_deviation(session, min_ms=100, max_ms=1000)
- unknown_protocol(session, allowed: list[str])
- Each returns list[dict]
- Mock the neo4j driver in tests — do NOT start Neo4j
- Tests in tests/test_queries.py

Stop after test_queries.py passes.
Do not proceed to Step 6 without being asked.
Only work inside ~/Desktop/guardance_v1/
Do not run apt, sudo, or system commands.

## Continuation — Unsupervised Build
Steps 1-4 complete, 72 tests passing (38 parser + 34 producer).
src/graph/writer.py and src/graph/consumer.py exist but untested.

Build everything remaining autonomously. Do not stop and ask for confirmation between steps. Complete the entire Phase 1 pipeline end to end.

## Remaining steps in order:

### Step 5: src/detect/queries.py
- Five detection functions using neo4j Python driver
- cross_zone_violations(session)
- new_devices(session, baseline_end: datetime)
- new_edges(session, baseline_end: datetime)
- interval_deviation(session, min_ms=100, max_ms=1000)
- unknown_protocol(session, allowed: list[str])
- Each returns list[dict]
- Mock neo4j driver in tests — do NOT start Neo4j
- Tests in tests/test_queries.py

### Step 6: src/main.py
- Top-level runner wiring the full pipeline
- Accepts --pcap-dir, --neo4j-uri, --bootstrap-servers as CLI args
- Reads all Zeek logs from pcap dir
- Publishes to Redpanda via producer
- Consumer writes to Neo4j
- Runs all 5 detection queries
- Logs results to stdout and logs/guardance.log
- Graceful shutdown on SIGINT/SIGTERM

### Step 7: Integration test
- tests/test_integration.py
- Uses real Zeek log files from data/pcaps/
- Mocks Neo4j and Redpanda
- Runs the full pipeline end to end
- Asserts detection queries return expected results given known input

### Step 8: README.md
- Project overview using the Guardance description
- Architecture diagram in ASCII
- Installation instructions
- How to run
- How to extend detection queries
- License: MIT

## When complete
Run the full test suite: pytest tests/ -v
All tests must pass before considering done.
Report final test count and any issues found.

## Constraints
- Only work inside ~/Desktop/guardance_v1/
- Do not run apt, sudo, or system-level commands
- Only pip for Python packages
- Do not start Neo4j or Redpanda — mock them in tests
- Handle all errors gracefully — never crash on bad data
- Type hints and docstrings on everything
- Logging over print statements throughout
