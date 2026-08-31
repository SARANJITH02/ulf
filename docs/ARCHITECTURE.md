# ULPF Architectural Design & Specification
## Universal Log Pre-processing Framework — Containerized Middleware Gateway

### 1. High-Level System Architecture

ULPF is engineered as a zero-cloud, air-gapped security telemetry pre-processing middleware gateway designed to sit between enterprise perimeter log emitters (Firewalls, IDS/IPS, Cloud Gateways, Endpoint Sensors) and destination SIEM/Data Lakes (ArcSight, IBM QRadar, Splunk, Elastic, Sentinel).

```
                  ┌──────────────────────────────────────────────┐
                  │          PERIMETER LOG EMITTERS              │
                  │  (Cisco ASA, Palo Alto, Suricata, AWS, etc.) │
                  └───────────────────────┬──────────────────────┘
                                          │ Syslog UDP/TCP (1514) / REST (8080)
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ULPF STANDALONE MIDDLEWARE GATEWAY                              │
│                                                                                        │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 1. INGESTION & CRYPTOGRAPHIC LINEAGE LAYER (Zero-Loss Preservation)                │ │
│ │  - Netty UDP/TCP Syslog Listeners + Spring REST Ingestion Endpoint                 │ │
│ │  - Immediate Bit-Exact SHA-256 Digest Calculation & RAW-UUID Generation            │ │
│ │  - Immutable Raw Storage in Database                                               │ │
│ └──────────────────────────────────────┬─────────────────────────────────────────────┘ │
│                                        ▼                                               │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 2. LOG FORMAT SIGNATURE CLASSIFIER                                                 │ │
│ │  - Fast Regex & Structural Pattern Matching: RFC5424, RFC3164/Cisco, CEF, LEEF,    │ │
│ │    JSON, CSV, KV-Pairs, and UNKNOWN                                                │ │
│ └──────────────────────────────────────┬─────────────────────────────────────────────┘ │
│                                        ▼                                               │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 3. PARSING & TWO-STAGE INFERENCE ENGINE                                            │ │
│ │  ┌─────────────────────────────────┐   ┌─────────────────────────────────────────┐ │ │
│ │  │ Hot-Registered Dynamic Parsers  │   │ Two-Stage Drain Inference Engine        │ │ │
│ │  │ (Priority 1 in memory)          │   │ Stage 1: Drain Tree Template Mining     │ │ │
│ │  ├─────────────────────────────────┤   │ Stage 2: Deterministic Semantic Typing  │ │ │
│ │  │ Native Parser Plugins           │   │ Synthesis: Group Regex & OCSF Mapping   │ │ │
│ │  │ (Syslog, CEF/LEEF, JSON, CSV)   │   │ Gate: Mandatory Operator Approval       │ │ │
│ │  └─────────────────────────────────┘   └─────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────┬─────────────────────────────────────────────┘ │
│                                        ▼                                               │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 4. NORMALIZATION & OFFLINE ENRICHMENT LAYER                                        │ │
│ │  - Canonical OCSF v1.1.0 JSON Construction + ECS Compatibility Aliasing            │ │
│ │  - Offline RFC1918 Private/Public IP Categorization (Zero DNS/Cloud lookup)         │ │
│ │  - Offline IANA Port-to-Service Resolution (Embedded Port Map)                     │ │
│ │  - Offline MITRE ATT&CK Heuristic Tagging                                          │ │
│ └──────────────────────────────────────┬─────────────────────────────────────────────┘ │
│                                        ▼                                               │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 5. GOVERNANCE, AUDIT & MULTI-SIEM EXPORT LAYER                                     │ │
│ │  - Cryptographic Non-Repudiation Verification Engine (/verify)                     │ │
│ │  - Dead-Letter Queue (DLQ) Quarantine & Retry Broker                               │ │
│ │  - Reverse Wire Exporters: ArcSight CEF Wire, IBM QRadar LEEF Wire, Elastic ECS    │ │
│ │  - Realtime STOMP WebSocket Live Telemetry Stream (/topic/metrics, /topic/events)  │ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 2. Core Subsystem Breakdown

#### 2.1 Cryptographic Lineage & Integrity
1. **Pre-Parse SHA-256 Computation:** Before any string mutation or parsing begins, `CryptographicLineageService` calculates the SHA-256 digest over the raw UTF-8 bytes and generates a deterministic `RAW-[UUID]` identifier.
2. **Normalized Traceability:** The resulting `NormalizedEvent` inherits the `rawEventId` and `rawHashSha256` in its primary keys and metadata payload.
3. **On-Demand Non-Repudiation Audit:** The verification endpoint (`/api/v1/events/{id}/verify`) fetches both the normalized record and the underlying raw record, recomputes the SHA-256 digest on-the-fly from the stored raw message string, and verifies that the stored pre-parse hash matches the recomputed hash with zero discrepancy.

#### 2.2 Two-Stage Unknown Log Inference Engine
1. **Stage 1 (Drain Tree Template Mining):**
   - Implemented in pure Java (`DrainStyleTemplateMiner`) with zero external machine learning libraries.
   - Groups incoming raw logs by sequence length and traverses a bounded-depth prefix tree (`MAX_DEPTH = 4`).
   - Identifies dynamic/variable slots (IPs, Ports, Numbers, Hashes, Timestamps, KV pairs) and replaces them with `<*>`.
2. **Stage 2 (Deterministic Semantic Field Recognition):**
   - `SemanticFieldRecognizer` evaluates each extracted variable slot using deterministic pattern matching.
   - Accurately identifies IPv4 addresses (and compound `ip:port`), port integers, protocol tokens, security actions (`allowed`, `blocked`, `dropped`, `denied`), timestamps, and vendor codes.
   - Maps each slot into canonical OCSF dot-notation paths (`source.ip`, `destination.port`, `event.action`, etc.).
   - Computes weighted confidence scores per field.
3. **Stage 3 (Dynamic Parser Synthesis):**
   - Synthesizes regex with named capture groups `(?<token0>\\S+)` and instantiates a `DynamicGeneratedParser`.
4. **Human Operator Approval Gate:**
   - Inferred parsers are strictly placed in a pending state until an authorized operator clicks **"Approve & Register Parser"** in the Unknown Log Lab.
   - Upon approval, `DynamicParserRegistry.registerApprovedParser()` hot-loads the parser into JVM concurrent memory with zero downtime or container restart.

#### 2.3 Air-Gapped Offline Enrichment
- **RFC1918 Classifier:** Validates `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and Loopback `127.0.0.0/8` subnets locally using fast bitwise bitmasks without performing DNS or external API queries.
- **IANA Dictionary:** Embedded offline JSON (`iana_ports.json`) resolving standard port mappings (`22` → `SSH`, `53` → `DNS`, `80` → `HTTP`, `443` → `HTTPS`, etc.).
- **MITRE ATT&CK Mapper:** Embedded heuristic rules (`mitre_rules.json`) classifying suspicious perimeter drop signatures (e.g. `T1110` Brute Force, `T1046` Network Service Scanning).

#### 2.4 Realtime Streaming & WebSocket STOMP
- Netty event loops process incoming UDP and TCP syslog packets on port `1514` and hand off messages asynchronously to the `IngestionService`.
- `LivePipelineMetrics` computes sliding EPS throughput and percentile latencies (`p50`, `p95`, `p99`).
- `MetricsBroadcaster` publishes live metric pulses every second to `/topic/metrics` and live normalized events to `/topic/events`.
