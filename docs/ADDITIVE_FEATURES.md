# ULPF: Missing Differentiators Architecture & Reference Guide

This document describes the three enterprise-grade differentiators and persistent storage architecture added to the **Universal Log Parser & Forwarder (ULPF)** platform without altering existing ingestion or parser-miner core code.

---

## 1. Architectural Overview

```
+---------------------------------------------------------------------------------------------------+
|                                  ULPF PIPELINE FLOW                                               |
+---------------------------------------------------------------------------------------------------+
| 1. Ingestion (Netty UDP/TCP 1514 | REST API)                                                      |
| 2. Classification & Format Identification (Syslog RFC, CEF, LEEF, JSON, CSV, Dynamic Inferred)   |
| 3. Normalization -> OCSF Schema v1.1.0 + ECS Aliases                                              |
| 4. Offline Enrichment:                                                                            |
|    - RFC1918 Private/Public IP Classification                                                     |
|    - IANA Port Services (49 offline signatures)                                                   |
|    - Heuristic MITRE ATT&CK Tactic & Technique Tagging                                            |
| 5. [NEW] Embedded Sigma Detection Rule Engine                                                     |
|    - Standard Perimeter YAML Rules -> Air-Gapped Regex & OCSF Evaluator                           |
|    - Tagged Detections -> Broadcast to Unified STOMP Topic (/topic/alerts)                        |
| 6. Validation & Dead-Letter Queue (DLQ)                                                           |
| 7. Event Persistence & Lineage (Raw SHA-256 Digest + Canonical Event Record)                      |
| 8. [NEW] Merkle Batching & Append-Only JSONL Audit Ledger                                         |
|    - Periodic Hourly / On-Demand Binary Merkle Tree Batching (RFC 6962)                           |
|    - Appended to persistent ledger file: ./data/ledger/merkle-ledger.jsonl                        |
|    - Zero-Knowledge O(log N) Inclusion Proof Generation & Third-Party Export Bundles              |
| 9. [NEW] Parser Quality Drift Monitor                                                             |
|    - 5-Minute Sliding Window Evaluator (Confidence & DLQ Drop)                                    |
|    - Threshold Breach Alerts -> Broadcast to Unified STOMP Topic (/topic/alerts)                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Storage Architecture & Persistence Prerequisite

### 2.1 File-Backed H2 Primary Datastore
- **JDBC URL**: `jdbc:h2:file:./data/db/ulpfdb;AUTO_SERVER=TRUE;DB_CLOSE_DELAY=-1`
- **Location**: `./data/db/ulpfdb.mv.db`
- **Behavior**: Preserves all parsed logs, dynamic parsers, operator rules, user accounts, Merkle batches, Sigma detection history, and drift alerts across process restarts without losing state.

### 2.2 Independent Append-Only Merkle Ledger
- **Ledger Path**: `./data/ledger/merkle-ledger.jsonl`
- **Format**: JSON Lines (`.jsonl`), strictly append-only.
- **Entry Structure**:
  ```json
  {
    "batchId": "BATCH-c0a32fd9-94c6-42ae-a374-6635f43246fd",
    "batchNumber": 1,
    "periodStart": "2026-09-03T04:00:00Z",
    "periodEnd": "2026-09-03T04:10:00Z",
    "eventCount": 2,
    "merkleRoot": "97c061f5451265f6f5d71bfe8d58bfc1093b12d0a430e9340edf051e083ae3a3",
    "leafOrderEventIds": ["RAW-0001-TEST", "RAW-0002-TEST"],
    "createdAt": "2026-09-03T04:10:19.855Z"
  }
  ```

---

## 3. Feature 1: Merkle-Batched Cryptographic Audit Ledger

### 3.1 Binary Merkle Tree Construction
- **Algorithm**: Standard Binary Merkle Tree using `SHA-256`.
- **Leaf Hashing**: Raw log message pre-parse SHA-256 digest (`rawHashSha256`).
- **Internal Nodes**: `SHA256(left_sibling + right_sibling)`.
- **Odd-Leaf Handling**: If a level has an odd number of nodes, the last node is duplicated (`SHA256(last + last)`).
- **Inclusion Proofs**: Generates deterministic sibling paths with directional flags (`LEFT` / `RIGHT`), enabling $O(\log N)$ third-party verification without exposing any other log payload in the batch.

### 3.2 REST API Endpoints
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/v1/audit/merkle-batches` | `ANALYST`, `ADMIN` | List all published Merkle batches |
| `GET` | `/api/v1/audit/merkle-batches/{id}` | `ANALYST`, `ADMIN` | Get single batch details and leaf event list |
| `GET` | `/api/v1/audit/merkle-batches/{id}/export` | `ANALYST`, `ADMIN` | Download signed standalone JSON audit package |
| `POST` | `/api/v1/audit/merkle-batches/trigger` | `ADMIN` (Locked) | Trigger immediate batch generation for unbatched events |
| `GET` | `/api/v1/events/{id}/verify-inclusion` | `ANALYST`, `ADMIN` | Verify Merkle inclusion proof for a specific event |

---

## 4. Feature 2: Embedded Sigma Detection Rule Engine

### 4.1 Specification & Capabilities
- Air-gapped Sigma subset evaluator operating directly in memory against normalized `OcsfSchema`.
- Supports field modifiers: `|contains`, `|startswith`, `|endswith`, `|re` (regular expressions), `|all`.
- Supports Boolean condition logic (`selection1 and selection2`, `selection1 or selection2`, `selection`).
- Zero external dependencies: parsed via `jackson-dataformat-yaml` and compiled into Java regex and predicate trees.

### 4.2 MITRE ATT&CK Aligned Starter Rule Pack
All 9 starter Sigma rules are bundled in `backend/src/main/resources/sigma_rules/` and strictly align with the platform's core MITRE techniques:

1. `SIGMA-T1110-SSH-001`: SSH Brute Force Authentication Failure (`T1110` / Credential Access)
2. `SIGMA-T1110-RDP-002`: RDP Remote Desktop Brute Force Attempt (`T1110` / Credential Access)
3. `SIGMA-T1046-SCAN-001`: Network Service Discovery and Port Scanning (`T1046` / Discovery)
4. `SIGMA-T1046-CISCO-002`: Cisco Firewall Teardown or Port Scan Signature (`T1046` / Discovery)
5. `SIGMA-T1071-C2PORT-001`: Outbound Traffic to Known C2 / Trojan Ports (`T1071` / Command and Control)
6. `SIGMA-T1071-IRC-002`: IRC or Botnet Protocol Tunneling (`T1071` / Command and Control)
7. `SIGMA-T1552-TELNET-001`: Cleartext Telnet Management Traffic (`T1552` / Credential Access)
8. `SIGMA-T1552-FTP-002`: Cleartext FTP Unsecured Authentication Protocol (`T1552` / Credential Access)
9. `SIGMA-T1048-DNS-001`: DNS Tunneling or Exfiltration Query Burst (`T1048` / Exfiltration)

### 4.3 REST API Endpoints
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/v1/rules/sigma` | `ANALYST`, `ADMIN` | List all loaded Sigma rules |
| `GET` | `/api/v1/rules/sigma/{id}` | `ANALYST`, `ADMIN` | Get rule YAML definition |
| `POST` | `/api/v1/rules/sigma` | `ADMIN` | Upload / compile new Sigma YAML rule |
| `PATCH` | `/api/v1/rules/sigma/{id}` | `ADMIN` | Enable / disable / update rule |
| `DELETE` | `/api/v1/rules/sigma/{id}` | `ADMIN` | Delete custom rule |
| `GET` | `/api/v1/alerts` | `ANALYST`, `ADMIN` | Search recorded Sigma matches |

---

## 5. Feature 3: Parser Drift Detection

### 5.1 Drift Detection Logic
- **Execution Interval**: Every 5 minutes (via `@Scheduled` cron `0 */5 * * * *`).
- **Rolling Window**: Last 100 events or 15 minutes of normalized traffic per parser.
- **Formulas**:
  - $\text{Confidence Drop} = \text{Baseline Confidence} - \text{Current Average Confidence}$
  - $\text{Success Rate} = \frac{\text{Normalized Count}}{\text{Normalized Count} + \text{DLQ Count}}$
- **Alert Triggers**:
  - $\text{Confidence Drop} \ge 0.15$ (15% drop) $\rightarrow$ `DRIFT_ALERT` (`OPEN`)
  - $\text{Success Rate} < 0.85$ (15% DLQ failure) $\rightarrow$ `DRIFT_ALERT` (`OPEN`)
- **Persistence & Deduping**: Stores `DriftAlert` entity in database; prevents spamming open alerts for the same parser within 15 minutes.

### 5.2 REST API Endpoints
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/v1/parsers/{name}/drift` | `ANALYST`, `ADMIN` | Get live drift metrics & sparkline history |
| `GET` | `/api/v1/parsers/drift-alerts` | `ANALYST`, `ADMIN` | List active / acknowledged drift alerts |
| `PATCH` | `/api/v1/parsers/drift-alerts/{id}/acknowledge` | `ADMIN` | Acknowledge open drift alert |
| `POST` | `/api/v1/parsers/drift/check` | `ADMIN` | Trigger immediate on-demand drift check |

---

## 7. Feature 4: Auto Root-Cause Correlation Engine

### 7.1 Deterministic Correlation Model & Core Principles
- **Zero Machine Learning**: Relies strictly on shared entity keys, sliding time windows, and deterministic MITRE Enterprise kill-chain tactic sequencing.
- **Correlation Keys**:
  - Primary Key: `source.ip` (e.g. `192.168.1.105`).
  - Secondary Key: `source.user` (e.g. `secops_admin`) to track compromised identity movement across multiple source IPs.
- **Promotion Threshold**: A group of related detections is promoted to a `CorrelatedIncident` **ONLY if it spans $\ge 2$ distinct MITRE tactics** within the sliding window (default 30 minutes, `ulpf.correlation.window-minutes`). Single-tactic bursts (e.g. 50 SSH brute-force hits) are treated as ongoing single detections, not multi-stage attack incidents.
- **Kill-Chain Progression Sequence**:
  $$\text{Reconnaissance} \rightarrow \text{Resource Dev} \rightarrow \text{Initial Access} \rightarrow \text{Execution} \rightarrow \text{Persistence} \rightarrow \text{Privilege Escalation} \rightarrow \text{Defense Evasion} \rightarrow \text{Credential Access} \rightarrow \text{Discovery} \rightarrow \text{Lateral Movement} \rightarrow \text{Collection} \rightarrow \text{Command and Control} \rightarrow \text{Exfiltration} \rightarrow \text{Impact}$$
- **Root Cause Framing (Mandatory Explicit Principle)**:
  > *The "root cause" is explicitly a **heuristic hypothesis** representing the earliest observed initiating event in the correlated sequence, not a proven causal certainty.*
  This wording is rendered verbatim across narrative templates, API documentation, and UI components.

### 7.2 Severity Formula
$$\text{Base Score} = \max(\text{Severity}(\text{Member Alerts}))$$
$$\text{Score}(\text{CRITICAL}) = 4, \quad \text{Score}(\text{HIGH}) = 3, \quad \text{Score}(\text{MEDIUM}) = 2, \quad \text{Score}(\text{LOW}) = 1$$
- If $\text{Distinct Tactics} \ge 4$: $\text{Final Score} = \min(4, \text{Base Score} + 1)$ (Escalate by 1 level).
- If $\text{Distinct Tactics} \ge 3$ and $\text{Base Score} \le 1$: $\text{Final Score} = 2$ (`MEDIUM`).

### 7.3 REST API Endpoints
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/v1/incidents` | `ANALYST`, `ADMIN` | List all correlated incidents with optional `status` filter |
| `GET` | `/api/v1/incidents/{id}` | `ANALYST`, `ADMIN` | Get incident details and member telemetry breakdown |
| `PATCH` | `/api/v1/incidents/{id}/status` | `ANALYST`, `ADMIN` | Transition status (`OPEN` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CLOSED`) |
| `POST` | `/api/v1/incidents/correlate/trigger` | `ADMIN` (Locked) | Trigger on-demand correlation scan over sliding window |

---

## 8. Unified Alert Notification System

Sigma detection matches, parser drift alerts, and correlated multi-stage incidents route through a single unified pipeline:
- **STOMP WebSocket Topic**: `/topic/alerts`
- **Frontend TopBar Alert Counter**: Real-time counter badge with transient popover notifications for incoming alerts.

---

## 9. Automated Test Suite Summary

Total Backend Tests: **46 passed (0 failures, 0 skipped)**
- `NarrativeBuilderTest`: Deterministic narrative generation, non-overclaiming wording assertion.
- `CorrelationEngineTest`:
  1. Multi-tactic attack chain promotion case ($\ge 2$ tactics).
  2. Single-tactic non-promotion case (50 repetitive brute-force hits).
  3. Window-boundary exclusion (>30m gap excluded) & inclusion (<30m gap included).
  4. Root-event selection guarantee under out-of-order event arrival.
  5. Severity calculation formula and tactical escalation verification.
- `MerkleTreeTest`: Binary Merkle tree root computation, odd-leaf duplication, inclusion proof verification, tamper detection.
- `MerkleLedgerServiceTest`: Batch generation, append-only JSONL persistence, inclusion proof verification, audit bundle export.
- `SigmaRuleParserTest`: YAML rule parsing, modifier extraction (`|contains`, `|startswith`, etc.), condition tree validation across all bundled rules.
- `SigmaRuleEvaluatorTest`: OCSF schema evaluation against matching and non-matching telemetry.
- `ParserDriftMonitorServiceTest`: Sliding window confidence calculation, baseline comparison, threshold breach alert generation.
- Plus existing 31 tests (Format classification, Drain clustering, Netty Syslog, OCSF validation, etc.).
