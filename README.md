# ULPF — Universal Log Pre-processing Framework
### Standalone Containerized Middleware Gateway for Security Operations Teams

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.3-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

---

## 🛡️ Overview

**ULPF (Universal Log Pre-processing Framework)** is a production-grade, air-gapped containerized middleware gateway engineered for enterprise Security Operations Centers (SOC). Sitting directly between perimeter security appliances (Firewalls, IDS/IPS, Cloud Audit Trails, Linux Hosts) and downstream SIEM/Data Lakes (ArcSight, IBM QRadar, Elastic, Splunk), ULPF provides:

1. **Lossless Raw Log Preservation & Cryptographic Lineage:** Instant pre-parse SHA-256 hashing and deterministic ID generation with on-demand non-repudiation verification.
2. **Canonical OCSF Normalization:** Automatic mapping into the Open Cybersecurity Schema Framework (OCSF v1.1.0) with Elastic Common Schema (ECS) aliasing.
3. **Two-Stage Drain Inference Engine (Zero Cloud / Native Java):** Online prefix-tree template mining + deterministic semantic recognizer for synthesizing parsers for novel and unseen log formats in real-time.
4. **Mandatory Human Operator Approval Gate:** Strict policy enforcement preventing unreviewed parsers from auto-deploying.
5. **Zero-Downtime Hot-Registration:** Newly approved dynamic parsers are instantly mounted into live JVM memory without requiring service or container restarts.
6. **Air-Gapped Offline Enrichment:** Subnet-level RFC1918 private/public IP classification, embedded IANA port service resolution, and offline heuristic MITRE ATT&CK technique mapping.
7. **Multi-SIEM Wire Translation:** Reverse translation of canonical OCSF events into ArcSight CEF, IBM QRadar LEEF, and Elastic ECS JSON.
8. **Real-time SOC Telemetry:** High-throughput Netty Syslog UDP/TCP listeners on port 1514, sliding EPS meter, percentile latencies (`p50`, `p95`, `p99`), and WebSocket STOMP live feeds.

---

## 🏗️ Architecture

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

## 🚀 Quickstart Guide

### Option 1: Full Stack via Docker Compose (Recommended)

```bash
# 1. Clone or navigate to the repository root
cd "new sentiapp"

# 2. Copy environment template
cp .env.example .env

# 3. Launch PostgreSQL, Backend Gateway, and Frontend UI
docker-compose up -d --build

# 4. Access the UI & Services
# - Web Control Panel:   http://localhost:3000
# - Backend REST API:    http://localhost:8080/api/v1
# - Syslog UDP Listener: localhost:1514
# - Syslog TCP Listener: localhost:1514
```

### Option 2: Local Development Setup

#### Backend (Spring Boot 3.3.3 + Java 21)
```bash
cd backend
mvn clean test
mvn spring-boot:run
```

#### Frontend (React 18 + Vite + TypeScript)
```bash
cd frontend
npm install
npm run build
npm run dev
```

---

## 🔑 Default Credentials

| Role | Username | Password | Capabilities |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `admin123` | Full access, Operator Approval Gate, Rule Tuning, DLQ Management |
| **SOC Analyst** | `analyst` | `analyst123` | Dashboard, Live Stream Viewer, Integrity Audit, SIEM Exporter |

---

## 🧪 Testing & Verification

Run the complete backend test suite:
```bash
cd backend
mvn test
```
*Executes 31 automated tests spanning unit parsers, template miners, semantic recognizers, enrichment modules, reverse exporters, cryptographic lineage, and full Spring Boot mock integration.*

Run the frontend TypeScript & build validation:
```bash
cd frontend
npm run build
```

---

## 📚 Documentation Directory

- [Architecture & Design Document](docs/ARCHITECTURE.md)
- [REST API & WebSocket STOMP Specification](docs/API.md)
- [SOC Operator & Analyst User Guide](docs/OPERATOR_GUIDE.md)

---

## 📄 License

Apache License 2.0. Built for security operations teams requiring reliable, air-gapped, zero-cloud log normalization and cryptographic lineage.
