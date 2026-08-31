# ULPF REST API & WebSocket Specification
## Universal Log Pre-processing Framework — API v1.0.0

Base URL: `http://localhost:8080/api/v1`

---

### Authentication

ULPF uses JWT (JSON Web Tokens) for role-based access control (RBAC).

#### 1. Operator Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```
**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "type": "Bearer",
  "username": "admin",
  "fullName": "System Administrator",
  "role": "ADMIN"
}
```

Include token in all subsequent requests: `Authorization: Bearer <token>`

---

### Log Ingestion

#### 2. Ingest Single Log Payload
```http
POST /api/v1/ingest
Content-Type: application/json

{
  "message": "<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443",
  "source": "PERIMETER_FW_01"
}
```
**Response (200 OK):**
```json
{
  "success": true,
  "eventId": "ULPF-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "rawEventId": "RAW-12345678-90ab-cdef-1234-567890abcdef",
  "detectedFormat": "RFC3164",
  "parserUsed": "syslog_rfc_parser",
  "normalizedEvent": { ... },
  "fieldConfidence": {
    "source.ip": 0.98,
    "destination.ip": 0.98,
    "event.action": 0.95
  }
}
```

#### 3. Ingest Bulk Logs
```http
POST /api/v1/ingest
Content-Type: application/json

{
  "logs": [
    "CEF:0|Suricata|Network-IDS|6.0.4|2001219|ET SCAN Potential SSH Scan|3|src=192.168.1.150 dst=10.10.10.20 spt=49152 dpt=22 proto=TCP act=blocked msg=ET SCAN",
    "{\"eventTime\":\"2026-08-30T10:32:21Z\",\"eventSource\":\"iam.amazonaws.com\",\"eventName\":\"CreateUser\",\"sourceIPAddress\":\"192.168.1.100\"}"
  ],
  "source": "BULK_FEED"
}
```

---

### Two-Stage Inference & Unknown Log Lab

#### 4. Infer Structure of Unknown Log Sample
```http
POST /api/v1/infer
Content-Type: application/json

{
  "logSample": "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest"
}
```
**Response (200 OK):**
```json
{
  "rawSample": "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest",
  "minedTemplate": "SEC-GW-01 <*> <*> proto=TCP src=<*> dst=<*> user=<*>",
  "synthesizedRegex": "^\\QSEC-GW-01\\E\\s+(?<token1>\\S+)\\s+(?<token2>\\S+)\\s+(?<token3>\\S+)\\s+(?<token4>\\S+)\\s+(?<token5>\\S+)\\s+(?<token6>\\S+)$",
  "suggestedParserName": "sec_gw_01_parser",
  "suggestedFormat": "CUSTOM",
  "inferredMappings": [
    {
      "slotName": "token1",
      "canonicalPath": "timestampUtc",
      "inferredType": "TIMESTAMP",
      "confidence": 0.95,
      "sampleValue": "2026-08-30T10:32:21Z"
    },
    {
      "slotName": "token2",
      "canonicalPath": "event.action",
      "inferredType": "ACTION",
      "confidence": 0.95,
      "sampleValue": "[BLOCK]"
    },
    {
      "slotName": "token4",
      "canonicalPath": "source.ip",
      "inferredType": "IPV4_COMPOUND",
      "confidence": 0.98,
      "sampleValue": "src=192.168.10.50:61000"
    }
  ],
  "overallConfidence": 0.94,
  "confidenceTier": "HIGH",
  "recommendedForApproval": true,
  "previewNormalizedEvent": { ... }
}
```

#### 5. Approve & Hot-Register Inferred Parser
```http
POST /api/v1/parsers/approve
Content-Type: application/json

{
  "parserName": "custom_secgw_parser",
  "displayName": "SecGW Hardware Appliance Parser",
  "version": "1.0",
  "formatType": "CUSTOM",
  "description": "Synthesized parser for perimeter gateway",
  "templatePattern": "SEC-GW-01 <*> <*> proto=TCP src=<*> dst=<*> user=<*>",
  "regexPattern": "^\\QSEC-GW-01\\E\\s+(?<token1>\\S+)\\s+(?<token2>\\S+)\\s+(?<token3>\\S+)\\s+(?<token4>\\S+)\\s+(?<token5>\\S+)\\s+(?<token6>\\S+)$",
  "fieldMappings": [ ... ],
  "averageConfidence": 0.94,
  "sampleLog": "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest"
}
```

---

### Cryptographic Lineage & Audit

#### 6. On-Demand Non-Repudiation Integrity Check
```http
GET /api/v1/events/{eventId}/verify
```
**Response (200 OK):**
```json
{
  "eventId": "ULPF-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "rawEventId": "RAW-12345678-90ab-cdef-1234-567890abcdef",
  "verified": true,
  "storedRawHash": "c2b3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
  "recomputedRawHash": "c2b3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
  "rawByteLength": 142,
  "checkedAt": "2026-08-30T10:45:00Z",
  "statusMessage": "Cryptographic Lineage Audit PASSED. Bit-exact integrity guaranteed.",
  "parserName": "syslog_rfc_parser",
  "parserVersion": "1.0.0",
  "schemaVersion": "1.1.0"
}
```

---

### SIEM Wire Exporters

#### 7. Reverse-Export to ArcSight CEF Wire Format
```http
POST /api/v1/export/cef
Content-Type: application/json

{
  "eventId": "ULPF-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```
**Response (200 OK):**
```json
{
  "format": "CEF",
  "wireFormat": "CEF:0|Cisco|ASA|1.0|4|Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443|4|src=192.168.1.5 spt=52100 dst=10.10.10.20 dpt=443 proto=TCP act=blocked"
}
```

#### 8. Reverse-Export to IBM QRadar LEEF Wire Format
```http
POST /api/v1/export/leef
Content-Type: application/json

{
  "eventId": "ULPF-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```
**Response (200 OK):**
```json
{
  "format": "LEEF:1.0",
  "wireFormat": "LEEF:1.0|Cisco|ASA|1.0|4|src=192.168.1.5\tspt=52100\tdst=10.10.10.20\tdpt=443\tproto=TCP\tact=blocked"
}
```

#### 9. Reverse-Export to Elastic ECS JSON
```http
POST /api/v1/export/ecs
Content-Type: application/json

{
  "eventId": "ULPF-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```
**Response (200 OK):**
```json
{
  "@timestamp": "2026-08-30T10:32:21Z",
  "event": {
    "category": "network_traffic",
    "type": "firewall",
    "action": "blocked"
  },
  "source": {
    "ip": "192.168.1.5",
    "port": 52100
  },
  "destination": {
    "ip": "10.10.10.20",
    "port": 443
  },
  "network": {
    "transport": "TCP",
    "protocol": "TCP"
  }
}
```

---

### Real-Time WebSocket Streaming

- **Endpoint:** `ws://localhost:8080/ws/ulpf` (STOMP Broker)
- **Channels:**
  - `/topic/metrics`: 1-second interval telemetry pulse containing live EPS, latency percentiles, format breakdown, and confidence tiers.
  - `/topic/events`: Immediate broadcast upon each normalized event arrival.
