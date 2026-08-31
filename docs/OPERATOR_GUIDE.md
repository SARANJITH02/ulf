# ULPF Operator & SOC Analyst Guide
## Universal Log Pre-processing Framework — Standard Operating Procedures

---

### 1. Getting Started & Authentication

1. Open the ULPF Control Panel in your browser at `http://localhost:3000` (or `http://localhost:8080` for standalone backend).
2. Sign in using assigned operator credentials or quick presets:
   - **Administrator:** `admin` / `admin123` (Full configuration, approval, and rule privileges)
   - **SOC Analyst:** `analyst` / `analyst123` (Operational monitoring, inspection, and SIEM export)

---

### 2. Unknown Log Lab Workflow (Handling Unseen Telemetry)

When a new hardware firewall, network appliance, or proprietary microservice emits logs in an unrecognized syntax:

1. Navigate to **Unknown Log Lab** from the sidebar.
2. Select a preset (e.g., *Unseen Custom Hardware Perimeter Appliance*) or paste the raw log sample.
3. Click **"Execute 2-Stage Inference"**:
   - **Stage 1 (Drain Miner):** Inspect the mined layout pattern. Verify that variable items (IPs, ports, action codes) are designated with `<*>`.
   - **Stage 2 (Semantic Recognizer):** Review the inferred slot table. Verify that `source.ip`, `destination.ip`, `event.action`, and protocols are accurately assigned with high confidence.
   - **Preview:** Verify the generated canonical OCSF v1.1.0 JSON object in the viewer.
4. **Operator Approval Gate:**
   - Click **"Approve & Register Parser"**.
   - Enter a clean identifier (e.g. `secgw_fw_v1`) and display name.
   - Click **"Sign & Hot-Register Parser"**.
5. **Zero-Restart Live Verification:**
   - In the follow-up verification card, paste a second event from the same appliance.
   - Click **"Test Live Parser"** to confirm that the newly registered parser processes subsequent telemetry without requiring a container restart!

---

### 3. Live Stream Viewer & Cryptographic Non-Repudiation Audit

For SOC audits and compliance investigations:

1. Navigate to **Live Stream Viewer**.
2. Filter events by Source IP, Severity, Action, or Detected Format.
3. Click **"Inspect & Audit"** on any normalized record.
4. Click **"Verify Cryptographic Integrity"**:
   - The engine retrieves the original immutable raw event string from the database.
   - Recomputes the SHA-256 digest on-the-fly and compares it against the recorded digest.
   - Outputs a green **"NON-REPUDIATION VERIFIED"** cryptographic certificate proving zero data tampering.

---

### 4. Dead-Letter Queue (DLQ) Remediation

When corrupt, truncated, or unparseable payloads enter the gateway:

1. Navigate to **Parser Manager** → **DLQ Inspector Tab**.
2. Review failed records with diagnostic failure codes (`UNPARSEABLE_FORMAT`, `LOW_CONFIDENCE`, `VALIDATION_FAILED`).
3. Click **"Inspect & Retry"** to view the raw payload and failure reason.
4. If a new parser has since been approved for this format, click **"Re-Ingest Through Pipeline"** to reprocess the quarantined payload immediately.

---

### 5. Multi-SIEM Wire Translation

To forward normalized canonical telemetry to downstream SIEM collectors:

1. Navigate to **SIEM Exporter**.
2. Select the normalized event from the stream list.
3. Switch between **CEF**, **LEEF**, and **ECS** target tabs to view the translated wire format.
4. Click **"Copy Payload"** or **"Download File"** for offline ingestion into ArcSight ESM, IBM QRadar, or Elasticsearch.
