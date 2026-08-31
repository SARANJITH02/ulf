# ULPF (Universal Log Pre-processing Framework) — Live Application Walkthrough

The **ULPF Containerized Middleware Gateway** is now running live! Both the Spring Boot 3.3.3 backend and the React 18 frontend have been started, connected, and end-to-end verified via automated browser testing.

---

## 🌐 Live Access URLs & Ports

| Component | URL / Port | Credentials / Purpose |
| :--- | :--- | :--- |
| **Web Control Panel** | [http://localhost:3000](http://localhost:3000) | `admin` / `admin123` or `analyst` / `analyst123` |
| **Backend REST API** | [http://localhost:8080/api/v1](http://localhost:8080/api/v1) | Spring Boot 3.3.3 REST Endpoints |
| **Syslog UDP Listener** | `localhost:1514` | Netty Non-Blocking UDP Datagram Listener |
| **Syslog TCP Listener** | `localhost:1514` | Netty Line-Based TCP Framing Listener |
| **WebSocket STOMP** | `ws://localhost:3000/ws/ulpf` | Real-time `/topic/metrics` and `/topic/events` |

---

## 📸 Automated Browser Test Validation Results

The entire end-to-end workflow was exercised by the automated browser subagent:

### 1. Operations & Normalization Dashboard
- Real-time pipeline active indicator with live UDP/TCP `:1514` status.
- Live KPIs (Throughput EPS, Average Latency, Success Rate %, Dead-Letter Queue).
- Live format distribution chart and confidence breakdown.
- Sample burst injection testing.

![Dashboard KPIs](file:///C:/Users/karan/.gemini/antigravity-ide/brain/c87d9635-9551-4f48-9576-95248e0172df/dashboard_kpis_1788074864388.png)

---

### 2. Unknown Log Lab (Flagship Two-Stage Inference & Operator Approval)
- Loaded unseen hardware perimeter appliance preset.
- Executed native Java 2-stage inference (Drain tree template mining + semantic field recognition) achieving **92% mapping confidence**.
- Reviewed side-by-side canonical OCSF v1.1.0 preview.
- Completed mandatory operator signing and hot-registered parser into JVM memory.
- Executed zero-restart live verification test confirming immediate automated normalization.

![Unknown Log Lab Verification](file:///C:/Users/karan/.gemini/antigravity-ide/brain/c87d9635-9551-4f48-9576-95248e0172df/lab_verification_success_1788075264439.png)

---

### 3. Cryptographic Lineage & Non-Repudiation Audit
- Inspected normalized event record in Live Stream Viewer.
- Triggered on-demand SHA-256 cryptographic audit.
- Verified stored raw digest against recomputed raw digest with bit-exact non-repudiation proof.

![Cryptographic Lineage Audit](file:///C:/Users/karan/.gemini/antigravity-ide/brain/c87d9635-9551-4f48-9576-95248e0172df/cryptographic_audit_success_1788075647487.png)

---

### 4. Multi-SIEM Wire Format Translation
- Selected normalized event and verified real-time reverse translations into:
  - **ArcSight CEF Wire Format**
  - **IBM QRadar LEEF Wire Format**
  - **Elastic ECS JSON** (with automated MITRE technique mappings `T1046 Network Service Discovery`).

![SIEM Exporter](file:///C:/Users/karan/.gemini/antigravity-ide/brain/c87d9635-9551-4f48-9576-95248e0172df/ecs_siem_exporter_1788076353425.png)

---

## 🎥 Browser Automation Recording

The complete recorded session of the browser interaction is available at:
`file:///C:/Users/karan/.gemini/antigravity-ide/brain/c87d9635-9551-4f48-9576-95248e0172df/ulpf_app_walkthrough_1788074808389.webp`
