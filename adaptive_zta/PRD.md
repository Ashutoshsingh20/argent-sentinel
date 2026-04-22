# Product Requirements Document (PRD): Argent Sentinel

## 1. Product Overview

### 1.1 Product Name
**Argent Sentinel**

### 1.2 Product Vision
Argent Sentinel is an autonomous, high-performance **Zero Trust Architecture (ZTA)** security engine. It aims to replace static, rule-based security policies with dynamic, AI-driven trust scores that evolve in real-time based on entity behavior, network context, and anomaly detection. 

### 1.3 Target Audience & Use Cases
- **Enterprise Security Teams (SecOps):** To automate threat detection and response without manual rule configuration.
- **Network Administrators:** To enforce dynamic access control (Allow, Rate-Limit, Isolate) seamlessly.
- **System Reliability Engineers (SREs):** To monitor system health and security events through unified dashboards and terminal interfaces.

---

## 2. Core Features & Capabilities

### 2.1 Dynamic Trust Scoring Engine
- **Continuous Trust Evaluation:** Calculates a real-time Trust Score $T(t)$ for every network entity based on behavioral momentum, context, and detected anomalies.
- **Enforcement Decisions:**
  - **ALLOW (Trust > 65):** Normal traffic flow.
  - **RATE-LIMIT (Trust 48 - 65):** Restricts entity to `READ_ONLY_SCOPED` permissions.
  - **ISOLATE (Trust < 48):** Immediate firewall blocking and network isolation.

### 2.2 Neural Intelligence Layer (The "Brain")
- **Behavioral Modeling (LSTM):** Predicts the next likely telemetry vector based on the last 20 events. Low trust is assigned when the Mean Squared Error (MSE) between predicted and actual behavior is high.
- **Point-Anomaly Detection:** Utilizes Isolation Forests to detect outliers in feature space (e.g., sudden geo-location changes or massive data bursts).
- **Simultaneous Online Learning:** Buffers new "normal" data and triggers background Neural Evolution Cycles every 1,000 events to retrain models on live production traffic with zero downtime.

### 2.3 High-Throughput Telemetry & Ingestion
- **Target Performance:** Sustains 200 events per second (12,000 events/minute).
- **Batch Processing:** Data Ingestor collects telemetry into batches of 100 before transmission to minimize network overhead.
- **Optimized Persistence:** Uses heavily indexed SQLite databases for sub-millisecond trust lookups even across millions of historical records.

### 2.4 Operation & Orchestration (Vanguard Controller)
- **Automated Lifecycle Management:** Handles system initialization, environment purging, and safe shutdowns.
- **Health Monitoring ("Argent Pulse"):** Continuously polls child processes (API, generators, ingestors) and safely gracefully cleans up the ecosystem if any component fails.
- **Thread Management:** Enforces strict single-threading for mathematical libraries to prevent deadlocks under high load.

### 2.5 Monitoring & Investigation Interfaces
- **Web Dashboard:** A central, real-time command center hosted via FastAPI.
- **TUI Forensics:** A Terminal User Interface (TUI) dashboard for deep-dive investigations, threat hunting, and log analysis without leaving the CLI.

### 2.6 Adaptive Access Gateway (Active Enforcement)
- **Gateway Enforcement Path:** Introduces an API gateway layer that turns trust outcomes into real request-time enforcement.
- **Authorize Endpoint (`/authorize`):** Evaluates incoming payloads and returns `{ decision, trust, reason }`.
- **Gateway Endpoint (`/gateway`):** Applies ALLOW / RATE_LIMIT / ISOLATE behavior before forwarding or blocking traffic.
- **Non-Blocking Design:** Request path performs fast inference first; telemetry and enforcement persistence are offloaded asynchronously.
- **Historical Context Preservation:** Gateway-provided features are accepted for speed, but historical context still comes from database-backed entity state.
- **Temporary Decision Distribution Policy (Critical):** Gateway applies temporary trust bands to force non-trivial decision spread during live validation.

#### Temporary Trust Bands (Gateway Policy Layer)
- `ALLOW`: trust > 55
- `RATE_LIMIT`: 40 <= trust <= 55
- `ISOLATE`: trust < 40

These thresholds are applied in the gateway enforcement layer as a temporary policy calibration, without changing core model training behavior.

---

## 3. System Architecture & Components

The system is a multi-process ecosystem coordinated by a master orchestrator (`vanguard.py`).

```text
Client Request
  ↓
Adaptive Access Gateway (/gateway)
  ↓
Argent Sentinel Trust Engine (/authorize logic)
  ↓
Decision (ALLOW / RATE_LIMIT / ISOLATE)
  ↓
Forward / Restrict / Block
  ↓
Target Service API
```

| Component | File / Service | Description | Technology Stack |
| :--- | :--- | :--- | :--- |
| **Orchestrator** | `vanguard.py` | Manages lifecycle, health monitoring, and cleanup of the entire stack. | Python Subprocess |
| **Control Plane** | `app.py` | Central API and decision-making engine. | FastAPI, Uvicorn |
| **Adaptive Gateway** | `app.py` (`/authorize`, `/gateway`) | Real-time access mediation, policy enforcement, and proxying to target APIs. | FastAPI, Requests |
| **Neural Core** | `vanguard_brain.py` | Handles behavioral (LSTM) and anomaly analytics. | PyTorch, Scikit-Learn |
| **Data Ingestor** | `ingestor.py` | High-throughput telemetry pipeline utilizing batching. | HTTP Requests |
| **Simulators / Red Team** | `data_generator.py` | Generates recursive live data streams for testing and learning. | NumPy, Pandas |
| **Persistence** | `database.py` | Stores historical intelligence securely and interactively. | SQLite, SQLAlchemy |
| **TUI Dashboard** | `tui_dashboard.py` | Text-based UI for monitoring and forensics. | Textual |

---

## 4. Non-Functional Requirements (NFRs)

### 4.1 Performance & Scalability
- Must handle a minimum of 200 req/sec pipeline ingestion without dropping packets.
- Sub-millisecond database queries via `entity_id` and `timestamp` indexing.
- Gateway authorization must remain non-blocking for downstream forwarding paths.

### 4.2 Reliability & Fallbacks
- **Graceful Degradation:** If the anomaly detector (scikit-learn) fails or hangs, the system must gracefully degrade to rely solely on the LSTM behavioral model and context weightings.
- **Crash Recovery:** If any worker crashes, the Orchestrator must detect the failure, log the exit code, and cleanly shut down remaining services to prevent orphaned zombie processes.
- **Gateway Continuity:** If downstream target APIs are unavailable, gateway returns controlled error responses without crashing trust evaluation.

### 4.3 Security
- AI models must operate iteratively on protected shadow state to prevent poisoning attacks.
- Operations MUST be restricted via dynamic access control seamlessly connected to infrastructure endpoints.

---

## 5. Technical Requirements & Deployment

### 5.1 Prerequisites
- Python 3.9+
- Activated Virtual Environment (`.venv`)
- Standard ML/Web Stack: `fastapi`, `uvicorn`, `torch`, `scikit-learn`, `pandas`, `sqlalchemy`, `textual`

### 5.2 Boot Sequence
1. **Phase 1 (Purge):** System wipes old logs, stale databases, and standardizes state.
2. **Phase 2 (Init):** Starts Neural Data Generators, Control Plane API, and validates port binding definitions (e.g., Port 8000).
3. **Phase 3 (Engagement):** Initiates network ingestion and unlocks monitoring interfaces.

### 5.3 Gateway API Contracts
#### `POST /authorize`
- **Input:** JSON payload containing `entity_id` and telemetry/context fields.
- **Output:**
  - `decision`: `ALLOW | RATE_LIMIT | ISOLATE`
  - `trust`: numeric trust score
  - `reason`: model decision rationale

#### `POST /gateway`
- **Input:** Same payload as `/authorize`.
- **Behavior:**
  - `ISOLATE`: returns blocked response.
  - `RATE_LIMIT`: returns restricted response with scoped access semantics.
  - `ALLOW`: forwards request to configured target API and returns proxied response.
- **Side Effects:** Enqueues telemetry and enforcement persistence asynchronously; updates hot state and infrastructure sentinel actions.

#### `POST /gateway/feedback`
- **Purpose:** Injects post-enforcement outcomes as learning signals for shadow adaptation.
- **Input:**
  - `entity_id`: target entity identifier
  - `true_label`: `0` (benign) or `1` (malicious)
- **Behavior:** Persists outcome as hard-sample feedback via the brain feedback hook.
- **Use Case:**
  - Blocked entity later confirmed malicious -> reinforces hard buffer.
  - Allowed entity later confirmed malicious -> captures miss as corrective signal.

### 5.4 Adversarial Validation Strategy
- Inject synthetic adversarial payloads with elevated rates, authentication failures, traversal depth, anomaly priors, and hostile protocol context.
- Validate outcome spread across `ALLOW`, `RATE_LIMIT`, and `ISOLATE` using distribution tests.
- Recommended script: `tmp/gateway_distribution_test.py`.

### 5.5 Multi-Target Gateway Routing (Current Scope)
- Gateway supports target resolution by service key (`target_service`) with default routing fallback.
- Current deployment remains single-service by default, but routing table structure is ready for expansion.

### 5.6 Validation Snapshot (Current)
- End-to-end gateway flow is operational: client -> `/gateway` -> trust decision -> target API forwarding.
- Gateway decision logs are emitted in live runtime (`GATEWAY: <entity> -> <decision> | trust=<score>`).
- Async persistence confirmed for gateway-generated telemetry and enforcement records.
- Gateway policy calibration now includes temporary distribution thresholds to increase decision diversity during test runs.
- Feedback loop endpoint (`/gateway/feedback`) adds confirmed outcomes into hard-sample signals for shadow learning.

---

## 6. Future Enhancements & Roadmap
- **Distributed Database Support:** Transition from SQLite to PostgreSQL/Redis for multi-node deployments.
- **Advanced Threat Intelligence Integrations:** Plug into external IOC (Indicator of Compromise) feeds.
- **Enhanced TUI Controls:** Allow manual threat isolation and un-banning directly from the terminal dashboard.
