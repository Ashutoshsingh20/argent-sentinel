# 🛡️ Argent Sentinel: Comprehensive System Manual

Argent Sentinel is an autonomous, high-performance **Zero Trust Architecture (ZTA)** security engine. It replaces static policies with dynamic, AI-driven trust scores that evolve in real-time based on entity behavior, network context, and point-anomalies.

---

## 🏗️ 1. System Architecture

Argent operates as a multi-process ecosystem coordinated by a master orchestrator.

| Component | Role | Technology |
| :--- | :--- | :--- |
| **Orchestrator** (`vanguard.py`) | Lifecycle, Health Monitoring, Cleanup | Python Subprocess |
| **Control Plane** (`app.py`) | Central API & Decision Engine | FastAPI / Uvicorn |
| **Neural Core** (`vanguard_brain.py`) | Behavioral & Anomaly Analytics | PyTorch / Scikit-Learn |
| **Data Ingestor** (`ingestor.py`) | High-Throughput Telemetry Pipe | Requests / Batching |
| **Simulators** (`data_generator.py`) | Recursive Red Team Data Stream | NumPy / Pandas |
| **Persistence** (`database.py`) | Historical Intelligence Store | SQLite / SQLAlchemy |

---

## 🧠 2. The Neural Intelligence Layer

The "Brain" of Argent Sentinel is a dual-tier analytics engine designed for both sequential continuity and sudden deviation detection.

### A. Behavioral LSTM
- **Function**: Uses a Long Short-Term Memory (LSTM) network to model the "Temporal Signature" of every entity.
- **Predictive Power**: It predicts the next likely telemetry vector based on the last 20 events.
- **Scoring**: $B(t)$ is derived from the Mean Squared Error (MSE) between predicted and actual behavior. High error = Low trust.

### B. Anomaly Detector (Isolation Forest)
- **Function**: Identifies point-anomalies that might look "normal" in sequence but are outliers in feature space (e.g., a sudden login from a new geo-location or a massive data burst).
- **Resilience Fallback**: On systems where `scikit-learn` might hang (e.g., macOS thread locks), the system automatically gracefully degrades to rely solely on the LSTM and context weights.

### C. Simultaneous Online Learning
The system does not require downtime for training. As new "normal" data arrives, it is buffered. Every **1,000 events**, a background thread triggers a **Neural Evolution Cycle** to retrain the model on live production traffic.

---

## 📈 3. Scaling & Throughput

Argent is optimized for high-velocity environments.

- **Target Throughput**: 200 events per second (12,000 events/minute).
- **Batch Processing**: The ingestor collects telemetry into batches of 100 before transmission, reducing network overhead.
- **Indexed DB**: SQLite tables are indexed on `entity_id` and `timestamp`, allowing for sub-millisecond trust lookups even with millions of records.
- **Thread Management**: The orchestrator enforces strict single-threading for math libraries (`OMP_NUM_THREADS=1`) to prevent system-level deadlocks during high-load periods.

---

## 📖 4. Operation & Orchestration

The system is managed via the **Unified Controller** (`vanguard.py`).

### Lifecycle Phases:
1.  **Phase 1 (Purge)**: Cleanses old logs and databases to ensure a fresh security state.
2.  **Phase 2 (Stack Initialization)**: 
    - Starts the **Neural Stream Generator**.
    - Launches the **Control Plane API**.
    - **Port Readiness Probe**: Waits for port 8000 to be active before proceeding.
3.  **Phase 3 (Engagement)**: Opens the Argent Dashboard and starts the **Data Ingestor**.

### Health Monitoring ("Argent Pulse")
The orchestrator continuously polls all child processes. If the API or any worker crashes, the system will:
1. Identify the failed component.
2. Log the exit code.
3. Trigger a graceful cleanup of all remaining services.

---

## ⚖️ 5. Control Plane & Trust Equation

The Trust Score $T(t)$ is the ultimate metric used for enforcement.

$$T(t) = \lambda \cdot T(t-1) + \alpha \cdot B(t) + \beta \cdot C(t) - \delta \cdot A(t)$$

- **$\lambda$ (0.75)**: Momentum. Prevents scores from jumping erratically.
- **$\alpha$ (0.20)**: Behavioral Weight. Impact of the LSTM model.
- **$\delta$ (0.45)**: Anomaly Penalty. Impact of the Isolation Forest.

### Enforcement Decisons:
- **ALLOW (Trust > 65)**: Traffic flows normally.
- **RATE-LIMIT (Trust 48 - 65)**: Entity is restricted to READ_ONLY_SCOPED permissions.
- **ISOLATE (Trust < 48)**: Immediate firewall block via the **Infrastructure Sentinel**.

---

## 🛠️ 6. Deployment Guide

### Prerequisites
- Python 3.9+
- Activated Virtual Environment (`.venv`)
- Dependencies: `fastapi`, `uvicorn`, `torch`, `scikit-learn`, `pandas`, `sqlalchemy`, `textual`

### Running the System
```bash
# Activate your environment
source .venv/bin/activate

# Launch the full stack
python vanguard.py
```

### Monitoring
Access the real-time command centers:
- **Web Dashboard**: `http://127.0.0.1:8000`
- **TUI Forensics**: `python tui_dashboard.py` (for deep-dive investigations)
