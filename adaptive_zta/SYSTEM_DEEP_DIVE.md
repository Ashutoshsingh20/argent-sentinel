# Argent Sentinel: Advanced Adaptive Trust Scoring System

Argent is a production-grade **Zero Trust Architecture (ZTA)** engine designed to autonomously manage access security for large-scale cloud infrastructures. It moves beyond static firewall rules by calculating a real-time "Trust Score" for every entity (User, API, Service) in your network.

---

## 🏗️ High-Level Architecture

The system operates as a **Service-Oriented Ecosystem**:

1.  **Control Plane (FastAPI)**: The central brain. It receives telemetry and exposes an API for firewalls to query trust scores in sub-milliseconds.
2.  **Intelligence Layer (AI Workers)**:
    - **LSTM Neural Network**: Analyzes sequential behavior to predict "Normal" activity patterns. If a user's sequence deviates, trust drops.
    - **Isolation Forest**: Detects point-anomalies (e.g., a sudden login from a new geo-location or a massive data burst).
3.  **Persistence Layer (SQLite)**: Stores state, telemetry history, and enforcement logs. This allows the system to scale to **3.0 Million+ records** without slowing down.
4.  **Command Center (Textual TUI)**: A high-performance dashboard that monitors the production database in real-time.

---

## 🧠 How Trust is Calculated: The Equation

Argent calculates trust using the **Global Adaptive Trust Equation**:

$$T(t) = \lambda \cdot T(t-1) + \alpha \cdot B(t) + \beta \cdot C(t) - \delta \cdot A(t)$$

| Parameter | Component | Description |
| :--- | :--- | :--- |
| $T(t-1)$ | **Historical State** | The previous trust score (provides stability). |
| $B(t)$ | **Behavioral Score** | Output of the **LSTM Model**. Measures how "regular" the sequence of actions is. |
| $C(t)$ | **Contextual Weight** | Based on environment factors (e.g., Protocol type, AWS vs GCP). |
| $A(t)$ | **Anomaly Penalty** | Output of the **Isolation Forest**. Heavy penalty for detected breaches. |

### 🛡️ Enforcement Actions
- **ALLOW (70 - 100)**: Full administrative access.
- **RATE-LIMIT (40 - 70)**: Throttled access. System suspects minor deviation.
- **ISOLATE (< 40)**: Immediate network isolation. Handled by the **Enforcement Engine**.

---

## 🚀 Scaling to 3,000,000 Records

To handle massive log volumes (150MB+ CSV files), Vanguard uses:
1.  **Indexed Lookups**: Only the last 20 events per entity are used for active inference, ensuring constant-time performance.
2.  **Asynchronous Ingestion**: Telemetry is accepted by the API and processed in the background, preventing network bottlenecks.
3.  **Elastic Sampling**: The dashboard uses aggregate queries (SQL `AVG`, `COUNT`) to visualize millions of rows without loading them into memory.

---

## 🔮 The Future: Autonomous RL Optimization

The next phase of Vanguard (**V3**) integrates **Reinforcement Learning**.
- Instead of humans setting the weights ($\alpha, \beta, \delta$), an RL Agent will observe the system's success.
- If it blocks too many valid users, it lowers sensitivity.
- If a breach is detected too late, it increases the anomaly penalty.
- **Result**: A self-tuning security system that evolves with the threat landscape.
