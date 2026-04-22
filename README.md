<div align="center">

![Status](https://img.shields.io/badge/status-operational-brightgreen?style=flat)
![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat&logo=python)
![FastAPI](https://img.shields.io/badge/fastapi-active-green?style=flat&logo=fastapi)
![TabNet](https://img.shields.io/badge/tabnet-neuralnet-purple?style=flat)
![Docker](https://img.shields.io/badge/docker-ready-blue?style=flat&logo=docker)

</div>

---

<div align="center">

# Argent Sentinel

## Adaptive Zero Trust Architecture

### "Trust Nothing. Verify Everything. Learn Continuously."

</div>

---

## Mission Brief

In a world where every entity is a potential threat, **Argent Sentinel** stands as the autonomous guardian — a self-evolving Zero Trust decision engine powered by **TabNet** deep learning. It watches. It learns. It adapts. And it never sleeps.

---

## System Modules

| Module | Tech | Status |
|:---|:---|:---|
| Neural Core | TabNet (`pytorch-tabnet`) | Active |
| Control Plane | FastAPI + Uvicorn | Online |
| Memory | SQLite (WAL) + Redis (opt) | Stable |
| Shadow Mind | Async Daemon | Learning |
| Interface | HTML Dashboard + WebSocket | Live |
| Terminal UI | Textual | Standby |
| Hull | Docker + Compose | Sealed |

---

## Initialize System

```bash
# Establish connection to the sentinel
git clone https://github.com/Ashutoshsingh20/argent-sentinel.git
cd argent-sentinel

# Activate neural substrate
python -m venv .venv
source .venv/bin/activate

# Load dependencies
pip install -r requirements.txt

# Launch sentinel core
python start_vanguard.py
```

**Dashboard:** `http://127.0.0.1:8000`

### Deploy via Docker

```bash
docker compose up --build
```

- **HTTP:** `http://localhost:8000`
- **TLS:** `https://localhost:8443`

---

## Architecture Matrix

```
+------------------+       +------------------------------------------+
|   Data Stream    |------>|  FastAPI Gateway                         |
|  (Generators)    |       |  /ingest    /ingest-batch                 |
+------------------+       |        |                                  |
                           |        v                                  |
                           |  Async Queue (high-throughput)            |
                           |        |                                  |
                           |        v                                  |
                           |  SQLite Vault + Trust Inference           |
                           |        |                                  |
                           |        v                                  |
                           |  Memory Buffers (bounded, O(1))           |
                           |        |                                  |
                           |        v                                  |
                           |  SHADOW MIND (async train/eval/promote)   |
                           |        |                                  |
                           |        v                                  |
                           |  Enforcement Matrix (firewall/IAM mock)   |
                           +--------+----------------------------------+
                                    |
                                    v
                      +----------------------------+
                      |  Command Dashboard + WS    |
                      +----------------------------+
```

---

## The Neural Core: TabNet Decision Engine

The sentinel evaluates every incoming entity through a **15-dimensional feature space**, computing a threat probability in microseconds.

| Dimension | Signal |
|:---|:---|
| `behavior_score` | Historical behavioral patterns |
| `context_score` | Session and environmental context |
| `history_score` | Long-term reputation tracking |
| `anomaly_score` | Statistical deviation detection |
| Interactions | Cross-feature neural embeddings |

### Trust Protocol

```
THRESHOLD = 0.550
MARGIN    = 0.162

if p >= THRESHOLD + MARGIN:  # p >= 0.712
    action = "ISOLATE"    # BLOCKED
elif p >= THRESHOLD:       # 0.550 <= p < 0.712
    action = "RATE_LIMIT" # THROTTLED
else:                      # p < 0.550
    action = "ALLOW"      # GRANTED

TRUST_SCORE = (1 - p) * 100
```

---

## The Shadow Mind

While the production model makes decisions, a **shadow clone** learns silently in the background — training on the hardest samples the main model has ever seen.

### Learning Cycle

1. **Capture** — Every inference leaves a trace in bounded telemetry buffers
2. **Flag** — Ambiguous decisions (`abs(prob - 0.5) < 0.15`) are marked as hard samples
3. **Train** — Shadow daemon trains on a **70/30** hard-to-recent sample ratio
4. **Prove** — Shadow must achieve `macro_f1 > main_macro_f1 + 0.02`
5. **Ascend** — If proven superior, shadow replaces the production model atomically

### Memory Buffer Status

| Buffer | Capacity | Purpose |
|:---|:---|:---|
| `recent_buffer` | 10,000 | Fresh telemetry stream |
| `hard_buffer` | 5,000 | Edge cases and near-misses |

---

## Communication Channels (API)

| Endpoint | Protocol | Function |
|:---|:---|:---|
| `/` | GET | Command Dashboard |
| `/healthz` | GET | System Liveness Probe |
| `/model-info` | GET | Neural Core Diagnostics |
| `/authorize` | POST | Instant Trust Decision |
| `/gateway` | POST | Adaptive Gateway Matrix |
| `/gateway/feedback` | POST | Ground-Truth Uplink |
| `/ingest` | POST | Direct Telemetry Injection |
| `/ingest-batch` | POST | High-Throughput Stream |
| `/trust/{entity_id}` | GET | Entity Trust Readout |
| `/dashboard/summary` | GET | System KPI Telemetry |
| `/metrics` | GET | Prometheus Data Stream |
| `/ws/metrics` | WS | Real-Time Metric Pulse |

---

## System Configuration

| Directive | Default | Effect |
|:---|:---|:---|
| `APP_HOST` | `0.0.0.0` | Listen on all interfaces |
| `APP_PORT` | `8000` | Gateway port |
| `REDIS_ENABLED` | `0` | Activate distributed state |
| `JWT_ENABLED` | `1` | Token-based access control |
| `JWT_SECRET` | `change-me` | HMAC signing key |
| `PROM_METRICS_ENABLED` | `1` | Expose metric telemetry |
| `LOG_FORMAT` | `json` | Structured logging format |
| `CLOUD_ACTIONS_ENABLED` | `0` | Enable cloud enforcement |

---

## Defense Protocols

- **Bearer Token Auth** — JWT middleware guards all sensitive endpoints
- **Rate Limiting** — Sliding window throttle (configurable)
- **TLS Redirection** — `FORCE_HTTPS=1` for encrypted channels
- **Cloud Enforcement** — AWS/Azure/GCP SDK-backed real-world actions

### Enforcement Mapping

| Verdict | AWS | Azure | GCP |
|:---|:---|:---|:---|
| ALLOW | IAM Allow | RBAC Permit | IAM Binding |
| RATE_LIMIT | API Gateway Throttle | APIM Throttle | Cloud Armor |
| ISOLATE | IAM Deny Inline | Conditional Access | VPC Firewall Deny |

---

## Prometheus Telemetry

| Metric | Description |
|:---|:---|
| `argent_requests_total` | Total request count |
| `argent_attack_decisions_total` | Decisions by threat category |
| `argent_gateway_latency_ms` | Gateway response histogram |
| `argent_sentinel_latency_ms` | Inference latency histogram |

---

## Core Modules

| Module | Responsibility |
|:---|:---|
| `app.py` | FastAPI gateway, endpoints, daemon lifecycle |
| `vanguard_brain.py` | TabNet inference + shadow mind daemon |
| `database.py` | SQLAlchemy ORM, migrations, hot-state cache |
| `infrastructure.py` | Enforcement plane simulator |
| `start_vanguard.py` | Multi-process launch orchestrator |
| `live_data_generator.py` | Synthetic threat stream generator |
| `tui_dashboard.py` | Textual terminal interface |
| `templates/dashboard.html` | Web command dashboard |

---

## Data Pipeline

```
1.  Telemetry injected -> /ingest or /ingest-batch
2.  Persisted to SQLite vault
3.  ArgentBrain builds 15-feature neural vector
4.  TabNet outputs prob_attack, trust, decision, explanation
5.  Buffers capture passive telemetry + hard samples
6.  Shadow mind trains on periodic buffer snapshots
7.  Shadow promotes only if f1 exceeds threshold + 0.02
8.  Entity state + enforcement action updated
9.  Dashboard broadcasts live system status
```

---

<div align="center">

**Argent Sentinel** — *Where AI meets Zero Trust.*

**License:** MIT

</div>
