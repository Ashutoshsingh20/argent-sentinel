# Argent Sentinel

> Adaptive Zero Trust Architecture (ZTA) with Shadow-Model Continuous Learning

A production-grade Zero Trust simulation stack featuring a **TabNet** decision engine, **FastAPI** control plane, **SQLite** persistence, a live web dashboard, and an asynchronous shadow-model learning daemon.

---

## Overview

Argent Sentinel evaluates entity trust in real-time using a static TabNet classifier. The inference path is **deterministic and low-latency** — no training happens on the request thread. Instead, a background daemon trains a shadow model on hard samples and recent telemetry, promoting it only when it strictly outperforms the production model.

| Component | Tech |
|---|---|
| Decision Engine | TabNet (`pytorch-tabnet`) |
| API Layer | FastAPI + Uvicorn |
| Persistence | SQLite (WAL mode) |
| State Store | In-memory cache + optional Redis |
| Dashboard | HTML/JS + WebSocket live metrics |
| TUI (optional) | Textual |
| Containerization | Docker + Docker Compose |

---

## Quick Start

```bash
# Clone and enter the project directory
git clone https://github.com/Ashutoshsingh20/argent-sentinel.git
cd argent-sentinel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the full stack (API + generator + TUI)
python start_vanguard.py
```

Open **http://127.0.0.1:8000** in your browser.

### Docker (Phase 6 ready)

```bash
docker compose up --build
```

Access via:
- HTTP: `http://localhost:8000`
- HTTPS: `https://localhost:8443`

---

## Architecture

```
┌────────────────┐     ┌─────────────────────────────────────────────────────┐
│  Generator(s)  │────>│  FastAPI (/ingest, /ingest-batch)                   │
└────────────────┘     │       │                                             │
                       │       v                                             │
                       │  In-memory Queue (for batch endpoint)               │
                       │       │                                             │
                       │       v                                             │
                       │  SQLite Persist + Trust Inference                   │
                       │       │                                             │
                       │       v                                             │
                       │  Bounded Buffers (telemetry + hard samples)         │
                       │       │                                             │
                       │       v                                             │
                       │  Shadow Learning Daemon (async train/eval/promote)  │
                       │       │                                             │
                       │       v                                             │
                       │  Enforcement Simulator (firewall/IAM mock)          │
                       └───────────┬─────────────────────────────────────────┘
                                   v
                       ┌───────────────────────────┐
                       │  Dashboard + Metrics API  │
                       └───────────────────────────┘
```

---

## Decision Logic

### TabNet Inference

The model produces a probability `p = prob_attack` from a 15-feature vector:

| Feature Category | Features |
|---|---|
| Behavioral | `behavior_score` |
| Contextual | `context_score` |
| Historical | `history_score` |
| Anomaly | `anomaly_score` |
| Interactions | Normalized raw feature interactions |

### Trust-to-Action Policy

```python
threshold = 0.550
margin = 0.162

if p >= threshold + margin:    # p >= 0.712
    action = "ISOLATE"
elif p >= threshold:           # 0.550 <= p < 0.712
    action = "RATE_LIMIT"
else:                          # p < 0.550
    action = "ALLOW"
```

Trust score: `trust = (1 - p) * 100`

---

## Adaptive Learning (Shadow Model)

### How It Works

1. **Data Collection** — Every inference passively records telemetry snapshots into bounded `deque` buffers.
2. **Hard Sample Detection** — Samples with `abs(prob - 0.5) < 0.15` or misclassifications are flagged.
3. **Shadow Training** — Background daemon periodically trains a detached model clone on a **70/30** mix of hard/recent samples.
4. **Evaluation Gate** — Shadow promotes only if `shadow_macro_f1 > main_macro_f1 + 0.02`.
5. **Atomic Swap** — Promotion is an in-memory lock-guarded swap followed by shadow reset.

### Buffer Config

| Buffer | Max Size | Purpose |
|---|---|---|
| `recent_buffer` | 10,000 | Post-inference telemetry |
| `hard_buffer` | 5,000 | Edge-case / low-confidence samples |

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Live dashboard |
| `/healthz` | GET | Liveness probe |
| `/model-info` | GET | Model metadata and thresholds |
| `/authorize` | POST | Decision-only authorization |
| `/gateway` | POST | Adaptive gateway (forward/rate-limit/isolate) |
| `/gateway/feedback` | POST | Ground-truth feedback ingestion |
| `/ingest` | POST | Sync telemetry ingest + decision |
| `/ingest-batch` | POST | Queue-based high-throughput ingest |
| `/trust/{entity_id}` | GET | Entity trust score and status |
| `/dashboard/summary` | GET | Dashboard KPI payload |
| `/dashboard/entities` | GET | Entity table query |
| `/enforcement/status` | GET | Infrastructure sentinel state |
| `/enforcement/check/{entity_id}` | GET | Block status for entity |
| `/metrics` | GET | Prometheus exposition format |
| `/metrics/snapshot` | GET | JSON metrics snapshot |
| `/ws/metrics` | WS | Live WebSocket metrics stream |

---

## Configuration (.env)

All runtime settings are loaded from `.env`. Key variables:

| Variable | Default | Description |
|---|---|---|
| `APP_HOST` | `0.0.0.0` | FastAPI bind host |
| `APP_PORT` | `8000` | FastAPI bind port |
| `REDIS_ENABLED` | `0` | Enable Redis-backed state |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_ENABLED` | `1` | Enable bearer token auth |
| `JWT_SECRET` | `change-me` | HMAC signing secret |
| `PROM_METRICS_ENABLED` | `1` | Prometheus metrics toggle |
| `LOG_FORMAT` | `json` | `json` or `text` |
| `CLOUD_ACTIONS_ENABLED` | `0` | Enable cloud SDK adapters |

---

## Security Features

- **JWT Bearer Auth** — Middleware enforces tokens on non-exempt paths
- **Rate Limiting** — In-memory sliding window (configurable requests/window)
- **Optional HTTPS Redirect** — App-level redirect via `FORCE_HTTPS=1`
- **Cloud Action Abstraction** — Feature-flagged AWS/Azure/GCP SDK adapters for real enforcement

### Cloud Action Mapping

| Decision | AWS | Azure | GCP |
|---|---|---|---|
| `ALLOW` | `IAM_ALLOW` | `RBAC_PERMIT` | `IAM_BINDING_ALLOW` |
| `RATE_LIMIT` | `API_GW_THROTTLE` | `APIM_THROTTLE` | `CLOUD_ARMOR` |
| `ISOLATE` | `IAM_DENY_INLINE` | `COND_ACCESS_BLOCK` | `VPC_FIREWALL_DENY` |

---

## Prometheus Metrics

Core metric families:

- `argent_requests_total` — Total request count
- `argent_attack_decisions_total` — Attack decisions by category
- `argent_gateway_latency_ms` — Gateway latency histogram
- `argent_sentinel_latency_ms` — Sentinel latency histogram

---

## File Reference

| File | Role |
|---|---|
| `app.py` | FastAPI app, endpoints, shadow daemon lifecycle |
| `vanguard_brain.py` | TabNet inference + shadow model daemon |
| `database.py` | SQLAlchemy models, migrations, hot-state cache |
| `infrastructure.py` | Mock enforcement plane (firewall/IAM) |
| `start_vanguard.py` | Multi-process launcher (API + generator + TUI) |
| `live_data_generator.py` | Real-time synthetic event generator |
| `tui_dashboard.py` | Textual terminal dashboard |
| `templates/dashboard.html` | Web dashboard UI |

---

## Data Flow (End-to-End)

1. Client POSTs telemetry to `/ingest` or `/ingest-batch`
2. Telemetry persisted to SQLite
3. `ArgentBrain.calculate_trust()` builds 15-feature vector
4. TabNet inference → `prob_attack`, trust, decision, explanation
5. Passive buffers capture telemetry and hard samples
6. Shadow daemon trains periodically on buffer snapshots
7. Shadow promotes only if `shadow_f1 > main_f1 + 0.02`
8. Entity state + enforcement action updated
9. Dashboard exposes model, shadow, and infra status

---

## License

MIT
