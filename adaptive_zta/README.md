# Argent Sentinel (Adaptive ZTA) - Static TabNet Runtime

This project is a local Zero Trust simulation stack with a static TabNet decision model, FastAPI control plane, SQLite persistence, a web dashboard, and optional local TUI and traffic generators.

The production inference path remains deterministic and low-latency, with adaptive learning handled in a separate background layer:

- No training work on the request thread.
- Production decisions are served by the active in-memory model.
- A background shadow model trains asynchronously and is promoted only after strict validation.

## Adaptive Foundation (Phase 1 & 2)

The runtime now includes a non-blocking data collection foundation to support future offline retraining cycles:

- Phase 1 (Passive Data Collection): bounded in-memory telemetry capture of post-inference feature snapshots.
- Phase 2 (Hard Sample Detection): bounded capture of low-confidence and misclassified samples.

These additions do **not** change model weights, decision thresholds, or the main trust-action policy.

## Adaptive Learning Layer (Phase 3)

Phase 3 introduces a shadow-model daemon for continuous adaptation without inference disruption:

- Shadow clone creation: detached model copy via save/load to avoid shared optimizer/graph state.
- Training scope: dual-stream buffers (`hard_buffer` + `recent_buffer`) only (not full historical replay).
- Dataset strategy: strict stratified `70/30` mix (hard/recent) to prevent catastrophic forgetting.
- Evaluation gate: shadow must beat production by a strict macro-F1 margin (`+0.02`).
- Promotion mode: atomic in-memory swap under lock, followed by shadow reset.
- Safety: no promotion on insufficient data, weak label diversity, or failed evaluation.
- Progressive memory: buffers are not cleared during training/promotion and roll naturally via `deque(maxlen=...)`.

## What The System Does

For each entity telemetry event, the system:

1. Stores raw telemetry.
2. Builds a fixed feature vector.
3. Runs TabNet inference.
4. Converts probability into a trust score and action.
5. Persists enforcement/action logs.
6. Passively stores recent inference telemetry and hard samples in bounded memory buffers.
7. Exposes status and explanations to the dashboard/API.

## Runtime Architecture

```text
Generator(s) -> FastAPI (/ingest or /ingest-batch)
                        -> In-memory queue (for batch endpoint)
                        -> Worker drains queue
                        -> SQLite persist + trust inference
                        -> Bounded passive buffers (telemetry + hard samples)
                        -> Shadow learning daemon (async train/eval/promote)
                        -> Enforcement simulator (firewall/IAM mock)
                        -> Dashboard endpoints + HTML UI
```

## Phase 6 Productization Guide

This repository now includes production-oriented runtime controls without changing model weights or training behavior.

### Implementation Status (19 April 2026)

- [x] 6.1 Containerization (Dockerfile + local container run)
- [x] 6.2 State externalization (Redis-backed state with fallback)
- [x] 6.3 Async gateway path (non-blocking forwarding)
- [x] 6.4 Observability (Prometheus metrics endpoint)
- [x] 6.5 Structured logging (JSON/text configurable)
- [x] 6.6 Config management (.env-driven runtime settings)
- [x] 6.7 Horizontal scaling (2 app replicas + Nginx LB)
- [x] 6.8 Security hardening (JWT + rate limiting + optional HTTPS redirect)
- [x] 6.9 Cloud integration adapters (AWS/Azure/GCP SDK-backed, feature-flagged)

### Quick Verification

1. Start stack:

```bash
docker compose up --build
```

2. Verify service health:

```bash
curl -s http://localhost:8000/healthz
```

3. Verify Prometheus metrics:

```bash
curl -s http://localhost:8000/metrics | head
```

4. Verify snapshot endpoint (dashboard JSON):

```bash
curl -s http://localhost:8000/metrics/snapshot
```

### Complete Environment Variable Reference

All runtime controls are loaded from `.env` using `runtime_settings.py`.

| Variable | Default | Purpose |
|---|---|---|
| `APP_HOST` | `0.0.0.0` | FastAPI bind host |
| `APP_PORT` | `8000` | FastAPI bind port |
| `TARGET_API` | `http://localhost:9000` | Upstream API target for gateway forwarding |
| `ENABLE_PHASE5_GATEWAY` | `1` | Enable/disable Phase 5 adaptive gateway path |
| `GATEWAY_ALLOW_THRESHOLD` | `55` | Gateway trust threshold (compatible setting) |
| `GATEWAY_ISOLATE_THRESHOLD` | `40` | Gateway trust threshold (compatible setting) |
| `REDIS_ENABLED` | `0` | Enable Redis-backed shared state |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `STATE_KEY_SCOPE` | `entity` | State isolation mode: `entity` or `principal` |
| `STATE_TTL_NORMAL_SECONDS` | `86400` | TTL for non-escalated state |
| `STATE_TTL_HIGH_RISK_SECONDS` | `604800` | TTL for escalated/high-risk state |
| `JWT_ENABLED` | `1` | Enable bearer token auth middleware |
| `JWT_SECRET` | `change-me` | HMAC secret for JWT verification |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_ISSUER` | `argent-sentinel` | Required token issuer |
| `JWT_AUDIENCE` | `argent-clients` | Required token audience |
| `JWT_EXEMPT_PATHS` | `/,/healthz,/metrics,/docs,/openapi.json` | Comma-separated auth bypass paths |
| `RATE_LIMIT_ENABLED` | `1` | Enable in-memory rate limiting |
| `RATE_LIMIT_REQUESTS` | `120` | Requests allowed per client/window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window size in seconds |
| `PROM_METRICS_ENABLED` | `1` | Metrics feature toggle (endpoint remains available) |
| `LOG_LEVEL` | `INFO` | Runtime log level |
| `LOG_FORMAT` | `json` | `json` or `text` logging format |
| `FORCE_HTTPS` | `0` | Enable app-level HTTPS redirect middleware |
| `CLOUD_ACTIONS_ENABLED` | `0` | Global switch for real cloud actions |
| `AWS_CLOUD_ACTIONS_ENABLED` | `0` | Enable AWS SDK action client |
| `AWS_LAMBDA_TARGET` | empty | Lambda function for concurrency actions |
| `AZURE_CLOUD_ACTIONS_ENABLED` | `0` | Enable Azure SDK action client |
| `AZURE_TAG_SCOPE` | empty | Azure resource scope for tag updates |
| `GCP_CLOUD_ACTIONS_ENABLED` | `0` | Enable GCP SDK action client |
| `GCP_PROJECT_ID` | empty | Target GCP project for label updates |

### Complete Endpoint Catalog (Current Runtime)

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Dashboard HTML |
| `/healthz` | `GET` | Liveness check |
| `/model-info` | `GET` | Model metadata |
| `/authorize` | `POST` | Decision-only authorization path |
| `/gateway` | `POST` | Adaptive gateway with forward/rate-limit/isolate behavior |
| `/gateway/feedback` | `POST` | Human/ground-truth feedback ingestion |
| `/ingest` | `POST` | Synchronous telemetry ingest + decision |
| `/ingest-batch` | `POST` | Queue-based high-throughput ingest |
| `/trust/{entity_id}` | `GET` | Current trust and status for entity |
| `/dashboard/summary` | `GET` | Dashboard summary payload |
| `/dashboard/entities` | `GET` | Entity table query |
| `/enforcement/status` | `GET` | Infrastructure sentinel summary |
| `/enforcement/check/{entity_id}` | `GET` | Check current block status |
| `/metrics` | `GET` | Prometheus exposition format |
| `/metrics/snapshot` | `GET` | JSON metrics snapshot for UI/API clients |
| `/ws/metrics` | `WS` | Live websocket metrics stream |

### Security Usage Example (JWT)

Generate a sample token compatible with defaults:

```bash
python - <<'PY'
import time, jwt
payload = {
    "sub": "demo-client",
    "iss": "argent-sentinel",
    "aud": "argent-clients",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}
print(jwt.encode(payload, "change-me", algorithm="HS256"))
PY
```

Call secured endpoints:

```bash
TOKEN="<paste-token>"
curl -s -H "Authorization: Bearer ${TOKEN}" http://localhost:8000/model-info
```

### Cloud Action Mapping (Feature-Flagged)

Policy decisions are mapped to cloud-specific actions by `phase5/policy.py`:

| Decision | AWS | Azure | GCP |
|---|---|---|---|
| `ALLOW` | `IAM_ALLOW` | `RBAC_PERMIT` | `IAM_BINDING_ALLOW` |
| `RATE_LIMIT` | `API_GATEWAY_THROTTLE` | `APIM_THROTTLE_POLICY` | `CLOUD_ARMOR_RATE_LIMIT` |
| `ISOLATE` | `IAM_DENY_INLINE` | `CONDITIONAL_ACCESS_BLOCK` | `VPC_FIREWALL_DENY` |

Default behavior is safe/local: mock clients stay active unless cloud flags are enabled.

### Validation Notes

- Runtime import smoke test passes in project venv (`import app`).
- If Redis is not reachable, runtime logs fallback and continues with in-memory hot state.
- Phase 5 burst suite can trigger `feature assembly budget exceeded` under heavy threaded load and strict local timing; this is an environment-sensitive SLA test path, not a model-weight/training change.

### 1) Containerization (Phase 6.1)

From `adaptive_zta/`:

```bash
docker build -t argent-sentinel:phase6 -f Dockerfile .
docker run --rm -p 8000:8000 --env-file .env argent-sentinel:phase6
```

Success checks:

- `GET /healthz` returns `{"status":"ok"}`
- API reachable on port `8000`

### 2) Redis Externalized State (Phase 6.2)

Environment variables:

- `REDIS_ENABLED=1`
- `REDIS_URL=redis://redis:6379/0`
- `STATE_KEY_SCOPE=entity` (strict entity isolation)
- `STATE_TTL_NORMAL_SECONDS`, `STATE_TTL_HIGH_RISK_SECONDS`

Notes:

- Phase 5 entity state and hot status keys are Redis-backed when available.
- If Redis is unavailable, runtime falls back to in-memory state with warning logs.

### 3) Async Gateway Path (Phase 6.3)

Gateway forwarding is non-blocking with `httpx.AsyncClient` and async handler flow.

- No blocking `requests.post` in gateway path.
- Sentinel and gateway latencies are emitted as Prometheus histograms.

### 4) Observability and Metrics (Phase 6.4)

- `GET /metrics` exposes Prometheus format metrics.
- `GET /metrics/snapshot` keeps the original dashboard-friendly JSON snapshot.

Core metric families:

- `argent_requests_total`
- `argent_attack_decisions_total`
- `argent_gateway_latency_ms`
- `argent_sentinel_latency_ms`

### 5) Structured Logging (Phase 6.5)

Logging is centrally configured in `runtime_logging.py`.

- `LOG_FORMAT=json|text`
- `LOG_LEVEL=INFO|DEBUG|...`

Decision and gateway events include entity, decision, trust/confidence, and latency context.

### 6) Dynamic Config via .env (Phase 6.6)

Configuration is loaded from `.env` and `.env.example` via `runtime_settings.py`.

Externalized controls include:

- host/port, target API
- Redis mode and state isolation
- JWT and rate limiting
- cloud action adapters and scopes

### 7) Horizontal Scaling with Nginx (Phase 6.7)

`docker-compose.yml` includes:

- `sentinel-1`
- `sentinel-2`
- shared `redis`
- `nginx` load balancer

Run:

```bash
docker compose up --build
```

Access:

- HTTP: `http://localhost:8000`
- HTTPS (TLS): `https://localhost:8443`

TLS cert files are expected under `deploy/nginx/certs/`.

### 8) Security Hardening (Phase 6.8)

- JWT bearer auth enforced on non-exempt routes.
- In-memory rate limiting with configurable window and request cap.
- Optional HTTPS redirect with `FORCE_HTTPS=1`.

JWT required config:

- `JWT_SECRET`
- `JWT_ISSUER`
- `JWT_AUDIENCE`

### 9) Cloud Integrations (Phase 6.9)

Policy abstraction now supports SDK-backed actions behind feature flags.

- AWS adapter: Lambda concurrency control for allow/rate-limit/isolate.
- Azure adapter: resource-scope tag updates via ARM SDK.
- GCP adapter: project label updates via Resource Manager SDK.

Enable with:

- `CLOUD_ACTIONS_ENABLED=1`
- per-cloud toggle variables and required target identifiers.

By default, mock clients remain active for safe local development.

## Decision Model

Core runtime model is in `vanguard_brain.py`.

- Model type: `TabNetClassifier` (`pytorch-tabnet`)
- Input schema: 15 runtime features
- Main business features:
    - behavior score
    - context score
    - history score
    - anomaly score
- Plus normalized/raw interactions to keep inference aligned with notebook training artifacts

### Decision Policy

Let `p = prob_attack`, `thr = threshold`, `m = rate_limit_margin`.

- `p >= thr + m` -> `ISOLATE`
- `thr <= p < thr + m` -> `RATE_LIMIT`
- `p < thr` -> `ALLOW`

Trust score is computed as:

$$
trust = (1 - p) * 100
$$

### Explainability Format

Each decision includes a compact reason string with top factors, for example:

```text
TABNET_STATIC_ATTACK p=0.712 thr=0.550 margin=0.162 top=anomaly:0.381,behavior:0.292 action=ISOLATE
```

`app.py` parses this into UI-friendly fields (`reason_explain`, `top_factors`) for dashboard rendering.

## Model Artifacts

Artifacts are loaded from `adaptive_zta/outputs` at runtime:

- `tabnet_validation_model.zip` (preferred)
- `argent_tabnet_model.zip` (legacy fallback)
- `tabnet_validation_scaler.joblib`
- `tabnet_validation_meta.json`

If scaler feature count does not match runtime vector size, inference still runs and scaler is skipped safely.

## Passive Telemetry Buffers

Phase 1/2 buffers live in the runtime engine and are intentionally bounded for predictable memory use:

- `recent_buffer` (`log_buffer` alias): last `10,000` post-inference events
- `hard_buffer`: last `5,000` hard/edge samples
- Backing structure: `collections.deque(maxlen=...)` for O(1) append/eviction
- Thread-safety: lightweight lock around buffer mutation

Captured telemetry schema:

```python
{
    "features": [...],
    "prob": float,
    "pred": int,
    "timestamp": float
}
```

Hard sample rules:

- Low confidence: `abs(prob - 0.5) < 0.15`
- Misclassified (when label exists): `pred != true_label`

Shadow dataset construction:

- Build from thread-safe snapshots of both buffers.
- Train on a strict 70/30 hard/recent sampling mix.
- Shuffle combined samples each cycle to reduce order bias.

Observability:

- Runtime logs buffer size status every 1000 captured telemetry items.

## API Surface

Primary endpoints in `app.py`:

- `GET /` -> dashboard HTML (`templates/dashboard.html`)
- `GET /model-info` -> current model metadata
- `POST /ingest` -> synchronous ingest + immediate decision
- `POST /ingest-batch` -> enqueue high-throughput records
- `GET /trust/{entity_id}` -> latest entity trust/status
- `GET /dashboard/summary` -> KPI cards + threat feed + reason explanations
- `GET /dashboard/entities?status=...&search=...` -> entity table
- `GET /metrics` -> Prometheus metrics
- `GET /metrics/snapshot` -> JSON snapshot metrics
- `GET /enforcement/status` -> infrastructure simulation state
- `GET /enforcement/check/{entity_id}` -> firewall blocked state
- `WS /ws/metrics` -> live metric stream

`GET /dashboard/summary` also returns `shadow_stats` for the shadow-training panel in the web UI.

### Input Validation

`TelemetryIn` enforces:

- Safe `entity_id` regex: alphanumeric plus `_.:@-`
- Protocol whitelist: `HTTPS`, `HTTP`, `SSH`

## Database And State

`database.py` defines:

- `Entity`
- `Telemetry`
- `EnforcementAction`

Database path:

- `outputs/vanguard_v3_live.db`

Also includes:

- WAL mode for concurrency
- schema auto-upgrade helper (`_ensure_live_schema`)
- in-process hot-state cache (`hot_state`) for quick trust/status reads

## Dashboard Behavior

### Web dashboard

- File: `templates/dashboard.html`
- Data source: polling summary and entity APIs
- Shows:
    - entity counts (`ALLOW`, `RATE_LIMIT`, `ISOLATE`, pending)
    - average trust
    - latest non-ALLOW threats
    - parsed explanation and top factors
    - shadow model training state (daemon status, cycle, train size, F1 pair, margin, last promotion)

### TUI dashboard (optional)

- File: `tui_dashboard.py`
- Uses Textual to show DB-live metrics and forensic detail

## How To Run

From `adaptive_zta/`:

```bash
source .venv/bin/activate
python app.py
```

Open:

- `http://127.0.0.1:8000`

Alternative all-in-one launcher:

```bash
python start_vanguard.py
```

This starts:

- FastAPI app
- live generator loop
- Textual TUI

## Common Operational Notes

- If port 8000 is busy, stop old processes before restart.
- Exit code `143` typically indicates process termination by signal (`SIGTERM`), commonly expected during controlled shutdown.
- `ingest-batch` is async queue-based; decisions appear after worker drain.

## End-To-End Data Flow

1. Client posts telemetry (`/ingest` or `/ingest-batch`).
2. Telemetry is persisted in SQLite.
3. `ArgentBrain.calculate_trust()` reads latest entity telemetry.
4. Inference computes `prob_attack`, trust, decision, explanation.
5. Runtime passively records telemetry and hard samples in bounded deques.
6. Background shadow daemon periodically snapshots buffers and builds a 70/30 hard/recent training set.
7. Candidate trains on progressive multi-cycle memory (no buffer wipe between cycles).
8. Candidate promotes only if `shadow_f1 > main_f1 + 0.02`.
9. Entity state and enforcement action are updated.
10. Infrastructure sentinel mock applies block/quarantine state.
11. Dashboard endpoints expose model, shadow, and infrastructure status.

## Python File Reference (Complete)

This section documents all Python files currently present under `adaptive_zta/` and `adaptive_zta/tmp/`.

### Core runtime files

- `app.py`
    - FastAPI application, validation models, ingestion endpoints, queue worker, dashboard APIs, websocket metrics.
    - Starts/stops shadow learning daemon in application lifespan.

- `vanguard_brain.py`
    - TabNet inference engine with guarded shadow adaptation layer.
    - Loads model/scaler/meta artifacts, builds 15-feature vector, predicts attack probability, produces reason text/details.
    - Hosts bounded dual-stream buffers (`recent_buffer` + `hard_buffer`) for stable adaptive learning.
    - Implements strict 70/30 shadow dataset builder, train/eval/promote loop, and shadow status telemetry.

- `database.py`
    - SQLAlchemy models and DB session factory.
    - Schema migrations and hot-state cache.

- `infrastructure.py`
    - Mock enforcement plane.
    - Applies `ISOLATE` (firewall block), `RATE_LIMIT` (IAM quarantine), and restores on `ALLOW`.

- `config.py`
    - Shared constants for simulation/training-era parameters and endpoint defaults.

- `start_vanguard.py`
    - Multi-process launcher for API + live generator + TUI.
    - Includes port-in-use guard and graceful shutdown.

### Dashboard/UI

- `tui_dashboard.py`
    - Textual terminal dashboard against live DB state.
    - Useful for local forensic view separate from browser UI.

- `templates/dashboard.html`
    - Browser UI with live Shadow Model Training panel.
    - Displays daemon state, cycle count, sample volume, F1 comparison, margin, and promotion timestamp.

### Data generation / ingestion scripts

- `live_data_generator.py`
    - Real-time synthetic event generator focused on runtime ingest.
    - Produces overlap-heavy normal/attack batches with easy/medium/hard attack difficulty split.
    - Injects feature correlation to prevent trivial single-feature shortcuts.
    - Logs class-mean separation guidance and posts generated records to `/ingest-batch`.

- `data_generator.py`
    - Larger research/stress simulation pipeline with attack/boundary/drift generation.
    - Writes stream-style telemetry CSV in standalone mode.

- `ingestor.py`
    - Reads telemetry CSV and pushes batches to `/ingest-batch`.
    - Useful for replaying file-backed streams.

### Evaluation/metrics utilities

- `evaluator.py`
    - Experiment metric logger (`outputs/experiments.json`).
    - Includes helper precision/recall/F1 calculations.

- `replay_signal_probe.py`
    - Single-sample static-model probe for prediction and feature contributions.

- `replay_signal_evolution_probe.py`
    - Multi-sample probability distribution probe against current model threshold.

### Legacy/offline pipeline components

These are mostly from earlier offline/stepwise pipeline stages and are not part of the active FastAPI static inference path:

- `context_engine.py`
    - Rule-based context scoring over offline feature matrix.

- `anomaly_detector.py`
    - IsolationForest contamination tuning and anomaly score export.

- `enforcement_engine.py`
    - Offline enforcement log synthesis from trust score CSV.

- `validate_phase1.py`
    - Offline phase validation plotting and separability checks.

- `validate_system.py`
    - Legacy validation script; references generator APIs not aligned with current runtime classes.

- `forced_cycle_check_300.py`
    - Legacy forced pretrain/evolution check; not applicable in static-only runtime.

- `vanguard.py`
    - Older subprocess orchestrator using shell commands and legacy flow.
    - Superseded by `start_vanguard.py` for current stack usage.

### Temporary scripts under `tmp/`

- `tmp/train_eval_tabnet_metrics.py`
    - Trains/evaluates TabNet metrics from telemetry CSV for experimentation.

- `tmp/forced_cycle_check.py`
    - Legacy forced training cycle script.

## Recommended Current Workflow

1. Keep runtime on static model (`app.py` + `vanguard_brain.py`).
2. Use `/ingest` for deterministic debugging and `/ingest-batch` for throughput simulation.
3. Monitor reasons/top factors and `shadow_stats` via `/dashboard/summary` and the Shadow Model Training UI panel.
4. Retrain/export artifacts in notebook only when intentionally updating model behavior.

## Troubleshooting

- Model not loading:
    - Ensure artifact files exist in `outputs/`.
    - Verify `pytorch-tabnet`, `torch`, and `joblib` are installed.

- No RATE_LIMIT events:
    - Check `threshold` and `rate_limit_margin` values in metadata.
    - Ensure event distribution produces probabilities inside the middle band.

- Hard sample buffer seems empty:
    - Confirm ingest traffic includes ambiguous probability cases near `0.5`.
    - Confirm labels (`is_attack`) are present if you expect misclassification capture.

- Shadow training never promotes:
    - Verify `hard_buffer` fills above minimum sample threshold.
    - Verify `recent_buffer` has enough baseline samples to satisfy the 70/30 mix.
    - Confirm train/validation splits contain both classes.
    - Review shadow margin in dashboard panel against promotion rule (`+0.02` macro-F1).

- Shadow daemon appears idle:
    - Confirm app lifespan startup completed successfully.
    - Check runtime logs for shadow loop wake cycles and evaluation output.

- Dashboard mismatch vs offline notebook metrics:
    - Runtime `brain_stats` are online/live-cycle metrics.
    - Notebook metrics reflect offline validation dataset.

- Slow UI with large data:
    - The app prunes old telemetry/enforcement rows periodically.

## Project Notes

- This repository contains both active runtime code and historical research scripts.
- Prefer `app.py`, `vanguard_brain.py`, `database.py`, `start_vanguard.py`, and web dashboard files for production-like execution.
