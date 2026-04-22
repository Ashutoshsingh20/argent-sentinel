# Argent Sentinel Detailed Overview

Last updated: 2026-04-20

## 1. Executive Summary
Argent Sentinel is an adaptive Zero Trust platform that ingests telemetry, computes risk using a TabNet-backed trust pipeline, and emits enforcement decisions (`ALLOW`, `RATE_LIMIT`, `ISOLATE`).

The system is designed around two priorities:
- deterministic online decisions in the request path
- controlled adaptability outside the request path (shadow learning, cloud feature discovery, policy extension)

Primary outcomes:
- low-latency trust decisions
- auditable decision reasoning
- safe cloud integration across AWS, Azure, and GCP
- configurable production hardening by default

## 2. Scope and Non-Scope

In scope:
- FastAPI control plane and HTML dashboard
- trust inference and gateway orchestration
- telemetry ingest (`/ingest`, `/ingest-batch`)
- persistence via SQLAlchemy/SQLite
- hot-state layer (Redis when available, in-memory fallback)
- runtime auth/rate-limit controls
- dynamic cloud capability listing
- cloud action execution APIs and UI

Not in scope:
- full RBAC authorization model for cloud actions (JWT validity is primary gate today)
- universal deep feature introspection for every cloud provider service

## 3. Architecture at a Glance

```text
Clients / Simulators
        |
        v
FastAPI App (app.py)
  |- Security middleware (JWT + rate limit)
  |- Trust and gateway endpoints
  |- UI and operator endpoints
  |- Cloud capability and cloud action endpoints
        |
        +--> Decision runtime (vanguard_brain.py + phase5)
        +--> SQL persistence (database.py)
        +--> Hot state (Redis or in-memory)
        +--> Metrics and structured logs
```

## 4. Request Processing Lifecycle

Online request path:
1. Request enters `app.py`.
2. Security middleware validates JWT (if enabled and route not exempt).
3. Rate limiter checks per-client window.
4. Feature construction and trust inference execute.
5. Decision and telemetry artifacts are persisted.
6. Recent event buffer is updated for UI routes.
7. Response returns with decision metadata.

Design guardrails:
- auth and rate failures return JSON responses from middleware
- request path avoids expensive retraining logic
- deterministic fallback behavior is preferred over hard failure where possible

## 5. Core Modules

### 5.1 API and Orchestration
- `app.py`
  - all major routes
  - middleware wiring
  - UI event buffers
  - cloud capability and action route integration

### 5.2 Trust and Gateway Runtime
- `vanguard_brain.py`
  - trust inference and adaptive internals
- `phase5/decision_engine.py`
  - authorization and escalation details
- `phase5/gateway.py`
  - adaptive gateway path and async-friendly integration

### 5.3 Persistence and State
- `database.py`
  - entity, telemetry, and enforcement persistence models
- hot state
  - Redis when enabled/reachable
  - automatic in-memory fallback if Redis is unavailable

### 5.4 Security and Metrics
- `runtime_security.py`
  - JWT validation (HS/RS, optional JWKS)
  - HTTPS gating for authenticated routes
  - in-memory rate limiter
- `runtime_metrics.py`
  - HTTP/decision counters and latency measurements
- `runtime_logging.py`
  - configurable structured/text logging

### 5.5 Cloud Integration Layer
- `cloud_features.py`
  - provider capability discovery and caching
  - AWS dynamic service list, optional Azure provider discovery, GCP baseline list
  - optional external manifest merge
- `cloud_actions.py`
  - provider invocation engine
  - read-only-safe defaults and mutation guard policy
  - timeout-controlled outbound cloud calls

## 6. Endpoint Inventory (Implemented)

### 6.1 Core Runtime Endpoints
- `GET /healthz`
- `GET /model-info`
- `POST /authorize`
- `POST /gateway`
- `POST /gateway/feedback`
- `POST /ingest`
- `POST /ingest-batch`
- `GET /metrics`
- `GET /metrics/snapshot`

### 6.2 UI and Operator Endpoints
- `GET /ui`
- `GET /ui/status`
- `GET /ui/events`
- `GET /ui/entity/{entity_id}`
- `GET /ui/cloud/features`
- `GET /ui/cloud/providers`

### 6.3 Cloud Action Endpoints
- `GET /cloud/actions/catalog`
- `POST /cloud/actions/invoke`

## 7. Authentication and Route Behavior

JWT middleware behavior:
- JWT checks apply when `JWT_ENABLED=1` and route is not exempt.
- Exempt path roots include:
  - `/`
  - `/healthz`
  - `/metrics`
  - `/docs`
  - `/openapi.json`
  - `/ui*`
  - `/static/*`
  - `/ws/*`
  - `/favicon.ico`

Implication:
- dashboard pages load without token by design
- cloud action routes are protected unless JWT is globally disabled

Transport/security gates:
- authenticated routes can require HTTPS (`JWT_REQUIRE_HTTPS_FOR_AUTH=1`)
- insecure default secret (`change-me`) is blocked unless explicit insecure-dev override is set

## 8. Cloud Capability and Action Model

### 8.1 Capability Discovery
- AWS: SDK session service discovery
- Azure: provider namespace listing when SDK + credentials + scope are valid
- GCP: baseline services, extensible through external manifests

### 8.2 Invocation Payload Patterns

AWS invocation:
```json
{
  "provider": "aws",
  "action": "invoke",
  "service": "sts",
  "operation": "get_caller_identity",
  "params": {}
}
```

Azure invocation:
```json
{
  "provider": "azure",
  "action": "invoke",
  "method": "GET",
  "path": "/subscriptions/<subId>/resourcegroups",
  "api_version": "2021-04-01"
}
```

GCP invocation:
```json
{
  "provider": "gcp",
  "action": "invoke",
  "method": "GET",
  "url": "https://cloudresourcemanager.googleapis.com/v1/projects"
}
```

### 8.3 Safety Controls
- global and per-provider enable flags must be on
- mutating operations are blocked by default
- outbound call timeout is centrally configured

## 9. Configuration Behavior (Important Nuance)

Static defaults (`runtime_settings.py`):
- cloud action flags default to disabled

Local launcher behavior (`run.sh`):
- sets safe local `JWT_SECRET` if missing or `change-me`
- enables cloud action provider flags for local testing
- keeps cloud mutation disabled by default

This means local `run.sh` behavior is intentionally more developer-friendly than bare process startup.

## 10. Operations Runbook

Start locally:
```bash
./run.sh
```

Open console:
```text
http://127.0.0.1:<selected_port>/ui
```

If Cloud Action Studio returns provider credential errors:
- AWS: configure AWS credential chain
- Azure: configure identity usable by `DefaultAzureCredential`
- GCP: configure ADC credentials

If cloud action routes return auth errors:
- verify token `iss` and `aud`
- verify HTTPS gating behavior (`x-forwarded-proto` in proxied/local setups)
- verify `JWT_SECRET`/JWKS alignment with the token

## 11. Known Constraints
- capability discovery does not guarantee executable access (credentials/permissions may still deny calls)
- advanced Azure/GCP discovery depth depends on installed SDKs and granted scopes
- frequent UI polling can create noisy access logs

## 12. Recommended Hardening Roadmap
1. Add allowlist policy for approved provider services/operations.
2. Add cloud action audit trail with actor identity and request hash.
3. Add role-based authorization for cloud action scopes.
4. Add prebuilt action templates with validation.
5. Add configurable UI polling intervals and server-side sampling for noisy endpoints.

## 13. File Map
- `app.py` - routes, middleware, orchestration
- `runtime_settings.py` - env-driven settings model
- `runtime_security.py` - auth and rate limiting
- `runtime_metrics.py` - metrics APIs and counters
- `cloud_features.py` - dynamic capability registry
- `cloud_actions.py` - provider invocation engine
- `static/index.html` - dashboard and Cloud Action Studio
- `run.sh` - single-command startup defaults

## 14. Bottom Line
Argent Sentinel currently functions as:
- a trust-decision control plane
- an operator-facing live dashboard
- a guarded multi-cloud action surface that is ready for enterprise hardening extensions
