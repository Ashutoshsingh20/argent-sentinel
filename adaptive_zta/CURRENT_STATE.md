# Argent Sentinel Current State

Last updated: 2026-04-19

## Project Description
Argent Sentinel is an adaptive Zero Trust security platform that evaluates every entity interaction in real time and converts model output into dynamic enforcement actions.

The system combines:
- a FastAPI control plane
- a TabNet-based trust decision engine
- high-throughput telemetry ingestion
- SQLite-backed persistent state
- enforcement simulation and observability dashboards

Its core objective is to move from static policy-only controls to model-informed, probability-driven trust decisions while preserving operational safety and explainability.

## Detailed Project Overview
### End-to-end objective
- Ingest live telemetry at scale.
- Build robust behavioral/context/anomaly signals per entity.
- Infer attack probability with the active TabNet model.
- Translate probability to trust and enforcement actions (ALLOW, RATE_LIMIT, ISOLATE).
- Persist evidence and expose transparent reasoning for operators.
- Continuously improve model quality through overlap-aligned retraining.

### Runtime architecture
- Control plane/API: app.py
- Decision engine: vanguard_brain.py
- Telemetry generator/simulator: data_generator.py
- Persistence: database.py (SQLite)
- Batch stream ingestor: ingestor.py
- Monitoring interfaces: dashboard + optional TUI

### Operational flow
1. Telemetry arrives through /ingest or /ingest-batch.
2. Records are validated and persisted.
3. Runtime features are constructed (behavior, context, history, anomaly + interactions).
4. TabNet predicts attack probability.
5. Probability is calibrated and mapped to decision thresholds.
6. Trust score and action are written to entity/enforcement state.
7. Explanation metadata and top factors are emitted to dashboard APIs.

### Current modeling approach
- Probability-led decisioning with staged thresholds.
- Temperature calibration for probability spread control.
- Feature signal shaping (behavior + anomaly emphasis).
- Overlap-focused generator distributions (hard/medium/easy attacks).
- Retraining uses mixed generated + real buffer/database data.
- Boundary-focused weighting and selective stabilization for distribution control.

### Enforcement semantics
- ALLOW: normal traffic permitted.
- RATE_LIMIT: restricted access posture.
- ISOLATE: high-risk entity containment.

### Why this design
- Keeps inference deterministic and fast for online paths.
- Supports iterative model shaping without changing core model architecture.
- Preserves traceability through persisted metadata and explicit probability diagnostics.

## Summary
The model-shaping cycle is complete for the current iteration.

Key completion gate achieved:
- p90 > 0.68 (current: 0.7555)

## Active Model Artifacts
- Retrained model: outputs/retrained_model.zip
- Active production model: outputs/production_model_latest.zip
- Active scaler: outputs/tabnet_validation_scaler.joblib
- Current metadata: outputs/retrained_meta.json

## Latest Validation Distribution
From outputs/retrained_meta.json:
- mean: 0.3830
- p10: 0.0091
- p50: 0.3800
- p90: 0.7555
- diagnosis: MIXED_INTERMEDIATE

## Current Decisioning Parameters
- Decision stage: 0
- Thresholds: allow/rate_limit at 0.40, isolate at 0.70
- Probability calibration temperature (T): 0.52

## Current Shaping Settings
### Runtime feature boost
- behavior feature multiplier: 1.2
- anomaly feature multiplier: 1.3

### Generator attack mix
- hard: 30%
- medium: 40%
- easy: 30%

### Generator mean shifts
- hard mu: 0.06
- medium mu: 0.12
- easy mu: 0.25

### Retraining weighting
- Base boundary weighting: 1 + 3 * (1 - confidence)
- Attack sharpening: y_adjusted = clip(y * 1.1, 0, 1)
- Selective normal stabilization: apply 1.1 weight only when label is normal and initial_prob < 0.2

## Latest Retraining Snapshot
- Dataset total: 89181
- Attack ratio: 0.3364
- Best validation AUC: 0.81267
- Model save targets updated during last run:
  - outputs/retrained_model.zip
  - outputs/production_model_latest.zip

## Notes
- This state reflects the final correction pass.
- Distribution still shows a very low p10, but upper-tail separation reached the requested completion gate.

## Phase 4 Validation Harness (Real-World Hardening)

Validation-only runner (no parameter edits, no retraining):
- Script: `validate_phase4_real_world.py`
- API paths used: `/authorize`, `/gateway`, `/gateway/feedback`, `/model-info`
- Log artifacts:
  - `outputs/phase4_validation_events.jsonl`
  - `outputs/phase4_validation_events.csv`
  - `outputs/phase4_validation_summary.json`

Default run (full target profile):

```bash
python validate_phase4_real_world.py \
  --api-url http://127.0.0.1:8000 \
  --normal-iterations 1000 \
  --recovery-normals 10 \
  --fp-normal-samples 300 \
  --fn-attack-samples 300 \
  --long-run-duration 3600 \
  --long-run-rps 3 \
  --adaptive-cycles 5 \
  --adaptive-per-cycle 20
```

Quick smoke run:

```bash
python validate_phase4_real_world.py \
  --normal-iterations 100 \
  --fp-normal-samples 60 \
  --fn-attack-samples 60 \
  --long-run-duration 60 \
  --adaptive-cycles 3 \
  --adaptive-per-cycle 10
```

## Phase 4 Clean Control Fixes Applied

Decision-path hardening now active in runtime (no retrain, no generator/model changes):
- Probability smoothing per entity: `p_smooth = 0.85 * prev + 0.15 * p`
- Hard hysteresis: `ISOLATE` hold window with cooldown before recovery
- Strict decision boundaries on smoothed probability:
  - `p_smooth < 0.40` -> `ALLOW`
  - `0.40 <= p_smooth < 0.70` -> `RATE_LIMIT`
  - `p_smooth >= 0.70` -> `ISOLATE`
- State transition control to block random jumps and enforce progression
- Confidence gate near boundary center to suppress weak flips

Gateway path is aligned to preserve model-policy decision as source-of-truth (no downstream decision override).

## Targeted Re-Validation (Requested 3 Tests)

Latest targeted result file:
- `outputs/phase4_targeted_results_100.json`

- Normal stability: PASS
- Gradual attack escalation: PASS
- Recovery/hysteresis: PASS

## Phase E Hardening (SOC Visibility)
- **Status**: Complete
- **Components Implemented**:
  1. **Alerting Engine (`alerting_engine.py`)**: SQLite-backed, background scanning subsystem with 12 built-in rules (isolation spikes, anomalies, fallback triggers, execution limit breaches). Supports lifecycle states (FIRING -> ACKNOWLEDGED -> RESOLVED).
  2. **Control Plane SOC Endpoints**: Added 9 new `/soc/*` endpoints to `app.py` bypassing tenant ID requirements. Exposes aggregated metrics, alerts, decision distribution, and timeline events for command-center consumption.
  3. **SOC Command Center Dashboard (`soc_dashboard.html`)**: Premium dark-mode interface at `/soc/dashboard` featuring live `Chart.js` tracking for decision distribution, component health telemetry, visual tenant limits, and timeline forensics. Auto-refreshes seamlessly.
- **Environment Stability**: Fixed integration issues. Live simulator now batches data successfully into the backend without degrading performance, simulating high-throughput conditions.
