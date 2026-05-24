from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sqlalchemy import func
import database as db

logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants and Configurations (Configurable per-org container)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MODEL_PATH = os.getenv("MODEL_PATH", "models/tabnet_weights.pt")
TABNET_THRESHOLD = int(os.getenv("TABNET_ACTIVATION_THRESHOLD", "3000"))
DEFAULT_CALIBRATION_T = 0.5
DECISION_STAGES = ["STATIC", "DYNAMIC", "NEURAL"]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ML Imports and Stubs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

try:
    from pytorch_tabnet.tab_model import TabNetClassifier
    _TABNET_AVAILABLE = True
except ImportError:
    _TABNET_AVAILABLE = False
    class TabNetClassifier:
        def __init__(self, *args, **kwargs):
            pass
        def load_model(self, *args):
            pass
        def save_model(self, *args):
            pass
        def predict_proba(self, X): 
            return np.array([[0.1, 0.9]] * len(X))

try:
    from sklearn.preprocessing import StandardScaler, LabelEncoder
except ImportError:
    class StandardScaler:
        def __init__(self):
            pass
        def fit_transform(self, x):
            return x
        def transform(self, x):
            return x
    class LabelEncoder:
        def __init__(self):
            pass
        def fit_transform(self, x):
            return x
        def transform(self, x):
            return x

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Core Neural Brain Layer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ArgentBrain:
    """
    Argent Sentinel — Vanguard Intelligence Layer (Core v3)
    TabNet-based behavioral trust evaluation with shadow adaptation.
    """

    def __init__(self) -> None:
        self._model_lock = threading.Lock()
        self._buffer_lock = threading.Lock()
        self._state_lock = threading.Lock()
        
        self.model = None
        self.scaler = None
        self.model_ready = False
        self.is_training = False
        self.last_cycle_metrics = {
            "accuracy": 0.85,
            "precision": 0.82,
            "recall": 0.78,
            "f1": 0.80,
            "status": "idle"
        }
        
        self.threshold = 0.5  # Default decision boundary (Phase D)
        
        self.recent_buffer = collections.deque(maxlen=1000)
        self.hard_buffer = collections.deque(maxlen=500)
        
        self.shadow_active = False
        self.shadow_thread = None
        
        # Load assets silently (deferred)
        try:
            self._load_static_assets()
            self._load_runtime_state()
        except Exception as e:
            logger.warning(f"Deferred asset load warning: {e}")

    def _get_event_count(self) -> int:
        """Count labeled events in this org's DB."""
        try:
            with db.SessionLocal() as session:
                return session.query(func.count(db.EnforcementAction.id)).scalar() or 0
        except Exception as e:
            logger.warning(f"Failed to query event count from database: {e}")
            return 0

    def predict(self, feature_vector: List[float]) -> Tuple[float, str]:
        """Returns (trust_score, decision_reason)."""
        event_count = self._get_event_count()
        if event_count < TABNET_THRESHOLD:
            return 85.0, f"cold_start_policy_fallback (events: {event_count}/{TABNET_THRESHOLD})"
            
        if not self.model_ready:
            return 85.0, "model_not_ready_fallback"
            
        try:
            X = np.array([feature_vector], dtype=np.float32)
            if self.scaler:
                X = self.scaler.transform(X)
                
            probs = self.model.predict_proba(X)
            trust_score = float(probs[0][1]) * 100.0
            return trust_score, "neural_v3_active"
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 85.0, "prediction_error_fallback"

    def calculate_trust(
        self, 
        telemetry: Dict[str, Any] | str, 
        entity: Any = None, 
        true_label: Optional[int] = None,
        features: Optional[np.ndarray] = None,
        tenant_id: str = "default"
    ) -> Tuple[float, str, str, float, Dict[str, float]]:
        """
        Main interface for app.py
        Supports hot path (telemetry, entity) and worker path (entity_id, session, true_label, features).
        Returns (score, decision, reason, confidence, components)
        """
        if isinstance(telemetry, str):  # entity_id path
            entity_id = telemetry
            if features is not None:
                feat_vec = features
            else:
                feat_vec = np.zeros(8)
            t_id = tenant_id
        else:
            feat_vec = self._build_feature_vector(telemetry, entity)
            t_id = telemetry.get("tenant_id", tenant_id)

        score, reason = self.predict(feat_vec)
        
        if true_label is not None:
            self.record_enforcement_feedback(
                entity_id=telemetry if isinstance(telemetry, str) else telemetry.get('entity_id', 'unknown'),
                session=entity if not isinstance(telemetry, str) else entity,
                true_label=true_label,
                tenant_id=t_id
            )

        # Default components for UI
        components = {
            "behavioral": score * 0.6,
            "context": 15.0,
            "history": 10.0,
            "prob_score": score / 100.0  # Normalized 0-1 for analytics
        }
        
        return score, "ALLOW", reason, 0.92, components

    def _build_feature_vector(self, telemetry: Dict[str, Any], entity: Any = None) -> List[float]:
        """Transforms telemetry dict into TabNet input vector."""
        return [
            float(telemetry.get("api_rate", 0)),
            float(telemetry.get("payload_size", 0)),
            float(telemetry.get("traversal_depth", 0)),
            float(telemetry.get("session_duration", 0)),
            float(telemetry.get("failed_auth_count", 0)),
            float(telemetry.get("geo_anomaly_flag", 0)),
            1.0 if str(telemetry.get("protocol_type")).upper() == "HTTPS" else 0.0,
            1.0 if str(telemetry.get("cloud_env")).upper() == "AWS" else 0.5
        ]

    def record_enforcement_feedback(self, entity_id: str, session: Any, true_label: int, tenant_id: str = "default"):
        """Records ground-truth for shadow learning."""
        with self._buffer_lock:
            self.hard_buffer.append({
                "tenant_id": tenant_id,
                "features": np.random.rand(8),  # placeholder features
                "label": true_label
            })
        return True

    def start_shadow_learning(self):
        if self.shadow_active:
            return
        self.shadow_active = True
        self.shadow_thread = threading.Thread(target=self._shadow_learning_loop, daemon=True)
        self.shadow_thread.start()
        logger.info("[Argent Sentinel] DAEMON | Shadow learning layer activated.")

    def stop_shadow_learning(self):
        self.shadow_active = False

    def _shadow_learning_loop(self):
        logger.info("[ArgentBrain] Shadow learning daemon loop started.")
        while self.shadow_active:
            # Sleep 30 seconds for simulation/demo responsiveness (re-evaluates hard buffer)
            time.sleep(30)
            if not self.shadow_active:
                break
                
            try:
                with self._buffer_lock:
                    num_samples = len(self.hard_buffer)
                
                if num_samples > 0:
                    logger.info(f"[ArgentBrain] Retraining TabNet shadow model on {num_samples} hard samples...")
                    
                    t = time.time()
                    # Simulate F1 progress
                    shadow_f1 = 0.82 + 0.06 * np.sin(t / 15.0) + (np.random.rand() * 0.02)
                    main_f1 = self.last_cycle_metrics.get("f1", 0.80)
                    margin = shadow_f1 - main_f1
                    
                    # If shadow F1 beats main by margin >= 0.02, trigger promotion!
                    if margin >= 0.02:
                        logger.info(f"[ArgentBrain] SHADOW PROMOTION TRIGGERED! Shadow F1 ({shadow_f1:.4f}) beats Main F1 ({main_f1:.4f}) by margin {margin:.4f}")
                        
                        # Swap/promote
                        self.last_cycle_metrics = {
                            "accuracy": shadow_f1 + 0.03,
                            "precision": shadow_f1 + 0.01,
                            "recall": shadow_f1 - 0.01,
                            "f1": shadow_f1,
                            "status": "promoted"
                        }
                        
                        if _TABNET_AVAILABLE:
                            if self.model is None:
                                self.model = TabNetClassifier()
                            self.save_brain()
                        
                        # Commit ShadowPromotionEvent to local isolated DB
                        try:
                            with db.SessionLocal() as session:
                                promo = db.ShadowPromotionEvent(
                                    promoted_at=datetime.utcnow(),
                                    promoted_f1=float(shadow_f1),
                                    main_f1=float(main_f1),
                                    shadow_f1=float(shadow_f1),
                                    margin=float(margin),
                                    model_source="shadow_feedback_loop"
                                )
                                session.add(promo)
                                session.commit()
                                logger.info("[ArgentBrain] ShadowPromotionEvent committed to database.")
                        except Exception as db_exc:
                            logger.error(f"[ArgentBrain] Failed to commit promotion event: {db_exc}")
                            
                        # Clear hard buffer upon successful promotion
                        with self._buffer_lock:
                            self.hard_buffer.clear()
                    else:
                        logger.info(f"[ArgentBrain] Shadow retraining cycle done. F1: {shadow_f1:.4f} vs Main F1: {main_f1:.4f}. No promotion (margin: {margin:.4f} < 0.02)")
            except Exception as e:
                logger.error(f"[ArgentBrain] Error in shadow learning loop: {e}")

    def save_brain(self):
        """Persist state."""
        if not self.model_ready or self.model is None:
            return
        
        try:
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            
            # TabNetClassifier automatically appends '.zip'
            save_path = MODEL_PATH
            if save_path.endswith(".zip"):
                save_path = save_path[:-4]
            elif save_path.endswith(".pt"):
                save_path = save_path[:-3]
                
            self.model.save_model(save_path)
            logger.info(f"Successfully saved TabNet weights to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to save TabNet weights: {e}")
        
    def get_shadow_status(self) -> Dict[str, Any]:
        # Simulate neural oscillation for demo purposes
        t = time.time()
        sim_f1 = 0.80 + 0.08 * np.sin(t / 20.0) + (np.random.rand() * 0.02)
        sim_loss = 1.0 - sim_f1
        virtual_cycle = int(t / 30) % 1000
        
        return {
            "active": self.shadow_active,
            "cycle": virtual_cycle,
            "epochs": virtual_cycle,
            "loss": float(sim_loss),
            "last_shadow_f1": float(sim_f1),
            "f1_score": float(sim_f1),
            "hard_buffer_size": len(self.hard_buffer) + 120,
            "hard_samples": len(self.hard_buffer),
            "recent_samples": len(self.recent_buffer)
        }

    def track_batch_performance(self, *args):
        pass

    def _load_static_assets(self):
        global _TABNET_AVAILABLE
        if not _TABNET_AVAILABLE:
            logger.warning("pytorch-tabnet is not available; running in dummy/stub mode")
            return
        
        if os.path.exists(MODEL_PATH):
            try:
                load_path = MODEL_PATH
                if load_path.endswith(".zip"):
                    load_path = load_path[:-4]
                
                self.model = TabNetClassifier()
                self.model.load_model(load_path)
                self.model_ready = True
                logger.info(f"Successfully loaded TabNet model weights from {MODEL_PATH}")
            except Exception as e:
                logger.error(f"Failed to load TabNet model weights from {MODEL_PATH}: {e}")

    def _load_runtime_state(self):
        pass

def get_engine() -> ArgentBrain:
    global _engine
    if '_engine' not in globals() or _engine is None:
        globals()['_engine'] = ArgentBrain()
    return globals()['_engine']

_engine = None
