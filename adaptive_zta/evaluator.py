import json
import os
import time
from datetime import datetime

class ArgentEvaluator:
    """
    Centralized logging for research experiments.
    Tracks Precision, Recall, F1, Detection Delay, and Coverage.
    """
    def __init__(self, log_path="outputs/experiments.json"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.current_experiment = []

    def log_metrics(self, cycle, metrics):
        """
        Saves a snapshot of metrics for the current training cycle.
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "cycle": cycle,
            "accuracy": round(metrics.get("accuracy", 0), 4),
            "precision": round(metrics.get("precision", 0), 4),
            "recall": round(metrics.get("recall", 0), 4),
            "f1": round(metrics.get("f1", 0), 4),
            "deploy_f1": round(metrics.get("deploy_f1", 0), 4),
            "shadow_f1": round(metrics.get("shadow_f1", 0), 4),
            "avg_delay": round(metrics.get("avg_delay", 0), 2),
            "coverage": round(metrics.get("coverage", 0), 4),
            "total_samples": metrics.get("total_samples", 0),
            "attack_ratio": round(metrics.get("attack_ratio", 0), 4),
            "adversarial_gain": round(metrics.get("adversarial_gain", 0), 4),
            "loss": round(metrics.get("loss", 0), 6),
            "tp": int(metrics.get("tp", 0)),
            "fp": int(metrics.get("fp", 0)),
            "fn": int(metrics.get("fn", 0)),
            "tn": int(metrics.get("tn", 0))
        }
        
        history = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r') as f:
                    history = json.load(f)
            except: pass
            
        history.append(entry)
        
        with open(self.log_path, 'w') as f:
            json.dump(history, f, indent=4)
            
        print(f"📊 Evaluator: Experiment Cycle {cycle} Persisted (F1: {entry['f1']})")

    def calculate_f1(self, tp, fp, fn):
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        return precision, recall, f1
