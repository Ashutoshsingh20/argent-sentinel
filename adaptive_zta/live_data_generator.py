import random
import numpy as np
from datetime import datetime
import time
import config
import requests


RANDOM_SEED = None
ATTACK_RATE = 0.15
TRAFFIC_WINDOW_SIZE = 20
TARGET_RATE_PER_SEC = 200

# [INFINITE SCALING] - Dynamic Pool Constants
REGISTRY_SIZE = 100000  # 100k active-recurring nodes
NEW_NODE_PROB = 0.05    # 5% chance of a totally new randomized ID

CLOUD_ENVS = ["AWS", "Azure", "GCP"]


class TrafficPattern:
    def __init__(self, attack_rate=ATTACK_RATE, window_size=TRAFFIC_WINDOW_SIZE):
        self.attack_rate = attack_rate
        self.window_size = window_size
        self._window = []

    def next_is_attack(self):
        if not self._window:
            attack_count = max(1, round(self.window_size * self.attack_rate))
            normal_count = max(1, self.window_size - attack_count)
            self._window = ([True] * attack_count) + ([False] * normal_count)
            random.shuffle(self._window)
        return self._window.pop()


def get_random_entity():
    """Generates an effectively infinite stream of nodes."""
    if random.random() < NEW_NODE_PROB:
        # Totally unique high-range ID
        node_id = random.randint(1000000, 9999999)
        return f"ext_{node_id}"
    
    # Large recurring pool
    node_id = random.randint(1, REGISTRY_SIZE)
    if node_id < 20000:
        return f"user_{node_id:05d}"
    if node_id < 40000:
        return f"svc_{node_id:05d}"
    return f"node_{node_id:05d}"


def entity_type_for(entity_id):
    if "user_" in entity_id:
        return "user"
    if "svc_" in entity_id:
        return "service"
    return "api"


def positive_normal(mean, std):
    return max(0.01, float(np.random.normal(mean, std)))


def weighted_choice(options):
    roll = random.random()
    total = 0.0
    for value, weight in options:
        total += weight
        if roll <= total:
            return value
    return options[-1][0]


def _build_overlapping_feature_batch(n_samples, attack_rate):
    """
    Build intentionally overlapping normal/attack distributions with attack difficulty tiers.
    Returns X in [0,1] space and y labels (0 normal, 1 attack).
    """
    n_attack = max(1, int(n_samples * attack_rate))
    n_normal = max(1, n_samples - n_attack)
    n_features = 6

    normal = np.random.normal(loc=0.5, scale=0.1, size=(n_normal, n_features))

    n_easy = max(1, int(n_attack * 0.2))
    n_med = max(1, int(n_attack * 0.3))
    n_hard = max(1, n_attack - n_easy - n_med)

    easy_attack = np.random.normal(loc=0.5, scale=0.1, size=(n_easy, n_features))
    easy_attack += np.random.normal(0.3, 0.1, easy_attack.shape)

    medium_attack = np.random.normal(loc=0.5, scale=0.1, size=(n_med, n_features))
    medium_attack += np.random.normal(0.15, 0.08, medium_attack.shape)

    hard_attack = np.random.normal(loc=0.5, scale=0.1, size=(n_hard, n_features))
    hard_attack += np.random.normal(0.05, 0.05, hard_attack.shape)

    X = np.concatenate([normal, easy_attack, medium_attack, hard_attack], axis=0)
    y = np.concatenate(
        [
            np.zeros(len(normal), dtype=np.int32),
            np.ones(len(easy_attack), dtype=np.int32),
            np.ones(len(medium_attack), dtype=np.int32),
            np.ones(len(hard_attack), dtype=np.int32),
        ],
        axis=0,
    )

    # Shortcut killer: enforce feature relationship so single-feature heuristics fail.
    X[:, 0] = X[:, 3] + np.random.normal(0, 0.05, len(X))
    X = np.clip(X, 0.0, 1.0)

    perm = np.random.permutation(len(X))
    return X[perm], y[perm], float(normal.mean())


def _vector_to_record(vec, label, entity_id):
    vec = np.asarray(vec, dtype=float)
    risk = float(np.clip(np.mean(vec[:5]), 0.0, 1.0))

    api_rate = 40.0 + vec[0] * 120.0
    payload_size = 400.0 + vec[1] * 2200.0
    traversal_depth = int(np.clip(round(1.0 + vec[2] * 9.0), 1, 15))
    session_duration = 60.0 + vec[3] * 600.0
    failed_auth_count = int(np.clip(round(vec[4] * 7.0), 0, 12))
    geo_prob = 0.01 + (0.22 * vec[5])
    geo_anomaly_flag = 1 if random.random() < geo_prob else 0

    if label:
        protocol_type = weighted_choice([
            ("HTTPS", max(0.0, 0.52 - 0.25 * risk)),
            ("HTTP", 0.26 + 0.15 * risk),
            ("SSH", 0.22 + 0.10 * risk),
        ])
    else:
        protocol_type = weighted_choice([
            ("HTTPS", max(0.0, 0.72 - 0.15 * risk)),
            ("HTTP", 0.20 + 0.10 * risk),
            ("SSH", 0.08 + 0.05 * risk),
        ])

    is_attack = int(label)
    if getattr(config, "FORCE_ATTACK_DEBUG", False):
        is_attack = 1
        api_rate = 1.0
        payload_size = 1000.0
        traversal_depth = 10
        failed_auth_count = 10
        geo_anomaly_flag = 1
        protocol_type = "SSH"
        session_duration = 10.0

    return {
        "entity_id": entity_id,
        "entity_type": entity_type_for(entity_id),
        "cloud_env": random.choice(CLOUD_ENVS),
        "timestamp": time.time(),
        "api_rate": round(float(api_rate), 2),
        "payload_size": round(float(payload_size), 2),
        "traversal_depth": int(traversal_depth),
        "session_duration": round(float(session_duration), 2),
        "failed_auth_count": int(failed_auth_count),
        "geo_anomaly_flag": int(geo_anomaly_flag),
        "protocol_type": protocol_type,
        "is_attack": is_attack,
    }


def generate_batch_records(batch_size, attack_rate=ATTACK_RATE):
    X, y, normal_mean = _build_overlapping_feature_batch(batch_size, attack_rate)
    attack_full = X[y == 1]
    if len(attack_full) > 0:
        print(
            f"[Argent Sentinel] GENERATOR | Normal Mean: {normal_mean:.4f} | "
            f"Attack Mean: {float(attack_full.mean()):.4f}",
            flush=True,
        )
        print("[Argent Sentinel] GENERATOR | Mean separation should be minimal (< 0.15).", flush=True)

    records = []
    for vec, label in zip(X, y):
        entity_id = get_random_entity()
        records.append(_vector_to_record(vec, int(label), entity_id))
    return records


def format_record(record, total_records, attack_records):
    attack_pct = (attack_records / total_records) * 100 if total_records else 0.0
    clock = datetime.now().strftime("%H:%M:%S")
    trust_hint = "ATTACK" if record["is_attack"] else "NORMAL"
    return (
        f"[{clock}] #{total_records} | {record['entity_id']} | "
        f"{record['entity_type']} | {record['protocol_type']} | is_attack={record['is_attack']}"
    )


def main():
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    total_records = 0
    attack_records = 0
    traffic_pattern = TrafficPattern()

    print(f"🚀 Argent Sentinel High-Throughput Generator Started.")
    print(f"📡 Rate: {TARGET_RATE_PER_SEC} events/sec | Pool: Infinite Dynamic")
    
    try:
        while True:
            start_cycle = time.time()
            
            # [THROUGHPUT BATCHING]
            batch = generate_batch_records(
                TARGET_RATE_PER_SEC,
                attack_rate=traffic_pattern.attack_rate,
            )
            for record in batch:
                total_records += 1
                if record["is_attack"]:
                    attack_records += 1

                # Optional: Check Block (sampled to prevent UI lag)
                if total_records % 50 == 0:
                    try:
                        check = requests.get(f"{config.API_URL}/enforcement/check/{record['entity_id']}", timeout=0.01)
                        if check.status_code == 200 and check.json().get("blocked"):
                            # Logic could drop the record, but for simulation we just log it
                            pass
                    except: pass

            # Submit Batch to Backend (Phase 8: Closed Loop Integration)
            try:
                payload = {"records": batch}
                headers = {"Content-Type": "application/json"}
                # [PHASE 8 NUCLEAR] Restored to 1.0s timeout (Back-end is now sub-10ms)
                resp = requests.post(f"{config.API_URL}/ingest-batch", json=payload, headers=headers, timeout=1.0)
                if resp.status_code not in [200, 202]:
                    print(f"⚠️ Batch submission failed: {resp.status_code} | {resp.text}")
            except Exception as e:
                print(f"⚠️ Connection Error: {e}")

            # Print a status summary every second instead of 200 separate lines
            last_record = batch[-1]
            print(f"{format_record(last_record, total_records, attack_records)} (Batch of {TARGET_RATE_PER_SEC} -> INGESTED)", flush=True)

            # Precise Timing: Adjust sleep to maintain exact 1Hz batch cycles
            elapsed = time.time() - start_cycle
            time.sleep(max(0, 1.0 - elapsed))
            
    except KeyboardInterrupt:
        attack_pct = (attack_records / total_records) * 100 if total_records else 0.0
        print(f"\nStopped. Total: {total_records} | Attacks: {attack_records} ({attack_pct:.2f}%)")


if __name__ == "__main__":
    main()
