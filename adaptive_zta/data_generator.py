import os
import pandas as pd
import numpy as np
import config
import time
from datetime import datetime, timedelta

class Simulator:
    """
    Argent Sentinel Stress Testing Simulator.
    Supports real-time mode switching for adversarial validation.
    """
    def __init__(self):
        self.mode = "normal"
        self.intensity = 0.5
        self.end_time = None
        
        print("🚀 Simulator: Initializing entity pool...")
        self.entities = self._initialize_entities()
        # Initial pool is just the first set, but run_cycle will now pick randomly
        self.active_pool_ids = [e['entity_id'] for e in self.entities[:config.TARGET_INGESTION_RATE]]
        
        # Internal Red Team Targets
        self.static_attack_entities = self._assign_static_attack_entities()

    def set_mode(self, mode, intensity=0.5, duration=60):
        self.mode = mode
        self.intensity = intensity
        self.end_time = time.time() + duration if mode != "normal" else None
        print(f"📡 Simulator: Mode changed to {mode.upper()} (Intensity: {intensity}, Duration: {duration}s)")

    def _initialize_entities(self):
        entities = []
        types_pool = []
        for e_type, frac in config.ENTITY_TYPES_DIST.items():
            types_pool.extend([e_type] * int(config.INITIAL_ACTIVE_ENTITIES * frac))
        
        while len(types_pool) < config.INITIAL_ACTIVE_ENTITIES:
            types_pool.append('human_user')
            
        clouds = np.random.choice(config.CLOUD_ENVIRONMENTS, config.INITIAL_ACTIVE_ENTITIES)
        np.random.shuffle(types_pool)
        
        for i in range(config.INITIAL_ACTIVE_ENTITIES):
            entities.append({
                'entity_id': f"ENT-{i:03d}",
                'cloud_env': clouds[i],
                'entity_type': types_pool[i]
            })
        return entities

    def _assign_static_attack_entities(self):
        count = max(1, int(len(self.entities) * 0.05))
        target_indices = np.random.choice(range(len(self.entities)), size=count, replace=False)
        return {self.entities[idx]['entity_id'] for idx in target_indices}

    def _spawn_new_entities(self):
        """Infinite Scaling: Add new entities to the pool."""
        if np.random.rand() < config.SPAWN_NEW_ENTITY_PROBABILITY:
            num_to_spawn = np.random.randint(1, config.MAX_NEW_SPAWNS_PER_STEP + 1)
            clouds = np.random.choice(config.CLOUD_ENVIRONMENTS, num_to_spawn)
            types_pool = list(config.ENTITY_TYPES_DIST.keys())
            
            for _ in range(num_to_spawn):
                new_idx = len(self.entities)
                self.entities.append({
                    'entity_id': f"ENT-{new_idx:03d}",
                    'cloud_env': np.random.choice(clouds),
                    'entity_type': np.random.choice(types_pool)
                })

    def compute_overlap(self, normal_samples, attack_samples):
        """Fix 5: Validate Distribution Overlap."""
        if not normal_samples or not attack_samples:
            return 0.0
            
        n_rates = [s['api_rate'] for s in normal_samples]
        a_rates = [s['api_rate'] for s in attack_samples]
        
        n_mu, n_std = np.mean(n_rates), np.std(n_rates)
        a_mu, a_std = np.mean(a_rates), np.std(a_rates)
        
        dist = abs(n_mu - a_mu)
        spread = (n_std + a_std) / 2.0
        score = 1.0 / (1.0 + (dist / (spread + 1e-6)))
        return round(score, 3)

    def generate_boundary_sample(self, features):
        """Boundary sampler with moderated perturbation (0.8-1.2)."""
        p_features = features.copy()
        # Perturb continuous behavioral features as a vector
        keys = ['api_rate', 'payload_size', 'traversal_depth', 'session_duration']
        feat_vec = np.array([p_features[k] for k in keys])
        perturbation = np.random.uniform(0.8, 1.2, size=feat_vec.shape)
        p_vec = feat_vec * perturbation
        for i, k in enumerate(keys):
            p_features[k] = p_vec[i]
        return p_features

    def generate_drift_sample(self, features):
        """FIX 6: Behavioral Drift (Slow, subtle increase in activity)"""
        d_features = features.copy()
        d_features['api_rate'] *= np.random.uniform(1.1, 1.5)
        d_features['payload_size'] *= np.random.uniform(1.2, 1.8)
        d_features['traversal_depth'] += 1
        return d_features

    def generate_overlap_attack_sample(self, features, profile):
        """Generate overlapping attack samples with controlled perturbation magnitudes."""
        a_features = features.copy()
        keys = ['api_rate', 'payload_size', 'traversal_depth', 'session_duration']
        base_vec = np.array([max(1.0, float(a_features[k])) for k in keys], dtype=float)

        if profile == 'HARD':
            mu, sigma = 0.06, 0.05
            fail_mean, geo_p = 0.2, 0.02
        elif profile == 'MEDIUM':
            mu, sigma = 0.12, 0.06
            fail_mean, geo_p = 0.5, 0.05
        else:
            mu, sigma = 0.25, 0.08
            fail_mean, geo_p = 1.0, 0.10

        noise = np.random.normal(mu, sigma, size=base_vec.shape)
        attacked_vec = base_vec + (noise * base_vec)
        attacked_vec = np.maximum(attacked_vec, 1.0)

        a_features['api_rate'] = attacked_vec[0]
        a_features['payload_size'] = attacked_vec[1]
        a_features['traversal_depth'] = int(max(0, round(attacked_vec[2])))
        a_features['session_duration'] = attacked_vec[3]
        a_features['failed_auth_count'] = int(np.random.poisson(fail_mean))
        a_features['geo_anomaly_flag'] = int(np.random.binomial(1, geo_p))
        a_features['protocol_type'] = np.random.choice(['HTTPS', 'HTTP', 'SSH'], p=[0.8, 0.15, 0.05])
        return a_features

    def _generate_features(self, is_attack, t, force_normal=False):
        # 1. Base Normal Features
        rate = max(1, np.random.normal(10, 3) + np.random.normal(0, 0.1))
        payload = max(1, (rate * 50) + np.random.normal(0, 5) + np.random.normal(0, 1.0))
        depth = np.random.poisson(1)
        
        features = {
            'api_rate': rate,
            'payload_size': payload,
            'traversal_depth': depth,
            'session_duration': np.random.exponential(120),
            'failed_auth_count': np.random.poisson(0.01),
            'geo_anomaly_flag': np.random.binomial(1, 0.001),
            'protocol_type': np.random.choice(['HTTPS', 'HTTP'], p=[0.98, 0.02])
        }

        if force_normal:
            return features, False

        # 2. Overlap-first attack generation for harder, more realistic discrimination.
        effective_is_attack = False
        sample_type = "NORMAL"

        if is_attack:
            roll = np.random.rand()
            if roll < 0.30:
                profile = 'HARD'
            elif roll < 0.70:
                profile = 'MEDIUM'
            else:
                profile = 'EASY'
            features = self.generate_overlap_attack_sample(features, profile)
            effective_is_attack = True
            sample_type = f"ATTACK_{profile}"
        elif np.random.rand() < 0.08:
            # Small benign variation in normal traffic to avoid over-clean baselines.
            features = self.generate_boundary_sample(features)
            sample_type = "NORMAL_VARIANT"

        if getattr(config, "FORCE_ATTACK_DEBUG", False):
            features["api_rate"] = 1.0
            features["payload_size"] = 1000.0
            features["traversal_depth"] = 10
            effective_is_attack = True
            sample_type = "FORCED_ATTACK"
            
        sample = np.array([features["api_rate"], features["payload_size"], features["traversal_depth"]], dtype=float)
        print(f"GEN SAMPLE: {sample}")
        print(f"GEN TYPE: {sample_type}")
        if sample_type != "NORMAL":
            print("ATTACK GENERATED")
            
        return features, effective_is_attack


    def run_cycle(self, t):
        """Executes one simulation timestep with dynamic sampling."""
        # 1. Handle Growth
        self._spawn_new_entities()

        # FIX 2: Restore Attack Generation Pipeline - Verify mode integrity
        print(f"SIM MODE: {self.mode}")

        # 2. Dynamic Sampling: Pick 200 random entities to report this second
        # This ensures the dashboard sees new nodes over time while rate is capped at 200/s
        sample_indices = np.random.choice(range(len(self.entities)), size=config.TARGET_INGESTION_RATE, replace=False)
        current_active = [self.entities[idx] for idx in sample_indices]


        timestep_data = []
        timestamp = time.time()

        attack_limit = getattr(config, 'ATTACK_RATIO_LIMIT', config.MAX_ATTACK_RATIO)
        max_attacks = int(attack_limit * len(current_active))
        attack_count = 0
        for ent in current_active:
            ent_id = ent['entity_id']
            is_attack = ent_id in self.static_attack_entities
            
            # Ground truth is_attack reflects either static target or probabilistic roll
            features, effective_is_attack = self._generate_features(is_attack, t)
            
            if effective_is_attack:
                attack_count += 1
            
            row = {
                'entity_id': ent_id,
                'cloud_env': ent['cloud_env'],
                'entity_type': ent['entity_type'],
                'timestamp': float(timestamp),
                'timestep': t,
                **features,
                'is_attack': 1 if effective_is_attack else 0
            }
            timestep_data.append(row)

        if attack_count > max_attacks:
            overflow = attack_count - max_attacks
            attack_indices = [idx for idx, row in enumerate(timestep_data) if row['is_attack'] == 1]
            if overflow > 0 and attack_indices:
                demote_indices = np.random.choice(attack_indices, size=min(overflow, len(attack_indices)), replace=False)
                for idx in demote_indices:
                    row = timestep_data[idx]
                    features, _ = self._generate_features(False, t, force_normal=True)
                    for key, value in features.items():
                        row[key] = value
                    row['is_attack'] = 0
                attack_count -= len(demote_indices)
                print(f"⚖️ Rebalanced attack ratio: demoted {len(demote_indices)} samples")
        
        # FIX 7: STABILITY CONSTRAINTS
        # FIX: Align with new 30/10/60 research mix + variance
        attack_ratio = attack_count / len(current_active)
        assert attack_ratio <= attack_limit, f"Attack ratio {attack_ratio:.2f} exceeds research bounds!"
        
        return timestep_data


if __name__ == "__main__":
    sim = Simulator()
    # Self-validation: collect only the feature dictionaries
    n_batch = [sim._generate_features(False, 0)[0] for _ in range(100)]
    a_batch = [sim._generate_features(True, 0)[0] for _ in range(100)]
    overlap = sim.compute_overlap(n_batch, a_batch)
    print(f"Validation Overlap: {overlap}")
    n_vec = np.asarray(
        [
            [
                min(1.0, s['api_rate'] / 500.0),
                min(1.0, s['payload_size'] / 5000.0),
                min(1.0, float(s['traversal_depth']) / 20.0),
                min(1.0, s['session_duration'] / 3600.0),
            ]
            for s in n_batch
        ],
        dtype=float,
    )
    a_vec = np.asarray(
        [
            [
                min(1.0, s['api_rate'] / 500.0),
                min(1.0, s['payload_size'] / 5000.0),
                min(1.0, float(s['traversal_depth']) / 20.0),
                min(1.0, s['session_duration'] / 3600.0),
            ]
            for s in a_batch
        ],
        dtype=float,
    )
    n_mean = float(np.mean(n_vec))
    a_mean = float(np.mean(a_vec))
    print(f"Normal mean: {n_mean:.4f}")
    print(f"Attack mean: {a_mean:.4f}")
    print(f"Mean difference: {abs(n_mean - a_mean):.4f}")
    if not getattr(config, "FORCE_ATTACK_DEBUG", False):
        assert overlap > 0.35, "Distributions too separable for research-grade boundary testing!"

    # --- REAL-TIME STREAMING LOOP ---
    OUTPUT_FILE = "outputs/telemetry_data.csv"
    os.makedirs("outputs", exist_ok=True)
    
    print(f"🚀 Neural Stream Generator: Streaming to {OUTPUT_FILE}...")
    
    # Write Header
    header = "entity_id,cloud_env,entity_type,timestamp,timestep,api_rate,payload_size,traversal_depth,session_duration,failed_auth_count,geo_anomaly_flag,protocol_type,is_attack\n"
    with open(OUTPUT_FILE, "w") as f:
        f.write(header)

    t = 0
    try:
        while True:
            start_time = time.time()
            
            data = sim.run_cycle(t)
            
            with open(OUTPUT_FILE, "a") as f:
                for row in data:
                    line = f"{row['entity_id']},{row['cloud_env']},{row['entity_type']}," \
                           f"{row['timestamp']},{row['timestep']},{row['api_rate']}," \
                           f"{row['payload_size']},{row['traversal_depth']},{row['session_duration']}," \
                           f"{row['failed_auth_count']},{row['geo_anomaly_flag']},{row['protocol_type']}," \
                           f"{row['is_attack']}\n"
                    f.write(line)
            
            # Precise Timing: Calculate sleep to maintain strict 1Hz frequency (200 records / sec)
            elapsed = time.time() - start_time
            sleep_time = max(0, 1.0 - elapsed)
            time.sleep(sleep_time) 
            
            t += 1
            if t % 10 == 0:
                # Real-time Telemetry: Total Sent is t * config.TARGET_INGESTION_RATE
                current_rate = config.TARGET_INGESTION_RATE / (time.time() - (start_time - (elapsed if t==1 else 0))) # heuristic
                print(f"📡 Neural Stream Generator: Step {t} | Throughput: {config.TARGET_INGESTION_RATE} events/sec")
                
    except KeyboardInterrupt:
        print("🛑 Neural Stream Generator: Stopping...")
