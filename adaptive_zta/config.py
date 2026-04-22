import random
import numpy as np
import time

# Global Seed for Reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# Simulation Constraints
INITIAL_ACTIVE_ENTITIES = 50000
SPAWN_NEW_ENTITY_PROBABILITY = 1.0
MAX_NEW_SPAWNS_PER_STEP = 50
TARGET_INGESTION_RATE = 200
TOTAL_TIMESTEPS = 9999999 # Effectively Infinite
TIMESTEP_DURATION_SEC = 60

# Attack configuration
ATTACK_START_TIMESTEP = 1 # Immediate engagement
ATTACK_END_TIMESTEP = 9999999
ATTACK_ENTITY_COUNT = int(INITIAL_ACTIVE_ENTITIES * 0.25) # More aggressive breach

# Environment configurations
base_envs = ['AWS', 'Azure', 'GCP']
CLOUD_ENVIRONMENTS = [base_envs[i % len(base_envs)] for i in range(INITIAL_ACTIVE_ENTITIES)]

ENTITY_TYPES_DIST = {
    'service_account': 0.35,
    'human_user': 0.25,
    'api_gateway': 0.25,
    'microservice': 0.15
}

# Research-Grade Constraints
ATTACK_RATIO_LIMIT = 0.3
MAX_ATTACK_RATIO = ATTACK_RATIO_LIMIT
TRAIN_INTERVAL = 1000
FREEZE_MODEL = True
COVERAGE_MARGIN = 10.0
ENABLE_CLEAN_PRETRAIN = False
FORCE_PRETRAIN = False
PRETRAIN_STEPS = 0
PRETRAIN_BATCH_SIZE = 64

# Core Trust Parameters
TRUST_PARAMS = {
    'lambda': 0.70, # temporal momentum
    'alpha': 0.50,  # behavioral weight
    'beta': 0.10,   # context weight
    'gamma': 0.10,  # historical weight
    'delta': 1.20   # anomaly penalty
}

PASS_THRESHOLD = 70.0
RATE_LIMIT_THRESHOLD = 45.0
ISOLATE_THRESHOLD = 35.0
TRAIN_THRESHOLD = PASS_THRESHOLD + 5
DROP_DAMPING = 0.8
BASE_COOLDOWN = 60
MAX_COOLDOWN = 600
API_URL = "http://127.0.0.1:8000"
FORCE_ATTACK_DEBUG = False
FORCE_ANOMALY_DEBUG = False
RL_UPDATE_INTERVAL = 100 # Match research cycles
RL_WEIGHTS_PATH = "outputs/rl_trust_params.json"
RL_OPTIMIZATION_GOAL = "maximum_security"

# Stable Baseline Configuration
STABLE_MSE_THRESHOLD = 0.6

T_INIT = 75.0
H_INIT = 0.75
MU = 0.05
SMOOTHING_FACTOR = 0.40
FORCE_ATTACK_DEBUG = False
FORCE_ANOMALY_DEBUG = False

