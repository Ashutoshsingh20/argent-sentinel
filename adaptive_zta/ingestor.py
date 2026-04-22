import pandas as pd
import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor
import config
import os
import sys

# Config
API_URL = f"{config.API_URL}/ingest-batch"
CHUNKS_PATH = 'outputs/telemetry_data.csv'
BATCH_SIZE = 100

def send_batch(batch_payload):
    try:
        requests.post(API_URL, json={"records": batch_payload}, timeout=10)
    except Exception as e:
        print(f"❌ Transmission Error: {e}")

def run_stream_simulation():
    print("Argent Sentinel V7.2 High-Throughput Batch Ingestor Online...")
    print(f"Piping telemetry from {CHUNKS_PATH}...")
    
    total_sent = 0
    batch = []
    
    while not os.path.exists(CHUNKS_PATH):
        time.sleep(1)

    with open(CHUNKS_PATH, 'r') as f:
        # Skip Header
        f.readline()
        
        while True:
            line = f.readline()
            if not line:
                if batch:
                    send_batch(batch)
                    total_sent += len(batch)
                    batch = []
                time.sleep(0.01) # Low latency wait
                continue
            
            try:
                vals = line.strip().split(',')
                if len(vals) < 13: continue
                
                payload = {
                    "entity_id": vals[0],
                    "cloud_env": vals[1],
                    "entity_type": vals[2],
                    "timestamp": float(vals[3]),
                    "timestep": int(vals[4]),
                    "api_rate": float(vals[5]),
                    "payload_size": float(vals[6]),
                    "traversal_depth": int(vals[7]),
                    "session_duration": float(vals[8]),
                    "failed_auth_count": int(vals[9]),
                    "geo_anomaly_flag": int(vals[10]),
                    "protocol_type": vals[11],
                    "is_attack": int(vals[12])
                }
                
                batch.append(payload)
                if len(batch) >= BATCH_SIZE:
                    send_batch(batch)
                    total_sent += len(batch)
                    batch = []
                
                if total_sent % 1000 == 0:
                    print(f"  🔥 Production Stream: {total_sent:,} events ingested", end="\r")
                    sys.stdout.flush()
            except Exception as e:
                pass # Skip bad lines

if __name__ == "__main__":
    run_stream_simulation()
