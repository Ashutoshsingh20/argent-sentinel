import multiprocessing as mp
import os
import signal
import socket
import time

import requests
import uvicorn

import config
import database as db
from app import app
from live_data_generator import TrafficPattern, format_record, generate_batch_records
from tui_dashboard import AdaptiveZTADashboard


def run_api():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


def port_in_use(host="127.0.0.1", port=8000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def run_live_generator():
    base_url = config.API_URL
    while True:
        try:
            requests.get(f"{base_url}/", timeout=2)
            break
        except requests.RequestException:
            print("Waiting for Vanguard API to start...")
            time.sleep(2)

    total_records = 0
    attack_records = 0
    timesteps = {}
    traffic_pattern = TrafficPattern()
    os.makedirs("outputs", exist_ok=True)
    print("Vanguard live generator attached to running system. Streaming log: outputs/live_generator.log")

    with open("outputs/live_generator.log", "w", encoding="utf-8") as log_file:
        while True:
            batch = generate_batch_records(10, traffic_pattern.attack_rate)
            for record in batch:
                total_records += 1
                if record["is_attack"]:
                    attack_records += 1

                entity_id = record["entity_id"]
                timesteps[entity_id] = timesteps.get(entity_id, 0) + 1
                
                # Make local copy to override timestep
                payload = dict(record)
                payload["timestep"] = timesteps[entity_id]
                
            last_record = batch[-1]
            log_file.write(format_record(last_record, total_records, attack_records) + "\n")
            log_file.flush()

            try:
                requests.post(f"{base_url}/ingest-batch", json={"records": batch}, timeout=2.0)
            except requests.RequestException as exc:
                log_file.write(f"Live generator could not post telemetry: {exc}\n")
                log_file.flush()

            time.sleep(0.5)


def main():
    if port_in_use():
        print("Port 8000 is already in use. Stop the old Vanguard API before starting V3.")
        print("Tip: run `lsof -nP -iTCP:8000 -sTCP:LISTEN` to find the stale process.")
        return

    print("Initializing Vanguard V3 database...")
    db.init_db()
    db.reset_live_data()
    print("Fresh live simulation started. Learned RL weights remain on disk.")

    processes = [
        mp.Process(target=run_api, name="vanguard-api", daemon=True),
        mp.Process(target=run_live_generator, name="vanguard-live-generator", daemon=True),
    ]

    for process in processes:
        process.start()

    def shutdown(signum=None, frame=None):
        print("\nShutting down Vanguard V3 stack...")
        for process in processes:
            if process.is_alive():
                process.terminate()
        for process in processes:
            process.join(timeout=5)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        AdaptiveZTADashboard().run()
    finally:
        shutdown()


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
