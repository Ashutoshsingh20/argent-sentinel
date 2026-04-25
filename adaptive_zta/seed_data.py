"""Quick data seeder — pumps realistic telemetry into the running Argent Sentinel."""

import random
import time
import requests

BASE = "http://localhost:8000"
ENTITIES = [f"ENT-{i:03d}" for i in range(50)]
CLOUDS = ["AWS", "Azure", "GCP"]
TYPES = ["human_user", "service_account", "api_gateway", "microservice"]
PROTOCOLS = ["HTTPS", "HTTP", "SSH"]

def normal_record(eid: str) -> dict:
    return {
        "entity_id": eid,
        "entity_type": random.choice(TYPES),
        "cloud_env": random.choice(CLOUDS),
        "timestamp": time.time(),
        "api_rate": max(1.0, random.gauss(12, 4)),
        "payload_size": max(1.0, random.gauss(600, 150)),
        "traversal_depth": random.randint(0, 3),
        "session_duration": max(10.0, random.gauss(180, 60)),
        "failed_auth_count": 0,
        "geo_anomaly_flag": 0,
        "protocol_type": "HTTPS",
        "is_attack": 0,
    }

def suspicious_record(eid: str) -> dict:
    return {
        "entity_id": eid,
        "entity_type": random.choice(TYPES),
        "cloud_env": random.choice(CLOUDS),
        "timestamp": time.time(),
        "api_rate": max(50.0, random.gauss(350, 80)),
        "payload_size": max(1000.0, random.gauss(3500, 800)),
        "traversal_depth": random.randint(5, 12),
        "session_duration": max(500.0, random.gauss(2500, 500)),
        "failed_auth_count": random.randint(2, 6),
        "geo_anomaly_flag": 1,
        "protocol_type": random.choice(["SSH", "HTTP"]),
        "is_attack": 1,
    }

def main():
    tenants = ["fintech-prod", "cyberdyne-ops"]

    for tenant in tenants:
        print(f"\n🚀 Seeding tenant: {tenant}")
        session = requests.Session()
        session.headers.update({"X-Tenant-ID": tenant})

        # Phase 1: Batch of 200 normal records
        print("📡 Phase 1: Sending 200 normal telemetry records...")
        batch = [normal_record(random.choice(ENTITIES)) for _ in range(200)]
        resp = session.post(f"{BASE}/ingest-batch", json={"records": batch})
        print(f"  → {resp.status_code}: {resp.json().get('accepted', '?')} accepted")
        time.sleep(0.5)

        # Phase 2: 30 suspicious/attack records
        print("🔴 Phase 2: Sending 30 suspicious records...")
        attack_entities = random.sample(ENTITIES, 10)
        batch = [suspicious_record(random.choice(attack_entities)) for _ in range(30)]
        resp = session.post(f"{BASE}/ingest-batch", json={"records": batch})
        print(f"  → {resp.status_code}: {resp.json().get('accepted', '?')} accepted")
        time.sleep(0.5)

        # Phase 3: Mixed stream (150 normal + 20 attacks, interleaved)
        print("⚡ Phase 3: Mixed stream (170 records)...")
        mixed = []
        for _ in range(150):
            mixed.append(normal_record(random.choice(ENTITIES)))
        for _ in range(20):
            mixed.append(suspicious_record(random.choice(attack_entities)))
        random.shuffle(mixed)
        resp = session.post(f"{BASE}/ingest-batch", json={"records": mixed})
        print(f"  → {resp.status_code}: {resp.json().get('accepted', '?')} accepted")

        # Phase 4: A few individual ingests for real-time visibility
        print("🔄 Phase 4: 20 individual ingest calls...")
        for i in range(20):
            eid = random.choice(ENTITIES)
            rec = suspicious_record(eid) if i % 5 == 0 else normal_record(eid)
            try:
                r = session.post(f"{BASE}/ingest", json=rec)
                status = r.json().get("decision", "?")
                trust = r.json().get("trust_score", "?")
                print(f"  [{i+1}/20] {eid}: decision={status}, trust={trust}")
            except Exception as e:
                print(f"  [{i+1}/20] {eid}: error={e}")
            time.sleep(0.1)

    print(f"\n✅ Done! Total: ~420 records per tenant sent. Refresh the dashboard.")

if __name__ == "__main__":
    main()
