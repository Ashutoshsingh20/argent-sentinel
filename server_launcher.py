import subprocess
import sys
import time
import os

print("Starting Argent Sentinel Launcher...")
env = os.environ.copy()
env["PYTHONUNBUFFERED"] = "1"

cmd = [
    "/Users/ashutoshsingh/Desktop/model/.venv/bin/uvicorn",
    "app:app",
    "--host", "127.0.0.1",
    "--port", "8000",
    "--app-dir", "/Users/ashutoshsingh/Desktop/model/adaptive_zta"
]

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)

print(f"Server process started with PID {process.pid}")

# Stream output for 60 seconds
start_time = time.time()
while time.time() - start_time < 60:
    line = process.stdout.readline()
    if line:
        print(f"[SERVER] {line.strip()}")
    if process.poll() is not None:
        print(f"Process exited with code {process.poll()}")
        break
    time.sleep(0.1)

if process.poll() is None:
    print("Server still running after observation period.")
else:
    print("Server failed to start.")
