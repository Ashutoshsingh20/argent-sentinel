import sys
import os

# Set app dir
sys.path.insert(0, os.path.join(os.getcwd(), "adaptive_zta"))

print("Importing app...", flush=True)
from app import app
print("App imported. Starting uvicorn...", flush=True)

import uvicorn
uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")
