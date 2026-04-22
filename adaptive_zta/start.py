#!/usr/bin/env python3
"""Single entrypoint to start Argent Sentinel reliably from this folder."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = ROOT_DIR.parent


def _set_default_env() -> None:
    defaults = {
        "STATE_KEY_SCOPE": "principal",
        "APP_HOST": "0.0.0.0",
        "APP_PORT": "8000",
        "JWT_ALGORITHM": "RS256",
        "JWT_EXEMPT_PATHS": (
            "/,/healthz,/metrics,/docs,/openapi.json,/model-info,"
            "/dashboard/summary,/dashboard/entities,/ingest,/ingest-batch,"
            "/intelligence/status,/intelligence/suggestions,/safety/status"
        ),
        "CLOUD_ACTIONS_ENABLED": "1",
        "AWS_CLOUD_ACTIONS_ENABLED": "1",
        "AZURE_CLOUD_ACTIONS_ENABLED": "1",
        "GCP_CLOUD_ACTIONS_ENABLED": "1",
        "CLOUD_ACTIONS_ALLOW_MUTATIONS": "1",
        "AUTH_ALLOW_INSECURE_DEV": "1",
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)

    jwt_secret = os.environ.get("JWT_SECRET", "").strip()
    if not jwt_secret or jwt_secret == "change-me":
        os.environ["JWT_SECRET"] = "argent-sentinel-local-dev-secret-2026-04-20-min-32-bytes"


def _ensure_rs256_keys() -> None:
    if os.environ.get("JWT_PRIVATE_KEY_PEM") and os.environ.get("JWT_PUBLIC_KEY_PEM"):
        return

    openssl = subprocess.run(["which", "openssl"], capture_output=True, text=True)
    if openssl.returncode != 0:
        return

    key_dir = Path(tempfile.gettempdir()) / "argent_sentinel_keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = key_dir / "dev_rs256_private.pem"
    public_key = key_dir / "dev_rs256_public.pem"

    if not private_key.exists() or private_key.stat().st_size == 0:
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-out",
                str(private_key),
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    if not public_key.exists() or public_key.stat().st_size == 0:
        subprocess.run(
            [
                "openssl",
                "rsa",
                "-pubout",
                "-in",
                str(private_key),
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    os.environ["JWT_PRIVATE_KEY_PEM"] = private_key.read_text(encoding="utf-8")
    os.environ["JWT_PUBLIC_KEY_PEM"] = public_key.read_text(encoding="utf-8")


def _is_port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def main() -> None:
    os.chdir(ROOT_DIR)
    _set_default_env()
    _ensure_rs256_keys()

    host = os.environ.get("APP_HOST", "0.0.0.0")
    selected_port = int(os.environ.get("APP_PORT", "8000"))
    os.environ["APP_PORT"] = str(selected_port)

    if not _is_port_free(selected_port):
        raise RuntimeError(f"Port {selected_port} is already in use. Stop existing process and retry.")

    print(f"Starting Argent Sentinel on {host}:{selected_port}")
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--app-dir",
        str(ROOT_DIR),
        "--host",
        host,
        "--port",
        str(selected_port),
        "--log-level",
        "info",
    ]
    code = subprocess.call(cmd, cwd=str(WORKSPACE_DIR), env=os.environ.copy())
    raise SystemExit(code)


if __name__ == "__main__":
    main()
