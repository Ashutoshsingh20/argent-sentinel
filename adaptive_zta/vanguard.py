import subprocess
import time
import sys
import os
import signal
import argparse
import webbrowser
import socket


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def _can_run_control_plane(py_path):
    try:
        probe = subprocess.run(
            [py_path, "-c", "import fastapi, httpx"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return probe.returncode == 0
    except Exception:
        return False


def _resolve_python():
    candidates = [
        os.path.join(os.path.dirname(ROOT_DIR), ".venv", "bin", "python"),
        os.path.join(ROOT_DIR, ".venv", "bin", "python"),
        sys.executable,
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and _can_run_control_plane(candidate):
            return candidate
    return sys.executable

class ArgentOrchestrator:
    """
    The Master Controller for the Argent System.
    Handles service lifecycle, orchestration, and health monitoring.
    """
    def __init__(self):
        self.processes = []
        self.python = _resolve_python()

    def _start_process(self, command, name):
        print(f"🚀 Starting {name}...")
        env = os.environ.copy()
        env["OMP_NUM_THREADS"] = "1"
        env["MKL_NUM_THREADS"] = "1"
        env["OPENBLAS_NUM_THREADS"] = "1"
        env["VECLIB_MAXIMUM_THREADS"] = "1"
        env["NUMEXPR_NUM_THREADS"] = "1"
        
        os.makedirs(os.path.join(ROOT_DIR, "tmp"), exist_ok=True)
        log_name = name.lower().replace(" ", "_") + ".log"
        log_path = os.path.join(ROOT_DIR, "tmp", log_name)
        log_handle = open(log_path, "a", encoding="utf-8")

        p = subprocess.Popen(
            command,
            shell=True,
            preexec_fn=os.setsid,
            env=env,
            cwd=ROOT_DIR,
            stdout=log_handle,
            stderr=log_handle,
        )
        self.processes.append({"process": p, "name": name, "log_path": log_path, "log_handle": log_handle})
        return p

    def _tail_log(self, path, lines=30):
        if not path or not os.path.exists(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.readlines()
            return "".join(data[-lines:])
        except Exception:
            return ""

    def _python_cmd(self, script_or_module, as_module=False):
        if as_module:
            return f'"{self.python}" -m {script_or_module}'
        return f'"{self.python}" {script_or_module}'

    def cleanup(self):
        print("\n🛑 Argent Sentinel Shutting Down...")
        for p_info in self.processes:
            p = p_info["process"]
            name = p_info["name"]
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                print(f"  - Terminated {name}")
            except: pass
            try:
                p_info.get("log_handle").close()
            except Exception:
                pass
        print("✅ System offline.")

    def _is_port_open(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0

    def run_init_phase(self):
        print("--- PHASE 1: PURGING BACKLOG & INITIATING REAL-TIME STREAM ---")
        files_to_purge = ['outputs/telemetry_data.csv']
        for f in files_to_purge:
            full_path = os.path.join(ROOT_DIR, f)
            if os.path.exists(full_path):
                os.remove(full_path)
                print(f"  - Purged: {f}")

        self._start_process(self._python_cmd("data_generator.py"), "Neural Stream Generator")
        print("✅ Adversarial Stream Engaged.")

    def _clear_port(self, port):
        """Surgically clear a port if it is in use."""
        try:
            # Use lsof to find PID and kill it
            cmd = f"lsof -ti :{port} | xargs kill -9"
            subprocess.run(cmd, shell=True, check=False, capture_output=True)
            time.sleep(1) # Wait for OS to release socket
        except: pass

    def start_stack(self):
        print("--- PHASE 2: LAUNCHING PRODUCTION STACK ---")
        self._clear_port(8000)
        try:
            # 1. Start Control Plane (FastAPI)
            self._start_process(self._python_cmd("uvicorn app:app --host 0.0.0.0 --port 8000", as_module=True), "Control Plane API")
            
            print("⏳ Waiting for Control Plane API to initialize...")
            max_retries = 60 # Increased timeout
            api_ready = False
            for i in range(max_retries):
                if self._is_port_open("127.0.0.1", 8000):
                    api_ready = True
                    break
                
                # Check if process died during init
                for p_info in self.processes:
                    if p_info["name"] == "Control Plane API" and p_info["process"].poll() is not None:
                        print(f"❌ ERROR: Control Plane API crashed during startup with exit code {p_info['process'].poll()}")
                        return
                        
                time.sleep(1)
            
            if not api_ready:
                print("❌ ERROR: API failed to start on port 8000 within 30 seconds.")
                return

            print("✅ API Online.")
            
            # 2. Start Autonomous Ingestor
            self._start_process(self._python_cmd("ingestor.py"), "Data Ingestor")
            
            # 3. Launch Web GUI
            print("--- PHASE 3: COMMAND CENTER ONLINE ---")
            print("🌍 Opening Argent Dashboard in your browser...")
            webbrowser.open("http://127.0.0.1:8000")
            
            print("\n🛡️ Argent Pulse: System monitoring active. Press Ctrl+C to terminate.")
            
            # Monitoring Loop
            while True:
                crashed_name = None
                for p_info in self.processes:
                    retcode = p_info["process"].poll()
                    if retcode is not None:
                        crashed_name = p_info["name"]
                        print(f"\n⚠️ WARNING: {crashed_name} has stopped (Exit Code: {retcode})")
                        if crashed_name == "Control Plane API":
                            log_tail = self._tail_log(p_info.get("log_path"))
                            if log_tail:
                                print("--- Control Plane Crash Tail ---")
                                print(log_tail)
                            return  # Control plane is critical.

                        # Restart non-critical data pipelines so shadow training keeps receiving telemetry.
                        self.processes = [x for x in self.processes if x["name"] != crashed_name]
                        if crashed_name == "Neural Stream Generator":
                            self._start_process(self._python_cmd("data_generator.py"), "Neural Stream Generator")
                            print("🔁 Restarted Neural Stream Generator")
                        elif crashed_name == "Data Ingestor":
                            self._start_process(self._python_cmd("ingestor.py"), "Data Ingestor")
                            print("🔁 Restarted Data Ingestor")
                        break
                time.sleep(2)
            
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argent Autonomous Sentinel Unified Controller")
    parser.add_argument("--init", action="store_true", help="Run High-Fidelity Data Gen and Training")
    args = parser.parse_args()
    
    ctrl = ArgentOrchestrator()
    ctrl.run_init_phase()
    ctrl.start_stack()
