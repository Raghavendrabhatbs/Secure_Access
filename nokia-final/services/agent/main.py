"""
Nokia SSH Agentic AI - Main Startup Script
Starts all agentic AI components together:
  - Anomaly detection model
  - LangGraph agent pipeline
  - Live Warpgate file watcher
  - Real-time threat detection
"""

import os
import sys
import time
import signal
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(__file__))

from agent_graph import initialize
from warpgate_watcher import start_watcher
from email_alerter import is_configured

RECORDINGS_PATH = os.getenv(
    "WARPGATE_RECORDINGS_HOST_ROOT",
    r"C:\Users\sumukh bhat\project\nokia-ai-assistant\.tmp\warpgate_data\recordings"
)


def print_banner():
    print()
    print("=" * 62)
    print("  Nokia SSH Session Intelligence - Agentic AI")
    print("=" * 62)
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Watching : {RECORDINGS_PATH}")
    print(f"  Email    : {'configured' if is_configured() else 'not configured'}")
    print("=" * 62)
    print()
    print("  Severity levels:")
    print("  CRITICAL -> Email + Valkey + DB log")
    print("  HIGH     -> Email + Valkey + DB log")
    print("  MEDIUM   -> DB log only")
    print("  LOW      -> Ignored")
    print()
    print("  Press Ctrl+C to stop")
    print("=" * 62)
    print()


def main():
    print_banner()

    print("[STARTUP] Loading anomaly model and building LangGraph agent...")
    try:
        agent = initialize()
    except Exception as exc:
        print(f"[STARTUP] Failed to initialize agent: {exc}")
        sys.exit(1)

    print("[STARTUP] Starting Warpgate file watcher...")
    observer = start_watcher(agent, RECORDINGS_PATH)
    if observer is None:
        print("[STARTUP] Could not start watcher. Check recordings path.")
        sys.exit(1)

    print("[STARTUP] All systems running. Monitoring SSH sessions...\n")

    def shutdown(signum, frame):
        print("\n[SHUTDOWN] Stopping Nokia SSH Agentic AI...")
        observer.stop()
        observer.join()
        print("[SHUTDOWN] Stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
