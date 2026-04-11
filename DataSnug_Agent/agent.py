"""
╔══════════════════════════════════════════════════════╗
║     DataSnug — Master Agent                          ║
║                                                      ║
║  Runs ALL protection layers simultaneously:          ║
║    Layer 1 → Clipboard Monitor                       ║
║    Layer 2 → File Watcher                            ║
║    Layer 3 → Dashboard (live terminal UI)            ║
║                                                      ║
║  Run: python agent.py                                ║
╚══════════════════════════════════════════════════════╝
"""

import sys
import time
import threading
import logging
import signal
from pathlib import Path
from datetime import datetime
from collections import deque

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = Path(__file__).parent / "agent.log"
logging.basicConfig(
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("DataSnug.Agent")

# ── Shared alert queue (all layers push here) ─────────────────────────────────
alert_queue = deque(maxlen=50)
stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0, "blocked": 0}


def push_alert(source: str, risk: str, detail: str):
    alert_queue.appendleft({
        "time":   datetime.now().strftime("%H:%M:%S"),
        "source": source,
        "risk":   risk,
        "detail": detail,
    })
    stats[risk] = stats.get(risk, 0) + 1
    stats["total"] += 1
    if risk == "HIGH":
        stats["blocked"] += 1


# ── Layer 1: Clipboard ────────────────────────────────────────────────────────
def run_clipboard_layer():
    try:
        import pyperclip
    except ImportError:
        log.warning("Clipboard layer disabled — run: pip install pyperclip")
        return

    sys.path.insert(0, str(Path(__file__).parent.parent / "DataSnug"))
    try:
        from models.detector import DataLeakDetector
        det = DataLeakDetector()
    except Exception:
        log.warning("Clipboard layer: detector not found, using fallback")
        det = None

    import re
    FALLBACK = [
        (r'\b\d{3}-\d{2}-\d{4}\b',   "SSN",         "HIGH"),
        (r'\b4[0-9]{12}(?:[0-9]{3})?\b', "Credit Card", "HIGH"),
        (r'(?i)password\s*[:=\s]\s*\S+', "Password",   "HIGH"),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "Email", "MEDIUM"),
        (r'\b[2-9][0-9]{11}\b',       "Aadhaar",     "HIGH"),
    ]

    last = ""
    last_alert = 0

    while True:
        try:
            current = pyperclip.paste()
        except Exception:
            time.sleep(1)
            continue

        if current and current != last and len(current.strip()) >= 6:
            last = current
            now = time.time()
            if now - last_alert >= 5:
                if det:
                    result = det.scan_text(current)
                else:
                    findings, score = [], 0
                    for rx, label, risk in FALLBACK:
                        if re.search(rx, current):
                            findings.append({"type": label, "risk": risk})
                            score += 3 if risk == "HIGH" else 2
                    level = "SAFE" if score == 0 else ("HIGH" if score > 6 else "MEDIUM")
                    result = {"risk_level": level, "findings": findings, "risk_score": score}

                if result["risk_level"] != "SAFE":
                    last_alert = now
                    types = ", ".join(f["type"] for f in result["findings"][:3])
                    push_alert("📋 Clipboard", result["risk_level"], types)
                    if result["risk_level"] == "HIGH":
                        pyperclip.copy("")  # clear clipboard
                        push_alert("📋 Clipboard", "HIGH", f"CLEARED: {types}")

        time.sleep(0.8)


# ── Layer 2: File Watcher ─────────────────────────────────────────────────────
def run_file_layer():
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        log.warning("File layer disabled — run: pip install watchdog")
        return

    import os, re

    sys.path.insert(0, str(Path(__file__).parent.parent / "DataSnug"))
    try:
        from models.detector import DataLeakDetector
        det = DataLeakDetector()
    except Exception:
        det = None

    SCAN_EXTS = {".txt",".csv",".json",".xml",".log",".sql",".env",".py",".md"}
    SUSP_NAMES = {"password","credentials","secret","employee","salary","payroll",
                  "confidential","ssn","database","dump","export","pii","private"}
    last_scanned = {}

    class Handler(FileSystemEventHandler):
        def _handle(self, path, etype):
            ext  = Path(path).suffix.lower()
            name = Path(path).stem.lower()

            # Flag suspicious filenames
            if any(s in name for s in SUSP_NAMES):
                push_alert(f"📁 File [{etype}]", "MEDIUM",
                           f"Suspicious filename: {Path(path).name}")

            if ext not in SCAN_EXTS:
                return
            try:
                if os.path.getsize(path) > 5 * 1024 * 1024:
                    return
            except OSError:
                return

            now = time.time()
            if now - last_scanned.get(path, 0) < 3:
                return
            last_scanned[path] = now

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(50000)
            except Exception:
                return

            if not content.strip():
                return

            result = det.scan_text(content) if det else {"risk_level":"SAFE","findings":[]}
            if result["risk_level"] != "SAFE":
                types = ", ".join(f["type"] for f in result["findings"][:3])
                push_alert(f"📁 File [{etype}]", result["risk_level"],
                           f"{Path(path).name} → {types}")

        def on_created(self, e):
            if not e.is_directory: self._handle(e.src_path, "CREATE")
        def on_modified(self, e):
            if not e.is_directory: self._handle(e.src_path, "MODIFY")
        def on_moved(self, e):
            if not e.is_directory:
                dest = e.dest_path.lower()
                if "/media/" in dest or "/mnt/" in dest or "/volumes/" in dest:
                    push_alert("💾 USB", "HIGH",
                               f"File copied to USB: {Path(e.src_path).name}")
                else:
                    self._handle(e.dest_path, "MOVE")

    watch_paths = [Path.home()/"Documents", Path.home()/"Desktop", Path.home()/"Downloads"]
    observer = Observer()
    handler  = Handler()
    for p in watch_paths:
        if p.exists():
            observer.schedule(handler, str(p), recursive=True)

    observer.start()
    log.info(f"File watcher active on {[str(p) for p in watch_paths if p.exists()]}")
    try:
        while True:
            time.sleep(1)
    except Exception:
        observer.stop()
    observer.join()


# ── Layer 3: Live Dashboard (terminal UI) ─────────────────────────────────────
def run_dashboard():
    """Prints a live updating terminal dashboard every 3 seconds."""
    COLORS = {
        "HIGH":   "\033[91m",   # red
        "MEDIUM": "\033[93m",   # yellow
        "LOW":    "\033[96m",   # cyan
        "RESET":  "\033[0m",
        "BOLD":   "\033[1m",
        "GREEN":  "\033[92m",
        "GREY":   "\033[90m",
    }
    C = COLORS

    def render():
        # Clear screen
        print("\033[H\033[J", end="")

        print(f"{C['BOLD']}{'='*60}{C['RESET']}")
        print(f"{C['BOLD']}  🛡️  DataSnug Agent  —  Live Dashboard{C['RESET']}")
        print(f"{C['GREY']}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C['RESET']}")
        print(f"{'='*60}")

        # Stats row
        print(f"\n  {C['BOLD']}Session Stats:{C['RESET']}")
        print(f"  Total Alerts : {C['BOLD']}{stats['total']}{C['RESET']}")
        print(f"  {C['HIGH']}HIGH  : {stats.get('HIGH',0)}{C['RESET']}   "
              f"  {C['MEDIUM']}MEDIUM: {stats.get('MEDIUM',0)}{C['RESET']}   "
              f"  {C['LOW']}LOW   : {stats.get('LOW',0)}{C['RESET']}")
        print(f"  Blocked/Cleared: {C['HIGH']}{stats['blocked']}{C['RESET']}\n")

        # Active layers
        print(f"  {C['BOLD']}Active Layers:{C['RESET']}")
        print(f"  {C['GREEN']}✅ Layer 1 — Clipboard Monitor{C['RESET']}")
        print(f"  {C['GREEN']}✅ Layer 2 — File Watcher{C['RESET']}")
        print(f"  {C['GREEN']}✅ Layer 3 — Dashboard{C['RESET']}\n")

        # Recent alerts
        print(f"  {C['BOLD']}Recent Alerts:{C['RESET']}")
        print(f"  {'-'*56}")

        if not alert_queue:
            print(f"  {C['GREY']}  No alerts yet. DataSnug is watching...{C['RESET']}")
        else:
            for a in list(alert_queue)[:10]:
                rc = C.get(a["risk"], C["RESET"])
                print(
                    f"  {C['GREY']}{a['time']}{C['RESET']}  "
                    f"{rc}{a['risk']:<6}{C['RESET']}  "
                    f"{a['source']:<22}  "
                    f"{C['GREY']}{a['detail'][:28]}{C['RESET']}"
                )

        print(f"\n  {C['GREY']}Press Ctrl+C to stop{C['RESET']}")
        print(f"{'='*60}")

    while True:
        try:
            render()
        except Exception:
            pass
        time.sleep(3)


# ── Main: Launch all layers as threads ───────────────────────────────────────
def main():
    log.info("DataSnug Agent starting — all layers initializing...")

    layers = [
        ("Clipboard Monitor", run_clipboard_layer),
        ("File Watcher",      run_file_layer),
        ("Dashboard",         run_dashboard),
    ]

    threads = []
    for name, fn in layers:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        threads.append(t)
        log.info(f"  ✅ {name} started")

    # Graceful shutdown
    def shutdown(sig, frame):
        log.info("\nShutting down DataSnug Agent...")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
