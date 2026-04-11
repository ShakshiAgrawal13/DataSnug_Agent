"""
╔══════════════════════════════════════════════════════╗
║     DataSnug — File Watcher                          ║
║                                                      ║
║  Monitors folders + USB drives for sensitive files.  ║
║  Triggers on: create, modify, move, copy to USB.     ║
║  Scans file content for PII/sensitive data.          ║
╚══════════════════════════════════════════════════════╝

Install: pip install watchdog plyer
Run:     python file_watcher.py
"""

import os
import sys
import time
import logging
import threading
import platform
from pathlib import Path
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent, FileModifiedEvent
except ImportError:
    print("❌ Run: pip install watchdog")
    sys.exit(1)

try:
    from plyer import notification
    NOTIFY_AVAILABLE = True
except ImportError:
    NOTIFY_AVAILABLE = False

# Add DataSnug root to path
sys.path.insert(0, str(Path(__file__).parent.parent / "DataSnug"))
try:
    from models.detector import DataLeakDetector
    detector = DataLeakDetector()
    DETECTOR_AVAILABLE = True
except Exception:
    DETECTOR_AVAILABLE = False

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = Path(__file__).parent / "file_alerts.log"
logging.basicConfig(
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("DataSnug.FileWatcher")

# ── Config ────────────────────────────────────────────────────────────────────

# Folders to watch (add your company's sensitive folders here)
WATCH_PATHS = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Downloads",
]

# File extensions to scan content of
SCAN_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".log",
    ".sql", ".py", ".js", ".ts", ".env",
    ".md",  ".yaml", ".yml", ".conf", ".ini",
    ".docx", ".xlsx",   # requires extra libs to parse
}

# File extensions to always flag just by name (regardless of content)
SUSPICIOUS_NAMES = {
    "password", "passwd", "credentials", "secret", "private",
    "employee", "salary", "payroll", "confidential", "ssn",
    "database", "db_backup", "dump", "export", "pii",
}

MAX_FILE_SIZE_MB = 5    # skip files larger than this
BLOCK_USB_COPY   = True # alert when files copied to USB/external drive
SCAN_COOLDOWN    = 3    # seconds


class DataSnugFileHandler(FileSystemEventHandler):

    def __init__(self):
        self._last_scanned = {}   # path → timestamp
        self._alert_count  = 0

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _should_scan(self, path: str) -> bool:
        ext = Path(path).suffix.lower()
        if ext not in SCAN_EXTENSIONS:
            return False
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                return False
        except OSError:
            return False
        # Cooldown
        now = time.time()
        if now - self._last_scanned.get(path, 0) < SCAN_COOLDOWN:
            return False
        self._last_scanned[path] = now
        return True

    def _read_file(self, path: str) -> str:
        """Read file content safely."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(50000)   # max 50KB
        except Exception:
            return ""

    def _scan_content(self, text: str) -> dict:
        if not text.strip():
            return {"risk_level": "SAFE", "findings": [], "risk_score": 0}
        if DETECTOR_AVAILABLE:
            return detector.scan_text(text)
        return {"risk_level": "SAFE", "findings": [], "risk_score": 0}

    def _is_suspicious_name(self, path: str) -> bool:
        name = Path(path).stem.lower()
        return any(s in name for s in SUSPICIOUS_NAMES)

    def _is_usb_path(self, path: str) -> bool:
        """Detect if path is on a USB / external drive."""
        p = path.lower()
        if platform.system() == "Windows":
            # Check if drive letter is not C: (system drive)
            if len(path) >= 2 and path[1] == ":":
                return path[0].upper() not in ("C",)
        elif platform.system() == "Darwin":
            return "/volumes/" in p
        else:  # Linux
            return "/media/" in p or "/mnt/" in p
        return False

    def _notify(self, path: str, result: dict, event_type: str):
        filename = Path(path).name
        risk     = result["risk_level"]
        types    = ", ".join(f["type"] for f in result["findings"][:3]) if result["findings"] else "Suspicious filename"

        title = f"🛡️ DataSnug — {risk} RISK [{event_type}]"
        msg   = f"{filename}\n{types}"

        log.warning(
            f"[FILE][{risk}][{event_type}] {path} | "
            f"Score:{result.get('risk_score',0)} | {types}"
        )

        if NOTIFY_AVAILABLE:
            try:
                notification.notify(
                    title=title,
                    message=msg,
                    app_name="DataSnug DLP",
                    timeout=8
                )
            except Exception:
                pass

        self._alert_count += 1

    def _handle(self, path: str, event_type: str):
        # Always flag suspicious-named files
        if self._is_suspicious_name(path):
            self._notify(path, {"risk_level": "MEDIUM", "findings": [], "risk_score": 2}, event_type)

        # Flag USB copies
        if BLOCK_USB_COPY and self._is_usb_path(path):
            content = self._read_file(path)
            result  = self._scan_content(content)
            if result["risk_level"] != "SAFE":
                self._notify(path, result, f"USB COPY — {event_type}")
                log.error(f"🚫 SENSITIVE FILE COPIED TO USB: {path}")
            return

        # Scan content
        if not self._should_scan(path):
            return

        content = self._read_file(path)
        if not content:
            return

        result = self._scan_content(content)
        if result["risk_level"] != "SAFE":
            self._notify(path, result, event_type)

    # ── Watchdog event handlers ───────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "CREATED")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "MODIFIED")

    def on_moved(self, event):
        if not event.is_directory:
            # Flag if moved to external/USB
            if self._is_usb_path(event.dest_path):
                content = self._read_file(event.dest_path)
                result  = self._scan_content(content)
                self._notify(event.dest_path, result, "MOVED TO USB")
                log.error(f"🚫 FILE MOVED TO USB: {event.src_path} → {event.dest_path}")
            else:
                self._handle(event.dest_path, "MOVED")


class FileWatcher:
    def __init__(self):
        self._observer = Observer()
        self._handler  = DataSnugFileHandler()

    def start(self):
        log.info("=" * 50)
        log.info("  DataSnug File Watcher — ACTIVE")
        log.info(f"  Watching {len(WATCH_PATHS)} paths")
        for p in WATCH_PATHS:
            if p.exists():
                self._observer.schedule(self._handler, str(p), recursive=True)
                log.info(f"  👁️  {p}")
            else:
                log.warning(f"  ⚠️  Path not found (skipping): {p}")
        log.info("=" * 50)

        self._observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._observer.stop()
        self._observer.join()
        log.info(f"File watcher stopped. Total alerts: {self._handler._alert_count}")


if __name__ == "__main__":
    watcher = FileWatcher()
    watcher.start()
