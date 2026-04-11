"""
╔══════════════════════════════════════════════════════╗
║     DataSnug — Clipboard Monitor                     ║
║                                                      ║
║  Watches clipboard in real-time across ALL apps.     ║
║  WhatsApp, Telegram, Notepad — doesn't matter.       ║
║  If sensitive data is copied → alert + BLOCK.        ║
╚══════════════════════════════════════════════════════╝

Install: pip install pyperclip plyer
Run:     python clipboard_monitor.py
"""

import time
import sys
import logging
from datetime import datetime
from pathlib import Path

try:
    import pyperclip
except ImportError:
    print("Run: pip install pyperclip")
    sys.exit(1)

try:
    from plyer import notification
    NOTIFY_AVAILABLE = True
except ImportError:
    NOTIFY_AVAILABLE = False
    print("pip install plyer  for desktop notifications")

# Add DataSnug root to path so we can use detector.py
sys.path.insert(0, str(Path(__file__).parent.parent / "DataSnug"))
try:
    from models.detector import DataLeakDetector
    detector = DataLeakDetector()
    DETECTOR_AVAILABLE = True
except Exception:
    DETECTOR_AVAILABLE = False
    print("DataSnug detector not found — using built-in patterns")

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = Path(__file__).parent / "clipboard_alerts.log"
logging.basicConfig(
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("DataSnug.Clipboard")

# ── Config ────────────────────────────────────────────────────────────────────
POLL_INTERVAL  = 0.3   # seconds between clipboard checks (faster = harder to paste before block)
MIN_TEXT_LENGTH = 6    # ignore very short copies
BLOCK_ON_HIGH  = True  # replace clipboard with warning if HIGH risk detected
BLOCK_ON_MEDIUM = False # set True to also block MEDIUM risk (emails, phone numbers)
ALERT_COOLDOWN = 5     # seconds before re-alerting same content

BLOCK_MESSAGE  = "[BLOCKED by DataSnug] Sensitive data was prevented from being shared."


class ClipboardMonitor:
    def __init__(self):
        self._last_value    = ""
        self._last_alert_at = 0
        self._running       = False
        self._alert_count   = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def _scan(self, text: str) -> dict:
        if DETECTOR_AVAILABLE:
            return detector.scan_text(text)
        import re
        patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b',                           "SSN",         "HIGH"),
            (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', "Credit Card", "HIGH"),
            (r'(?i)(?:password|passwd)\s*[:=\s]\s*\S+',           "Password",    "HIGH"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "Email",    "MEDIUM"),
            (r'\b[2-9][0-9]{11}\b',                               "Aadhaar",     "HIGH"),
            (r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b',                   "Phone",       "MEDIUM"),
        ]
        findings, score = [], 0
        weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for regex, label, risk in patterns:
            if re.search(regex, text):
                findings.append({"type": label, "risk": risk, "count": 1})
                score += weights[risk]
        level = "SAFE" if score == 0 else ("HIGH" if score > 8 else ("MEDIUM" if score > 3 else "LOW"))
        return {
            "findings": findings,
            "risk_level": level,
            "risk_score": score,
            "summary": f"Detected: {', '.join(f['type'] for f in findings)}" if findings else "Safe"
        }

    def _notify(self, result: dict, types: str, blocked: bool):
        action = "BLOCKED" if blocked else "DETECTED"
        title  = f"DataSnug [{result['risk_level']}] {action}"
        msg    = f"{types}\n{'Paste will show warning message!' if blocked else 'Logged.'}"

        if NOTIFY_AVAILABLE:
            try:
                notification.notify(
                    title=title,
                    message=msg,
                    app_name="DataSnug DLP",
                    timeout=6
                )
            except Exception:
                pass

        log.warning(
            f"[CLIPBOARD][{result['risk_level']}][{action}] "
            f"Score:{result['risk_score']} | {types}"
        )

    def _should_block(self, risk_level: str) -> bool:
        if risk_level == "HIGH" and BLOCK_ON_HIGH:
            return True
        if risk_level == "MEDIUM" and BLOCK_ON_MEDIUM:
            return True
        return False

    def _check(self):
        try:
            current = pyperclip.paste()
        except Exception:
            return

        # Skip if empty, unchanged, or too short
        if not current or current == self._last_value:
            return
        if len(current.strip()) < MIN_TEXT_LENGTH:
            self._last_value = current
            return
        # Skip if this is our own block message
        if current == BLOCK_MESSAGE:
            return

        self._last_value = current
        now = time.time()

        # Cooldown to avoid re-alerting on same content
        if now - self._last_alert_at < ALERT_COOLDOWN:
            return

        result = self._scan(current)

        if result["risk_level"] == "SAFE":
            return

        self._last_alert_at = now
        self._alert_count[result["risk_level"]] = \
            self._alert_count.get(result["risk_level"], 0) + 1

        types   = ", ".join(f["type"] for f in result["findings"][:3])
        blocked = self._should_block(result["risk_level"])

        if blocked:
            # Replace clipboard with warning — if user pastes, they see this instead
            pyperclip.copy(BLOCK_MESSAGE)
            self._last_value = BLOCK_MESSAGE
            log.warning(f"[BLOCKED] Clipboard replaced with warning. Original had: {types}")

        self._notify(result, types, blocked)

    def start(self):
        self._running = True
        log.info("=" * 55)
        log.info("  DataSnug Clipboard Monitor — ACTIVE")
        log.info(f"  Polling every {POLL_INTERVAL}s")
        log.info(f"  Block HIGH risk  : {BLOCK_ON_HIGH}")
        log.info(f"  Block MEDIUM risk: {BLOCK_ON_MEDIUM}")
        log.info(f"  Block message    : {BLOCK_MESSAGE}")
        log.info("=" * 55)

        try:
            while self._running:
                self._check()
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._running = False
        log.info("Clipboard monitor stopped.")
        log.info(
            f"Session summary — HIGH: {self._alert_count.get('HIGH', 0)} | "
            f"MEDIUM: {self._alert_count.get('MEDIUM', 0)} | "
            f"LOW: {self._alert_count.get('LOW', 0)}"
        )


if __name__ == "__main__":
    monitor = ClipboardMonitor()
    monitor.start()