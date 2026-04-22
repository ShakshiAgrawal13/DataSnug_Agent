"""
╔══════════════════════════════════════════════════════╗
║     DataSnug — Flask Backend                         ║
║                                                      ║
║  Provides a web dashboard + REST API for the agent.  ║
║  Run: python app.py                                  ║
╚══════════════════════════════════════════════════════╝

Install: pip install flask
Run:     python app.py
Then open: http://localhost:5000
"""

from flask import Flask, jsonify, render_template_string
from collections import deque
from datetime import datetime
import threading
import time
import sys
import re
from pathlib import Path

app = Flask(__name__)

# ── Shared state (same structure as agent.py) ─────────────────────────────────
alert_queue = deque(maxlen=100)
stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0, "blocked": 0}
start_time = datetime.now()

# ── PII Patterns (same fallback as agent.py) ──────────────────────────────────
PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b',                              "SSN",         "HIGH"),
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b',                        "Credit Card", "HIGH"),
    (r'(?i)password\s*[:=\s]\s*\S+',                        "Password",    "HIGH"),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',"Email",       "MEDIUM"),
    (r'\b[2-9][0-9]{11}\b',                                  "Aadhaar",    "HIGH"),
    (r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b',                      "Phone",       "MEDIUM"),
]

def scan_text(text):
    findings, score = [], 0
    for rx, label, risk in PATTERNS:
        if re.search(rx, text):
            findings.append({"type": label, "risk": risk})
            score += 3 if risk == "HIGH" else 2
    level = "SAFE" if score == 0 else ("HIGH" if score >= 3 else ("MEDIUM" if score >= 2 else "LOW"))
    return {"risk_level": level, "findings": findings, "risk_score": score}

def push_alert(source, risk, detail):
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

BLOCK_MESSAGE = "[BLOCKED by DataSnug] Sensitive data was prevented from being shared."

# ── Clipboard Monitor Thread ──────────────────────────────────────────────────
def run_clipboard_monitor():
    try:
        import pyperclip
    except ImportError:
        print("pip install pyperclip  to enable clipboard monitoring")
        return

    last = ""
    last_alert = 0

    while True:
        try:
            current = pyperclip.paste()
        except Exception:
            time.sleep(1)
            continue

        if current and current != last and len(current.strip()) >= 6:
            # Skip our own block message to avoid re-triggering
            if current == BLOCK_MESSAGE:
                last = current
                time.sleep(0.3)
                continue

            last = current
            now = time.time()
            if now - last_alert >= 2:
                result = scan_text(current)
                if result["risk_level"] != "SAFE":
                    last_alert = now
                    types = ", ".join(f["type"] for f in result["findings"][:3])
                    push_alert("Clipboard", result["risk_level"], types)
                    if result["risk_level"] == "HIGH":
                        # Replace with warning — user sees this if they try to paste
                        pyperclip.copy(BLOCK_MESSAGE)
                        last = BLOCK_MESSAGE
                        push_alert("Clipboard", "HIGH", f"BLOCKED: {types}")

        time.sleep(0.1)

# ── File Watcher Thread ───────────────────────────────────────────────────────
def run_file_watcher():
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("⚠️  pip install watchdog  to enable file monitoring")
        return

    import os
    last_scanned = {}
    SCAN_EXTS  = {".txt",".csv",".json",".xml",".log",".sql",".env",".py",".md"}
    SUSP_NAMES = {"password","credentials","secret","employee","salary","payroll",
                  "confidential","ssn","database","dump","export","pii","private"}

    class Handler(FileSystemEventHandler):
        def _handle(self, path, etype):
            ext  = Path(path).suffix.lower()
            name = Path(path).stem.lower()
            if any(s in name for s in SUSP_NAMES):
                push_alert(f"File [{etype}]", "MEDIUM", f"Suspicious: {Path(path).name}")
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
            result = scan_text(content)
            if result["risk_level"] != "SAFE":
                types = ", ".join(f["type"] for f in result["findings"][:3])
                push_alert(f"File [{etype}]", result["risk_level"],
                           f"{Path(path).name} -> {types}")

        def on_created(self, e):
            if not e.is_directory: self._handle(e.src_path, "CREATE")
        def on_modified(self, e):
            if not e.is_directory: self._handle(e.src_path, "MODIFY")
        def on_moved(self, e):
            if not e.is_directory: self._handle(e.dest_path, "MOVE")

    watch_paths = [Path.home()/"Documents", Path.home()/"Desktop", Path.home()/"Downloads"]
    observer = Observer()
    for p in watch_paths:
        if p.exists():
            observer.schedule(Handler(), str(p), recursive=True)
    observer.start()
    print(f"File watcher active on {[str(p) for p in watch_paths if p.exists()]}")
    while True:
        time.sleep(1)

# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    """Returns latest alerts as JSON."""
    return jsonify(list(alert_queue))

@app.route("/api/stats")
def api_stats():
    """Returns session stats as JSON."""
    uptime = str(datetime.now() - start_time).split(".")[0]
    return jsonify({**stats, "uptime": uptime})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Scan any text for PII. POST JSON: { 'text': '...' }"""
    from flask import request
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400
    result = scan_text(text)
    push_alert("API Scan", result["risk_level"], result.get("summary", "Manual scan"))
    return jsonify(result)

# ── Web Dashboard ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>DataSnug Dashboard</title>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="3">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f0f1a; color: #e0e0e0; font-family: 'Segoe UI', monospace; padding: 24px; }
    h1 { color: #7dd3fc; font-size: 1.6rem; margin-bottom: 4px; }
    .subtitle { color: #64748b; font-size: 0.85rem; margin-bottom: 24px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
    .card { background: #1e1e2e; border-radius: 10px; padding: 16px 24px; min-width: 140px; }
    .card .label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
    .card .value { font-size: 2rem; font-weight: bold; margin-top: 4px; }
    .high { color: #f87171; } .medium { color: #fbbf24; } .low { color: #34d399; } .total { color: #7dd3fc; }
    table { width: 100%; border-collapse: collapse; background: #1e1e2e; border-radius: 10px; overflow: hidden; }
    th { background: #2a2a3e; padding: 12px 16px; text-align: left; font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
    td { padding: 11px 16px; border-bottom: 1px solid #2a2a3e; font-size: 0.88rem; }
    tr:last-child td { border-bottom: none; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold; }
    .badge.HIGH { background: #450a0a; color: #f87171; }
    .badge.MEDIUM { background: #451a03; color: #fbbf24; }
    .badge.LOW { background: #052e16; color: #34d399; }
    .empty { text-align: center; color: #475569; padding: 32px; }
    .uptime { color: #475569; font-size: 0.8rem; margin-top: 20px; }
  </style>
</head>
<body>
  <h1>🛡️ DataSnug — Live Dashboard</h1>
  <div class="subtitle">Auto-refreshes every 3 seconds &nbsp;|&nbsp; {{ now }}</div>

  <div class="cards">
    <div class="card"><div class="label">Total</div><div class="value total">{{ stats.total }}</div></div>
    <div class="card"><div class="label">High</div><div class="value high">{{ stats.HIGH }}</div></div>
    <div class="card"><div class="label">Medium</div><div class="value medium">{{ stats.MEDIUM }}</div></div>
    <div class="card"><div class="label">Low</div><div class="value low">{{ stats.LOW }}</div></div>
    <div class="card"><div class="label">Blocked</div><div class="value high">{{ stats.blocked }}</div></div>
  </div>

  <table>
    <thead><tr><th>Time</th><th>Source</th><th>Risk</th><th>Detail</th></tr></thead>
    <tbody>
      {% if alerts %}
        {% for a in alerts %}
        <tr>
          <td style="color:#64748b">{{ a.time }}</td>
          <td>{{ a.source }}</td>
          <td><span class="badge {{ a.risk }}">{{ a.risk }}</span></td>
          <td style="color:#94a3b8">{{ a.detail }}</td>
        </tr>
        {% endfor %}
      {% else %}
        <tr><td colspan="4" class="empty">No alerts yet. DataSnug is watching...</td></tr>
      {% endif %}
    </tbody>
  </table>

  <div class="uptime">Uptime: {{ stats.uptime }}</div>
</body>
</html>
"""

@app.route("/")
def dashboard():
    uptime = str(datetime.now() - start_time).split(".")[0]
    return render_template_string(
        DASHBOARD_HTML,
        alerts=list(alert_queue),
        stats={**stats, "uptime": uptime},
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

# ── Start background threads + Flask ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  DataSnug Flask Backend starting...")
    print("  Dashboard : http://localhost:5000")
    print("  Alerts API: http://localhost:5000/api/alerts")
    print("  Stats API : http://localhost:5000/api/stats")
    print("  Scan API  : POST http://localhost:5000/api/scan")
    print("=" * 50)

    threading.Thread(target=run_clipboard_monitor, daemon=True).start()
    threading.Thread(target=run_file_watcher,      daemon=True).start()

    app.run(host="0.0.0.0", port=5000, debug=False)
