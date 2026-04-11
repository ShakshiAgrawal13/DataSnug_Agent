# DataSnug Agent — System-Level DLP

Prevents employees from leaking company data through ANY channel —
WhatsApp Desktop, Telegram, copy-paste, USB drives, email clients.

---

## Quick Start

```bash
cd DataSnug_Agent/
pip install -r requirements_agent.txt
python agent.py
```

That's it. A live dashboard appears in the terminal.

---

## What Each Layer Does

### Layer 1 — Clipboard Monitor (`clipboard_monitor.py`)
- Polls clipboard every 0.8 seconds
- Works across ALL apps: WhatsApp, Telegram, Notepad, browser
- If HIGH risk (SSN, credit card, Aadhaar, password) → clipboard is CLEARED
- Desktop notification fires immediately
- Logs to `clipboard_alerts.log`

**Example:** Employee copies `SSN: 123-45-6789` from HR sheet to paste into WhatsApp
→ DataSnug detects it, clears clipboard, shows notification. Paste fails.

---

### Layer 2 — File Watcher (`file_watcher.py`)
- Watches Documents, Desktop, Downloads folders recursively
- Triggers on: file create, modify, move
- Scans file content for PII on every save
- Detects USB copies (Linux: /media, Mac: /Volumes, Windows: non-C: drive)
- Flags suspicious filenames: `employee_data.csv`, `passwords.txt`, etc.
- Logs to `file_alerts.log`

**Example:** Employee saves `salary_list.csv` to Desktop or copies it to USB
→ DataSnug scans the content, finds PII, logs HIGH alert + desktop notification.

---

### Layer 3 — Live Dashboard
- Terminal UI that refreshes every 3 seconds
- Shows real-time alert feed from all layers
- Session stats: total, HIGH/MEDIUM/LOW counts, blocked count

---

## Combined Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Employee's Computer                    │
│                                                          │
│  WhatsApp ──copy/paste──→ Clipboard Monitor ──→ BLOCK   │
│  Telegram ──copy/paste──→ Clipboard Monitor ──→ BLOCK   │
│  Any App  ──copy/paste──→ Clipboard Monitor ──→ LOG     │
│                                                          │
│  Save file ────────────→ File Watcher ──────→ ALERT     │
│  USB copy  ────────────→ File Watcher ──────→ BLOCK     │
│  Modify file ──────────→ File Watcher ──────→ SCAN      │
│                                                          │
│  Browser (all sites) ──→ Proxy ─────────────→ BLOCK     │
│  Browser text fields ──→ Extension ─────────→ WARN      │
└─────────────────────────────────────────────────────────┘
```

---

## Run Everything Together

```bash
# Terminal 1 — Flask Backend
cd DataSnug/
python app.py

# Terminal 2 — Proxy (intercepts browser traffic)
cd DataSnug_Proxy/
mitmdump --scripts proxy.py --listen-port 8080

# Terminal 3 — System Agent (clipboard + files)
cd DataSnug_Agent/
python agent.py

# Chrome — Load DataSnug_Extension (browser field scanner)
```

---

## Adding More Watch Folders

Edit `file_watcher.py` or `agent.py`, find `watch_paths` and add:

```python
watch_paths = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Downloads",
    Path("/shared/company_drive"),   # ← add your network drives here
    Path("D:/HR/Records"),           # ← Windows example
]
```

---

## Log Files

| File | Contains |
|---|---|
| `agent.log` | Master log from all layers |
| `clipboard_alerts.log` | Clipboard-specific alerts |
| `file_alerts.log` | File-specific alerts |
| `proxy_alerts.log` | Network/proxy alerts (in DataSnug_Proxy/) |
