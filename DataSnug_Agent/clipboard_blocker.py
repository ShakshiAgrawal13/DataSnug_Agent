"""
╔══════════════════════════════════════════════════════╗
║     DataSnug — Instant Clipboard Blocker             ║
║                                                      ║
║  Uses Windows hooks to block sensitive data          ║
║  the INSTANT it is copied — no polling delay.        ║
║                                                      ║
║  Run: python clipboard_blocker.py                    ║
╚══════════════════════════════════════════════════════╝
"""

import re
import sys
import time
import threading
import win32api
import win32con
import win32gui
import win32clipboard
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
BLOCK_MESSAGE = "[BLOCKED by DataSnug] Sensitive data was prevented from being shared."

PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b',                               "SSN",         "HIGH"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b',    "Credit Card", "HIGH"),
    (r'(?i)(?:password|passwd)\s*[:=\s]\s*\S+',               "Password",    "HIGH"),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',  "Email",       "MEDIUM"),
    (r'\b[2-9][0-9]{11}\b',                                   "Aadhaar",     "HIGH"),
    (r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b',                       "Phone",       "MEDIUM"),
]

BLOCK_LEVELS = {"HIGH"}   # add "MEDIUM" to also block emails/phones

# ── Scanner ───────────────────────────────────────────────────────────────────
def scan(text):
    findings, score = [], 0
    for rx, label, risk in PATTERNS:
        if re.search(rx, text):
            findings.append({"type": label, "risk": risk})
            score += 3 if risk == "HIGH" else 2
    # Use the highest individual risk level, not just the total score
    risks = [f["risk"] for f in findings]
    if "HIGH" in risks:
        level = "HIGH"
    elif "MEDIUM" in risks:
        level = "MEDIUM"
    elif findings:
        level = "LOW"
    else:
        level = "SAFE"
    return level, findings

# ── Clipboard read/write ──────────────────────────────────────────────────────
def get_clipboard_text():
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        else:
            data = ""
        win32clipboard.CloseClipboard()
        return data
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass
        return ""

def set_clipboard_text(text):
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)
        win32clipboard.CloseClipboard()
        return True
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass
        return False

# ── Windows Message Window ────────────────────────────────────────────────────
class ClipboardHook:
    def __init__(self):
        self._last_blocked = ""
        self._hwnd = None

    def _on_clipboard_change(self):
        # Small delay to let the source app finish writing to clipboard
        time.sleep(0.05)

        text = get_clipboard_text()

        if not text or len(text.strip()) < 6:
            return
        if text == BLOCK_MESSAGE:
            return
        if text == self._last_blocked:
            return

        level, findings = scan(text)

        if level in BLOCK_LEVELS:
            types = ", ".join(f["type"] for f in findings[:3])
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] BLOCKED [{level}] {types} — replacing clipboard...")

            # Retry replacing clipboard 5 times to make sure it sticks
            for i in range(5):
                set_clipboard_text(BLOCK_MESSAGE)
                time.sleep(0.05)
                verify = get_clipboard_text()
                if verify == BLOCK_MESSAGE:
                    self._last_blocked = BLOCK_MESSAGE
                    print(f"[{ts}] Clipboard successfully replaced on attempt {i+1}")
                    break
                else:
                    print(f"[{ts}] Retrying block... attempt {i+1}")

        elif level != "SAFE":
            types = ", ".join(f["type"] for f in findings[:3])
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] DETECTED [{level}] {types} — logged only")

    def start(self):
        # Register a hidden window to receive WM_CLIPBOARDUPDATE messages
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = self._wnd_proc
        wc.lpszClassName = "DataSnugClipboardWatcher"
        wc.hInstance = win32api.GetModuleHandle(None)

        try:
            win32gui.RegisterClass(wc)
        except Exception:
            pass

        self._hwnd = win32gui.CreateWindowEx(
            0, "DataSnugClipboardWatcher", "DataSnug",
            0, 0, 0, 0, 0,
            win32con.HWND_MESSAGE, None,
            win32api.GetModuleHandle(None), None
        )

        # Subscribe to clipboard changes
        user32 = __import__('ctypes').windll.user32
        user32.AddClipboardFormatListener(self._hwnd)

        print("=" * 55)
        print("  DataSnug Instant Clipboard Blocker — ACTIVE")
        print("  Using Windows hooks (zero polling delay)")
        print(f"  Blocking: {', '.join(BLOCK_LEVELS)}")
        print("  Press Ctrl+C to stop")
        print("=" * 55)

        try:
            win32gui.PumpMessages()
        except KeyboardInterrupt:
            self.stop()

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        WM_CLIPBOARDUPDATE = 0x031D
        if msg == WM_CLIPBOARDUPDATE:
            # Small delay to let the app finish writing to clipboard
            threading.Thread(target=self._on_clipboard_change, daemon=True).start()
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def stop(self):
        if self._hwnd:
            ctypes = __import__('ctypes')
            ctypes.windll.user32.RemoveClipboardFormatListener(self._hwnd)
            win32gui.DestroyWindow(self._hwnd)
        print("\nDataSnug Clipboard Blocker stopped.")


if __name__ == "__main__":
    hook = ClipboardHook()
    hook.start()