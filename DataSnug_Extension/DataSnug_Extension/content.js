/**
 * DataSnug — Content Script
 * Intercepts ALL file input changes and form submissions.
 * Scans file content for PII before allowing upload.
 */

const BLOCK_MESSAGE = "[BLOCKED by DataSnug] This file contains sensitive data and cannot be uploaded.";

const PATTERNS = [
  { rx: /\b\d{3}-\d{2}-\d{4}\b/,                              label: "SSN",         risk: "HIGH" },
  { rx: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/,   label: "Credit Card", risk: "HIGH" },
  { rx: /(?:password|passwd)\s*[:=\s]\s*\S+/i,                 label: "Password",    risk: "HIGH" },
  { rx: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, label: "Email",       risk: "MEDIUM" },
  { rx: /\b[2-9][0-9]{11}\b/,                                  label: "Aadhaar",     risk: "HIGH" },
  { rx: /\b(?:\+91[-\s]?)?[6-9]\d{9}\b/,                      label: "Phone",       risk: "MEDIUM" },
];

const SUSPICIOUS_NAMES = [
  "password", "credentials", "secret", "employee", "salary",
  "payroll", "confidential", "ssn", "database", "dump",
  "export", "pii", "private"
];

const SCANNABLE_TYPES = [
  "text/plain", "text/csv", "application/json",
  "text/xml", "application/xml", "text/html",
  "application/sql", "text/markdown"
];

// ── Scanner ──────────────────────────────────────────────────────────────────
function scanText(text) {
  const findings = [];
  for (const p of PATTERNS) {
    if (p.rx.test(text)) {
      findings.push({ type: p.label, risk: p.risk });
    }
  }
  const risks = findings.map(f => f.risk);
  const level = risks.includes("HIGH") ? "HIGH"
              : risks.includes("MEDIUM") ? "MEDIUM"
              : findings.length ? "LOW" : "SAFE";
  return { level, findings };
}

function isSuspiciousName(filename) {
  const lower = filename.toLowerCase();
  return SUSPICIOUS_NAMES.some(s => lower.includes(s));
}

// ── Show block overlay ────────────────────────────────────────────────────────
function showBlockOverlay(filename, findings) {
  // Remove existing overlay
  const existing = document.getElementById("datasnug-overlay");
  if (existing) existing.remove();

  const types = findings.map(f => f.type).join(", ");

  const overlay = document.createElement("div");
  overlay.id = "datasnug-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.75); z-index: 999999;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Segoe UI', sans-serif;
  `;

  overlay.innerHTML = `
    <div style="
      background: #1e1e2e; border: 2px solid #f87171;
      border-radius: 12px; padding: 32px 40px; max-width: 480px;
      text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    ">
      <div style="font-size: 48px; margin-bottom: 12px;">🛡️</div>
      <h2 style="color: #f87171; margin: 0 0 8px; font-size: 1.3rem;">Upload Blocked by DataSnug</h2>
      <p style="color: #94a3b8; margin: 0 0 16px; font-size: 0.9rem;">
        The file <strong style="color:#e2e8f0">${filename}</strong> contains sensitive data and cannot be uploaded.
      </p>
      <div style="
        background: #2a2a3e; border-radius: 8px; padding: 12px 16px;
        margin-bottom: 20px; font-size: 0.85rem; color: #fbbf24;
      ">
        Detected: <strong>${types}</strong>
      </div>
      <button onclick="document.getElementById('datasnug-overlay').remove()" style="
        background: #f87171; color: white; border: none;
        padding: 10px 28px; border-radius: 8px; cursor: pointer;
        font-size: 0.95rem; font-weight: bold;
      ">Dismiss</button>
    </div>
  `;

  document.body.appendChild(overlay);
}

// ── Scan a single file ────────────────────────────────────────────────────────
function scanFile(file) {
  return new Promise((resolve) => {
    // Always flag suspicious filenames
    if (isSuspiciousName(file.name)) {
      resolve({
        blocked: true,
        filename: file.name,
        findings: [{ type: "Suspicious Filename", risk: "MEDIUM" }]
      });
      return;
    }

    // Only scan text-based files
    if (!SCANNABLE_TYPES.includes(file.type) && !file.name.match(/\.(txt|csv|json|xml|sql|log|env|md|py)$/i)) {
      resolve({ blocked: false });
      return;
    }

    // Limit scan to first 100KB
    const blob = file.slice(0, 100 * 1024);
    const reader = new FileReader();

    reader.onload = (e) => {
      const text = e.target.result;
      const result = scanText(text);
      if (result.level === "HIGH") {
        resolve({ blocked: true, filename: file.name, findings: result.findings });
      } else {
        resolve({ blocked: false, filename: file.name, findings: result.findings, level: result.level });
      }
    };

    reader.onerror = () => resolve({ blocked: false });
    reader.readAsText(blob);
  });
}

// ── Intercept file inputs ─────────────────────────────────────────────────────
function attachToFileInput(input) {
  if (input._datasnug) return;
  input._datasnug = true;

  input.addEventListener("change", async (e) => {
    const files = Array.from(input.files);
    if (!files.length) return;

    for (const file of files) {
      const result = await scanFile(file);
      if (result.blocked) {
        // Clear the file input
        input.value = "";
        showBlockOverlay(result.filename, result.findings);

        // Log to background
        chrome.runtime.sendMessage({
          type: "ALERT",
          source: "File Upload",
          risk: "HIGH",
          detail: `BLOCKED: ${result.filename} — ${result.findings.map(f => f.type).join(", ")}`,
          url: window.location.hostname
        });
        return;
      }
    }
  }, true);
}

// ── Intercept form submissions ────────────────────────────────────────────────
function attachToForm(form) {
  if (form._datasnug) return;
  form._datasnug = true;

  form.addEventListener("submit", async (e) => {
    const inputs = Array.from(form.querySelectorAll('input[type="file"]'));
    for (const input of inputs) {
      const files = Array.from(input.files || []);
      for (const file of files) {
        const result = await scanFile(file);
        if (result.blocked) {
          e.preventDefault();
          e.stopImmediatePropagation();
          showBlockOverlay(result.filename, result.findings);
          return;
        }
      }
    }
  }, true);
}

// ── Watch for dynamically added inputs ───────────────────────────────────────
function scanDOM() {
  document.querySelectorAll('input[type="file"]').forEach(attachToFileInput);
  document.querySelectorAll("form").forEach(attachToForm);
}

// Initial scan
scanDOM();

// Watch for new elements added dynamically (e.g. React/Vue apps)
const observer = new MutationObserver(() => scanDOM());
observer.observe(document.body || document.documentElement, {
  childList: true,
  subtree: true
});
