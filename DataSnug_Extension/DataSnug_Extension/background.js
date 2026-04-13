/**
 * DataSnug — Background Service Worker
 * Receives alerts from content script and stores them.
 */

const alerts = [];
const stats = { HIGH: 0, MEDIUM: 0, LOW: 0, total: 0, blocked: 0 };

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ALERT") {
    const alert = {
      time: new Date().toLocaleTimeString(),
      source: msg.source,
      risk: msg.risk,
      detail: msg.detail,
      url: msg.url || ""
    };
    alerts.unshift(alert);
    if (alerts.length > 100) alerts.pop();

    stats[msg.risk] = (stats[msg.risk] || 0) + 1;
    stats.total += 1;
    if (msg.risk === "HIGH") stats.blocked += 1;

    // Show Chrome notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon.png",
      title: `DataSnug — ${msg.risk} RISK BLOCKED`,
      message: msg.detail
    });

    sendResponse({ ok: true });
  }

  if (msg.type === "GET_ALERTS") {
    sendResponse({ alerts, stats });
  }
});
