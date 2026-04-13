chrome.runtime.sendMessage({ type: "GET_ALERTS" }, (res) => {
  if (!res) return;
  const { alerts, stats } = res;

  document.getElementById("total").textContent = stats.total;
  document.getElementById("high").textContent = stats.blocked;
  document.getElementById("medium").textContent = stats.MEDIUM || 0;

  const list = document.getElementById("list");
  if (!alerts.length) return;

  list.innerHTML = alerts.slice(0, 20).map(a => `
    <div class="item">
      <div class="row1">
        <span class="time">${a.time}</span>
        <span class="badge ${a.risk}">${a.risk}</span>
      </div>
      <div class="detail">${a.detail}</div>
      <div class="url">${a.url}</div>
    </div>
  `).join("");
});
