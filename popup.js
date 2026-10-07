document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('firewall-toggle');
  const statusIndicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('status-text');
  const blockedCountEl = document.getElementById('blocked-count');
  const logList = document.getElementById('log-list');
  const refreshBtn = document.getElementById('refresh-logs');

  async function loadState() {
    chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (res) => {
      if (!res) return;

      const { firewallEnabled = true, redactedCount = 0, inspectionLogs = [] } = res;

      toggle.checked = firewallEnabled;
      if (firewallEnabled) {
        statusIndicator.className = 'status-indicator active';
        statusText.textContent = 'Protection Active';
      } else {
        statusIndicator.className = 'status-indicator paused';
        statusText.textContent = 'Firewall Paused';
      }

      blockedCountEl.textContent = `${redactedCount} inputs redacted`;
      renderLogs(inspectionLogs);
    });
  }

  function renderLogs(logs) {
    if (!logs || logs.length === 0) {
      logList.innerHTML = '<div class="empty-state">No events captured yet.</div>';
      return;
    }

    logList.innerHTML = logs.map(log => {
      const isRedacted = log.verdict === 'REDACTED';
      const badgeClass = isRedacted ? 'blocked' : 'allowed';
      const badgeLabel = isRedacted ? 'REDACTED' : 'CLEAN';
      const timeStr = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      return `
        <div class="log-item ${badgeClass}">
          <div class="log-header">
            <span>${escapeHtml(log.origin)}</span>
            <span class="badge ${badgeClass}">${badgeLabel}</span>
          </div>
          <div class="log-snippet">${escapeHtml(log.snippet || '')}</div>
          ${isRedacted ? `<div style="font-size:10px;color:#fab387;">${log.redactions || 0} item(s) hashed</div>` : ''}
          <div style="font-size: 10px; color: #a6adc8;">${timeStr}</div>
        </div>
      `;
    }).join('');
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  toggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({ action: 'TOGGLE_FIREWALL' }, () => {
      loadState();
    });
  });

  refreshBtn.addEventListener('click', loadState);

  loadState();
});
