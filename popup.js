/**
 * popup.js — Security Firewall Dashboard
 * Displays:
 *  - Total prompts scanned
 *  - Total threats blocked
 *  - Total PII redactions
 *  - Attack mitigation rate bar
 *  - Scrollable filterable audit log
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── Element References ─────────────────────────────────────────────────────
  const toggle       = document.getElementById('firewall-toggle');
  const statusDot    = document.getElementById('status-dot');
  const statusText   = document.getElementById('status-text');
  const statusSub    = document.getElementById('status-sub');
  const statusBadge  = document.getElementById('status-badge');

  const valScanned   = document.getElementById('val-scanned');
  const valBlocked   = document.getElementById('val-blocked');
  const valRedacted  = document.getElementById('val-redacted');

  const coverageFill = document.getElementById('coverage-fill');
  const mitigationPct = document.getElementById('mitigation-pct');

  const logList      = document.getElementById('log-list');
  const logCountEl   = document.getElementById('log-count');

  const btnRefresh   = document.getElementById('btn-refresh');
  const btnClear     = document.getElementById('btn-clear');
  const btnFilter    = document.getElementById('btn-filter');
  const filterStrip  = document.getElementById('filter-strip');
  const filterBtns   = document.querySelectorAll('.filter-btn');

  let currentFilter = 'ALL';
  let allLogs = [];

  // ── State Load ─────────────────────────────────────────────────────────────

  function loadState() {
    chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (res) => {
      if (chrome.runtime.lastError || !res) return;

      const {
        firewallEnabled = true,
        scannedCount    = 0,
        redactedCount   = 0,
        blockedCount    = 0,
        inspectionLogs  = []
      } = res;

      allLogs = inspectionLogs;
      const totalScanned = Math.max(scannedCount, inspectionLogs.length);

      // Toggle UI
      toggle.checked = firewallEnabled;
      applyFirewallState(firewallEnabled);

      // Stats
      animateCounter(valScanned,  totalScanned);
      animateCounter(valBlocked,  blockedCount);
      animateCounter(valRedacted, redactedCount);

      // Mitigation rate
      const threats = blockedCount + redactedCount;
      const detectionRate = totalScanned > 0
        ? Math.min(100, Math.round((threats / totalScanned) * 100))
        : 0;

      coverageFill.style.width = detectionRate + '%';
      mitigationPct.textContent = detectionRate + '%';
      mitigationPct.style.color = detectionRate >= 80 ? '#a6e3a1' : detectionRate >= 50 ? '#fab387' : '#f38ba8';

      // Render logs
      renderLogs(filterLogs(allLogs, currentFilter));
    });
  }

  function applyFirewallState(enabled) {
    if (enabled) {
      statusDot.className   = 'status-dot active';
      statusText.textContent = 'Protection Active';
      statusSub.textContent  = 'Monitoring all inputs';
      statusBadge.textContent = 'LIVE';
      statusBadge.className  = 'status-badge';
    } else {
      statusDot.className   = 'status-dot paused';
      statusText.textContent = 'Firewall Paused';
      statusSub.textContent  = 'All traffic passing through';
      statusBadge.textContent = 'OFF';
      statusBadge.className  = 'status-badge off';
    }
  }

  // ── Counters ────────────────────────────────────────────────────────────────

  function animateCounter(el, target) {
    const start   = parseInt(el.textContent, 10) || 0;
    const delta   = target - start;
    if (delta === 0) return;
    const steps   = 20;
    const stepMs  = 16;
    let step = 0;

    const timer = setInterval(() => {
      step++;
      const val = Math.round(start + (delta * (step / steps)));
      el.textContent = val;
      if (step >= steps) { el.textContent = target; clearInterval(timer); }
    }, stepMs);
  }

  // ── Log Rendering ──────────────────────────────────────────────────────────

  function filterLogs(logs, filter) {
    if (filter === 'ALL') return logs;
    return logs.filter(l => l.verdict === filter);
  }

  function renderLogs(logs) {
    logCountEl.textContent = `${logs.length} event${logs.length !== 1 ? 's' : ''}`;

    if (!logs || logs.length === 0) {
      logList.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">📋</div>
          <p>${currentFilter === 'ALL' ? 'No events captured yet.' : `No ${currentFilter.toLowerCase()} events.`}</p>
          <small>${currentFilter === 'ALL' ? 'Submit a prompt on any page to begin scanning.' : 'Try a different filter.'}</small>
        </div>
      `;
      return;
    }

    logList.innerHTML = logs.map(log => {
      const isBlocked  = log.verdict === 'BLOCKED';
      const isRedacted = log.verdict === 'REDACTED';
      const isClean    = log.verdict === 'CLEAN';

      const verdictClass = isBlocked ? 'verdict-blocked' : isRedacted ? 'verdict-redacted' : 'verdict-clean';
      const badgeLabel   = isBlocked ? 'BLOCKED' : isRedacted ? 'REDACTED' : 'CLEAN';
      const badgeIcon    = isBlocked ? '🚫' : isRedacted ? '✂️' : '✅';

      const timeStr  = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const dateStr  = new Date(log.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });

      const threatType = isBlocked
        ? `Rule: <code>${esc(log.firewallResult?.matchedRule || 'N/A')}</code>`
        : isRedacted
        ? `${log.redactions || 0} item(s) hashed`
        : 'No threats';

      const threatTier = isBlocked && log.firewallResult?.matchedRule
        ? getTierFromRuleId(log.firewallResult.matchedRule)
        : null;

      return `
        <div class="log-item ${verdictClass}" data-id="${esc(log.id)}">
          <div class="log-top">
            <div class="log-origin">${esc(log.origin || 'Unknown')}</div>
            <div class="log-badge-wrap">
              ${threatTier ? `<span class="tier-chip">${tierLabel(threatTier)}</span>` : ''}
              <span class="verdict-badge ${verdictClass}">${badgeIcon} ${badgeLabel}</span>
            </div>
          </div>
          <div class="log-snippet">${esc(log.snippet || '—')}</div>
          <div class="log-meta">
            <span class="threat-detail">${threatType}</span>
            <span class="log-time">${dateStr} · ${timeStr}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function getTierFromRuleId(ruleId) {
    if (!ruleId) return null;
    if (ruleId.startsWith('PI-')) return 1;
    if (ruleId.startsWith('DE-')) return 2;
    if (ruleId.startsWith('PE-')) return 3;
    return null;
  }

  function tierLabel(t) {
    return t === 1 ? 'T1·Injection' : t === 2 ? 'T2·Exfiltration' : 'T3·Escalation';
  }

  function esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Filter ─────────────────────────────────────────────────────────────────

  btnFilter.addEventListener('click', () => {
    const shown = !filterStrip.hidden;
    filterStrip.hidden = shown;
    btnFilter.setAttribute('aria-pressed', String(!shown));
  });

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderLogs(filterLogs(allLogs, currentFilter));
    });
  });

  // ── Toggle ─────────────────────────────────────────────────────────────────

  toggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({ action: 'TOGGLE_FIREWALL' }, (res) => {
      if (res) applyFirewallState(res.firewallEnabled);
    });
  });

  // ── Refresh & Clear ────────────────────────────────────────────────────────

  btnRefresh.addEventListener('click', () => {
    btnRefresh.style.transform = 'rotate(360deg)';
    setTimeout(() => btnRefresh.style.transform = '', 400);
    loadState();
  });

  btnClear.addEventListener('click', () => {
    if (!confirm('Clear all audit logs? This cannot be undone.')) return;
    chrome.storage.local.set({ inspectionLogs: [], scannedCount: 0, blockedCount: 0, redactedCount: 0 }, () => {
      allLogs = [];
      animateCounter(valScanned,  0);
      animateCounter(valBlocked,  0);
      animateCounter(valRedacted, 0);
      coverageFill.style.width = '0%';
      mitigationPct.textContent = '0%';
      renderLogs([]);
    });
  });

  // ── Init ───────────────────────────────────────────────────────────────────
  loadState();
});
