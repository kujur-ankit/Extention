/**
 * Content Script: Security Firewall Interceptor
 * Intercepts submissions across standard inputs, textareas, and rich contenteditable
 * containers (such as ChatGPT ProseMirror, Claude Lexical, and web forms).
 *
 * Blocked prompts show a Shadow DOM modal with Cancel / Override options.
 * Redacted prompts show a non-blocking toast notification.
 */

(() => {
  const approvedEvents = new WeakSet();
  let isProcessing = false;

  // ── Selectors ──────────────────────────────────────────────────────────────
  const INPUT_SELECTORS = [
    '#prompt-textarea',
    '.ProseMirror',
    '[contenteditable="true"]',
    '[contenteditable=""]',
    '[contenteditable="plaintext-only"]',
    '[role="textbox"]',
    'textarea',
    'input[type="text"]',
    'input[type="search"]',
    'input:not([type])'
  ];

  const SEND_BUTTON_SELECTORS = [
    'button[data-testid*="send" i]',
    'button[data-testid*="submit" i]',
    'button[aria-label*="send" i]',
    'button[aria-label*="submit" i]',
    'button[id*="send" i]',
    'button[class*="send" i]',
    'button[type="submit"]',
    'input[type="submit"]',
    '[role="button"][aria-label*="send" i]'
  ];

  // ── DOM Helpers ────────────────────────────────────────────────────────────

  function findTargetInput(fromElement) {
    if (!fromElement) fromElement = document.activeElement;

    for (const sel of INPUT_SELECTORS) {
      if (fromElement?.matches?.(sel)) return fromElement;
    }

    const container = fromElement?.closest?.(
      'form, div[class*="chat" i], div[class*="prompt" i], div[class*="input" i], div[class*="composer" i], main, section, [role="main"]'
    ) || document;

    const inp = container.querySelector?.(INPUT_SELECTORS.join(','));
    if (inp) return inp;

    if (document.activeElement && isEditableElement(document.activeElement)) {
      return document.activeElement;
    }
    return null;
  }

  function isEditableElement(el) {
    if (!el || !(el instanceof Element)) return false;
    return (
      el instanceof HTMLInputElement ||
      el instanceof HTMLTextAreaElement ||
      el.isContentEditable ||
      el.getAttribute('contenteditable') !== null ||
      el.getAttribute('role') === 'textbox'
    );
  }

  function getText(el) {
    if (!el) return '';
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      return el.value || '';
    }
    return el.innerText || el.textContent || '';
  }

  function setSanitizedText(el, newText) {
    if (!el) return;

    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      const proto = el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, newText);
      else el.value = newText;

      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertReplacementText' }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      el.focus();
      try {
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        sel.removeAllRanges();
        sel.addRange(range);
        if (!document.execCommand('insertText', false, newText)) {
          el.innerText = newText;
        }
      } catch {
        el.innerText = newText;
      }
      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertReplacementText', data: newText }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function findSendButton(relativeEl) {
    const root = relativeEl?.closest?.('form, div[class*="chat" i], div[class*="prompt" i], div[class*="composer" i], main, body') || document.body;
    for (const sel of SEND_BUTTON_SELECTORS) {
      const btn = root.querySelector(sel);
      if (btn && btn.offsetParent !== null) return btn;
    }
    return null;
  }

  // ── Background Communication ───────────────────────────────────────────────

  function inspectPayload(text) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { action: 'INSPECT_PAYLOAD', data: { text, origin: window.location.origin } },
          (response) => {
            if (chrome.runtime.lastError || !response) {
              resolve({ needsRedaction: false, sanitizedText: text });
            } else {
              resolve(response);
            }
          }
        );
      } catch (err) {
        console.error('[Firewall Content] Error communicating with background:', err);
        resolve({ needsRedaction: false, sanitizedText: text });
      }
    });
  }

  // ── Submission Helpers ─────────────────────────────────────────────────────

  function triggerSubmit(inputEl) {
    const sendBtn = findSendButton(inputEl);
    if (sendBtn && !sendBtn.disabled) {
      approvedEvents.add(sendBtn);
      sendBtn.click();
      return;
    }

    const form = inputEl?.form || inputEl?.closest?.('form');
    if (form) {
      approvedEvents.add(form);
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit();
      } else {
        form.submit();
      }
      return;
    }

    const enterEvent = new KeyboardEvent('keydown', {
      key: 'Enter', code: 'Enter', keyCode: 13, which: 13,
      bubbles: true, cancelable: true, composed: true
    });
    approvedEvents.add(enterEvent);
    inputEl.dispatchEvent(enterEvent);
  }

  // ── Event Handlers ─────────────────────────────────────────────────────────

  async function handleKeyDown(event) {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
    if (approvedEvents.has(event)) return;
    if (isProcessing) return;

    const inputEl = findTargetInput(event.target);
    if (!inputEl) return;

    const rawText = getText(inputEl).trim();
    if (!rawText) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    isProcessing = true;

    try {
      const result = await inspectPayload(rawText);

      if (result.blocked) {
        showBlockedModal({
          reason:      result.reason,
          matchedRule: result.matchedRule,
          threatLevel: result.threatLevel,
          onCancel:    () => { inputEl.focus(); },
          onOverride:  async () => {
            await new Promise((r) => setTimeout(r, 60));
            triggerSubmit(inputEl);
          }
        });
        return;
      }

      if (result.needsRedaction) {
        setSanitizedText(inputEl, result.sanitizedText);
        showRedactionToast(result.reason, result.redactionCount);
        await new Promise((r) => setTimeout(r, 60));
      }

      triggerSubmit(inputEl);
    } finally {
      isProcessing = false;
    }
  }

  async function handleClick(event) {
    if (approvedEvents.has(event.target) || approvedEvents.has(event)) return;
    if (isProcessing) return;

    const btn = event.target.closest?.(SEND_BUTTON_SELECTORS.join(','));
    if (!btn) return;

    const inputEl = findTargetInput(btn);
    if (!inputEl) return;

    const rawText = getText(inputEl).trim();
    if (!rawText) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    isProcessing = true;

    try {
      const result = await inspectPayload(rawText);

      if (result.blocked) {
        showBlockedModal({
          reason:      result.reason,
          matchedRule: result.matchedRule,
          threatLevel: result.threatLevel,
          onCancel:    () => { inputEl.focus(); },
          onOverride:  async () => {
            await new Promise((r) => setTimeout(r, 60));
            approvedEvents.add(btn);
            btn.click();
          }
        });
        return;
      }

      if (result.needsRedaction) {
        setSanitizedText(inputEl, result.sanitizedText);
        showRedactionToast(result.reason, result.redactionCount);
        await new Promise((r) => setTimeout(r, 60));
      }

      approvedEvents.add(btn);
      btn.click();
    } finally {
      isProcessing = false;
    }
  }

  async function handleSubmit(event) {
    const form = event.target;
    if (approvedEvents.has(form)) return;
    if (isProcessing) return;

    const inputs = form.querySelectorAll(INPUT_SELECTORS.join(','));
    let anyRedacted = false;

    for (const inp of inputs) {
      const rawText = getText(inp).trim();
      if (!rawText) continue;

      const result = await inspectPayload(rawText);

      if (result.blocked) {
        event.preventDefault();
        event.stopImmediatePropagation();
        showBlockedModal({
          reason:      result.reason,
          matchedRule: result.matchedRule,
          threatLevel: result.threatLevel,
          onCancel:    () => { inp.focus(); },
          onOverride:  () => {
            approvedEvents.add(form);
            setTimeout(() => {
              if (typeof form.requestSubmit === 'function') form.requestSubmit();
              else form.submit();
            }, 50);
          }
        });
        isProcessing = false;
        return;
      }

      if (result.needsRedaction) {
        setSanitizedText(inp, result.sanitizedText);
        anyRedacted = true;
        showRedactionToast(result.reason, result.redactionCount);
      }
    }

    if (anyRedacted) {
      event.preventDefault();
      event.stopImmediatePropagation();
      approvedEvents.add(form);
      setTimeout(() => {
        if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else form.submit();
      }, 50);
    }
  }

  // ── Shadow DOM Blocked Modal ───────────────────────────────────────────────

  /**
   * Inject a fully isolated Shadow DOM modal for blocked prompts.
   * Uses attachShadow to prevent host-page CSS from leaking in.
   *
   * @param {Object} opts
   * @param {string}   opts.reason       - Full reason string from firewall engine
   * @param {string}   opts.matchedRule  - Rule ID, e.g. 'PI-001'
   * @param {number}   opts.threatLevel  - 1-5
   * @param {Function} opts.onCancel     - Called when user clicks "Cancel / Fix Prompt"
   * @param {Function} opts.onOverride   - Called when user clicks "Override & Send Anyway"
   */
  function showBlockedModal({ reason, matchedRule, threatLevel, onCancel, onOverride }) {
    // Remove any existing modal
    document.getElementById('fw-modal-host')?.remove();

    // Host element — invisible container in the real DOM
    const host = document.createElement('div');
    host.id = 'fw-modal-host';
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
    document.documentElement.appendChild(host);

    // Attach shadow root — closed so page JS can't intrude
    const shadow = host.attachShadow({ mode: 'closed' });

    // Threat level colour palette
    const palette = threatLevel >= 5
      ? { accent: '#f38ba8', glow: 'rgba(243,139,168,0.25)', badge: '#f38ba8', badgeBg: 'rgba(243,139,168,0.12)' }
      : threatLevel >= 3
      ? { accent: '#fab387', glow: 'rgba(250,179,135,0.2)',  badge: '#fab387', badgeBg: 'rgba(250,179,135,0.12)' }
      : { accent: '#f9e2af', glow: 'rgba(249,226,175,0.2)',  badge: '#f9e2af', badgeBg: 'rgba(249,226,175,0.12)' };

    const threatLabel = threatLevel >= 5 ? 'CRITICAL' : threatLevel >= 3 ? 'HIGH' : 'MEDIUM';

    shadow.innerHTML = `
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.65);
          backdrop-filter: blur(6px);
          -webkit-backdrop-filter: blur(6px);
          display: flex;
          align-items: center;
          justify-content: center;
          pointer-events: all;
          animation: fw-fade-in 0.2s ease;
        }

        @keyframes fw-fade-in {
          from { opacity: 0; }
          to   { opacity: 1; }
        }

        @keyframes fw-slide-up {
          from { opacity: 0; transform: translateY(24px) scale(0.96); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }

        .modal {
          background: linear-gradient(145deg, #1e1e2e 0%, #181825 60%, #11111b 100%);
          border: 1px solid ${palette.accent};
          box-shadow:
            0 0 0 1px rgba(255,255,255,0.04) inset,
            0 24px 64px rgba(0,0,0,0.8),
            0 0 40px ${palette.glow};
          border-radius: 16px;
          width: 480px;
          max-width: calc(100vw - 32px);
          padding: 28px 28px 24px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', sans-serif;
          color: #cdd6f4;
          animation: fw-slide-up 0.3s cubic-bezier(0.16, 1, 0.3, 1);
          position: relative;
        }

        /* Header */
        .modal-header {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 12px;
          margin-bottom: 18px;
        }

        .header-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .shield-wrap {
          width: 44px;
          height: 44px;
          border-radius: 12px;
          background: ${palette.badgeBg};
          border: 1px solid ${palette.accent}44;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 22px;
          flex-shrink: 0;
        }

        .title-block h2 {
          font-size: 15px;
          font-weight: 700;
          color: ${palette.accent};
          letter-spacing: -0.01em;
          line-height: 1.3;
        }

        .title-block p {
          font-size: 11px;
          color: #6c7086;
          margin-top: 2px;
          font-weight: 500;
          letter-spacing: 0.02em;
          text-transform: uppercase;
        }

        .close-btn {
          background: none;
          border: none;
          color: #585b70;
          cursor: pointer;
          font-size: 20px;
          line-height: 1;
          padding: 2px 6px;
          border-radius: 6px;
          transition: color 0.15s, background 0.15s;
          flex-shrink: 0;
        }
        .close-btn:hover { color: #cdd6f4; background: rgba(255,255,255,0.08); }

        /* Threat Badge */
        .threat-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          background: ${palette.badgeBg};
          border: 1px solid ${palette.accent}55;
          border-radius: 6px;
          padding: 5px 10px;
          font-size: 11px;
          font-weight: 700;
          color: ${palette.badge};
          letter-spacing: 0.06em;
          margin-bottom: 14px;
        }

        .threat-badge .dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: ${palette.accent};
          box-shadow: 0 0 6px ${palette.accent};
          animation: fw-pulse 1.5s ease-in-out infinite;
        }

        @keyframes fw-pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.5; transform: scale(0.8); }
        }

        /* Divider */
        .divider {
          height: 1px;
          background: linear-gradient(90deg, transparent, #313244, transparent);
          margin: 0 -28px 18px;
        }

        /* Rule pill */
        .rule-pill {
          display: inline-block;
          background: rgba(137, 180, 250, 0.1);
          border: 1px solid rgba(137, 180, 250, 0.25);
          color: #89b4fa;
          border-radius: 4px;
          padding: 2px 8px;
          font-size: 11px;
          font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
          font-weight: 600;
          margin-bottom: 10px;
        }

        /* Reason box */
        .reason-box {
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid #313244;
          border-radius: 8px;
          padding: 12px 14px;
          font-size: 12.5px;
          line-height: 1.6;
          color: #a6adc8;
          margin-bottom: 22px;
          word-break: break-word;
        }

        /* Buttons */
        .btn-row {
          display: flex;
          gap: 10px;
          flex-direction: row-reverse;
        }

        .btn {
          flex: 1;
          padding: 10px 16px;
          border-radius: 9px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          border: none;
          transition: all 0.2s ease;
          letter-spacing: -0.01em;
        }

        .btn-cancel {
          background: rgba(255,255,255,0.06);
          border: 1px solid #45475a;
          color: #cdd6f4;
        }
        .btn-cancel:hover {
          background: rgba(255,255,255,0.1);
          border-color: #585b70;
        }

        .btn-override {
          background: linear-gradient(135deg, ${palette.accent}22, ${palette.accent}15);
          border: 1px solid ${palette.accent}66;
          color: ${palette.accent};
        }
        .btn-override:hover {
          background: linear-gradient(135deg, ${palette.accent}33, ${palette.accent}22);
          border-color: ${palette.accent};
          box-shadow: 0 0 16px ${palette.glow};
        }

        /* Footer note */
        .modal-footer {
          margin-top: 16px;
          font-size: 10.5px;
          color: #45475a;
          text-align: center;
          line-height: 1.5;
        }
      </style>

      <div class="overlay" id="fw-overlay">
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="fw-title">
          <div class="modal-header">
            <div class="header-left">
              <div class="shield-wrap">⚠️</div>
              <div class="title-block">
                <h2 id="fw-title">Agent Firewall Alert</h2>
                <p>Unsafe Prompt Detected</p>
              </div>
            </div>
            <button class="close-btn" id="fw-close" aria-label="Close">✕</button>
          </div>

          <div class="threat-badge">
            <span class="dot"></span>
            THREAT LEVEL ${threatLevel}/5 &nbsp;·&nbsp; ${threatLabel}
          </div>

          <div class="divider"></div>

          ${matchedRule ? `<div class="rule-pill">Rule: ${matchedRule}</div>` : ''}

          <div class="reason-box">${escapeForModal(reason)}</div>

          <div class="btn-row">
            <button class="btn btn-cancel" id="fw-cancel">✏️&nbsp;&nbsp;Cancel / Fix Prompt</button>
            <button class="btn btn-override" id="fw-override">⚡&nbsp;&nbsp;Override &amp; Send Anyway</button>
          </div>

          <p class="modal-footer">
            Overriding sends your original unmodified prompt. Use only for authorized testing.
          </p>
        </div>
      </div>
    `;

    // Wire up buttons
    const overlay  = shadow.getElementById('fw-overlay');
    const closeBtn = shadow.getElementById('fw-close');
    const cancelBtn = shadow.getElementById('fw-cancel');
    const overrideBtn = shadow.getElementById('fw-override');

    function dismiss() { host.remove(); }

    closeBtn.addEventListener('click', () => { dismiss(); onCancel?.(); });
    cancelBtn.addEventListener('click', () => { dismiss(); onCancel?.(); });
    overrideBtn.addEventListener('click', () => { dismiss(); onOverride?.(); });

    // Click outside modal to cancel
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) { dismiss(); onCancel?.(); }
    });

    // Escape key to cancel
    const keyHandler = (e) => {
      if (e.key === 'Escape') { dismiss(); onCancel?.(); document.removeEventListener('keydown', keyHandler, true); }
    };
    document.addEventListener('keydown', keyHandler, true);

    // Focus the cancel button for accessibility
    setTimeout(() => cancelBtn.focus(), 50);
  }

  function escapeForModal(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Redaction Toast ────────────────────────────────────────────────────────

  function showRedactionToast(reason, count) {
    document.getElementById('fw-toast-host')?.remove();

    const host = document.createElement('div');
    host.id = 'fw-toast-host';
    host.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:2147483646;pointer-events:none;';
    document.documentElement.appendChild(host);

    const shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes fw-slide-in {
          from { opacity: 0; transform: translateY(16px) scale(0.95); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }
        .toast {
          pointer-events: all;
          background: linear-gradient(135deg, #1e1e2e, #181825);
          border: 1px solid #fab387;
          box-shadow: 0 12px 40px rgba(0,0,0,0.7), 0 0 24px rgba(250,179,135,0.15);
          border-radius: 12px;
          padding: 14px 18px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 13px;
          max-width: 380px;
          display: flex;
          flex-direction: column;
          gap: 6px;
          animation: fw-slide-in 0.3s cubic-bezier(0.16,1,0.3,1);
        }
        .toast-title {
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-weight: 700;
          color: #f9e2af;
        }
        .toast-body { color: #a6adc8; font-size: 11.5px; line-height: 1.5; }
        .close-btn {
          background: none; border: none; color: #6c7086;
          cursor: pointer; font-size: 17px; line-height: 1;
        }
        .close-btn:hover { color: #cdd6f4; }
      </style>
      <div class="toast">
        <div class="toast-title">
          <span>🛡️ Sensitive Data Sanitized (${count})</span>
          <button class="close-btn" id="fw-toast-close">✕</button>
        </div>
        <div class="toast-body">${escapeForModal(reason)}</div>
      </div>
    `;

    shadow.getElementById('fw-toast-close').addEventListener('click', () => host.remove());
    setTimeout(() => { if (host.parentElement) host.remove(); }, 6000);
  }

  // ── Register Listeners ─────────────────────────────────────────────────────
  window.addEventListener('keydown', handleKeyDown, true);
  window.addEventListener('click',   handleClick,   true);
  window.addEventListener('submit',  handleSubmit,  true);

  console.log('[Firewall Content Script] Protection Active — Shadow DOM modal firewall enabled.');
})();
