/**
 * Content Script: Security Firewall Interceptor
 * Captures submissions from textareas, inputs, and contenteditable elements,
 * sends content to background for inspection, and REPLACES sensitive data
 * with hashed/redacted tokens before allowing submission to proceed.
 */

(() => {
  const approvedActions = new WeakSet();

  const INPUT_SELECTORS = [
    'textarea',
    'input[type="text"]',
    'input[type="search"]',
    '[contenteditable="true"]',
    '[contenteditable=""]',
    '[contenteditable="plaintext-only"]',
    '[role="textbox"]'
  ];

  const SUBMIT_BUTTON_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button[aria-label*="send" i]',
    'button[aria-label*="submit" i]',
    'button[data-testid*="send" i]',
    'button[id*="send" i]',
    'button[class*="send" i]'
  ];

  /**
   * Find the nearest input/chat element relative to a target
   */
  function findNearestInput(element) {
    if (!element) return null;

    // Is the element itself an input?
    for (const sel of INPUT_SELECTORS) {
      if (element.matches?.(sel)) return element;
    }

    // Walk up to find a form or container, then search within
    const form = element.closest('form');
    if (form) {
      const inp = form.querySelector(INPUT_SELECTORS.join(','));
      if (inp) return inp;
    }

    const container = element.closest(
      'div[class*="chat" i], div[class*="prompt" i], div[class*="input" i], div[class*="composer" i], main, section'
    );
    if (container) {
      const inp = container.querySelector(INPUT_SELECTORS.join(','));
      if (inp) return inp;
    }

    return null;
  }

  function isTargetInput(element) {
    if (!element || !(element instanceof Element)) return false;
    return INPUT_SELECTORS.some(sel => element.matches(sel));
  }

  /**
   * Extract text from an input element
   */
  function getTextFromInput(el) {
    if (!el) return '';
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      return el.value || '';
    }
    return el.innerText || el.textContent || '';
  }

  /**
   * Write sanitized text back into the input element
   */
  function setTextOnInput(el, text) {
    if (!el) return;

    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      // Use native setter to trigger React/Angular/Vue change detection
      const nativeSetter = Object.getOwnPropertyDescriptor(
        el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
        'value'
      )?.set;

      if (nativeSetter) {
        nativeSetter.call(el, text);
      } else {
        el.value = text;
      }

      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      // contenteditable
      el.innerText = text;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  /**
   * Intercept 'Enter' key on text fields
   */
  async function handleKeyDown(event) {
    if (event.key !== 'Enter' || event.shiftKey) return;
    if (!isTargetInput(event.target)) return;
    if (approvedActions.has(event)) return;

    const target = event.target;
    const payload = getTextFromInput(target).trim();
    if (!payload) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const result = await inspectWithBackground(payload);

    if (result.needsRedaction) {
      // Replace content in the field with the sanitized version
      setTextOnInput(target, result.sanitizedText);
      showRedactionNotice(result.reason, result.redactionCount);
    }

    // Re-dispatch the Enter key to let it proceed (with original or redacted text)
    const newEvent = new KeyboardEvent('keydown', {
      key: 'Enter',
      code: 'Enter',
      keyCode: 13,
      which: 13,
      bubbles: true,
      cancelable: true,
      composed: true
    });
    approvedActions.add(newEvent);
    target.dispatchEvent(newEvent);
  }

  /**
   * Intercept clicks on send / submit buttons
   */
  async function handleClick(event) {
    const target = event.target.closest('button, input[type="submit"], [role="button"]');
    if (!target) return;

    const isSubmit = SUBMIT_BUTTON_SELECTORS.some(sel => target.matches(sel)) || target.type === 'submit';
    if (!isSubmit) return;
    if (approvedActions.has(event)) return;

    const inputEl = findNearestInput(target);
    const payload = getTextFromInput(inputEl).trim();
    if (!payload) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const result = await inspectWithBackground(payload);

    if (result.needsRedaction) {
      setTextOnInput(inputEl, result.sanitizedText);
      showRedactionNotice(result.reason, result.redactionCount);
    }

    // Re-trigger click
    const newEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
      composed: true
    });
    approvedActions.add(newEvent);
    target.dispatchEvent(newEvent);
  }

  /**
   * Intercept standard form submit events
   */
  async function handleSubmit(event) {
    const form = event.target;
    if (approvedActions.has(form)) return;

    const inputs = form.querySelectorAll(INPUT_SELECTORS.join(','));
    let anyRedacted = false;

    for (const inp of inputs) {
      const payload = getTextFromInput(inp).trim();
      if (!payload) continue;

      const result = await inspectWithBackground(payload);
      if (result.needsRedaction) {
        setTextOnInput(inp, result.sanitizedText);
        anyRedacted = true;
        showRedactionNotice(result.reason, result.redactionCount);
      }
    }

    if (!anyRedacted) {
      // Nothing to redact, let it go through
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    // Re-submit with sanitized content
    approvedActions.add(form);
    form.submit();
  }

  /**
   * Request inspection from background service worker
   */
  function inspectWithBackground(text) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          {
            action: 'INSPECT_PAYLOAD',
            data: { text, origin: window.location.origin }
          },
          (response) => {
            if (chrome.runtime.lastError || !response) {
              console.warn('[Firewall Content] Inspection unavailable:', chrome.runtime.lastError);
              resolve({ needsRedaction: false, sanitizedText: text });
            } else {
              resolve(response);
            }
          }
        );
      } catch (err) {
        console.error('[Firewall Content] Message error:', err);
        resolve({ needsRedaction: false, sanitizedText: text });
      }
    });
  }

  /**
   * Display redaction notification toast
   */
  function showRedactionNotice(reason, count) {
    const existing = document.getElementById('firewall-security-alert');
    if (existing) existing.remove();

    const alertBox = document.createElement('div');
    alertBox.id = 'firewall-security-alert';
    alertBox.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      background: linear-gradient(135deg, #1e1e2e 0%, #181825 100%);
      color: #fab387;
      border: 1px solid #fab387;
      box-shadow: 0 10px 40px rgba(0,0,0,0.6), 0 0 20px rgba(250,179,135,0.15);
      border-radius: 10px;
      padding: 14px 18px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      max-width: 400px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      animation: firewall-slide-in 0.35s cubic-bezier(0.16, 1, 0.3, 1);
    `;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes firewall-slide-in {
        from { opacity: 0; transform: translateY(20px) scale(0.95); }
        to   { opacity: 1; transform: translateY(0) scale(1); }
      }
    `;
    alertBox.appendChild(style);

    const titleRow = document.createElement('div');
    titleRow.style.cssText = 'display:flex;align-items:center;justify-content:space-between;font-weight:700;color:#f9e2af;';
    titleRow.innerHTML = `
      <span>🛡️ Sensitive Data Redacted (${count})</span>
      <button style="background:none;border:none;color:#a6adc8;cursor:pointer;font-size:18px;line-height:1;" id="firewall-close-btn">&times;</button>
    `;

    const body = document.createElement('div');
    body.style.cssText = 'color:#cdd6f4;font-size:12px;line-height:1.5;';
    body.textContent = reason;

    alertBox.appendChild(titleRow);
    alertBox.appendChild(body);
    document.body.appendChild(alertBox);

    document.getElementById('firewall-close-btn')?.addEventListener('click', () => alertBox.remove());
    setTimeout(() => { if (alertBox.parentElement) alertBox.remove(); }, 5000);
  }

  // Register capture-phase listeners
  window.addEventListener('keydown', handleKeyDown, true);
  window.addEventListener('click', handleClick, true);
  window.addEventListener('submit', handleSubmit, true);

  console.log('[Firewall Content Script] Active — monitoring and redacting sensitive inputs.');
})();
