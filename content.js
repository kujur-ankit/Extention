/**
 * Content Script: Security Firewall Interceptor
 * Intercepts submissions across standard inputs, textareas, and rich contenteditable
 * containers (such as ChatGPT ProseMirror, Claude Lexical, and web forms).
 * Redacts/hashes sensitive data in-place and securely triggers submission with sanitized content.
 */

(() => {
  const approvedEvents = new WeakSet();
  let isProcessing = false;

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

  /**
   * Find the active or target input element
   */
  function findTargetInput(fromElement) {
    if (!fromElement) {
      fromElement = document.activeElement;
    }

    // Check if the element itself matches
    for (const sel of INPUT_SELECTORS) {
      if (fromElement?.matches?.(sel)) return fromElement;
    }

    // Check inside nearest form or container
    const container = fromElement?.closest?.(
      'form, div[class*="chat" i], div[class*="prompt" i], div[class*="input" i], div[class*="composer" i], main, section, [role="main"]'
    ) || document;

    const inp = container.querySelector?.(INPUT_SELECTORS.join(','));
    if (inp) return inp;

    // Fallback to activeElement if editable
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

  /**
   * Extract raw text from any input or rich editor
   */
  function getText(el) {
    if (!el) return '';
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      return el.value || '';
    }
    // For rich editors (ProseMirror, Lexical, contenteditable)
    return el.innerText || el.textContent || '';
  }

  /**
   * Universal text replacer that works with ProseMirror (ChatGPT), Lexical (Claude),
   * React controlled inputs, and standard HTML elements.
   */
  function setSanitizedText(el, newText) {
    if (!el) return;

    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      // Use prototype setter to trigger React/framework change detection
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) {
        setter.call(el, newText);
      } else {
        el.value = newText;
      }
      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertReplacementText' }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      // Rich text / ProseMirror / contenteditable
      el.focus();

      try {
        // Use Selection + execCommand('insertText') so ProseMirror synchronously updates its state model
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        sel.removeAllRanges();
        sel.addRange(range);

        const success = document.execCommand('insertText', false, newText);
        if (!success) {
          el.innerText = newText;
        }
      } catch {
        el.innerText = newText;
      }

      // Dispatch input events
      el.dispatchEvent(new InputEvent('input', {
        bubbles: true,
        cancelable: true,
        inputType: 'insertReplacementText',
        data: newText
      }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  /**
   * Locate the nearest send / submit button
   */
  function findSendButton(relativeEl) {
    const root = relativeEl?.closest?.('form, div[class*="chat" i], div[class*="prompt" i], div[class*="composer" i], main, body') || document.body;
    for (const sel of SEND_BUTTON_SELECTORS) {
      const btn = root.querySelector(sel);
      if (btn && btn.offsetParent !== null) return btn;
    }
    return null;
  }

  /**
   * Request inspection from background service worker
   */
  function inspectPayload(text) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          {
            action: 'INSPECT_PAYLOAD',
            data: { text, origin: window.location.origin }
          },
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

  /**
   * Handle Enter key press
   */
  async function handleKeyDown(event) {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
    if (approvedEvents.has(event)) return;
    if (isProcessing) return;

    const inputEl = findTargetInput(event.target);
    if (!inputEl) return;

    const rawText = getText(inputEl).trim();
    if (!rawText) return;

    // Prevent original Enter submission while inspecting
    event.preventDefault();
    event.stopImmediatePropagation();
    isProcessing = true;

    try {
      const result = await inspectPayload(rawText);

      if (result.needsRedaction) {
        // Replace text in-place with hashed / sanitized values
        setSanitizedText(inputEl, result.sanitizedText);
        showRedactionNotice(result.reason, result.redactionCount);

        // Allow UI frameworks (React, ProseMirror) to reconcile state
        await new Promise((r) => setTimeout(r, 60));
      }

      // Trigger submission with sanitized text
      const sendBtn = findSendButton(inputEl);
      if (sendBtn && !sendBtn.disabled) {
        approvedEvents.add(sendBtn);
        sendBtn.click();
      } else {
        // Re-dispatch synthetic Enter event
        const enterEvent = new KeyboardEvent('keydown', {
          key: 'Enter',
          code: 'Enter',
          keyCode: 13,
          which: 13,
          bubbles: true,
          cancelable: true,
          composed: true
        });
        approvedEvents.add(enterEvent);
        inputEl.dispatchEvent(enterEvent);
      }
    } finally {
      isProcessing = false;
    }
  }

  /**
   * Handle Send Button click
   */
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

      if (result.needsRedaction) {
        setSanitizedText(inputEl, result.sanitizedText);
        showRedactionNotice(result.reason, result.redactionCount);
        await new Promise((r) => setTimeout(r, 60));
      }

      approvedEvents.add(btn);
      btn.click();
    } finally {
      isProcessing = false;
    }
  }

  /**
   * Handle standard Form Submit
   */
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
      if (result.needsRedaction) {
        setSanitizedText(inp, result.sanitizedText);
        anyRedacted = true;
        showRedactionNotice(result.reason, result.redactionCount);
      }
    }

    if (anyRedacted) {
      event.preventDefault();
      event.stopImmediatePropagation();
      approvedEvents.add(form);
      setTimeout(() => {
        if (typeof form.requestSubmit === 'function') {
          form.requestSubmit();
        } else {
          form.submit();
        }
      }, 50);
    }
  }

  /**
   * Display floating redaction notification toast
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
      max-width: 420px;
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
      <span>🛡️ Sensitive Data Sanitized (${count})</span>
      <button style="background:none;border:none;color:#a6adc8;cursor:pointer;font-size:18px;line-height:1;" id="firewall-close-btn">&times;</button>
    `;

    const body = document.createElement('div');
    body.style.cssText = 'color:#cdd6f4;font-size:12px;line-height:1.5;';
    body.textContent = reason;

    alertBox.appendChild(titleRow);
    alertBox.appendChild(body);
    document.body.appendChild(alertBox);

    document.getElementById('firewall-close-btn')?.addEventListener('click', () => alertBox.remove());
    setTimeout(() => { if (alertBox.parentElement) alertBox.remove(); }, 6000);
  }

  // Register capture-phase listeners on window
  window.addEventListener('keydown', handleKeyDown, true);
  window.addEventListener('click', handleClick, true);
  window.addEventListener('submit', handleSubmit, true);

  console.log('[Firewall Content Script] Protection Active — intercepting and sanitizing prompts before sending.');
})();
