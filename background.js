/**
 * Background Service Worker: Security Firewall Inspection Engine
 * Inspects intercepted text payloads sent by content scripts.
 * Redacts/hashes sensitive content in-place before allowing submission.
 */

// Initialize default firewall settings on installation
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(['firewallEnabled', 'inspectionLogs', 'redactedCount']);
  if (existing.firewallEnabled === undefined) {
    await chrome.storage.local.set({
      firewallEnabled: true,
      redactedCount: 0,
      inspectionLogs: []
    });
    console.log('[Firewall Background] Initialized default configuration.');
  }
});

// ── PII / Sensitive Data Patterns ──────────────────────────────────────────
// Each pattern uses the global flag so we can find ALL matches and replace them.
const SECURITY_PATTERNS = [
  {
    id: 'phone_number',
    name: 'Phone Number',
    severity: 'High',
    // Matches 10-digit Indian numbers, international +XX formats, US formats, etc.
    regex: /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b/g,
    hash: (match) => hashValue(match, 'PHONE')
  },
  {
    id: 'email_address',
    name: 'Email Address',
    severity: 'High',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    hash: (match) => hashValue(match, 'EMAIL')
  },
  {
    id: 'aadhaar_number',
    name: 'Aadhaar Number (India)',
    severity: 'Critical',
    regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
    hash: (match) => hashValue(match, 'AADHAAR')
  },
  {
    id: 'ssn',
    name: 'Social Security Number (US)',
    severity: 'Critical',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    hash: (match) => hashValue(match, 'SSN')
  },
  {
    id: 'credit_card',
    name: 'Payment Card Number',
    severity: 'High',
    regex: /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
    hash: (match) => hashValue(match, 'CARD')
  },
  {
    id: 'api_key_secret',
    name: 'Exposed Secret / API Key',
    severity: 'High',
    regex: /(?:sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z-_]{35}|xox[baprs]-[0-9a-zA-Z]{10,48})/gi,
    hash: (match) => hashValue(match, 'SECRET')
  },
  {
    id: 'private_key',
    name: 'Private Key Header',
    severity: 'Critical',
    regex: /-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PRIVATE)\s+KEY-----[\s\S]*?-----END\s+\w+\s+KEY-----/gi,
    hash: (match) => '[REDACTED:PRIVATE_KEY]'
  },
  {
    id: 'ip_address',
    name: 'IP Address',
    severity: 'Medium',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    hash: (match) => hashValue(match, 'IP')
  }
];

/**
 * Simple deterministic hash for display (SHA-256 truncated).
 * Uses a fast sync djb2 hash since crypto.subtle is async.
 */
function hashValue(value, label) {
  const stripped = value.replace(/[\s\-().+]/g, '');
  let hash = 5381;
  for (let i = 0; i < stripped.length; i++) {
    hash = ((hash << 5) + hash + stripped.charCodeAt(i)) >>> 0;
  }
  const hex = hash.toString(16).padStart(8, '0');
  return `[${label}:###${hex}]`;
}

/**
 * Inspect and sanitize text content against firewall policy rules.
 * Returns the redacted text plus metadata about what was found.
 */
function inspectAndRedact(text) {
  if (!text || typeof text !== 'string') {
    return { sanitizedText: text, detectedThreats: [], redactionCount: 0 };
  }

  const detectedThreats = [];
  let sanitized = text;
  let redactionCount = 0;

  for (const pattern of SECURITY_PATTERNS) {
    // Reset regex lastIndex since they're global
    pattern.regex.lastIndex = 0;

    const matches = sanitized.match(pattern.regex);
    if (matches && matches.length > 0) {
      detectedThreats.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        matchCount: matches.length
      });

      // Replace each match with its hashed placeholder
      sanitized = sanitized.replace(pattern.regex, (match) => {
        redactionCount++;
        return pattern.hash(match);
      });
    }
  }

  const needsRedaction = redactionCount > 0;

  return {
    sanitizedText: sanitized,
    originalText: text,
    needsRedaction,
    redactionCount,
    detectedThreats,
    reason: needsRedaction
      ? `Redacted ${redactionCount} sensitive item(s): ${detectedThreats.map(t => t.name).join(', ')}`
      : 'Clean — no sensitive data detected.'
  };
}

/**
 * Log inspection event to storage
 */
async function logInspectionEvent(eventData) {
  try {
    const { inspectionLogs = [], redactedCount = 0 } = await chrome.storage.local.get(['inspectionLogs', 'redactedCount']);
    const newLog = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      ...eventData
    };

    const updatedLogs = [newLog, ...inspectionLogs].slice(0, 50);
    const updatedCount = eventData.verdict === 'REDACTED' ? redactedCount + 1 : redactedCount;

    await chrome.storage.local.set({
      inspectionLogs: updatedLogs,
      redactedCount: updatedCount
    });
  } catch (err) {
    console.error('[Firewall Background] Error logging inspection:', err);
  }
}

// Handle incoming messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'INSPECT_PAYLOAD') {
    handlePayloadInspection(message.data, sender).then(sendResponse);
    return true;
  }

  if (message.action === 'GET_STATUS') {
    chrome.storage.local.get(['firewallEnabled', 'redactedCount', 'inspectionLogs']).then(sendResponse);
    return true;
  }

  if (message.action === 'TOGGLE_FIREWALL') {
    chrome.storage.local.get(['firewallEnabled']).then(async ({ firewallEnabled }) => {
      const newState = !firewallEnabled;
      await chrome.storage.local.set({ firewallEnabled: newState });
      sendResponse({ firewallEnabled: newState });
    });
    return true;
  }
});

async function handlePayloadInspection(data, sender) {
  const { firewallEnabled = true } = await chrome.storage.local.get(['firewallEnabled']);

  if (!firewallEnabled) {
    return { needsRedaction: false, sanitizedText: data?.text || '', reason: 'Firewall is currently bypassed.' };
  }

  const text = data?.text || '';
  const origin = data?.origin || sender?.url || 'Unknown Origin';
  const result = inspectAndRedact(text);

  logInspectionEvent({
    origin,
    verdict: result.needsRedaction ? 'REDACTED' : 'CLEAN',
    threats: result.detectedThreats,
    redactions: result.redactionCount,
    snippet: text.length > 60 ? text.substring(0, 60) + '...' : text
  });

  console.log(`[Firewall Background] ${origin}: ${result.needsRedaction ? 'REDACTED ' + result.redactionCount + ' items' : 'CLEAN'}`);

  return result;
}
