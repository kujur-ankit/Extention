/**
 * Background Service Worker: Security Firewall Inspection Engine
 * Inspects intercepted text payloads sent by content scripts.
 * Redacts/hashes sensitive content in-place before allowing submission.
 *
 * Multi-tier prompt firewall is handled by firewall-engine.js:
 *   Tier 1 — Prompt Injection Check
 *   Tier 2 — Data Exfiltration Check
 *   Tier 3 — Privilege Escalation / Tool Abuse Check
 */
import { evaluatePrompt } from './firewall-engine.js';

// Initialize default firewall settings on installation
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(['firewallEnabled', 'inspectionLogs', 'scannedCount', 'redactedCount', 'blockedCount']);
  if (existing.firewallEnabled === undefined) {
    await chrome.storage.local.set({
      firewallEnabled: true,
      scannedCount: 0,
      redactedCount: 0,
      blockedCount: 0,
      inspectionLogs: []
    });
    console.log('[Firewall Background] Initialized default configuration.');
  }
});

// ── PII / Sensitive Data & Threat Patterns ──────────────────────────────────
// ORDER MATTERS: longer / more specific patterns first to avoid partial matches.
const SECURITY_PATTERNS = [

  // ── 1. CRYPTOGRAPHIC KEYS ────────────────────────────────────────────────
  {
    id: 'private_key',
    name: 'Private Key Block',
    severity: 'Critical',
    regex: /-----BEGIN\s+[A-Z0-9\s_-]+KEY-----[\s\S]*?-----END\s+[A-Z0-9\s_-]+KEY-----/gi,
    hash: () => '[REDACTED:PRIVATE_KEY]'
  },

  // ── 2. API KEYS & TOKENS ────────────────────────────────────────────────
  {
    id: 'api_key_secret',
    name: 'API Key / Secret Token',
    severity: 'High',
    // OpenAI (sk-..., sk-proj-..., sk-ant-...), GitHub (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_),
    // Google (AIza...), AWS (AKIA/ASIA), Slack (xox...), HuggingFace (hf_), Stripe (sk_live_, pk_live_),
    // Twilio, SendGrid (SG.), Firebase, Vercel, JWTs, and generic key=value pairs
    regex: /(?:\b(?:sk-(?:proj-|svcacct-|ant-)?[a-zA-Z0-9_\-]{10,})\b|\b(?:gh[pousr]_[a-zA-Z0-9]{16,}|github_pat_[a-zA-Z0-9_]{20,})\b|\bAIza[0-9A-Za-z\-_]{30,}\b|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b|\bhf_[a-zA-Z0-9]{20,}\b|\b(?:sk_live_|pk_live_|rk_live_)[a-zA-Z0-9]{20,}\b|\bSG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\b|\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b|(?:\b(?:api[_\-\s]?key|secret[_\-\s]?key|access[_\-\s]?key|access[_\-\s]?token|auth[_\-\s]?token|bearer|token|password|passwd|secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.]{10,})['"]?\b))/gi,
    hash: (match) => hashValue(match, 'SECRET')
  },

  // ── 3. CREDIT / DEBIT CARD NUMBERS ──────────────────────────────────────
  {
    id: 'credit_card',
    name: 'Payment Card Number',
    severity: 'High',
    // 16 digits grouped by 4 with optional spaces/dashes, or a plain 16-digit run
    regex: /\b(?:\d{4}[ \-]){3}\d{4}\b|\b\d{16}\b/g,
    hash: (match) => hashValue(match, 'CARD')
  },

  // ── 4. NATIONAL ID: AADHAAR (India) ─────────────────────────────────────
  {
    id: 'aadhaar_number',
    name: 'Aadhaar Number (India)',
    severity: 'Critical',
    // 12 digits with optional space/dash separators: "1234 5678 9012" or "1234-5678-9012" or "123456789012"
    regex: /\b\d{4}[ \-]?\d{4}[ \-]?\d{4}\b/g,
    hash: (match) => hashValue(match, 'AADHAAR')
  },

  // ── 5. PAN CARD (India) ─────────────────────────────────────────────────
  {
    id: 'pan_card',
    name: 'PAN Card (India)',
    severity: 'High',
    // Format: ABCDE1234F (5 letters, 4 digits, 1 letter)
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
    hash: (match) => hashValue(match, 'PAN')
  },

  // ── 6. SSN (US) ─────────────────────────────────────────────────────────
  {
    id: 'ssn',
    name: 'Social Security Number (US)',
    severity: 'Critical',
    // Formats: "123-45-6789", "123 45 6789", "123456789"
    regex: /\b\d{3}[ \-]?\d{2}[ \-]?\d{4}\b/g,
    hash: (match) => hashValue(match, 'SSN')
  },

  // ── 7. PASSPORT NUMBER ──────────────────────────────────────────────────
  {
    id: 'passport',
    name: 'Passport Number',
    severity: 'High',
    // Indian passports (e.g., A1234567, J1234567) and general alpha-numeric 6-9 char passports
    regex: /\b[A-Z][0-9]{7}\b/g,
    hash: (match) => hashValue(match, 'PASSPORT')
  },

  // ── 8. EMAIL ADDRESS ────────────────────────────────────────────────────
  {
    id: 'email_address',
    name: 'Email Address',
    severity: 'High',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    hash: (match) => hashValue(match, 'EMAIL')
  },

  // ── 9. PHONE NUMBERS (broadly international) ────────────────────────────
  {
    id: 'phone_number',
    name: 'Phone Number',
    severity: 'High',
    // Catches:
    //   +91 98765 43210   |  +91-9876543210  |  +919876543210  |  9876543210
    //   +1 (555) 123-4567 |  555-123-4567    |  (555) 123 4567
    //   +44 7911 123456   |  +61 4XX XXX XXX |  and many more
    regex: /(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{1,4}\)[\s.\-]?)?\d{2,5}[\s.\-]?\d{2,5}[\s.\-]?\d{2,5}\b/g,
    hash: (match) => hashValue(match, 'PHONE')
  },

  // ── 10. IBAN (International Bank Account Number) ─────────────────────────
  {
    id: 'iban',
    name: 'IBAN Number',
    severity: 'High',
    // Starts with 2 country letters + 2 check digits, then up to 30 alphanumeric characters
    regex: /\b[A-Z]{2}\d{2}[ ]?[\dA-Z]{4}[ ]?[\dA-Z]{4}[ ]?[\dA-Z]{4}(?:[ ]?[\dA-Z]{4}){0,5}\b/g,
    hash: (match) => hashValue(match, 'IBAN')
  },

  // ── 11. IP ADDRESS ──────────────────────────────────────────────────────
  {
    id: 'ip_address',
    name: 'IP Address',
    severity: 'Medium',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    hash: (match) => hashValue(match, 'IP')
  },

  // ── 12. DATABASE / CONNECTION STRINGS ────────────────────────────────────
  {
    id: 'connection_string',
    name: 'Database Connection String',
    severity: 'Critical',
    // mongodb://, postgres://, mysql://, redis:// with embedded credentials
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|ftp)s?:\/\/[^\s"'`]+/gi,
    hash: () => '[REDACTED:CONNECTION_STRING]'
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
    const { inspectionLogs = [], scannedCount = 0, redactedCount = 0, blockedCount = 0 } = await chrome.storage.local.get(['inspectionLogs', 'scannedCount', 'redactedCount', 'blockedCount']);
    const newLog = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      ...eventData
    };

    const updatedLogs = [newLog, ...inspectionLogs].slice(0, 50);
    const updatedScannedCount  = scannedCount + 1;
    const updatedRedactedCount = eventData.verdict === 'REDACTED' ? redactedCount + 1 : redactedCount;
    const updatedBlockedCount  = eventData.verdict === 'BLOCKED'  ? blockedCount + 1  : blockedCount;

    await chrome.storage.local.set({
      inspectionLogs: updatedLogs,
      scannedCount: updatedScannedCount,
      redactedCount: updatedRedactedCount,
      blockedCount: updatedBlockedCount
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
    chrome.storage.local.get(['firewallEnabled', 'scannedCount', 'redactedCount', 'blockedCount', 'inspectionLogs']).then(sendResponse);
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

  const text   = data?.text || '';
  const origin = data?.origin || sender?.url || 'Unknown Origin';

  // ── Multi-tier firewall check (Tier 1–3) ─────────────────────────────────
  const firewallResult = evaluatePrompt(text, { earlyExit: true, verbose: true });

  if (firewallResult.status === 'BLOCKED') {
    console.warn(`[Firewall Engine] BLOCKED (${firewallResult.matchedRule}) — ${origin}`);

    logInspectionEvent({
      origin,
      verdict:    'BLOCKED',
      threats:    firewallResult.matches ?? [],
      redactions: 0,
      snippet:    text.length > 60 ? text.substring(0, 60) + '...' : text,
      firewallResult
    });

    return {
      needsRedaction: false,
      sanitizedText:  text,
      blocked:        true,
      status:         firewallResult.status,
      threatLevel:    firewallResult.threatLevel,
      reason:         firewallResult.reason,
      matchedRule:    firewallResult.matchedRule
    };
  }

  // ── PII redaction pass (existing logic) ──────────────────────────────────
  const result = inspectAndRedact(text);

  logInspectionEvent({
    origin,
    verdict:       result.needsRedaction ? 'REDACTED' : 'CLEAN',
    threats:       result.detectedThreats,
    redactions:    result.redactionCount,
    snippet:       text.length > 60 ? text.substring(0, 60) + '...' : text,
    firewallResult
  });

  console.log(`[Firewall Background] ${origin}: ${result.needsRedaction ? 'REDACTED ' + result.redactionCount + ' items' : 'CLEAN'}`);

  return {
    ...result,
    firewallStatus:     firewallResult.status,
    firewallThreatLevel: firewallResult.threatLevel
  };
}
