<<<<<<< HEAD
# Security Firewall Chrome Extension (Manifest V3)

A boilerplate Chrome Extension designed to detect and inspect input fields (standard inputs, textareas, and rich `contenteditable` chat containers) before submitting payloads.

## 📁 Architecture Overview

- **[manifest.json](file:///c:/Users/samir/Desktop/agentEXT/manifest.json)**: Manifest V3 specification with permissions (`storage`, `activeTab`, `<all_urls>`), background service worker, and content scripts.
- **[content.js](file:///c:/Users/samir/Desktop/agentEXT/content.js)**: Runs in the capturing phase on web pages. Automatically detects inputs, textareas, and `contenteditable` elements, intercepts submission attempts (`Enter` key without shift, submit clicks, form submissions), and halts propagation until vetted by the background worker.
- **[background.js](file:///c:/Users/samir/Desktop/agentEXT/background.js)**: Service worker with inspection heuristic rules (e.g., detecting API secrets, private keys, payment card PII, prompt injection patterns) and audit log storage.
- **[popup.html](file:///c:/Users/samir/Desktop/agentEXT/popup.html)** / **[popup.css](file:///c:/Users/samir/Desktop/agentEXT/popup.css)** / **[popup.js](file:///c:/Users/samir/Desktop/agentEXT/popup.js)**: Dashboard popup allowing real-time toggling of firewall protection, viewing inspection status, and browsing recent audit events.

---

## 🚀 How to Install & Test

1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select this directory (`c:\Users\samir\Desktop\agentEXT`).
4. Test on any webpage with text fields or chat boxes (such as ChatGPT, Claude, or any web form):
   - **Safe input**: Pressing `Enter` or clicking submit will proceed normally.
   - **Test Threat / Blocked input**: Try typing a dummy secret like `sk-1234567890abcdef1234567890abcdef` or `-----BEGIN PRIVATE KEY-----` and press `Enter` to see the firewall block the submission and display a security alert.

