# 🛡️ Agent Firewall: Security Layer for Tool-Using Agents

> **Track 05 • Problem 21 Deliverables & Technical Architecture**  
> Complete implementation of a multi-layer Agent Firewall, Least-Privilege Policy Engine, Sandboxed Tool Execution, and Cryptographically Tamper-Evident Audit Ledger.

---

## 📌 Executive Summary

Autonomous AI agents that browse the web, process emails, and invoke tool functions are vulnerable to **indirect prompt injection**, **privilege escalation**, and **covert data exfiltration**. Attackers embed adversarial commands into web pages or email bodies that hijack the agent's LLM context window, causing the agent to exfiltrate private credentials or execute destructive tool commands.

This project delivers an enterprise-grade, defense-in-depth security layer that wraps around autonomous tool-using agents:
1. **Multi-Phase Firewall**: Deep inspection of inputs, tool calls, and outputs.
2. **Policy Engine**: Role-based access control enforcing **Least Privilege by Default (Default Deny)**.
3. **Tool Execution Sandbox**: File chrooting, SSRF prevention, AST syntax validation, and resource timeouts.
4. **Tamper-Evident Audit Ledger**: SHA-256 blockchain-style hash-chained records with HMAC signatures for cryptographic non-repudiation.
5. **Red-Team Suite & ASR Measurement**: Full measurement of Attack Success Rate (ASR) before and after protection.
6. **False-Positive Analysis**: Rigorous testing across benign tasks demonstrating 0.0% False Positive Rate.
7. **Deployable Proxy & Library**: Drop-in Python package (`agent_firewall`) and FastAPI REST / OpenAI proxy gateway.

---

## 🏛️ Architecture & Defense Lifecycle

```
[User Input / Retrieved Web / Incoming Email]
                        │
                        ▼
┌──────────────────────────────────────────────┐
│  Phase 1: Input Firewall Inspection          │
│  • Direct Prompt Injection (DPI-001..004)    │ ──► [Block / Quarantine]
│  • Indirect Prompt Injection (IPI-001..003)  │
│  • Zero-Width Smuggling (PI-006)             │
└──────────────────────────────────────────────┘
                        │ (Allowed)
                        ▼
┌──────────────────────────────────────────────┐
│  Phase 2: Least-Privilege Policy Engine      │
│  • Default Deny (Tool Authorization)         │ ──► [Block Unauthorized Tools]
│  • Domain Allowlist (SSRF Prevention)        │ ──► [Block Path Traversal]
│  • Path Containment (Sandbox Boundary)       │ ──► [Trigger HITL Approval]
│  • Read-Only DB Constraints (SELECT only)    │
└──────────────────────────────────────────────┘
                        │ (Authorized)
                        ▼
┌──────────────────────────────────────────────┐
│  Phase 3: Sandboxed Tool Execution           │
│  • Isolated Virtual Filesystem               │ ──► [Safely Execute Function]
│  • AST Code Verification (Blocked Imports)   │
│  • Strict Resource Timeouts                  │
└──────────────────────────────────────────────┘
                        │ (Output Generated)
                        ▼
┌──────────────────────────────────────────────┐
│  Phase 4: Output Exfiltration Firewall       │
│  • API Key Scanner (OpenAI, AWS, GitHub)     │ ──► [Redact In-Place / Block]
│  • Cryptographic Key Redaction (PEM / RSA)   │
│  • Database URI Credential Masking           │
└──────────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────┐
│  Phase 5: Tamper-Evident Audit Ledger        │
│  • Block_n = SHA256(Block_{n-1} + EventData) │ ──► [Cryptographic Integrity]
│  • HMAC Non-Repudiation Signatures           │
└──────────────────────────────────────────────┘
```

---

## 📦 Deliverables & File Structure

| Deliverable | File / Directory | Purpose |
|---|---|---|
| **Deployable Library** | [`agent_firewall/`](file:///c:/Users/jeet%20raj/Extention/agent_firewall) | Python package providing `AgentFirewall`, `PolicyEngine`, `ToolSandbox`, and `TamperEvidentAuditLogger`. |
| **Deployable Proxy** | [`agent_firewall/proxy.py`](file:///c:/Users/jeet%20raj/Extention/agent_firewall/proxy.py) | FastAPI service exposing REST inspection endpoints, safe execution, and audit verification. |
| **Attack Taxonomy** | [`attack_taxonomy.json`](file:///c:/Users/jeet%20raj/Extention/attack_taxonomy.json) & [`ATTACK_TAXONOMY.md`](file:///c:/Users/jeet%20raj/Extention/ATTACK_TAXONOMY.md) | Formal taxonomy of 24+ attack vectors across DPI, IPI, THPT, DEX, PESC, and DOS. |
| **Least-Privilege Policies** | [`policies/`](file:///c:/Users/jeet%20raj/Extention/policies) | YAML policy configurations (`default_policy.yaml`, `web_researcher.yaml`, `email_assistant.yaml`, `data_analyst.yaml`). |
| **Red Team Benchmark** | [`agent_red_team_benchmark.py`](file:///c:/Users/jeet%20raj/Extention/agent_red_team_benchmark.py) | Evaluates attack scenarios and measures ASR before and after protection. |
| **False Positive Benchmark** | [`false_positive_benchmark.py`](file:///c:/Users/jeet%20raj/Extention/false_positive_benchmark.py) | Evaluates benign developer and user tasks to measure false positive rate (FPR). |
| **End-to-End Demo** | [`demo_agent.py`](file:///c:/Users/jeet%20raj/Extention/demo_agent.py) | Runnable demonstration showing indirect injection defense, policy blocking, and log tamper detection. |
| **Benchmark Reports** | [`agent_benchmark_report.json`](file:///c:/Users/jeet%20raj/Extention/agent_benchmark_report.json) & [`false_positive_report.json`](file:///c:/Users/jeet%20raj/Extention/false_positive_report.json) | Structured JSON benchmark results. |
| **Browser Extension** | `manifest.json`, `background.js`, `content.js`, `popup.*` | Standalone Chrome extension providing client-side form and chat injection protection (existing code preserved). |

---

## 📊 Benchmark Results

### 1. Attack Success Rate (ASR) Before & After Protection
*Evaluated using [`agent_red_team_benchmark.py`](file:///c:/Users/jeet%20raj/Extention/agent_red_team_benchmark.py) across 25 attack vectors:*

| Metric | Unprotected Agent | Protected by Agent Firewall |
|---|---|---|
| **Attack Success Rate (ASR)** | **100.0%** (25/25 succeeded) | **0.0%** (0/25 succeeded) |
| **Firewall Mitigation Effectiveness** | 0.0% | **100.0%** |
| **Cryptographic Audit Ledger** | N/A | **VERIFIED (Valid SHA-256 Hash Chain)** |
| **Events Logged & Verified** | 0 | 25 events |

### 2. False-Positive Analysis on Benign Tasks
*Evaluated using [`false_positive_benchmark.py`](file:///c:/Users/jeet%20raj/Extention/false_positive_benchmark.py) across 20 realistic benign operations:*

| Metric | Result | Target Benchmark |
|---|---|---|
| **Total Benign Tasks Evaluated** | 20 | 20 |
| **Correctly Allowed (True Negatives)** | 20 / 20 | 100% |
| **Incorrectly Blocked (False Positives)**| **0** | **0** |
| **False Positive Rate (FPR)** | **0.0%** | < 2.0% |
| **System Specificity** | **100.0%** | > 98.0% |

---

## 🚀 Quickstart & Usage Guide

### 1. Running the Automated Benchmarks
```bash
# Run Red-Team Benchmark (Measures ASR before vs after protection)
python agent_red_team_benchmark.py

# Run False-Positive Analysis (Verifies 0% FPR on benign tasks)
python false_positive_benchmark.py

# Run End-to-End Agent Demo
python demo_agent.py
```

### 2. Using the Library in Your Agent Code
```python
from agent_firewall import AgentFirewall

# 1. Initialize firewall
firewall = AgentFirewall()

# 2. Assign agent role (Least Privilege)
firewall.policy_engine.assign_role("agent_1", "web_researcher")

# 3. Inspect untrusted input or web page
verdict = firewall.inspect_input(content=retrieved_web_text, source="web", agent_id="agent_1")
if not verdict.is_allowed:
    print(f"Blocked indirect injection: {verdict.reason}")

# 4. Safely execute a tool (Firewall + Policy + Sandbox + Redaction + Audit)
result = firewall.safe_execute_tool(
    agent_id="agent_1",
    tool_name="web_fetch",
    tool_args={"url": "https://en.wikipedia.org/wiki/Artificial_intelligence"}
)
print(result["output"])

# 5. Cryptographically verify audit log integrity
is_valid, msg, _ = firewall.audit_logger.verify_integrity()
print(f"Audit status: {msg}")
```

### 3. Deploying the Security Proxy Server
```bash
python -m uvicorn agent_firewall.proxy:app --host 0.0.0.0 --port 8080 --reload
```
Available API Endpoints:
- `POST /v1/inspect/input`: Inspect prompt or external web/email content.
- `POST /v1/inspect/tool-call`: Check tool call against policy rules.
- `POST /v1/execute/tool`: Safe end-to-end sandbox execution.
- `POST /v1/inspect/output`: Redact sensitive secrets in outputs.
- `GET /v1/audit/verify`: Cryptographically verify audit log chain.
- `GET /stats`: Real-time scan and mitigation stats.
