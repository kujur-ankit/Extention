# 🛡️ Track 05: Agent Firewall Attack Taxonomy

Comprehensive Security Taxonomy for Autonomous & Tool-Using AI Agents.

---

## 📑 Executive Summary

Autonomous AI agents that execute tools, browse external web pages, read emails, and query databases are uniquely vulnerable to **instruction hijacking** and **confused deputy attacks**. Because agents interleave untrusted external data directly into their LLM reasoning context, attackers can inject commands that cause the agent to exfiltrate private credentials or execute destructive tool actions.

This taxonomy categorizes attacks into **6 Core Categories** across the agent lifecycle:
1. **Direct Prompt Injection (DPI)** — Adversarial user prompts.
2. **Indirect Prompt Injection (IPI)** — Hidden instructions inside browsed pages, emails, and RAG documents.
3. **Tool Hijacking & Parameter Tampering (THPT)** — Manipulating tool function arguments (command injection, path traversal, SQL injection, SSRF).
4. **Data Exfiltration (DEX)** — Leaking secrets, keys, and PII via tool parameters or model outputs.
5. **Privilege Escalation (PESC)** — Violating least-privilege role boundaries and sandbox escapes.
6. **Denial of Service & Resource Abuse (DOS)** — Recursive tool loops, payload exhaustion, and ReDoS.

---

## 🎯 Attack Vectors & Threat Matrix

| Vector ID | Category | Attack Vector | Target | Severity | Primary Defense Mechanism |
|---|---|---|---|---|---|
| **DPI-001** | Direct Injection | Direct Instruction Override | Input | Critical | Pattern regex heuristic, boundary tokens |
| **DPI-002** | Direct Injection | Jailbreak / DAN Mode | Input | High | Persona hijack detector, safety guardrails |
| **DPI-003** | Direct Injection | Invisible Character Smuggling | Input | High | NFKC Unicode normalization, zero-width strip |
| **DPI-004** | Direct Injection | System Delimiter Injection | Input | Medium | Token sanitizer (`<\|im_start\|>`, `[INST]`) |
| **IPI-001** | Indirect Injection | Web Page Instruction Hijack | Retrieved Web | Critical | Content quarantine, untrusted source tagging |
| **IPI-002** | Indirect Injection | Inbound Email Body Poisoning | Email | Critical | Least-privilege separation, content isolation |
| **IPI-003** | Indirect Injection | RAG Document Poisoning | Knowledge Base | High | Structural chunk validation |
| **THPT-001**| Tool Hijacking | Shell Command Injection | Tool Call | Critical | AST syntax validation, command banning |
| **THPT-002**| Tool Hijacking | Piped Dropper (`curl \| bash`) | Tool Call | Critical | Process isolation, pipe operator ban |
| **THPT-003**| Tool Hijacking | Directory Traversal (`../../`) | Tool Call | Critical | Strict filesystem chroot boundary check |
| **THPT-004**| Tool Hijacking | Destructive SQL Injection | Tool Call | High | Read-only connection, SELECT-only policy |
| **THPT-005**| Tool Hijacking | SSRF (Cloud Metadata Access) | Tool Call | High | Domain allowlists, private IP address blocking |
| **DEX-001** | Exfiltration | API Key / Token Exfiltration | Output / Tool | Critical | Secret pattern scanner, token redaction |
| **DEX-002** | Exfiltration | PEM Cryptographic Key Leakage| Output | Critical | Output firewall redaction, hash masking |
| **DEX-003** | Exfiltration | Database URI Leakage | Output | High | URI credential masking |
| **DEX-004** | Exfiltration | System Prompt Harvesting | Input / Output | Medium | Confidential prompt leak filter |
| **PESC-001**| Privilege Escalation| Unauthorized Tool Invocation | Tool Call | Critical | Least-privilege Default Deny Policy Engine |
| **PESC-002**| Privilege Escalation| Sandbox Filesystem Escape | Tool Call | Critical | Virtual sandbox root confinement |
| **PESC-003**| Privilege Escalation| Bypassing Human-in-the-Loop | Tool Call | High | Mandatory approval gate in Policy Engine |
| **DOS-001** | Resource Abuse | Recursive Tool Call Loop | Tool Call | Medium | Per-turn tool quota, call limiters |
| **DOS-002** | Resource Abuse | Mega-Payload Buffer Overflow | Input / Tool | Medium | Max payload size limits (e.g. 64KB) |

---

## 🔒 Defense-in-Depth Lifecycle

```
[Untrusted Input / Web / Email]
           │
           ▼
┌──────────────────────────────────────┐
│  Phase 1: Input Firewall Inspection  │ ──► [Block Direct & Indirect Injections]
└──────────────────────────────────────┘
           │ (Allowed)
           ▼
┌──────────────────────────────────────┐
│  Phase 2: Policy Engine              │ ──► [Enforce Least Privilege by Default]
│  (Role, Allowlist, Parameter Check)  │     [Block Unauthorized Tools & Escapes]
└──────────────────────────────────────┘
           │ (Allowed)
           ▼
┌──────────────────────────────────────┐
│  Phase 3: Sandboxed Tool Execution   │ ──► [Isolated Virtual Filesystem & SSRF-safe]
└──────────────────────────────────────┘
           │ (Executed)
           ▼
┌──────────────────────────────────────┐
│  Phase 4: Output Firewall & Redact   │ ──► [Redact API Keys, Private Keys, PII]
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  Phase 5: Tamper-Evident Audit Log   │ ──► [Cryptographic SHA-256 Hash Chain]
└──────────────────────────────────────┘
```
