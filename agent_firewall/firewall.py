"""
firewall.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive Multi-Layer Firewall for Tool-Using AI Agents.
Inspects inputs, tool calls, and outputs for:
  • Prompt injection (Direct and Indirect across web/email/docs)
  • Data exfiltration (Secrets, API keys, PII, canary tokens)
  • Privilege escalation (Sandbox escape, unauthorized tools, command injection)
─────────────────────────────────────────────────────────────────────────────
"""

import re
import unicodedata
import base64
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

from .policy_engine import PolicyEngine, PolicyDecision
from .sandbox import ToolSandbox, SandboxResult
from .audit_logger import TamperEvidentAuditLogger, AuditRecord


@dataclass
class FirewallVerdict:
    """Standardized decision returned for inputs, tool calls, and outputs."""
    status: str                         # "ALLOWED", "BLOCKED", "REDACTED", "QUARANTINED"
    threat_level: int                   # 0 (clean) to 5 (critical)
    reason: str
    rule_id: Optional[str] = None
    sanitized_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_allowed(self) -> bool:
        return self.status in ("ALLOWED", "REDACTED")


class AgentFirewall:
    """
    Main Agent Firewall coordinating Input, Tool Call, Output Inspection,
    Policy Engine, Sandbox Execution, and Tamper-Evident Audit Logging.
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        sandbox: Optional[ToolSandbox] = None,
        audit_logger: Optional[TamperEvidentAuditLogger] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.sandbox = sandbox or ToolSandbox()
        self.audit_logger = audit_logger or TamperEvidentAuditLogger()
        self._init_regexes()

    def _init_regexes(self):
        # ── Tier 1: Prompt Injection Patterns (Direct & Indirect) ────────────
        self.re_direct_override = re.compile(
            r"\b((ignore|disregard|forget|bypass|override)\s+(all\s+)?(your\s+|the\s+)?(previous|prior|above|earlier|original|system)\s+"
            r"(instructions?|prompts?|guidelines?|rules?|constraints?|context))\b",
            re.IGNORECASE
        )
        self.re_jailbreak = re.compile(
            r"\b(jailbreak|d\.?a\.?n\.?|do\s+anything\s+now|stan\s+mode|aim\s+mode|"
            r"developer\s+mode|god\s+mode|unlock\s+mode|unrestricted\s+mode|no-filter\s+mode)\b",
            re.IGNORECASE
        )
        self.re_persona_hijack = re.compile(
            r"\b(you\s+are\s+now\s+(a|an)|pretend\s+(you\s+are|to\s+be)|"
            r"act\s+(as|like)\s+(a|an)|roleplay\s+as|from\s+now\s+on\s+you\s+(are|will\s+be)|"
            r"forget\s+you\s+are)\b",
            re.IGNORECASE
        )
        self.re_delimiters = re.compile(
            r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|\[SYSTEM\]|\[INST\]|\[\/INST\])",
            re.IGNORECASE
        )
        self.re_context_reset = re.compile(
            r"\b(forget\s+everything|start\s+over\s+from\s+scratch|wipe\s+(your\s+)?memory|reset\s+conversation)\b",
            re.IGNORECASE
        )
        # Indirect Injection markers inside emails/webpages
        self.re_indirect_injection = re.compile(
            r"(?:\b(important:\s*(ignore|forward|send|exfiltrate|delete)|"
            r"system\s*instruction\s*:|hidden\s*command\s*:|"
            r"ai\s*agent\s*:\s*(ignore|override|execute))|"
            r"hidden\s+command\s*:\s*(?:exfiltrate|dump|leak|steal))",
            re.IGNORECASE
        )

        # ── Tier 2: Sensitive Data & Secret Patterns (Output & Exfiltration) ─
        self.re_private_keys = re.compile(
            r"-----BEGIN\s+[A-Z0-9\s_-]+KEY-----[\s\S]*?-----END\s+[A-Z0-9\s_-]+KEY-----",
            re.IGNORECASE
        )
        self.re_api_keys = re.compile(
            r"(?:\b(?:sk-(?:proj-|svcacct-|ant-)?[a-zA-Z0-9_\-]{20,})\b|"
            r"\b(?:gh[pousr]_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})\b|"
            r"\bAIza[0-9A-Za-z\-_]{30,}\b|"
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
            r"\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b|"
            r"\bhf_[a-zA-Z0-9]{20,}\b|"
            r"\b(?:sk_live_|pk_live_|rk_live_)[a-zA-Z0-9]{20,}\b|"
            r"\bSG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\b|"
            r"\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b)",
            re.IGNORECASE
        )
        self.re_db_connection = re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite):\/\/[^\s\/]+",
            re.IGNORECASE
        )
        self.re_prompt_leak_request = re.compile(
            r"\b(reveal|print|show|dump|leak|display|output)\s+(your\s+|the\s+)?"
            r"(system\s+prompt|initial\s+instructions?|secret\s+key|internal\s+configuration)\b",
            re.IGNORECASE
        )

        # ── Tier 3: Privilege Escalation & Command Injection ─────────────────
        self.re_shell_exec = re.compile(
            r"\b(os\.system|subprocess\.(Popen|run|call)|exec\(|eval\(|"
            r"Runtime\.getRuntime\(\)\.exec|cmd\.exe|/bin/sh|/bin/bash)\b",
            re.IGNORECASE
        )
        self.re_piped_dropper = re.compile(
            r"\b(curl|wget)\s+[^|;&\n]+\|\s*(ba?sh|python|perl|ruby|sh)\b",
            re.IGNORECASE
        )
        self.re_sensitive_files = re.compile(
            r"(\/etc\/(passwd|shadow|hosts)|(?:~?\/|\b|\'|\")\.ssh\/(id_rsa|id_ed25519|known_hosts)|\.env\b|"
            r"C:\\Windows\\System32|C:\\Windows\\win\.ini)",
            re.IGNORECASE
        )
        self.re_powershell_attack = re.compile(
            r"\b(powershell(\.exe)?\s+(-(encodedcommand|e|enc)\s+[a-z0-9+/=]+|"
            r"-(command|c)\s+.*iex|.*downloadstring|iex\s*\(new-object))\b",
            re.IGNORECASE
        )
        self.re_directory_traversal = re.compile(
            r"(\.\.[\/\\]\.\.[\/\\]|\.\.[\/\\])",
            re.IGNORECASE
        )

    # ── Normalization Helper ─────────────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        # Strip invisible unicode
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u00AD\u2028\u2029\u202A-\u202F\u2060-\u206F\u0000]", "", text)
        # NFKC normalize
        return unicodedata.normalize("NFKC", cleaned).lower()

    # ── 1. INPUT INSPECTION ──────────────────────────────────────────────────
    def inspect_input(
        self,
        content: str,
        source: str = "user",
        agent_id: str = "agent_default"
    ) -> FirewallVerdict:
        """
        Inspect incoming inputs (user prompts or untrusted content like web/email/docs).
        Detects direct and indirect prompt injection.
        """
        raw = content or ""
        norm = self._normalize(raw)

        # Check Hidden Unicode characters (PI-006)
        if re.search(r"[\u200B-\u200D\uFEFF\u00AD\u202A-\u202F\u2060-\u206F]", raw):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason="Hidden zero-width Unicode characters detected (Obfuscation).",
                rule_id="PI-006"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-006"})
            return verdict

        # Check Direct Override (PI-001)
        if self.re_direct_override.search(norm):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Direct instruction override detected.",
                rule_id="PI-001"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-001"})
            return verdict

        # Check Jailbreak / DAN (PI-003)
        if self.re_jailbreak.search(norm):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Known jailbreak or DAN mode persona activation detected.",
                rule_id="PI-003"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-003"})
            return verdict

        # Check Persona / Role Hijack (PI-004)
        if self.re_persona_hijack.search(norm):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason="Persona or role hijacking phrase detected.",
                rule_id="PI-004"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-004"})
            return verdict

        # Check Delimiter Smuggling (PI-008)
        if self.re_delimiters.search(raw):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason="System prompt delimiters detected in input.",
                rule_id="PI-008"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-008"})
            return verdict

        # Check Context Reset (PI-009)
        if self.re_context_reset.search(norm):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=3,
                reason="Context memory wipe attempt detected.",
                rule_id="PI-009"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "PI-009"})
            return verdict

        # Check Indirect Prompt Injection from untrusted source (email, web, doc)
        if source in ("web", "email", "document", "external"):
            if self.re_indirect_injection.search(norm):
                verdict = FirewallVerdict(
                    status="QUARANTINED",
                    threat_level=5,
                    reason=f"Indirect prompt injection detected in retrieved {source} content.",
                    rule_id="IPI-001"
                )
                self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "QUARANTINED", {"rule": "IPI-001"})
                return verdict

        # Check System Prompt Exfiltration Request (DE-012)
        if self.re_prompt_leak_request.search(norm):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason="Attempt to solicit system prompt or secret credentials.",
                rule_id="DE-012"
            )
            self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "BLOCKED", {"rule": "DE-012"})
            return verdict

        # Clean input
        self.audit_logger.log("INPUT_INSPECTION", agent_id, f"source:{source}", "ALLOWED", {"status": "clean"})
        return FirewallVerdict(status="ALLOWED", threat_level=0, reason="Input passed all security inspections.")

    # ── 2. TOOL CALL INSPECTION ──────────────────────────────────────────────
    def inspect_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any]
    ) -> FirewallVerdict:
        """
        Inspect tool invocation for:
          1. Policy Engine rules (Least Privilege by default)
          2. Privilege Escalation & Command Injection
          3. Directory Traversal & Sensitive File Access
          4. Exfiltration in tool parameters
        """
        args_str = str(tool_args)

        # 1. Check Policy Engine (Least Privilege)
        policy_decision: PolicyDecision = self.policy_engine.evaluate_tool_call(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args
        )
        if not policy_decision.allowed:
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason=policy_decision.reason,
                rule_id=f"POL-{policy_decision.rule_violated or 'DENY'}"
            )
            self.audit_logger.log(
                "TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED",
                {"reason": policy_decision.reason, "rule": verdict.rule_id, "args": tool_args}
            )
            return verdict

        # 2. Check Shell Execution / Code Injection (PE-001)
        if self.re_shell_exec.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Unauthorized shell execution or code injection detected in tool arguments.",
                rule_id="PE-001"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "PE-001", "args": tool_args})
            return verdict

        # 3. Check Piped Droppers (PE-002)
        if self.re_piped_dropper.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Piped remote dropper command detected.",
                rule_id="PE-002"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "PE-002"})
            return verdict

        # 4. Check Sensitive System Files (PE-003)
        if self.re_sensitive_files.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Attempt to access sensitive system credential file (/etc/passwd, id_rsa, .env).",
                rule_id="PE-003"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "PE-003"})
            return verdict

        # 5. Check Directory Traversal
        if self.re_directory_traversal.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=4,
                reason="Directory traversal pattern ('../') detected.",
                rule_id="PE-004"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "PE-004"})
            return verdict

        # 6. Check PowerShell Exploit (PE-010)
        if self.re_powershell_attack.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="PowerShell malicious download cradle or encoded command detected.",
                rule_id="PE-010"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "PE-010"})
            return verdict

        # 7. Check Data Exfiltration via Tool Parameters (e.g. sending API keys via email or HTTP)
        if self.re_api_keys.search(args_str) or self.re_private_keys.search(args_str):
            verdict = FirewallVerdict(
                status="BLOCKED",
                threat_level=5,
                reason="Tool argument contains raw API keys or private keys (Data Exfiltration attempt).",
                rule_id="DEX-001"
            )
            self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "BLOCKED", {"rule": "DEX-001"})
            return verdict

        # Tool call passed all inspections
        self.audit_logger.log("TOOL_CALL", agent_id, f"tool:{tool_name}", "ALLOWED", {"args": tool_args})
        return FirewallVerdict(status="ALLOWED", threat_level=0, reason="Tool call authorized by policy.")

    # ── 3. OUTPUT INSPECTION ─────────────────────────────────────────────────
    def inspect_output(
        self,
        agent_id: str,
        output_text: str,
        redact_in_place: bool = True
    ) -> FirewallVerdict:
        """
        Inspect tool execution output and agent responses for sensitive data exfiltration.
        Redacts API keys, cryptographic private keys, and DB credentials.
        """
        sanitized = output_text or ""
        threats_found = []

        # Check Private Keys
        if self.re_private_keys.search(sanitized):
            threats_found.append("DE-009")
            sanitized = self.re_private_keys.sub("[REDACTED:PRIVATE_KEY]", sanitized)

        # Check API Keys
        if self.re_api_keys.search(sanitized):
            threats_found.append("DE-001")
            sanitized = self.re_api_keys.sub("[REDACTED:API_KEY]", sanitized)

        # Check DB URIs
        if self.re_db_connection.search(sanitized):
            threats_found.append("DE-010")
            sanitized = self.re_db_connection.sub("[REDACTED:DB_URI]", sanitized)

        if threats_found:
            status = "REDACTED" if redact_in_place else "BLOCKED"
            verdict = FirewallVerdict(
                status=status,
                threat_level=5,
                reason=f"Exfiltration detected: Redacted sensitive secrets ({', '.join(threats_found)}).",
                rule_id=threats_found[0],
                sanitized_content=sanitized
            )
            self.audit_logger.log("OUTPUT_INSPECTION", agent_id, "sanitize", status, {"rules": threats_found})
            return verdict

        self.audit_logger.log("OUTPUT_INSPECTION", agent_id, "scan", "ALLOWED", {"status": "clean"})
        return FirewallVerdict(status="ALLOWED", threat_level=0, reason="Output clean.", sanitized_content=sanitized)

    # ── 4. COMPLETE SAFE EXECUTION PIPELINE ──────────────────────────────────
    def safe_execute_tool(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        End-to-end safe tool execution:
          1. Firewall & Policy Inspection
          2. Sandboxed Execution
          3. Output Exfiltration Inspection & Redaction
          4. Cryptographic Audit Logging
        """
        # Step 1: Tool Call Inspection
        call_verdict = self.inspect_tool_call(agent_id, tool_name, tool_args)
        if not call_verdict.is_allowed:
            return {
                "success": False,
                "error": f"Security Firewall Blocked Tool: {call_verdict.reason}",
                "rule_id": call_verdict.rule_id,
                "threat_level": call_verdict.threat_level
            }

        # Step 2: Sandboxed Execution
        sandbox_res: SandboxResult = self.sandbox.execute_tool(tool_name, tool_args)
        if not sandbox_res.success:
            self.audit_logger.log("SANDBOX_EXECUTION", agent_id, f"tool:{tool_name}", "ERROR", {"error": sandbox_res.error})
            return {
                "success": False,
                "error": sandbox_res.error,
                "execution_time_ms": sandbox_res.execution_time_ms
            }

        # Step 3: Output Inspection
        out_str = str(sandbox_res.output)
        out_verdict = self.inspect_output(agent_id, out_str)
        final_output = out_verdict.sanitized_content if out_verdict.sanitized_content is not None else sandbox_res.output

        self.audit_logger.log("SANDBOX_EXECUTION", agent_id, f"tool:{tool_name}", "ALLOWED", {"time_ms": sandbox_res.execution_time_ms})
        return {
            "success": True,
            "output": final_output,
            "was_redacted": out_verdict.status == "REDACTED",
            "execution_time_ms": sandbox_res.execution_time_ms
        }
