"""
policy_engine.py
─────────────────────────────────────────────────────────────────────────────
Least-Privilege-by-Default Policy Engine for AI Agents.
Enforces strict Role-Based Access Control (RBAC), argument schemas,
path containment, domain allowlists, and Human-in-the-Loop gates.
─────────────────────────────────────────────────────────────────────────────
"""

import os
import re
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field


@dataclass
class ToolRule:
    """Constraints for a specific permitted tool."""
    tool_name: str
    allowed_domains: Optional[List[str]] = None      # For web/network tools
    allowed_paths: Optional[List[str]] = None        # Directory containment
    read_only: bool = False                          # E.g. SELECT-only for DB
    blocked_patterns: List[str] = field(default_factory=list) # Dangerous substrings/regexes
    max_payload_size: int = 65536                    # Max bytes for arguments
    requires_approval: bool = False                  # Human-in-the-Loop gate


@dataclass
class AgentPolicy:
    """Security policy definition for an agent role."""
    role_name: str
    description: str
    allowed_tools: Set[str] = field(default_factory=set)
    tool_rules: Dict[str, ToolRule] = field(default_factory=dict)
    default_action: str = "DENY"                     # Least privilege by default
    require_hitl_for_elevated: bool = True
    max_tool_calls_per_turn: int = 10


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    reason: str
    rule_violated: Optional[str] = None
    requires_approval: bool = False
    sanitized_args: Optional[Dict[str, Any]] = None


class PolicyEngine:
    """
    Central Policy Engine enforcing least privilege by default.
    """

    def __init__(self):
        self.policies: Dict[str, AgentPolicy] = {}
        self.agent_roles: Dict[str, str] = {}        # agent_id -> role_name
        self._register_default_policies()

    def _register_default_policies(self):
        """Register built-in least-privilege policies."""
        # 1. Minimal Agent: Zero tool access
        self.register_policy(AgentPolicy(
            role_name="minimal_agent",
            description="Pure conversational agent with no tool execution rights.",
            allowed_tools=set(),
            default_action="DENY"
        ))

        # 2. Web Researcher: Allowed web fetch only, strict domain allowlist
        self.register_policy(AgentPolicy(
            role_name="web_researcher",
            description="Permitted to search and browse public resources.",
            allowed_tools={"web_search", "web_fetch"},
            tool_rules={
                "web_fetch": ToolRule(
                    tool_name="web_fetch",
                    allowed_domains=["wikipedia.org", "arxiv.org", "github.com", "docs.python.org", "stackoverflow.com"],
                    blocked_patterns=[r"localhost", r"127\.0\.0\.1", r"169\.254\.", r"10\.", r"192\.168\."], # Anti-SSRF
                    max_payload_size=32768
                ),
                "web_search": ToolRule(
                    tool_name="web_search",
                    blocked_patterns=[r"<script", r"javascript:", r"file://"],
                    max_payload_size=1024
                )
            },
            default_action="DENY"
        ))

        # 3. Email Assistant: Email read and draft, strict recipient checks
        self.register_policy(AgentPolicy(
            role_name="email_assistant",
            description="Handles incoming emails and drafts replies. Cannot execute code.",
            allowed_tools={"read_email", "list_emails", "draft_reply"},
            tool_rules={
                "draft_reply": ToolRule(
                    tool_name="draft_reply",
                    blocked_patterns=[r"-----BEGIN", r"sk-[a-zA-Z0-9]{20,}", r"AKIA[0-9A-Z]{16}"], # Prevent key leakage
                    requires_approval=True # HITL gate
                )
            },
            default_action="DENY"
        ))

        # 4. Data Analyst: Read-only SQL, safe report generation
        self.register_policy(AgentPolicy(
            role_name="data_analyst",
            description="Queries analytics database and writes to safe output dir.",
            allowed_tools={"sql_query", "export_csv"},
            tool_rules={
                "sql_query": ToolRule(
                    tool_name="sql_query",
                    read_only=True,
                    blocked_patterns=[
                        r"\b(drop|delete|insert|update|alter|truncate|create|grant|revoke|exec|execute)\b",
                        r";\s*--", r"information_schema"
                    ]
                ),
                "export_csv": ToolRule(
                    tool_name="export_csv",
                    allowed_paths=["./sandbox/reports", "./reports", "sandbox/reports"]
                )
            },
            default_action="DENY"
        ))

        # 5. Sandbox Code Runner: Isolated computation
        self.register_policy(AgentPolicy(
            role_name="code_runner",
            description="Executes restricted computations in isolated sandbox.",
            allowed_tools={"sandbox_exec_python", "read_sandbox_file"},
            tool_rules={
                "sandbox_exec_python": ToolRule(
                    tool_name="sandbox_exec_python",
                    blocked_patterns=[
                        r"import\s+os", r"import\s+sys", r"import\s+subprocess",
                        r"import\s+shutil", r"import\s+socket", r"__import__",
                        r"open\(", r"eval\(", r"exec\("
                    ],
                    max_payload_size=8192
                ),
                "read_sandbox_file": ToolRule(
                    tool_name="read_sandbox_file",
                    allowed_paths=["./sandbox", "sandbox"]
                )
            },
            default_action="DENY"
        ))

    def register_policy(self, policy: AgentPolicy) -> None:
        """Register or update an agent policy."""
        self.policies[policy.role_name] = policy

    def assign_role(self, agent_id: str, role_name: str) -> None:
        """Assign an agent to a specific security role."""
        if role_name not in self.policies:
            raise ValueError(f"Unknown role '{role_name}'. Available: {list(self.policies.keys())}")
        self.agent_roles[agent_id] = role_name

    def get_role_for_agent(self, agent_id: str) -> str:
        """Get the role assigned to an agent, or fallback to 'minimal_agent'."""
        return self.agent_roles.get(agent_id, "minimal_agent")

    def evaluate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Evaluate tool invocation against the agent's policy.
        Enforces least privilege: if not explicitly allowed, DENY.
        """
        role_name = self.get_role_for_agent(agent_id)
        policy = self.policies.get(role_name)

        if not policy:
            return PolicyDecision(
                allowed=False,
                reason=f"No policy registered for role '{role_name}'. Default DENY.",
                rule_violated="POLICY_MISSING"
            )

        # 1. Check tool authorization (Default Deny)
        if tool_name not in policy.allowed_tools:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{tool_name}' is NOT authorized for role '{role_name}' (Least Privilege Default Deny).",
                rule_violated="TOOL_UNAUTHORIZED"
            )

        rule = policy.tool_rules.get(tool_name)
        if not rule:
            # Tool is in allowed_tools with no special constraints
            return PolicyDecision(allowed=True, reason="Tool authorized by role policy.")

        # 2. Check Payload Size
        args_str = str(tool_args)
        if len(args_str) > rule.max_payload_size:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool arguments size ({len(args_str)} bytes) exceeds limit ({rule.max_payload_size} bytes).",
                rule_violated="PAYLOAD_LIMIT_EXCEEDED"
            )

        # 3. Check Blocked Patterns (Dangerous tokens/commands)
        for pattern in rule.blocked_patterns:
            if re.search(pattern, args_str, re.IGNORECASE):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Arguments contain prohibited pattern: '{pattern}'.",
                    rule_violated="DANGEROUS_PATTERN_DETECTED"
                )

        # 4. Check Domain Allowlists for Web Tools
        if rule.allowed_domains is not None and "url" in tool_args:
            url = str(tool_args["url"]).lower()
            domain_matched = False
            for allowed in rule.allowed_domains:
                if allowed.lower() in url:
                    domain_matched = True
                    break
            if not domain_matched:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Destination URL '{url}' is not in allowed domains {rule.allowed_domains}.",
                    rule_violated="DOMAIN_NOT_ALLOWED"
                )

        # 5. Check Path Containment for File Tools
        if rule.allowed_paths is not None and ("path" in tool_args or "filepath" in tool_args):
            raw_path = str(tool_args.get("path") or tool_args.get("filepath"))
            normalized_path = os.path.normpath(raw_path).replace("\\", "/")

            # Enforce that path must strictly start within one of the allowed roots
            path_allowed = False
            for allowed in rule.allowed_paths:
                allowed_norm = os.path.normpath(allowed).replace("\\", "/")
                if normalized_path.startswith(allowed_norm) or normalized_path.startswith("./" + allowed_norm):
                    # Also guard against traversal escaping
                    if ".." not in raw_path:
                        path_allowed = True
                        break

            if not path_allowed or ".." in raw_path or raw_path.startswith("~") or raw_path.startswith("/"):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Path '{raw_path}' violates containment boundary. Must reside inside {rule.allowed_paths}.",
                    rule_violated="PATH_TRAVERSAL_DETECTED"
                )

        # 6. Check Read-Only SQL Restrictions
        if rule.read_only and "query" in tool_args:
            query = str(tool_args["query"]).strip().upper()
            if not query.startswith("SELECT") and not query.startswith("WITH"):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Tool '{tool_name}' is restricted to read-only queries (must begin with SELECT).",
                    rule_violated="READ_ONLY_VIOLATION"
                )

        # 7. Check HITL Requirement
        if rule.requires_approval:
            return PolicyDecision(
                allowed=True,
                reason="Operation conforms to policy but requires Human-in-the-Loop approval.",
                requires_approval=True
            )

        return PolicyDecision(allowed=True, reason="Tool execution conforms to policy.")
