"""
Agent Firewall Package
─────────────────────────────────────────────────────────────────────────────
Security Layer for Tool-Using AI Agents.
Provides:
  - Input, Tool Call, and Output Firewall Inspection
  - Least-Privilege-by-Default Policy Engine
  - Sandboxed Tool Execution
  - Tamper-Evident Cryptographic Audit Logging
  - Deployable Proxy / Gateway
─────────────────────────────────────────────────────────────────────────────
"""

from .audit_logger import TamperEvidentAuditLogger, AuditRecord
from .policy_engine import PolicyEngine, AgentPolicy, ToolRule, PolicyDecision
from .sandbox import ToolSandbox, SandboxResult
from .firewall import AgentFirewall, FirewallVerdict
from .confinement_model import ActionConfinementModel, IntentScope, ConfinementDecision

__all__ = [
    "AgentFirewall",
    "FirewallVerdict",
    "PolicyEngine",
    "AgentPolicy",
    "ToolRule",
    "PolicyDecision",
    "ToolSandbox",
    "SandboxResult",
    "TamperEvidentAuditLogger",
    "AuditRecord",
    "ActionConfinementModel",
    "IntentScope",
    "ConfinementDecision",
]

