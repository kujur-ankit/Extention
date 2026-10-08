"""
confinement_model.py
─────────────────────────────────────────────────────────────────────────────
Strict Intent Confinement & Private Information Access Guard Model.
Ensures:
  1. AI agents CANNOT access private personal information, documents, or credentials.
  2. Strict Action Confinement: If the user says "open Chrome", the agent can ONLY
     open Chrome. Any attempt by the agent to open or touch any other app, file,
     command, or process is immediately intercepted and blocked.
─────────────────────────────────────────────────────────────────────────────
"""

import os
import re
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .audit_logger import TamperEvidentAuditLogger


@dataclass
class IntentScope:
    """Represents the strictly bounded authorization granted by the user."""
    raw_user_prompt: str
    authorized_actions: Set[str]        # e.g. {"open", "launch"}
    authorized_targets: Set[str]        # e.g. {"chrome", "google chrome", "chrome.exe"}
    allowed_parameters: Dict[str, Any] = field(default_factory=dict)
    allow_private_data: bool = False    # NEVER allowed by default


@dataclass
class ConfinementDecision:
    """Outcome of intent confinement and privacy boundary verification."""
    allowed: bool
    status: str                         # "ALLOWED", "BLOCKED_PRIVACY_VIOLATION", "BLOCKED_SCOPE_VIOLATION"
    reason: str
    target_attempted: str
    authorized_targets: List[str]
    violation_rule: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ActionConfinementModel:
    """
    Security Guard Model enforcing:
      • Zero-access boundary for private personal information.
      • Strict Single-Intent Confinement: Agent may ONLY execute what the user explicitly authorized.
    """

    # Protected private information targets (strictly off-limits to agents)
    PRIVATE_INFO_PATTERNS = [
        # Private filesystem paths & directories
        r"(?:c:[\\\/]users[\\\/][^\\\/]+[\\\/](?:documents|desktop|pictures|videos|downloads|appdata))",
        r"(?:~?\/|\b|\'|\")(?:\.ssh|\.aws|\.gnupg|\.config|\.env|credentials|cookies|history|id_rsa)",
        r"(?:google[\\\/]chrome[\\\/]user data[\\\/]default[\\\/](?:cookies|history|login data|web data))",
        r"(?:microsoft[\\\/]edge[\\\/]user data[\\\/]default[\\\/](?:cookies|history|login data))",
        r"(?:c:[\\\/]windows[\\\/](?:system32|win\.ini|sam|security))",
        r"\/etc\/(?:passwd|shadow|hosts|sudoers)",

        # Sensitive credentials & personal identifiers
        r"(?:password|passwd|secret|api[_\-\s]?key|private[_\-\s]?key|bearer\s+[a-z0-9_\-\.]+)",
        r"(?:credit[_\-\s]?card|ssn|aadhaar|pan[_\-\s]?card|bank[_\-\s]?account)"
    ]

    # Known application alias mappings for normalization
    APP_ALIASES = {
        "chrome": ["chrome", "google chrome", "google-chrome", "chrome.exe"],
        "firefox": ["firefox", "mozilla firefox", "firefox.exe"],
        "edge": ["edge", "microsoft edge", "msedge", "msedge.exe"],
        "notepad": ["notepad", "notepad.exe"],
        "calculator": ["calc", "calculator", "calc.exe"],
        "vscode": ["code", "vscode", "visual studio code", "code.exe"],
    }

    # Dangerous system utilities that must NEVER be opened unless specifically designed
    DANGEROUS_SYSTEM_TOOLS = {
        "cmd", "cmd.exe", "powershell", "powershell.exe", "bash", "sh",
        "terminal", "regedit", "regedit.exe", "taskmgr", "taskmgr.exe"
    }

    def __init__(self, audit_logger: Optional[TamperEvidentAuditLogger] = None):
        self.audit_logger = audit_logger or TamperEvidentAuditLogger()
        self.re_private = [re.compile(p, re.IGNORECASE) for p in self.PRIVATE_INFO_PATTERNS]

    # ── 1. PARSE & BIND USER INTENT ──────────────────────────────────────────
    def parse_user_intent(self, user_prompt: str) -> IntentScope:
        """
        Analyze what the user explicitly requested.
        Creates a locked-down authorization scope allowing ONLY that specific target.
        """
        prompt = user_prompt.strip().lower()
        authorized_targets = set()
        authorized_actions = set()

        # Detect action verb
        if re.search(r"\b(open|launch|start|run|display)\b", prompt):
            authorized_actions.add("open")
            authorized_actions.add("launch")

        # Detect requested application / target
        for canonical_app, aliases in self.APP_ALIASES.items():
            for alias in aliases:
                if re.search(rf"\b{re.escape(alias)}\b", prompt):
                    authorized_targets.add(canonical_app)
                    for a in aliases:
                        authorized_targets.add(a.lower())
                    break

        return IntentScope(
            raw_user_prompt=user_prompt,
            authorized_actions=authorized_actions or {"execute"},
            authorized_targets=authorized_targets,
            allow_private_data=False
        )

    # ── 2. VALIDATE AGENT ACTION AGAINST SCOPE & PRIVACY ─────────────────────
    def validate_agent_action(
        self,
        agent_id: str,
        intent_scope: IntentScope,
        attempted_action: str,
        attempted_target: str,
        attempted_args: Optional[Dict[str, Any]] = None
    ) -> ConfinementDecision:
        """
        Evaluates the action an AI agent is attempting to take.
        Rules:
          1. PRIVACY SHIELD: Blocks access to private user information, paths, or secrets.
          2. STRICT SCOPE CONFINEMENT: If user said "open Chrome", the agent may ONLY open Chrome.
             Any attempt to open anything else is immediately blocked!
        """
        args_payload = f"{attempted_action} {attempted_target} {str(attempted_args or {})}"
        target_norm = attempted_target.strip().lower()

        # ── Check 1: Private Information Access Shield ────────────────────────
        for pattern in self.re_private:
            if pattern.search(args_payload):
                decision = ConfinementDecision(
                    allowed=False,
                    status="BLOCKED_PRIVACY_VIOLATION",
                    reason=f"Access Denied: Attempted to access private personal data or confidential path ('{attempted_target}').",
                    target_attempted=attempted_target,
                    authorized_targets=list(intent_scope.authorized_targets),
                    violation_rule="PRIVACY_SHIELD_001"
                )
                self.audit_logger.log(
                    "CONFINEMENT_VIOLATION",
                    agent_id,
                    f"attempt:{attempted_target}",
                    "BLOCKED",
                    {"reason": decision.reason, "rule": decision.violation_rule}
                )
                return decision

        # ── Check 2: Dangerous System Tools Guard ────────────────────────────
        if target_norm in self.DANGEROUS_SYSTEM_TOOLS and target_norm not in intent_scope.authorized_targets:
            decision = ConfinementDecision(
                allowed=False,
                status="BLOCKED_SCOPE_VIOLATION",
                reason=f"Privilege Escalation Blocked: AI agent attempted to open dangerous system shell ('{attempted_target}') outside authorized intent.",
                target_attempted=attempted_target,
                authorized_targets=list(intent_scope.authorized_targets),
                violation_rule="SYSTEM_SHELL_TAMPER_002"
            )
            self.audit_logger.log(
                "CONFINEMENT_VIOLATION",
                agent_id,
                f"attempt:{attempted_target}",
                "BLOCKED",
                {"reason": decision.reason, "rule": decision.violation_rule}
            )
            return decision

        # ── Check 3: Strict Intent Target Matching ────────────────────────────
        # Is the target in the authorized set granted by user?
        is_target_authorized = False
        for auth_target in intent_scope.authorized_targets:
            if auth_target in target_norm or target_norm in auth_target:
                is_target_authorized = True
                break

        if not is_target_authorized:
            decision = ConfinementDecision(
                allowed=False,
                status="BLOCKED_SCOPE_VIOLATION",
                reason=(
                    f"Strict Confinement Block: User authorized ONLY {list(intent_scope.authorized_targets) or 'NONE'} "
                    f"for prompt '{intent_scope.raw_user_prompt}'. "
                    f"AI agent attempted to access unauthorized target '{attempted_target}'."
                ),
                target_attempted=attempted_target,
                authorized_targets=list(intent_scope.authorized_targets),
                violation_rule="INTENT_CONFINEMENT_003"
            )
            self.audit_logger.log(
                "CONFINEMENT_VIOLATION",
                agent_id,
                f"attempt:{attempted_target}",
                "BLOCKED",
                {"reason": decision.reason, "rule": decision.violation_rule}
            )
            return decision

        # ── Authorized Action ────────────────────────────────────────────────
        decision = ConfinementDecision(
            allowed=True,
            status="ALLOWED",
            reason=f"Action '{attempted_action}' on target '{attempted_target}' strictly matches user authorization.",
            target_attempted=attempted_target,
            authorized_targets=list(intent_scope.authorized_targets)
        )
        self.audit_logger.log(
            "CONFINEMENT_ALLOWED",
            agent_id,
            f"open:{attempted_target}",
            "ALLOWED",
            {"status": "confinement_verified"}
        )
        return decision

    # ── 3. MACHINE LEARNING NEURAL PREDICTION ───────────────────────────────
    def predict_neural_net(
        self,
        user_prompt: str,
        action: str,
        target: str,
        model_path: str = "models/confinement_neural_net.pt"
    ) -> Dict[str, Any]:
        """
        Uses the trained PyTorch Deep Neural Network to predict whether an action
        is ALLOWED, BLOCKED_SCOPE_VIOLATION, BLOCKED_PRIVACY_VIOLATION, or BLOCKED_PROMPT_INJECTION.
        """
        import torch
        from train_agent_model import AgentSecurityNeuralNet, extract_features

        if not os.path.exists(model_path):
            return {"error": f"Model weights '{model_path}' not found. Run train_agent_model.py first."}

        checkpoint = torch.load(model_path, map_location="cpu")
        vocab = checkpoint["vocab"]
        classes = checkpoint["classes"]
        hidden_dim = checkpoint.get("hidden_dim", 128)

        model = AgentSecurityNeuralNet(vocab_size=len(vocab), num_classes=len(classes), hidden_dim=hidden_dim)
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        sample = {"user_prompt": user_prompt, "action": action, "target": target}
        bow, domain = extract_features(sample, vocab)

        with torch.no_grad():
            logits = model(bow.unsqueeze(0), domain.unsqueeze(0))
            probs = torch.softmax(logits, dim=1)[0]
            pred_idx = torch.argmax(probs).item()
            pred_label = classes[pred_idx]
            confidence = probs[pred_idx].item()

        return {
            "prediction": pred_label,
            "confidence": confidence,
            "is_allowed": pred_label == "ALLOWED",
            "probabilities": {classes[i]: probs[i].item() for i in range(len(classes))}
        }

