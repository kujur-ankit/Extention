"""
proxy.py
─────────────────────────────────────────────────────────────────────────────
Deployable Security Proxy & Gateway for Tool-Using AI Agents.
Provides REST API endpoints and an OpenAI-compatible proxy to inspect
inputs, tool calls, sandbox execution, and tamper-evident audit logs.
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .firewall import AgentFirewall, FirewallVerdict
from .policy_engine import PolicyEngine, AgentPolicy, ToolRule
from .sandbox import ToolSandbox
from .audit_logger import TamperEvidentAuditLogger

# Initialize FastAPI Application
app = FastAPI(
    title="Agent Firewall Security Proxy",
    description="Drop-in security proxy and policy engine for tool-using AI agents.",
    version="1.0.0"
)

# Enable CORS for browser extension and local web dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Firewall Instance
firewall = AgentFirewall()


# ── Request / Response Models ────────────────────────────────────────────────

class InputInspectRequest(BaseModel):
    content: str
    source: str = Field(default="user", description="user, web, email, or document")
    agent_id: str = Field(default="agent_default")

class ToolCallInspectRequest(BaseModel):
    agent_id: str = Field(default="agent_default")
    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)

class ToolExecuteRequest(BaseModel):
    agent_id: str = Field(default="agent_default")
    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)

class OutputInspectRequest(BaseModel):
    agent_id: str = Field(default="agent_default")
    output_text: str
    redact_in_place: bool = True

class AssignRoleRequest(BaseModel):
    agent_id: str
    role_name: str


# ── API Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Health check and status."""
    return {
        "status": "healthy",
        "service": "Agent Firewall Proxy",
        "audit_records_count": firewall.audit_logger.count()
    }


@app.get("/stats")
def get_stats():
    """Real-time firewall statistics."""
    records = firewall.audit_logger.chain
    total_events = len(records)
    blocked_count = len([r for r in records if r.verdict == "BLOCKED" or r.verdict == "QUARANTINED"])
    redacted_count = len([r for r in records if r.verdict == "REDACTED"])
    allowed_count = len([r for r in records if r.verdict == "ALLOWED"])

    return {
        "total_scanned": total_events,
        "blocked": blocked_count,
        "redacted": redacted_count,
        "allowed": allowed_count,
        "mitigation_rate": f"{(blocked_count / total_events * 100):.1f}%" if total_events > 0 else "0.0%"
    }


@app.post("/v1/inspect/input")
def inspect_input_endpoint(req: InputInspectRequest):
    """Inspect input or retrieved web/email content for prompt injection."""
    verdict = firewall.inspect_input(content=req.content, source=req.source, agent_id=req.agent_id)
    return {
        "status": verdict.status,
        "threat_level": verdict.threat_level,
        "reason": verdict.reason,
        "rule_id": verdict.rule_id,
        "is_allowed": verdict.is_allowed
    }


@app.post("/v1/inspect/tool-call")
def inspect_tool_call_endpoint(req: ToolCallInspectRequest):
    """Inspect tool invocation against policy engine and security boundaries."""
    verdict = firewall.inspect_tool_call(
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        tool_args=req.tool_args
    )
    return {
        "status": verdict.status,
        "threat_level": verdict.threat_level,
        "reason": verdict.reason,
        "rule_id": verdict.rule_id,
        "is_allowed": verdict.is_allowed
    }


@app.post("/v1/execute/tool")
def execute_tool_endpoint(req: ToolExecuteRequest):
    """
    End-to-End Safe Execution:
    Inspects tool call -> Executes in isolated sandbox -> Inspects & redacts output -> Logs to audit ledger.
    """
    result = firewall.safe_execute_tool(
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        tool_args=req.tool_args
    )
    return result


@app.post("/v1/inspect/output")
def inspect_output_endpoint(req: OutputInspectRequest):
    """Inspect agent tool outputs or final responses for sensitive data exfiltration."""
    verdict = firewall.inspect_output(
        agent_id=req.agent_id,
        output_text=req.output_text,
        redact_in_place=req.redact_in_place
    )
    return {
        "status": verdict.status,
        "threat_level": verdict.threat_level,
        "reason": verdict.reason,
        "rule_id": verdict.rule_id,
        "sanitized_content": verdict.sanitized_content,
        "is_allowed": verdict.is_allowed
    }


@app.post("/v1/policy/assign-role")
def assign_role_endpoint(req: AssignRoleRequest):
    """Assign an agent ID to a specific security policy role."""
    try:
        firewall.policy_engine.assign_role(req.agent_id, req.role_name)
        return {"status": "success", "agent_id": req.agent_id, "role": req.role_name}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/v1/audit/logs")
def get_audit_logs():
    """Retrieve the cryptographically linked audit ledger records."""
    return [r.to_dict() for r in firewall.audit_logger.chain]


@app.get("/v1/audit/verify")
def verify_audit_ledger():
    """Cryptographically verify the integrity of the audit chain."""
    is_valid, msg, err_idx = firewall.audit_logger.verify_integrity()
    return {
        "is_valid": is_valid,
        "message": msg,
        "tampered_index": err_idx,
        "total_records": firewall.audit_logger.count()
    }


def start_proxy(host: str = "127.0.0.1", port: int = 8080):
    """Start the proxy server."""
    print(f"\n🛡️  Starting Agent Firewall Proxy on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_proxy()
