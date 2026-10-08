"""
audit_logger.py
─────────────────────────────────────────────────────────────────────────────
Cryptographically Tamper-Evident Audit Logging for AI Agents.
Uses SHA-256 hash chaining (blockchain-style ledger) with optional HMAC
signatures so that any log modification, deletion, or insertion can be
instantly detected.
─────────────────────────────────────────────────────────────────────────────
"""

import json
import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class AuditRecord:
    """Represents an immutable, hash-linked log entry."""

    def __init__(
        self,
        index: int,
        timestamp: str,
        event_type: str,
        agent_id: str,
        action: str,
        verdict: str,
        details: Dict[str, Any],
        prev_hash: str,
        hmac_key: Optional[bytes] = None,
    ):
        self.index = index
        self.timestamp = timestamp
        self.event_type = event_type
        self.agent_id = agent_id
        self.action = action
        self.verdict = verdict
        self.details = details
        self.prev_hash = prev_hash
        self.entry_hash = self._compute_hash()
        self.signature = self._compute_signature(hmac_key) if hmac_key else None

    def _canonical_payload(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "action": self.action,
            "verdict": self.verdict,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(payload, sort_keys=True)

    def _compute_hash(self) -> str:
        return hashlib.sha256(self._canonical_payload().encode("utf-8")).hexdigest()

    def _compute_signature(self, key: bytes) -> str:
        return hmac.new(key, self.entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "action": self.action,
            "verdict": self.verdict,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditRecord":
        record = cls.__new__(cls)
        record.index = data["index"]
        record.timestamp = data["timestamp"]
        record.event_type = data["event_type"]
        record.agent_id = data["agent_id"]
        record.action = data["action"]
        record.verdict = data["verdict"]
        record.details = data["details"]
        record.prev_hash = data["prev_hash"]
        record.entry_hash = data["entry_hash"]
        record.signature = data.get("signature")
        return record


class TamperEvidentAuditLogger:
    """
    Tamper-Evident Audit Ledger.
    Maintains a cryptographically linked chain of all security decisions,
    tool executions, and inspection events.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, secret_key: Optional[str] = None):
        self.hmac_key = secret_key.encode("utf-8") if secret_key else None
        self.chain: List[AuditRecord] = []

    def log(
        self,
        event_type: str,
        agent_id: str,
        action: str,
        verdict: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append an event to the tamper-evident chain."""
        index = len(self.chain)
        prev_hash = self.chain[-1].entry_hash if self.chain else self.GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()

        record = AuditRecord(
            index=index,
            timestamp=timestamp,
            event_type=event_type,
            agent_id=agent_id,
            action=action,
            verdict=verdict,
            details=details or {},
            prev_hash=prev_hash,
            hmac_key=self.hmac_key,
        )
        self.chain.append(record)
        return record

    def verify_integrity(self) -> Tuple[bool, str, Optional[int]]:
        """
        Verifies the cryptographic integrity of the entire audit chain.
        Returns (is_valid, message, error_index).
        """
        if not self.chain:
            return True, "Audit log is empty (valid).", None

        for i, record in enumerate(self.chain):
            # 1. Check index sequence
            if record.index != i:
                return False, f"Broken sequence at index {i}: expected {i}, got {record.index}", i

            # 2. Check previous hash linkage
            expected_prev = self.chain[i - 1].entry_hash if i > 0 else self.GENESIS_HASH
            if record.prev_hash != expected_prev:
                return (
                    False,
                    f"Hash link broken at index {i}: prev_hash does not match predecessor.",
                    i,
                )

            # 3. Check entry hash computation
            recomputed_hash = record._compute_hash()
            if record.entry_hash != recomputed_hash:
                return (
                    False,
                    f"Tampered record content at index {i}: entry_hash mismatch.",
                    i,
                )

            # 4. Check HMAC signature if enabled
            if self.hmac_key and record.signature:
                recomputed_sig = record._compute_signature(self.hmac_key)
                if not hmac.compare_digest(record.signature, recomputed_sig):
                    return False, f"Invalid signature at index {i}: HMAC validation failed.", i

        return True, f"Integrity verified for all {len(self.chain)} records.", None

    def export_json(self) -> str:
        """Export the chain as a JSON string."""
        return json.dumps([r.to_dict() for r in self.chain], indent=2)

    def save_to_file(self, filepath: str) -> None:
        """Save the chain to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.export_json())

    def load_from_file(self, filepath: str) -> None:
        """Load and verify a chain from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            raw_records = json.load(f)
        self.chain = [AuditRecord.from_dict(d) for d in raw_records]
        is_valid, msg, err_idx = self.verify_integrity()
        if not is_valid:
            raise ValueError(f"Loaded audit log failed integrity verification: {msg}")

    def count(self) -> int:
        return len(self.chain)

    def filter_by_verdict(self, verdict: str) -> List[AuditRecord]:
        return [r for r in self.chain if r.verdict.upper() == verdict.upper()]
