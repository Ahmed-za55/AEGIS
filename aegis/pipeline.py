"""LLM proposes code -> guard checks -> sandbox runs -> tamper-evident log.

With max_attempts > 1 the guard's rejection reasons are fed back to the LLM,
which gets another chance to write a compliant program.
"""
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field

from aegis.guard import check_code
from aegis.redact import redact

GENESIS = "0" * 64


def env_audit_key() -> bytes | None:
    """Secret for the HMAC chain, from the AEGIS_AUDIT_KEY variable."""
    value = os.environ.get("AEGIS_AUDIT_KEY")
    return value.encode("utf-8") if value else None


class HashChainLog:
    """Hash-chained log. With a secret key the chain is an HMAC chain:
    forging or rewriting history then requires the key."""

    def __init__(self, key: bytes | None = None):
        self.entries: list[dict] = []
        self._key = key

    def _digest(self, body: dict) -> str:
        raw = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
        if self._key:
            return hmac.new(self._key, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    def append(self, event: str, data: dict) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"index": len(self.entries), "event": event,
                "data": data, "prev": prev}
        entry = {**body, "hash": self._digest(body)}
        self.entries.append(entry)
        return entry

    def first_invalid(self):
        """Index of the first entry that breaks the chain, else None."""
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            try:
                body = {k: entry[k] for k in ("index", "event", "data", "prev")}
                ok = (entry["index"] == i and entry["prev"] == prev
                      and entry["hash"] == self._digest(body))
            except (KeyError, TypeError):
                ok = False
            if not ok:
                return i
            prev = entry["hash"]
        return None

    def verify(self) -> bool:
        return self.first_invalid() is None

    def head(self) -> str:
        """Hash of the last entry. Store it elsewhere to detect truncation."""
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for entry in self.entries:
                fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    @classmethod
    def load(cls, path, key: bytes | None = None):
        log = cls(key=key)
        with open(path, encoding="utf-8") as fh:
            log.entries = [json.loads(line) for line in fh if line.strip()]
        return log


@dataclass
class RunReport:
    task: str
    status: str  # "blocked" | "executed" | "failed"
    code: str = ""
    stdout: str = ""
    stderr: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)
    attempts: int = 1


class SecureCodeRunner:
    def __init__(self, llm, sandbox, guard=check_code, log=None,
                 max_attempts: int = 1):
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1.")
        self.llm, self.sandbox, self.guard = llm, sandbox, guard
        self.log = log if log is not None else HashChainLog(key=env_audit_key())
        self.max_attempts = max_attempts

    def _propose(self, task: str, feedback):
        if feedback:
            return self.llm.propose_code(task, feedback=feedback)
        return self.llm.propose_code(task)

    def run(self, task: str) -> RunReport:
        feedback = None
        report = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                code = self._propose(task, feedback)
            except Exception as exc:       # LLM down, rate limited, empty answer
                message = redact(f"{type(exc).__name__}: {exc}")
                self.log.append("llm_error", {"error": message, "attempt": attempt})
                return RunReport(task, "error", "", reasons=(message,),
                                 attempts=attempt)
            self.log.append("proposed", {
                "task": task, "code": code, "attempt": attempt,
            })

            verdict = self.guard(code)
            if verdict.allowed:
                result = self.sandbox.run(code)
                self.log.append("executed", {
                    "success": result.success,
                    "exit_code": result.exit_code,
                    "attempt": attempt,
                })
                status = "executed" if result.success else "failed"
                return RunReport(task, status, code, redact(result.stdout),
                                 redact(result.stderr), attempts=attempt)

            self.log.append("blocked", {
                "reasons": list(verdict.reasons), "attempt": attempt,
            })
            feedback = list(verdict.reasons)
            report = RunReport(task, "blocked", code,
                               reasons=verdict.reasons, attempts=attempt)
        return report
