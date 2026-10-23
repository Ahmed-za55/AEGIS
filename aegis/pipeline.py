"""LLM proposes code -> guard checks -> sandbox runs -> tamper-evident log."""
import hashlib
import json
from dataclasses import dataclass, field

from aegis.guard import check_code

GENESIS = "0" * 64


class HashChainLog:
    def __init__(self):
        self.entries: list[dict] = []

    @staticmethod
    def _digest(body: dict) -> str:
        raw = json.dumps(body, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def append(self, event: str, data: dict) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"index": len(self.entries), "event": event,
                "data": data, "prev": prev}
        entry = {**body, "hash": self._digest(body)}
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: entry[k] for k in ("index", "event", "data", "prev")}
            if entry["index"] != i or entry["prev"] != prev:
                return False
            if entry["hash"] != self._digest(body):
                return False
            prev = entry["hash"]
        return True


@dataclass
class RunReport:
    task: str
    status: str  # "blocked" | "executed" | "failed"
    code: str = ""
    stdout: str = ""
    stderr: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)


class SecureCodeRunner:
    def __init__(self, llm, sandbox, guard=check_code, log=None):
        self.llm, self.sandbox, self.guard = llm, sandbox, guard
        self.log = log if log is not None else HashChainLog()

    def run(self, task: str) -> RunReport:
        code = self.llm.propose_code(task)
        self.log.append("proposed", {"task": task, "code": code})

        verdict = self.guard(code)
        if not verdict.allowed:
            self.log.append("blocked", {"reasons": list(verdict.reasons)})
            return RunReport(task, "blocked", code, reasons=verdict.reasons)

        result = self.sandbox.run(code)
        self.log.append("executed", {
            "success": result.success, "exit_code": result.exit_code,
        })
        status = "executed" if result.success else "failed"
        return RunReport(task, status, code, result.stdout, result.stderr)
