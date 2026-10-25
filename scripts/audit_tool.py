"""Audit-log tool.

python scripts/audit_tool.py verify audit.jsonl [--head <hash>]
python scripts/audit_tool.py demo
"""
import json
import pathlib
import sys
import tempfile

from aegis.pipeline import HashChainLog


def verify(path, head=None) -> int:
    log = HashChainLog.load(path)
    bad = log.first_invalid()
    if bad is not None:
        print(f"TAMPERED: chain breaks at entry {bad}")
        return 1
    if head and log.head() != head:
        print("TRUNCATED OR REPLACED: head hash does not match the stored one")
        return 1
    print(f"OK: {len(log.entries)} entries, head {log.head()[:16]}...")
    return 0


def demo() -> int:
    work = pathlib.Path(tempfile.mkdtemp(prefix="aegis_audit_"))
    path = work / "audit.jsonl"

    log = HashChainLog()
    log.append("proposed", {"task": "Save a note", "attempt": 1})
    log.append("blocked", {"reasons": ["use of 'open' is not allowed"], "attempt": 1})
    log.append("proposed", {"task": "Save a note", "attempt": 2})
    log.append("executed", {"success": True, "exit_code": 0, "attempt": 2})
    log.save(path)
    head = log.head()
    print(f"1) saved {len(log.entries)} entries to {path}")
    print("2) verify:", end=" ")
    verify(path, head)

    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["event"] = "executed"            # pretend the block never happened
    lines[1] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("3) after editing entry 1 ('blocked' -> 'executed'):", end=" ")
    verify(path, head)

    log.save(path)
    path.write_text("\n".join(path.read_text(encoding="utf-8").splitlines()[:-1]) + "\n",
                    encoding="utf-8")
    print("4) after deleting the last entry:", end=" ")
    verify(path, head)
    return 0


def main(argv) -> int:
    if len(argv) >= 2 and argv[0] == "verify":
        head = argv[argv.index("--head") + 1] if "--head" in argv else None
        return verify(argv[1], head)
    if argv[:1] == ["demo"]:
        return demo()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
