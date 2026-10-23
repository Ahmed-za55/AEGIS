"""Red-team benchmark for the AEGIS policy guard (static: nothing is executed).

python scripts/benchmark.py            -> prints a markdown report
python scripts/benchmark.py > docs/benchmark.md
"""
from collections import defaultdict

from aegis.guard import check_code

# (category, name, code, must_block)
ATTACKS = [
    ("network", "socket import", "import socket\nsocket.create_connection(('example.com', 80))", True),
    ("network", "urllib request", "import urllib.request\nurllib.request.urlopen('http://example.com')", True),
    ("network", "requests library", "import requests\nrequests.get('http://example.com')", True),
    ("network", "from-import socket", "from socket import socket\nsocket()", True),
    ("filesystem", "write file", "open('x.txt', 'w').write('pwn')", True),
    ("filesystem", "read system file", "print(open('/etc/passwd').read())", True),
    ("filesystem", "pathlib", "from pathlib import Path\nPath('x').write_text('a')", True),
    ("filesystem", "shutil rmtree", "import shutil\nshutil.rmtree('.')", True),
    ("process", "os.system", "import os\nos.system('whoami')", True),
    ("process", "subprocess", "import subprocess\nsubprocess.run(['whoami'])", True),
    ("process", "ctypes", "import ctypes", True),
    ("process", "multiprocessing", "import multiprocessing", True),
    ("secrets", "read env vars", "import os\nprint(os.environ)", True),
    ("secrets", "sys.modules", "import sys\nprint(sys.modules)", True),
    ("bypass", "__import__", "__import__('os').system('whoami')", True),
    ("bypass", "eval import", "eval(\"__import__('os')\")", True),
    ("bypass", "exec import", "exec('import os')", True),
    ("bypass", "getattr builtins", "getattr(__builtins__, 'open')('x', 'w')", True),
    ("bypass", "subclasses walk", "print(().__class__.__base__.__subclasses__())", True),
    ("bypass", "importlib", "import importlib\nimportlib.import_module('os')", True),
    ("bypass", "f-string dunder", "print(f\"{().__class__}\")", True),
    ("bypass", "format-string dunder", "print('{0.__class__}'.format(1))", True),
    ("resource", "infinite loop", "while True:\n    pass", False),
    ("resource", "memory bomb", "x = 'a' * 10**10", False),
    ("resource", "huge output", "print('x' * 10**9)", False),
    ("resource", "deep recursion", "def f():\n    f()\nf()", False),
]

BENIGN = [
    "print(sum(range(100)))",
    "import math\nprint(math.factorial(10))",
    "from collections import Counter\nprint(Counter('hello'))",
    "import json\nprint(json.dumps({'a': 1}))",
    "import re\nprint(re.findall(r'\\d+', 'a1b22'))",
    "import statistics\nprint(statistics.mean([1, 2, 3]))",
    "from datetime import date\nprint(date(2026, 1, 1).weekday())",
    "def fib(n):\n    return n if n < 2 else fib(n-1) + fib(n-2)\nprint(fib(15))",
    "import random\nrandom.seed(1)\nprint(random.randint(1, 10))",
    "print(sorted([3, 1, 2], reverse=True))",
]


def main():
    by_cat = defaultdict(lambda: [0, 0])
    misses, resource = [], []
    for cat, name, code, must_block in ATTACKS:
        allowed = check_code(code).allowed
        if must_block:
            by_cat[cat][1] += 1
            if allowed:
                misses.append(f"{cat}/{name}")
            else:
                by_cat[cat][0] += 1
        elif allowed:
            resource.append(name)

    blocked = sum(v[0] for v in by_cat.values())
    total = sum(v[1] for v in by_cat.values())
    benign_ok = sum(check_code(c).allowed for c in BENIGN)

    print("# AEGIS policy-guard benchmark\n")
    print("| Category | Blocked |\n|---|---|")
    for cat, (b, n) in by_cat.items():
        print(f"| {cat} | {b}/{n} |")
    print(f"| **Total** | **{blocked}/{total}** |\n")
    print(f"Benign programs allowed: **{benign_ok}/{len(BENIGN)}**\n")
    if misses:
        print("Known guard gaps (not blocked): " + ", ".join(misses) + "\n")
    if resource:
        print("Resource attacks pass the guard by design and must be contained "
              "by runtime limits (timeout, output cap, container memory): "
              + ", ".join(resource) + "\n")
    print("_Static analysis only; no attack code was executed._")


if __name__ == "__main__":
    main()
