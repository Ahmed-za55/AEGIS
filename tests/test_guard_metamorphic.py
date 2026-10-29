"""Metamorphic test: wrapping a blocked program in any control structure must
not make the guard let it through."""
import ast
import textwrap

import pytest

from aegis.guard import check_code

SEEDS = [
    "import socket",
    "import os\nos.system('whoami')",
    "import subprocess",
    "open('x', 'w').write('a')",
    "eval('1')",
    "f = open\nf('x', 'w')",
    "import random\nrandom._os.system('whoami')",
    "import json\njson.codecs.open('x', 'w')",
    "import typing\nprint(typing.sys.modules)",
    "print('{0.__class__}'.format(1))",
    "import typing\ntyping.get_type_hints(print)",
    "g = (1 for _ in [0])\nprint(g.gi_frame.f_builtins['open'])",
    "async def f():\n    pass\nprint(f().cr_frame)",
    "help('modules')",
    "__import__('os')",
]


def _ind(code, n=4):
    return textwrap.indent(code, " " * n)


WRAPPERS = {
    "function": lambda c: "def _w():\n" + _ind(c) + "\n_w()",
    "try": lambda c: "try:\n" + _ind(c) + "\nexcept Exception:\n    pass",
    "if": lambda c: "if True:\n" + _ind(c),
    "for": lambda c: "for _ in range(1):\n" + _ind(c),
    "while": lambda c: "while True:\n" + _ind(c) + "\n    break",
    "class": lambda c: "class _C:\n" + _ind(c),
    "nested": lambda c: "def _a():\n    def _b():\n" + _ind(c, 8) + "\n    _b()\n_a()",
    "async": lambda c: "async def _w():\n" + _ind(c),
}


@pytest.mark.parametrize("seed", SEEDS)
def test_seed_is_blocked(seed):
    assert not check_code(seed).allowed


@pytest.mark.parametrize("wrapper", list(WRAPPERS))
@pytest.mark.parametrize("seed", SEEDS)
def test_wrapped_attack_stays_blocked(seed, wrapper):
    wrapped = WRAPPERS[wrapper](seed)
    ast.parse(wrapped)                      # must be valid Python, else the test is void
    assert not check_code(wrapped).allowed
