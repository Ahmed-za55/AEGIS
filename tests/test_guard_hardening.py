import pytest

from aegis.guard import check_code


@pytest.mark.parametrize("code", [
    "f = open\nf('x', 'w').write('a')",
    "[open][0]('x', 'w')",
    "list(map(open, ['/etc/hostname']))",
    "(lambda: open)()('x', 'w')",
    "import random\nrandom._os.system('whoami')",
    "import collections\nprint(collections._sys.modules)",
    "import json\njson.codecs.open('x', 'w')",
    "import typing\nprint(typing.sys.modules['os'])",
    "from typing import sys",
    "import json.tool",
    "import random\nprint(('{0.' + '__globals__[_os].environ}').format(random.seed))",
    "import string\nstring.Formatter().vformat('{0.__class__}', (1,), {})",
    "fmt = '{0.__class__}'\nprint(fmt.format(1))",
])
def test_hardened_guard_blocks_bypass(code):
    assert not check_code(code).allowed


@pytest.mark.parametrize("code", [
    "print('{} and {}'.format(1, 2))",
    "print('{:.2f}'.format(3.14159))",
    "from collections import namedtuple\nP = namedtuple('P', 'x y')\nprint(P(1, 2).x)",
    "from collections.abc import Mapping\nprint(isinstance({}, Mapping))",
    "input_value = 3\nopened = input_value + 1\nprint(opened)",
    "def f(open_count):\n    return open_count * 2\nprint(f(4))",
])
def test_hardened_guard_keeps_benign_code(code):
    assert check_code(code).allowed
