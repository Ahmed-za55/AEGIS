# AEGIS policy-guard benchmark

| Category | Blocked |
|---|---|
| network | 4/4 |
| filesystem | 4/4 |
| process | 4/4 |
| secrets | 2/2 |
| bypass | 8/8 |
| **Total** | **22/22** |

Benign programs allowed: **10/10**

Resource attacks pass the guard by design and must be contained by runtime limits (timeout, output cap, container memory): infinite loop, memory bomb, huge output, deep recursion

_Static analysis only; no attack code was executed._
