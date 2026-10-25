"""Redacts secrets from program output before it goes back to the LLM."""
import os
import re

_PATTERNS = [
    (re.compile(r"nvapi-[A-Za-z0-9_\-]{20,}"), "[REDACTED:nvidia-key]"),
    (re.compile(r"sk-[A-Za-z0-9_\-]{20,}"), "[REDACTED:api-key]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws-key]"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "[REDACTED:github-token]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "[REDACTED:jwt]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), "[REDACTED:private-key]"),
]
_NAME_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD")
_MIN_SECRET_LEN = 8


def known_secret_values(environ=None) -> list[str]:
    """Values of environment variables that look like secrets (longest first)."""
    environ = os.environ if environ is None else environ
    values = {v for k, v in environ.items()
              if any(h in k.upper() for h in _NAME_HINTS)
              and len(v) >= _MIN_SECRET_LEN}
    return sorted(values, key=len, reverse=True)


def redact(text: str, extra_secrets=None) -> str:
    if not text:
        return text
    for secret in list(extra_secrets or []) + known_secret_values():
        text = text.replace(secret, "[REDACTED]")
    for pattern, label in _PATTERNS:
        text = pattern.sub(label, text)
    return text
