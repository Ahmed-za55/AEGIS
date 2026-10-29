from aegis.pipeline import SecureCodeRunner
from aegis.redact import redact


def test_known_key_formats_are_redacted():
    text = "k=nvapi-" + "A" * 30 + " and AKIA" + "B" * 16
    out = redact(text)
    assert "nvapi-" not in out and "AKIA" not in out


def test_private_key_block_is_redacted():
    block = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    assert "abc" not in redact("x " + block)


def test_secret_env_values_are_redacted(monkeypatch):
    monkeypatch.setenv("MY_SERVICE_API_KEY", "super-secret-value-123")
    monkeypatch.setenv("HARMLESS_NAME", "plain-visible-value")
    out = redact("a super-secret-value-123 b plain-visible-value")
    assert "super-secret-value-123" not in out and "plain-visible-value" in out


def test_short_or_empty_values_are_ignored(monkeypatch):
    monkeypatch.setenv("TINY_SECRET", "abc")
    assert redact("abc stays") == "abc stays"
    assert redact("") == ""


def test_runner_redacts_program_output(monkeypatch):
    monkeypatch.setenv("DEMO_TOKEN", "tok-1234567890-abcdef")

    class L:
        def propose_code(self, task, feedback=None):
            return "print(1)"

    class R:
        success, exit_code = True, 0
        stdout, stderr = "leak tok-1234567890-abcdef", ""

    class S:
        def run(self, code):
            return R()

    report = SecureCodeRunner(L(), S()).run("t")
    assert "tok-1234567890-abcdef" not in report.stdout
