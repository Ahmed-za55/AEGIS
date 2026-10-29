from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy


def unsafe_sandbox(**kwargs):
    """Test-only: RuntimeSandbox with explicit opt-in to unisolated local run."""
    if "security_policy" not in kwargs:
        kwargs["security_policy"] = SandboxSecurityPolicy(
            allow_network=kwargs.pop("allow_network", False),
            allow_unsafe_local=True,
        )
    return RuntimeSandbox(**kwargs)
