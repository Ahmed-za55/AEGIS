from aegis.core.models import SandboxResult
from aegis.core.policy import PermissionLevel
from aegis.core.tool import Tool
from aegis.runtime.sandbox import RuntimeSandbox


class SandboxTool(Tool):
    name = "sandbox"
    description = "Executes Python code inside the AEGIS runtime sandbox."
    permission_level = PermissionLevel.RESTRICTED

    def __init__(self, sandbox: RuntimeSandbox | None = None):
        self.sandbox = sandbox or RuntimeSandbox()

    def execute(self, code: str) -> SandboxResult:
        return self.sandbox.run(code)