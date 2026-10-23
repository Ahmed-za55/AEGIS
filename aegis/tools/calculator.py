from typing import Any

from aegis.core.policy import PermissionLevel
from aegis.core.tool import Tool


class CalculatorTool(Tool):

    name = "calculator"

    description = "Performs basic arithmetic operations."

    permission_level = PermissionLevel.SAFE

    def execute(
        self,
        operation: str,
        a: float,
        b: float,
    ) -> Any:

        if operation == "add":
            return a + b

        if operation == "subtract":
            return a - b

        if operation == "multiply":
            return a * b

        if operation == "divide":

            if b == 0:
                raise ValueError(
                    "Cannot divide by zero."
                )

            return a / b

        raise ValueError(
            f"Unknown operation: {operation}"
        )