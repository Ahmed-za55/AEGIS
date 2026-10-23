from dataclasses import dataclass
from enum import Enum


class PermissionLevel(str, Enum):
    SAFE = "SAFE"
    RESTRICTED = "RESTRICTED"
    DANGEROUS = "DANGEROUS"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:

    def __init__(
        self,
        max_allowed_level: PermissionLevel = PermissionLevel.SAFE,
    ):
        self.max_allowed_level = max_allowed_level

    def authorize(
        self,
        tool_level: PermissionLevel,
    ) -> PolicyDecision:

        levels = {
            PermissionLevel.SAFE: 0,
            PermissionLevel.RESTRICTED: 1,
            PermissionLevel.DANGEROUS: 2,
        }

        allowed = (
            levels[tool_level]
            <= levels[self.max_allowed_level]
        )

        if allowed:
            return PolicyDecision(
                allowed=True,
                reason=(
                    f"Tool permission level "
                    f"{tool_level.value} is allowed."
                ),
            )

        return PolicyDecision(
            allowed=False,
            reason=(
                f"Tool permission level "
                f"{tool_level.value} exceeds "
                f"maximum allowed level "
                f"{self.max_allowed_level.value}."
            ),
        )