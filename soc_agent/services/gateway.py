"""Agent Gateway stand-in: unified routing + policy enforcement in front of the action agent.

Only the action agent identity may call through this gateway, and only with
one of the allowed action types. This is the single choke point that can
touch anything external — everything upstream (ingestion, triage) is
read-only by construction, not just by convention.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

ActionType = Literal["escalated", "closed", "notified"]

ALLOWED_IDENTITY = "action-agent"
ALLOWED_ACTIONS: tuple[ActionType, ...] = ("escalated", "closed", "notified")


class GatewayPolicyError(Exception):
    pass


@dataclass
class ActionRecord:
    type: ActionType
    actor_agent_identity: str
    executed_at: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "actor_agent_identity": self.actor_agent_identity,
            "executed_at": self.executed_at,
        }


def execute_action(actor_identity: str, action_type: str) -> ActionRecord:
    if actor_identity != ALLOWED_IDENTITY:
        raise GatewayPolicyError(
            f"identity '{actor_identity}' is not authorized to call the Agent Gateway"
        )
    if action_type not in ALLOWED_ACTIONS:
        raise GatewayPolicyError(f"action_type '{action_type}' is not in the allowed policy set")

    return ActionRecord(
        type=action_type,  # type: ignore[arg-type]
        actor_agent_identity=actor_identity,
        executed_at=datetime.now(timezone.utc).isoformat(),
    )
