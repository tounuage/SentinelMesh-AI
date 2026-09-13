from __future__ import annotations

import httpx

from security_engine.config import settings
from security_engine.models.response import ContainmentApplyRequest, DefensiveAction


class SimulatorEnforcer:
    """Pushes autonomous decisions onto the IoT simulator enforcement plane."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or settings.simulator_url).rstrip("/")

    def apply(self, action: DefensiveAction) -> bool:
        payload = ContainmentApplyRequest(
            device_id=action.device_id,
            response_state=action.response_state,
            blocked_peers=action.effects.network_blocking.blocked_peers,
            blocked_ports=action.effects.network_blocking.blocked_ports,
            revoked_permissions=action.effects.permission_reduction.revoked,
            allowed_peers=action.effects.network_blocking.allowed_peers,
            safe_mode=action.effects.safe_operation_mode.applied,
            extra_telemetry=action.telemetry_policy.collect_additional,
            isolated=action.response_state.value == "quarantine",
            recover=action.transition in {"recovering", "recovered", "forced_recovery"},
            full_recovery=action.response_state.value == "normal"
            and action.transition in {"recovered", "forced_recovery"},
        )
        try:
            with httpx.Client(timeout=2.0) as client:
                response = client.post(
                    f"{self.base_url}/api/v1/containment/apply",
                    json=payload.model_dump(mode="json"),
                )
                return response.status_code < 300
        except httpx.HTTPError:
            return False
