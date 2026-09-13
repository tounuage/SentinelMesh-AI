from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from security_engine.models.response import ContainmentApplyRequest, DefensiveAction, ResponseState
from security_engine.response.effects import CONTROLLER_PEER


@dataclass
class DeviceContainment:
    state: ResponseState = ResponseState.NORMAL
    isolated: bool = False
    extra_telemetry: bool = False
    safe_mode: bool = False
    blocked_ips: list[str] = field(default_factory=list)
    blocked_ports: list[int] = field(default_factory=list)
    revoked_permissions: list[str] = field(default_factory=list)
    allowed_peers: list[str] = field(default_factory=list)
    denied_commands: list[str] = field(default_factory=list)
    detected_at: datetime | None = None
    requested_at: datetime | None = None
    applied_at: datetime | None = None
    first_denied_at: datetime | None = None

    @property
    def network_mode(self) -> str:
        if self.state == ResponseState.QUARANTINE:
            return "full_isolation"
        if self.state == ResponseState.RESTRICTED:
            return "trusted_only"
        if self.state == ResponseState.MONITOR:
            return "capture"
        return "allow_all"

    def apply_action(self, action: DefensiveAction, at: datetime | None = None) -> None:
        effects = action.effects
        entering = self.state not in {ResponseState.RESTRICTED, ResponseState.QUARANTINE} and action.response_state in {
            ResponseState.RESTRICTED,
            ResponseState.QUARANTINE,
        }
        stamp = at or datetime.now(UTC)
        self.state = action.response_state
        self.isolated = action.response_state == ResponseState.QUARANTINE
        self.safe_mode = action.response_state in {
            ResponseState.RESTRICTED,
            ResponseState.QUARANTINE,
        }
        self.extra_telemetry = action.telemetry_policy.collect_additional
        self.blocked_ips = list(effects.network_blocking.blocked_peers)
        self.blocked_ports = list(effects.network_blocking.blocked_ports)
        self.revoked_permissions = list(effects.permission_reduction.revoked)
        self.allowed_peers = list(effects.network_blocking.allowed_peers) or [CONTROLLER_PEER]
        self.denied_commands = []
        if action.response_state in {ResponseState.RESTRICTED, ResponseState.QUARANTINE}:
            self.requested_at = self.requested_at or action.timestamp or stamp
            self.applied_at = stamp
            if entering:
                self.first_denied_at = None
        if action.response_state == ResponseState.NORMAL:
            self.clear()

    def apply_request(self, request: ContainmentApplyRequest, at: datetime | None = None) -> None:
        entering = self.state not in {ResponseState.RESTRICTED, ResponseState.QUARANTINE} and request.response_state in {
            ResponseState.RESTRICTED,
            ResponseState.QUARANTINE,
        }
        stamp = at or datetime.now(UTC)
        self.state = request.response_state
        self.isolated = request.isolated or request.response_state == ResponseState.QUARANTINE
        self.safe_mode = request.safe_mode or request.response_state in {
            ResponseState.RESTRICTED,
            ResponseState.QUARANTINE,
        }
        self.extra_telemetry = request.extra_telemetry or request.response_state != ResponseState.NORMAL
        self.blocked_ips = list(request.blocked_peers)
        self.blocked_ports = list(request.blocked_ports)
        self.revoked_permissions = list(request.revoked_permissions)
        self.allowed_peers = list(request.allowed_peers) or [CONTROLLER_PEER]
        self.denied_commands = []
        if request.response_state in {ResponseState.RESTRICTED, ResponseState.QUARANTINE}:
            self.requested_at = self.requested_at or stamp
            self.applied_at = stamp
            if entering:
                self.first_denied_at = None
        if request.full_recovery or request.response_state == ResponseState.NORMAL:
            self.clear()

    def clear(self) -> None:
        self.state = ResponseState.NORMAL
        self.isolated = False
        self.extra_telemetry = False
        self.safe_mode = False
        self.blocked_ips = []
        self.blocked_ports = []
        self.revoked_permissions = []
        self.allowed_peers = ["*"]
        self.denied_commands = []
        self.detected_at = None
        self.requested_at = None
        self.applied_at = datetime.now(UTC)
        self.first_denied_at = None
