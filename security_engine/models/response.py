from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class ResponseState(str, Enum):
    NORMAL = "normal"
    MONITOR = "monitor"
    RESTRICTED = "restricted"
    QUARANTINE = "quarantine"


class DeviceActionRequest(BaseModel):
    device_id: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=100.0)
    threat_type: str


class RecoverRequest(BaseModel):
    device_id: str = Field(min_length=1)
    force: bool = False


class NetworkBlockingEffect(BaseModel):
    applied: bool
    mode: str
    blocked_peers: list[str] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_peers: list[str] = Field(default_factory=list)
    description: str


class PermissionReductionEffect(BaseModel):
    applied: bool
    revoked: list[str] = Field(default_factory=list)
    remaining: list[str] = Field(default_factory=list)
    description: str


class SafeOperationEffect(BaseModel):
    applied: bool
    actions: list[str] = Field(default_factory=list)
    description: str


class RecoveryEffect(BaseModel):
    eligible: bool
    in_progress: bool
    restored: list[str] = Field(default_factory=list)
    next_state: ResponseState | None = None
    conditions: str
    description: str


class TelemetryPolicy(BaseModel):
    collect_additional: bool
    packet_capture: bool
    dns_logging: bool
    command_audit: str
    sample_multiplier: int = 1


class SimulatedEffects(BaseModel):
    network_blocking: NetworkBlockingEffect
    permission_reduction: PermissionReductionEffect
    safe_operation_mode: SafeOperationEffect
    recovery: RecoveryEffect


class DefensiveAction(BaseModel):
    action_id: UUID
    timestamp: datetime
    device_id: str
    device_kind: str
    risk_score: float
    threat_type: str
    previous_state: ResponseState
    response_state: ResponseState
    transition: str
    autonomous: bool = True
    action: str
    rationale: str
    steps_executed: list[str]
    effects: SimulatedEffects
    telemetry_policy: TelemetryPolicy
    enforced: bool = False
    enforcement_target: str | None = None


class ContainmentApplyRequest(BaseModel):
    device_id: str
    response_state: ResponseState
    blocked_peers: list[str] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    revoked_permissions: list[str] = Field(default_factory=list)
    allowed_peers: list[str] = Field(default_factory=list)
    safe_mode: bool = False
    extra_telemetry: bool = False
    isolated: bool = False
    recover: bool = False
    full_recovery: bool = False


class DeviceResponseStatus(BaseModel):
    device_id: str
    response_state: ResponseState
    last_risk_score: float
    last_threat_type: str
    consecutive_low_scores: int
    last_action: DefensiveAction | None = None


class ControllerHeartbeat(BaseModel):
    active: bool
    fresh: bool = False
    last_beat_at: datetime | None = None
    cycle_count: int = 0
    last_error: str | None = None
    poll_interval_seconds: float
    heartbeat_stale_seconds: float
    enforcement_enabled: bool = True
    last_enforced_at: datetime | None = None
    last_ingest_count: int = 0
    bootstrapped: bool = False


class ControllerUpdate(BaseModel):
    enforcement_enabled: bool | None = None
