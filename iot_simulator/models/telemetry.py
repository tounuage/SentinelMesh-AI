from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from iot_simulator.models.attacks import AttackIntensity, AttackType
from iot_simulator.models.devices import DeviceStatus, DeviceType


class NetworkConnection(BaseModel):
    remote_ip: str
    remote_port: int
    protocol: str
    direction: str
    bytes_transferred: int
    reputation: str = Field(description="trusted, unknown, or suspicious")
    process: str | None = None


class NetworkActivity(BaseModel):
    interface: str
    local_ip: str
    mac_address: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    active_connections: list[NetworkConnection]
    dns_queries: list[str]
    unusual_ports: list[int] = Field(default_factory=list)


class PowerConsumption(BaseModel):
    watts: float
    voltage: float
    current_amps: float
    energy_wh: float
    baseline_watts: float
    deviation_percent: float


class CommandRecord(BaseModel):
    timestamp: datetime
    command: str
    actor: str
    source_ip: str
    authorized: bool
    result: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContainmentReport(BaseModel):
    response_state: str = "normal"
    isolated: bool = False
    safe_mode: bool = False
    extra_telemetry: bool = False
    blocked_ips: list[str] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    revoked_permissions: list[str] = Field(default_factory=list)
    denied_commands: list[str] = Field(default_factory=list)
    allowed_peers: list[str] = Field(default_factory=list)
    network_mode: str = "allow_all"
    detected_at: datetime | None = None
    requested_at: datetime | None = None
    applied_at: datetime | None = None
    first_denied_at: datetime | None = None


class IncidentStep(BaseModel):
    id: str
    label: str
    kind: Literal["intended", "observed"]
    complete: bool = False
    at: datetime | None = None
    detail: str = ""


class ActionOutcome(BaseModel):
    label: str
    intended: str
    observed: str
    matched: bool


class VerifiedContainment(BaseModel):
    device_id: str
    verified: bool = False
    detection_latency_ms: float | None = None
    containment_latency_ms: float | None = None
    intended: list[str] = Field(default_factory=list)
    observed: list[str] = Field(default_factory=list)
    outcomes: list[ActionOutcome] = Field(default_factory=list)
    sequence: list[IncidentStep] = Field(default_factory=list)


class TelemetrySample(BaseModel):
    timestamp: datetime
    device_id: str
    device_type: DeviceType
    name: str
    room: str
    status: DeviceStatus
    firmware_version: str
    firmware_signed: bool
    firmware_checksum: str
    last_firmware_change: datetime | None = None
    network: NetworkActivity
    power: PowerConsumption
    sensors: dict[str, Any]
    command_history: list[CommandRecord]
    anomaly_indicators: list[str] = Field(default_factory=list)
    attack_signals: list[str] = Field(default_factory=list)
    containment: ContainmentReport = Field(default_factory=ContainmentReport)
    verified_containment: VerifiedContainment | None = None


class DeviceSnapshot(BaseModel):
    device_id: str
    device_type: DeviceType
    name: str
    room: str
    status: DeviceStatus
    firmware_version: str
    response_state: str = "normal"
    contained: bool = False
    latest_telemetry: TelemetrySample | None = None


class ActiveAttack(BaseModel):
    attack_id: UUID
    attack_type: AttackType
    device_id: str
    intensity: AttackIntensity
    started_at: datetime
    expires_at: datetime


class EnvironmentSnapshot(BaseModel):
    generated_at: datetime
    tick: int
    devices: list[TelemetrySample]
    active_attacks: list[ActiveAttack]
