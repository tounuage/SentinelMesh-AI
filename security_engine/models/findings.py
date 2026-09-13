from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    BENIGN = "benign"
    ABNORMAL_NETWORK_TRAFFIC = "abnormal_network_traffic"
    UNAUTHORIZED_COMMANDS = "unauthorized_commands"
    SUSPICIOUS_IP_CONNECTIONS = "suspicious_ip_connections"
    FIRMWARE_MODIFICATION = "firmware_modification"
    ABNORMAL_POWER_USAGE = "abnormal_power_usage"
    MULTI_STAGE_COMPROMISE = "multi_stage_compromise"
    UNKNOWN_ANOMALY = "unknown_anomaly"


class DetectorResult(BaseModel):
    detector: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    details: dict[str, Any] = Field(default_factory=dict)
    contributing_features: list[str] = Field(default_factory=list)


class PhysicalAssessment(BaseModel):
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    hazard: str = "none"
    severity: str = "none"
    consequences: list[str] = Field(default_factory=list)
    safe_mode: str = ""


class AnalysisResult(BaseModel):
    device: str
    risk_score: float = Field(ge=0.0, le=100.0)
    threat_type: str
    explanation: str
    recommended_action: str
    response_state: str | None = None
    defensive_action: str | None = None
    physical: PhysicalAssessment = Field(default_factory=PhysicalAssessment)
    source: str = "engine"


class CorrelatedEvent(BaseModel):
    device_id: str
    device_name: str
    device_type: str
    command: str
    source_ip: str
    timestamp: datetime
    authorized: bool
    result: str


class MeshIncident(BaseModel):
    """One cross-device incident produced by a deterministic correlation rule."""

    id: str
    title: str
    detail: str
    method: str
    rule: str
    window_seconds: float
    source_ip: str
    device_ids: list[str]
    sequence: list[CorrelatedEvent] = Field(default_factory=list)
    observed_at: datetime
    delta_seconds: float
    explanation: str
