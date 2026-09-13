from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class AttackType(str, Enum):
    ABNORMAL_NETWORK_TRAFFIC = "abnormal_network_traffic"
    UNAUTHORIZED_COMMANDS = "unauthorized_commands"
    SUSPICIOUS_IP_CONNECTIONS = "suspicious_ip_connections"
    FIRMWARE_MODIFICATION = "firmware_modification"
    ABNORMAL_POWER_USAGE = "abnormal_power_usage"


class AttackIntensity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AttackRequest(BaseModel):
    attack_type: AttackType
    device_id: str | None = Field(
        default=None,
        description="Target a specific device. If omitted, a compatible device is chosen.",
    )
    duration_seconds: int = Field(default=60, ge=5, le=3600)
    intensity: AttackIntensity = AttackIntensity.MEDIUM


class AttackStopRequest(BaseModel):
    attack_id: UUID | None = None
    device_id: str | None = None
