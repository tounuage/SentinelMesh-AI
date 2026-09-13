from enum import Enum


class DeviceType(str, Enum):
    SMART_CAMERA = "smart_camera"
    SMART_PLUG = "smart_plug"
    SMART_THERMOSTAT = "smart_thermostat"
    SMART_LOCK = "smart_lock"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    COMPROMISED = "compromised"
    MONITORING = "monitoring"
    RESTRICTED = "restricted"
    QUARANTINED = "quarantined"
