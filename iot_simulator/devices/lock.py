from datetime import datetime
from typing import Any

from iot_simulator.devices.base import VirtualDevice
from iot_simulator.models.attacks import AttackIntensity, AttackType
from iot_simulator.models.devices import DeviceType


class SmartLock(VirtualDevice):
    device_type = DeviceType.SMART_LOCK

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.locked = True
        self.door_ajar = False

    def _bootstrap_commands(self) -> list[tuple[int, str, str]]:
        return [(180, "lock", "owner"), (15, "status_poll", "home_hub")]

    def _sensors(
        self, now: datetime, hour: int, attacks: dict[AttackType, AttackIntensity]
    ) -> dict[str, Any]:
        if AttackType.UNAUTHORIZED_COMMANDS in attacks and not self.containment.safe_mode:
            self.locked = False
            self.door_ajar = True
        return {
            "locked": self.locked,
            "door_ajar": bool(self.door_ajar),
            "battery_percent": 76,
            "tamper_switch": AttackType.FIRMWARE_MODIFICATION in attacks,
            "failed_pin_attempts": 4 if AttackType.UNAUTHORIZED_COMMANDS in attacks else 0,
            "auto_relock_seconds": 8,
            "ble_clients": 1 if 7 <= hour <= 9 else 0,
        }

    def _apply_safe_mode(self, sensors: dict[str, Any]) -> dict[str, Any]:
        sensors = super()._apply_safe_mode(sensors)
        self.locked = True
        sensors["locked"] = True
        sensors["door_ajar"] = bool(self.door_ajar)
        sensors["auto_relock_seconds"] = 1
        sensors["remote_unlock_enabled"] = False
        return sensors

    def _restore_operational_defaults(self) -> None:
        self.locked = True
        self.door_ajar = False

    def _baseline_watts(self, hour: int, sensors: dict[str, Any]) -> float:
        return 1.6 if sensors["ble_clients"] else 0.9

    def _normal_traffic(self, hour: int, sensors: dict[str, Any]) -> tuple[int, int]:
        return (1_100, 900)

    def _normal_command(self, hour: int, sensors: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        if 7 <= hour <= 8:
            return ("unlock", "owner_phone", {"method": "ble"})
        return ("lock", "auto_relock", {})

    def _unauthorized_command(self) -> tuple[str, dict[str, Any]]:
        return ("unlock", {"method": "remote_api", "pin_bypass": True})
