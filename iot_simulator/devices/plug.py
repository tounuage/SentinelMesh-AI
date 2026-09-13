from datetime import datetime
from typing import Any

from iot_simulator.devices.base import VirtualDevice
from iot_simulator.models.attacks import AttackType
from iot_simulator.models.devices import DeviceType


class SmartPlug(VirtualDevice):
    device_type = DeviceType.SMART_PLUG

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.relay_on = True
        self.load_name = "desk_lamp"

    def _bootstrap_commands(self) -> list[tuple[int, str, str]]:
        return [(90, "turn_on", "owner"), (12, "energy_report", "home_hub")]

    def _sensors(
        self, now: datetime, hour: int, attacks: dict[AttackType, AttackIntensity]
    ) -> dict[str, Any]:
        occupied = 7 <= hour <= 23
        self.relay_on = occupied or AttackType.ABNORMAL_POWER_USAGE in attacks
        return {
            "relay_on": self.relay_on,
            "load_name": self.load_name,
            "frequency_hz": 60.0,
            "power_factor": 0.97 if self.relay_on else 0.0,
            "in_rush_detected": False,
            "schedule_active": True,
        }

    def _apply_safe_mode(self, sensors: dict[str, Any]) -> dict[str, Any]:
        sensors = super()._apply_safe_mode(sensors)
        self.relay_on = False
        sensors["relay_on"] = False
        sensors["power_factor"] = 0.0
        return sensors

    def _restore_operational_defaults(self) -> None:
        self.relay_on = True

    def _baseline_watts(self, hour: int, sensors: dict[str, Any]) -> float:
        if not sensors["relay_on"]:
            return 0.6
        return 9.5 if 8 <= hour <= 22 else 2.1

    def _normal_traffic(self, hour: int, sensors: dict[str, Any]) -> tuple[int, int]:
        return (2_400, 1_800)

    def _normal_command(self, hour: int, sensors: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        if hour == 23:
            return ("turn_off", "automation", {"rule": "night_energy_saver"})
        return ("energy_report", "home_hub", {"interval_s": 30})

    def _unauthorized_command(self) -> tuple[str, dict[str, Any]]:
        return ("turn_on", {"bypass_schedule": True, "duration": "indefinite"})
