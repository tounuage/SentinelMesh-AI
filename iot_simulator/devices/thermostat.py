from datetime import datetime
from typing import Any

from iot_simulator.devices.base import VirtualDevice
from iot_simulator.models.attacks import AttackType
from iot_simulator.models.devices import DeviceType


class SmartThermostat(VirtualDevice):
    device_type = DeviceType.SMART_THERMOSTAT

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.setpoint_c = 21.5

    def _bootstrap_commands(self) -> list[tuple[int, str, str]]:
        return [(120, "set_mode", "owner"), (8, "set_setpoint", "home_hub")]

    def _sensors(
        self, now: datetime, hour: int, attacks: dict[AttackType, AttackIntensity]
    ) -> dict[str, Any]:
        ambient = 19.0 if hour < 7 else 22.4 if hour < 18 else 20.8
        if AttackType.UNAUTHORIZED_COMMANDS in attacks:
            self.setpoint_c = 32.0
        hvac = "heat" if ambient < self.setpoint_c - 0.4 else "cool" if ambient > self.setpoint_c + 0.6 else "idle"
        return {
            "ambient_temp_c": round(ambient, 2),
            "humidity_percent": 41 if hour < 12 else 47,
            "setpoint_c": self.setpoint_c,
            "hvac_mode": hvac,
            "fan": hvac != "idle",
            "occupancy": 7 <= hour <= 22,
            "eco_mode": hour >= 23 or hour < 6,
        }

    def _apply_safe_mode(self, sensors: dict[str, Any]) -> dict[str, Any]:
        sensors = super()._apply_safe_mode(sensors)
        self.setpoint_c = 18.5
        sensors["setpoint_c"] = 18.5
        sensors["hvac_mode"] = "idle"
        sensors["fan"] = False
        sensors["eco_mode"] = True
        sensors["controls_locked"] = True
        return sensors

    def _restore_operational_defaults(self) -> None:
        self.setpoint_c = 21.5

    def _baseline_watts(self, hour: int, sensors: dict[str, Any]) -> float:
        if sensors["hvac_mode"] == "idle":
            return 2.2
        return 18.0 if sensors["fan"] else 8.5

    def _normal_traffic(self, hour: int, sensors: dict[str, Any]) -> tuple[int, int]:
        return (3_200, 2_600)

    def _normal_command(self, hour: int, sensors: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        if sensors["eco_mode"]:
            return ("set_setpoint", "automation", {"setpoint_c": 18.5})
        return ("weather_sync", "hvac_cloud", {})

    def _unauthorized_command(self) -> tuple[str, dict[str, Any]]:
        return ("set_setpoint", {"setpoint_c": 32.0, "lock_controls": True})
