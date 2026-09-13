from datetime import datetime
from typing import Any

from iot_simulator.devices.base import VirtualDevice
from iot_simulator.models.attacks import AttackType
from iot_simulator.models.devices import DeviceType


class SmartCamera(VirtualDevice):
    device_type = DeviceType.SMART_CAMERA

    def _bootstrap_commands(self) -> list[tuple[int, str, str]]:
        return [
            (55, "arm_motion_detection", "owner"),
            (20, "snapshot", "home_hub"),
        ]

    def _sensors(
        self, now: datetime, hour: int, attacks: dict[AttackType, AttackIntensity]
    ) -> dict[str, Any]:
        night = hour < 6 or hour >= 21
        motion = 0.02 if 1 <= hour < 6 else 0.12 if hour < 18 else 0.28
        recording = night or motion > 0.2
        if AttackType.ABNORMAL_NETWORK_TRAFFIC in attacks:
            recording = True
            motion = min(1.0, motion + 0.5)
        return {
            "motion_probability": round(motion, 3),
            "lux": 4 if night else 420 if 10 <= hour <= 16 else 90,
            "night_vision": night,
            "recording": recording,
            "resolution": "1080p",
            "bitrate_kbps": 4500 if recording else 800,
            "storage_used_gb": 18.4,
            "camera_temp_c": 41.2 if recording else 33.1,
            "privacy_shutter_open": True,
        }

    def _apply_safe_mode(self, sensors: dict[str, Any]) -> dict[str, Any]:
        sensors = super()._apply_safe_mode(sensors)
        sensors["privacy_shutter_open"] = False
        sensors["recording"] = False
        sensors["bitrate_kbps"] = 0
        sensors["motion_probability"] = 0.0
        return sensors

    def _baseline_watts(self, hour: int, sensors: dict[str, Any]) -> float:
        return 7.8 if sensors["recording"] else 3.4

    def _normal_traffic(self, hour: int, sensors: dict[str, Any]) -> tuple[int, int]:
        if sensors["recording"]:
            return 180_000, 12_000
        return 18_000, 6_000

    def _normal_command(self, hour: int, sensors: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        if sensors["motion_probability"] > 0.2:
            return ("clip_upload", "nvr", {"clip_seconds": 12})
        return ("heartbeat", "camera_cloud", {})

    def _unauthorized_command(self) -> tuple[str, dict[str, Any]]:
        return ("disable_recording", {"privacy_shutter": "forced_open"})
