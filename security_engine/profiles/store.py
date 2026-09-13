from __future__ import annotations

from security_engine.features.extractor import FeatureVector
from security_engine.profiles.baseline import DeviceBehaviorProfile
from iot_simulator.models.telemetry import TelemetrySample


class ProfileStore:
    def __init__(self) -> None:
        self._profiles: dict[str, DeviceBehaviorProfile] = {}

    def get(self, device_id: str) -> DeviceBehaviorProfile | None:
        return self._profiles.get(device_id)

    def get_or_create(self, sample: TelemetrySample) -> DeviceBehaviorProfile:
        profile = self._profiles.get(sample.device_id)
        if profile is None:
            profile = DeviceBehaviorProfile(
                device_id=sample.device_id,
                device_type=sample.device_type.value,
                name=sample.name,
            )
            self._profiles[sample.device_id] = profile
        return profile

    def update_from_sample(self, sample: TelemetrySample, vector: FeatureVector) -> DeviceBehaviorProfile:
        profile = self.get_or_create(sample)
        trusted_ips = [
            conn.remote_ip
            for conn in sample.network.active_connections
            if conn.reputation == "trusted"
        ]
        commands = [cmd.command for cmd in sample.command_history if cmd.authorized]
        profile.update(
            vector=vector,
            sample_ips=trusted_ips,
            sample_ports=[
                conn.remote_port
                for conn in sample.network.active_connections
                if conn.reputation == "trusted"
            ],
            dns=list(sample.network.dns_queries),
            commands=commands,
            firmware=sample.firmware_version,
            bytes_sent=sample.network.bytes_sent,
        )
        return profile

    def all(self) -> list[DeviceBehaviorProfile]:
        return list(self._profiles.values())

    def clear(self) -> None:
        self._profiles.clear()
