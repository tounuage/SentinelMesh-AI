from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import numpy as np

from iot_simulator.models.telemetry import TelemetrySample

if TYPE_CHECKING:
    from security_engine.profiles.baseline import DeviceBehaviorProfile

FEATURE_NAMES: tuple[str, ...] = (
    "packets_sent",
    "packets_recv",
    "bytes_sent_delta",
    "connection_count",
    "suspicious_peer_count",
    "unusual_port_count",
    "dns_query_count",
    "watts",
    "power_deviation_percent",
    "firmware_unsigned",
    "unauthorized_command_count",
    "command_count",
    "failed_pin_attempts",
    "tamper_switch",
    "suspicious_dns_count",
)

SUSPICIOUS_DNS_MARKERS = ("malicious", "exfil", "c2-", "dropzone", "example.test")


@dataclass
class BehavioralSignals:
    suspicious_ips: list[str] = field(default_factory=list)
    unusual_ports: list[int] = field(default_factory=list)
    unauthorized_commands: list[str] = field(default_factory=list)
    unauthorized_event_count: int = 0
    unsigned_firmware: bool = False
    firmware_version: str = ""
    firmware_changed: bool = False
    power_deviation_percent: float = 0.0
    watts: float = 0.0
    new_remote_ips: list[str] = field(default_factory=list)
    suspicious_dns: list[str] = field(default_factory=list)
    unauthorized_actors: list[str] = field(default_factory=list)


@dataclass
class FeatureVector:
    device_id: str
    device_type: str
    name: str
    names: tuple[str, ...]
    values: np.ndarray
    signals: BehavioralSignals

    def as_row(self) -> np.ndarray:
        return self.values.reshape(1, -1)


def _sensor_number(sensors: dict[str, Any], key: str) -> float:
    value = sensors.get(key, 0)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


class FeatureExtractor:
    """Maps IoT telemetry into a stable numeric vector plus forensic signals."""

    names = FEATURE_NAMES

    def extract(
        self,
        sample: TelemetrySample,
        profile: DeviceBehaviorProfile | None = None,
    ) -> FeatureVector:
        suspicious_peers = [
            conn.remote_ip
            for conn in sample.network.active_connections
            if conn.reputation == "suspicious"
        ]
        unauthorized = [cmd.command for cmd in sample.command_history if not cmd.authorized]
        unauthorized_actors = [
            cmd.actor for cmd in sample.command_history if not cmd.authorized
        ]
        unauthorized_sources = [
            cmd.source_ip for cmd in sample.command_history if not cmd.authorized
        ]
        suspicious_dns = [
            query
            for query in sample.network.dns_queries
            if any(marker in query.lower() for marker in SUSPICIOUS_DNS_MARKERS)
        ]
        last_bytes = profile.last_bytes_sent if profile and profile.last_bytes_sent else sample.network.bytes_sent
        bytes_delta = max(0, sample.network.bytes_sent - last_bytes)
        known_ips = profile.trusted_remote_ips if profile else set()
        new_ips = [
            conn.remote_ip
            for conn in sample.network.active_connections
            if known_ips and conn.remote_ip not in known_ips
        ]
        firmware_changed = bool(
            profile
            and profile.typical_firmware
            and sample.firmware_version != profile.typical_firmware
        )

        values = np.array(
            [
                float(sample.network.packets_sent),
                float(sample.network.packets_recv),
                float(bytes_delta),
                float(len(sample.network.active_connections)),
                float(len(suspicious_peers)),
                float(len(sample.network.unusual_ports)),
                float(len(sample.network.dns_queries)),
                float(sample.power.watts),
                float(sample.power.deviation_percent),
                0.0 if sample.firmware_signed else 1.0,
                float(len(unauthorized)),
                float(len(sample.command_history)),
                _sensor_number(sample.sensors, "failed_pin_attempts"),
                _sensor_number(sample.sensors, "tamper_switch"),
                float(len(suspicious_dns)),
            ],
            dtype=np.float64,
        )
        signals = BehavioralSignals(
            suspicious_ips=list(dict.fromkeys([*suspicious_peers, *unauthorized_sources])),
            unusual_ports=list(sample.network.unusual_ports),
            unauthorized_commands=list(dict.fromkeys(unauthorized)),
            unauthorized_event_count=len(unauthorized),
            unsigned_firmware=not sample.firmware_signed,
            firmware_version=sample.firmware_version,
            firmware_changed=firmware_changed,
            power_deviation_percent=sample.power.deviation_percent,
            watts=sample.power.watts,
            new_remote_ips=list(dict.fromkeys(new_ips)),
            suspicious_dns=list(dict.fromkeys(suspicious_dns)),
            unauthorized_actors=list(dict.fromkeys(unauthorized_actors)),
        )
        return FeatureVector(
            device_id=sample.device_id,
            device_type=sample.device_type.value,
            name=sample.name,
            names=self.names,
            values=values,
            signals=signals,
        )
