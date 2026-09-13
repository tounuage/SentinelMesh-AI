from __future__ import annotations

import hashlib
import random
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from iot_simulator.config import settings
from iot_simulator.models.attacks import AttackIntensity, AttackType
from iot_simulator.models.devices import DeviceStatus, DeviceType
from iot_simulator.models.telemetry import (
    CommandRecord,
    ContainmentReport,
    NetworkActivity,
    NetworkConnection,
    PowerConsumption,
    TelemetrySample,
)
from iot_simulator.simulation.containment import DeviceContainment
from security_engine.models.response import ContainmentApplyRequest, DefensiveAction, ResponseState
from security_engine.response.effects import CONTROLLER_PEER

INTENSITY_MULTIPLIER = {
    AttackIntensity.LOW: 1.8,
    AttackIntensity.MEDIUM: 4.0,
    AttackIntensity.HIGH: 9.0,
}

TRUSTED_CLOUD = {
    DeviceType.SMART_CAMERA: ("52.12.88.21", "camera-cloud.sentinelmesh.local", 443),
    DeviceType.SMART_PLUG: ("3.21.45.90", "mqtt.homehub.local", 8883),
    DeviceType.SMART_THERMOSTAT: ("18.210.11.44", "hvac-api.sentinelmesh.local", 443),
    DeviceType.SMART_LOCK: ("34.201.9.18", "lock-api.sentinelmesh.local", 443),
}

SUSPICIOUS_ENDPOINTS = [
    ("203.0.113.66", 4444, "tcp"),
    ("198.51.100.77", 6667, "tcp"),
    ("203.0.113.91", 8089, "tcp"),
    ("198.51.100.23", 53, "udp"),
]

# One hostile session across devices so observed-source correlation can fire.
HOSTILE_COMMAND_SOURCE_IP = "203.0.113.66"


class VirtualDevice:
    device_type: DeviceType

    def __init__(
        self,
        device_id: str,
        name: str,
        room: str,
        local_ip: str,
        mac_address: str,
        firmware_version: str,
    ) -> None:
        self.rng = random.Random()
        self.behavior_hour: int | None = None
        self.device_id = device_id
        self.name = name
        self.room = room
        self.local_ip = local_ip
        self.mac_address = mac_address
        self.firmware_version = firmware_version
        self._stock_firmware = firmware_version
        self.firmware_signed = True
        self.firmware_payload = f"{device_id}:{firmware_version}:signed"
        self.last_firmware_change: datetime | None = None
        self.status = DeviceStatus.ONLINE
        self.energy_wh = self.rng.uniform(12.0, 80.0)
        self.command_history: deque[CommandRecord] = deque(
            maxlen=settings.command_history_limit
        )
        self._bytes_sent = self.rng.randint(50_000, 250_000)
        self._bytes_recv = self.rng.randint(80_000, 400_000)
        self._firmware_tampered = False
        self.containment = DeviceContainment()
        self._seed_normal_commands()

    def tick(
        self, now: datetime, active_attacks: dict[AttackType, AttackIntensity]
    ) -> TelemetrySample:
        hour = now.hour if self.behavior_hour is None else self.behavior_hour
        sensors = self._sensors(now, hour, active_attacks)
        if self.containment.safe_mode:
            sensors = self._apply_safe_mode(sensors)
        baseline_watts = self._baseline_watts(hour, sensors)
        power = self._power(baseline_watts, active_attacks)
        if self.containment.safe_mode:
            power = self._cap_power(power, baseline_watts)
        network = self._network(now, hour, sensors, active_attacks)
        network = self._enforce_network(network)
        self._maybe_issue_normal_command(now, hour, sensors, active_attacks)
        self._apply_unauthorized_commands(now, active_attacks)
        self._apply_firmware_attack(now, active_attacks)
        if self.containment.extra_telemetry:
            sensors = self._enrich_telemetry(sensors, network)

        indicators, signals, status = self._classify(network, power, active_attacks)
        self.status = status
        self.energy_wh += power.watts * (settings.tick_interval_seconds / 3600.0)

        return TelemetrySample(
            timestamp=now,
            device_id=self.device_id,
            device_type=self.device_type,
            name=self.name,
            room=self.room,
            status=self.status,
            firmware_version=self.firmware_version,
            firmware_signed=self.firmware_signed,
            firmware_checksum=self._checksum(),
            last_firmware_change=self.last_firmware_change,
            network=network,
            power=power,
            sensors=sensors,
            command_history=list(self.command_history),
            anomaly_indicators=indicators,
            attack_signals=signals,
            containment=self._containment_report(),
        )

    def reset(self, seed: str | None = None, behavior_hour: int | None = None) -> None:
        self.rng.seed(seed)
        self.behavior_hour = behavior_hour
        self.command_history.clear()
        self.containment.clear()
        self._seed_normal_commands()
        self.energy_wh = self.rng.uniform(12.0, 80.0)
        self._bytes_sent = self.rng.randint(50_000, 250_000)
        self._bytes_recv = self.rng.randint(80_000, 400_000)
        self.firmware_version = self._stock_firmware
        self.firmware_signed = True
        self.firmware_payload = f"{self.device_id}:{self.firmware_version}:signed"
        self.last_firmware_change = None
        self.status = DeviceStatus.ONLINE
        self._firmware_tampered = False
        self._restore_operational_defaults()

    def apply_response(self, action: DefensiveAction, at: datetime | None = None) -> None:
        previous = self.containment.state
        self.containment.apply_action(action, at=at)
        if action.response_state == ResponseState.NORMAL:
            self._recover_device(full=True)
        elif previous in {ResponseState.QUARANTINE, ResponseState.RESTRICTED} and action.transition in {
            "recovering",
            "recovered",
            "forced_recovery",
        }:
            self._recover_device(full=action.response_state == ResponseState.NORMAL)

    def apply_containment(self, request: ContainmentApplyRequest, at: datetime | None = None) -> None:
        self.containment.apply_request(request, at=at)
        if request.full_recovery or request.response_state == ResponseState.NORMAL:
            self._recover_device(full=True)
        elif request.recover:
            self._recover_device(full=False)

    def _recover_device(self, full: bool) -> None:
        self.firmware_version = self._stock_firmware
        self.firmware_signed = True
        self.firmware_payload = f"{self.device_id}:{self.firmware_version}:signed"
        self._firmware_tampered = False
        if full:
            self._restore_operational_defaults()
            self.containment.clear()

    def _restore_operational_defaults(self) -> None:
        return

    def _apply_safe_mode(self, sensors: dict[str, Any]) -> dict[str, Any]:
        sensors = dict(sensors)
        sensors["safe_mode"] = True
        sensors["remote_admin"] = False
        return sensors

    def _checksum(self) -> str:
        return hashlib.sha256(self.firmware_payload.encode()).hexdigest()[:16]

    def _seed_clock(self) -> datetime:
        if self.behavior_hour is None:
            return datetime.now(UTC)
        return datetime(2026, 9, 14, self.behavior_hour, 0, tzinfo=UTC)

    def _seed_normal_commands(self) -> None:
        now = self._seed_clock()
        for minutes_ago, command, actor in self._bootstrap_commands():
            self.command_history.append(
                CommandRecord(
                    timestamp=now - timedelta(minutes=minutes_ago),
                    command=command,
                    actor=actor,
                    source_ip="192.168.1.10",
                    authorized=True,
                    result="ok",
                )
            )

    def _bootstrap_commands(self) -> list[tuple[int, str, str]]:
        return [(40, "heartbeat_ack", "controller")]

    def _sensors(
        self, now: datetime, hour: int, attacks: dict[AttackType, AttackIntensity]
    ) -> dict[str, Any]:
        raise NotImplementedError

    def _baseline_watts(self, hour: int, sensors: dict[str, Any]) -> float:
        raise NotImplementedError

    def _power(
        self, baseline: float, attacks: dict[AttackType, AttackIntensity]
    ) -> PowerConsumption:
        noise = self.rng.uniform(-0.08, 0.08) * baseline
        watts = max(0.4, baseline + noise)
        if AttackType.ABNORMAL_POWER_USAGE in attacks:
            watts *= INTENSITY_MULTIPLIER[attacks[AttackType.ABNORMAL_POWER_USAGE]]
        voltage = self.rng.uniform(118.5, 121.5)
        current = watts / voltage
        deviation = ((watts - baseline) / baseline) * 100 if baseline else 0.0
        return PowerConsumption(
            watts=round(watts, 3),
            voltage=round(voltage, 2),
            current_amps=round(current, 4),
            energy_wh=round(self.energy_wh, 3),
            baseline_watts=round(baseline, 3),
            deviation_percent=round(deviation, 2),
        )

    def _network(
        self,
        now: datetime,
        hour: int,
        sensors: dict[str, Any],
        attacks: dict[AttackType, AttackIntensity],
    ) -> NetworkActivity:
        sent, recv = self._normal_traffic(hour, sensors)
        connections = [self._trusted_connection(sent // 2)]
        dns = [TRUSTED_CLOUD[self.device_type][1], "time.nist.gov"]
        unusual_ports: list[int] = []

        if AttackType.ABNORMAL_NETWORK_TRAFFIC in attacks:
            factor = INTENSITY_MULTIPLIER[attacks[AttackType.ABNORMAL_NETWORK_TRAFFIC]]
            sent = int(sent * factor * 12)
            recv = int(recv * factor * 4)
            unusual_ports.extend([4444, 6667, 31337])
            connections.append(
                NetworkConnection(
                    remote_ip="203.0.113.66",
                    remote_port=4444,
                    protocol="tcp",
                    direction="outbound",
                    bytes_transferred=sent // 3,
                    reputation="suspicious",
                    process="unknown_bin",
                )
            )
            dns.append("c2-dropzone.example.test")

        if AttackType.SUSPICIOUS_IP_CONNECTIONS in attacks:
            intensity = attacks[AttackType.SUSPICIOUS_IP_CONNECTIONS]
            count = 2 if intensity == AttackIntensity.LOW else 4 if intensity == AttackIntensity.MEDIUM else 6
            for ip, port, proto in self.rng.sample(SUSPICIOUS_ENDPOINTS, k=min(count, len(SUSPICIOUS_ENDPOINTS))):
                connections.append(
                    NetworkConnection(
                        remote_ip=ip,
                        remote_port=port,
                        protocol=proto,
                        direction="outbound",
                        bytes_transferred=self.rng.randint(8_000, 90_000),
                        reputation="suspicious",
                        process="firmware_agent",
                    )
                )
            dns.extend(["update-cdn.malicious.test", "exfil.example.test"])

        self._bytes_sent += sent
        self._bytes_recv += recv
        return NetworkActivity(
            interface="wlan0",
            local_ip=self.local_ip,
            mac_address=self.mac_address,
            bytes_sent=self._bytes_sent,
            bytes_recv=self._bytes_recv,
            packets_sent=max(1, sent // 800),
            packets_recv=max(1, recv // 900),
            active_connections=connections,
            dns_queries=dns,
            unusual_ports=unusual_ports,
        )

    def _normal_traffic(self, hour: int, sensors: dict[str, Any]) -> tuple[int, int]:
        raise NotImplementedError

    def _trusted_connection(self, bytes_transferred: int) -> NetworkConnection:
        ip, _, port = TRUSTED_CLOUD[self.device_type]
        return NetworkConnection(
            remote_ip=ip,
            remote_port=port,
            protocol="tls",
            direction="outbound",
            bytes_transferred=max(200, bytes_transferred),
            reputation="trusted",
            process="device_agent",
        )

    def _maybe_issue_normal_command(
        self,
        now: datetime,
        hour: int,
        sensors: dict[str, Any],
        attacks: dict[AttackType, AttackIntensity],
    ) -> None:
        if AttackType.UNAUTHORIZED_COMMANDS in attacks:
            return
        if self.containment.state == ResponseState.QUARANTINE:
            return
        if self.rng.random() > 0.18:
            return
        command, actor, metadata = self._normal_command(hour, sensors)
        if self.containment.state == ResponseState.RESTRICTED and command in {
            "unlock",
            "turn_on",
            "set_setpoint",
            "firmware_flash",
        }:
            self.command_history.append(
                CommandRecord(
                    timestamp=now,
                    command=command,
                    actor=actor,
                    source_ip="192.168.1.10",
                    authorized=True,
                    result="denied_by_containment",
                    metadata={**metadata, "policy": self.containment.state.value},
                )
            )
            self.containment.denied_commands.append(command)
            return
        self.command_history.append(
            CommandRecord(
                timestamp=now,
                command=command,
                actor=actor,
                source_ip="192.168.1.10",
                authorized=True,
                result="ok",
                metadata=metadata,
            )
        )

    def _normal_command(self, hour: int, sensors: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        return ("sync_state", "home_hub", {})

    def _apply_unauthorized_commands(
        self, now: datetime, attacks: dict[AttackType, AttackIntensity]
    ) -> None:
        if AttackType.UNAUTHORIZED_COMMANDS not in attacks:
            return
        intensity = attacks[AttackType.UNAUTHORIZED_COMMANDS]
        burst = 1 if intensity == AttackIntensity.LOW else 2 if intensity == AttackIntensity.MEDIUM else 3
        blocked = self.containment.state in {ResponseState.RESTRICTED, ResponseState.QUARANTINE}
        for _ in range(burst):
            command, metadata = self._unauthorized_command()
            result = "denied_by_containment" if blocked else "accepted_without_authz"
            wall = datetime.now(UTC)
            if not blocked and self.containment.detected_at is None:
                self.containment.detected_at = wall
            # Camera casing precedes the lock when both fire on the same tick.
            stamp = now - timedelta(seconds=3) if self.device_type == DeviceType.SMART_CAMERA else now
            self.command_history.append(
                CommandRecord(
                    timestamp=stamp,
                    command=command,
                    actor="unknown_session",
                    source_ip=HOSTILE_COMMAND_SOURCE_IP,
                    authorized=False,
                    result=result,
                    metadata={**metadata, "blocked": blocked, "policy": self.containment.state.value},
                )
            )
            if blocked:
                self.containment.denied_commands.append(command)
                if self.containment.first_denied_at is None:
                    self.containment.first_denied_at = wall

    def _unauthorized_command(self) -> tuple[str, dict[str, Any]]:
        return ("debug_shell", {"channel": "telnet"})

    def _apply_firmware_attack(
        self, now: datetime, attacks: dict[AttackType, AttackIntensity]
    ) -> None:
        if AttackType.FIRMWARE_MODIFICATION not in attacks or self._firmware_tampered:
            return
        if self.containment.state in {ResponseState.RESTRICTED, ResponseState.QUARANTINE}:
            self.command_history.append(
                CommandRecord(
                    timestamp=now,
                    command="firmware_flash",
                    actor="unsigned_updater",
                    source_ip="203.0.113.91",
                    authorized=False,
                    result="ota_blocked_by_containment",
                    metadata={"signed": False, "channel": "ota_sideload", "blocked": True},
                )
            )
            self.containment.denied_commands.append("firmware_flash")
            return
        self._firmware_tampered = True
        intensity = attacks[AttackType.FIRMWARE_MODIFICATION]
        unsigned = intensity != AttackIntensity.LOW
        self.firmware_signed = not unsigned
        bump = {"low": "99", "medium": "1337", "high": "0.0.0-backdoor"}[intensity.value]
        self.firmware_version = f"{self.firmware_version.split('+')[0]}+{bump}"
        self.firmware_payload = f"{self.device_id}:{self.firmware_version}:tampered:{now.isoformat()}"
        self.last_firmware_change = now
        self.command_history.append(
            CommandRecord(
                timestamp=now,
                command="firmware_flash",
                actor="unsigned_updater",
                source_ip="203.0.113.91",
                authorized=False,
                result="checksum_mismatch",
                metadata={"signed": False, "channel": "ota_sideload"},
            )
        )

    def _classify(
        self,
        network: NetworkActivity,
        power: PowerConsumption,
        attacks: dict[AttackType, AttackIntensity],
    ) -> tuple[list[str], list[str], DeviceStatus]:
        indicators: list[str] = []
        signals = [attack.value for attack in attacks]
        if any(c.reputation == "suspicious" for c in network.active_connections):
            indicators.append("suspicious_remote_endpoint")
        if network.unusual_ports:
            indicators.append("nonstandard_egress_ports")
        if power.deviation_percent > 80:
            indicators.append("power_draw_spike")
        if not self.firmware_signed:
            indicators.append("unsigned_firmware")
        if any(not cmd.authorized and cmd.result != "denied_by_containment" for cmd in list(self.command_history)[-5:]):
            indicators.append("unauthorized_command_burst")
        if self.containment.denied_commands:
            indicators.append("containment_denied_commands")
        if self.containment.isolated:
            indicators.append("device_isolated")
        if self.containment.state == ResponseState.RESTRICTED:
            indicators.append("suspicious_traffic_blocked")

        if self.containment.state == ResponseState.QUARANTINE:
            status = DeviceStatus.QUARANTINED
        elif self.containment.state == ResponseState.RESTRICTED:
            status = DeviceStatus.RESTRICTED
        elif self.containment.state == ResponseState.MONITOR:
            status = DeviceStatus.MONITORING
        elif attacks:
            status = DeviceStatus.COMPROMISED if len(attacks) > 1 or indicators else DeviceStatus.DEGRADED
        else:
            status = DeviceStatus.ONLINE
        return indicators, signals, status

    def _enforce_network(self, network: NetworkActivity) -> NetworkActivity:
        state = self.containment.state
        if state in {ResponseState.NORMAL, ResponseState.MONITOR}:
            return network
        controller = self._controller_connection()
        if state == ResponseState.QUARANTINE:
            return NetworkActivity(
                interface=network.interface,
                local_ip=network.local_ip,
                mac_address=network.mac_address,
                bytes_sent=self._bytes_sent,
                bytes_recv=self._bytes_recv,
                packets_sent=1,
                packets_recv=1,
                active_connections=[controller],
                dns_queries=["sentinelmesh.local"],
                unusual_ports=[],
            )
        blocked_ips = [
            conn.remote_ip
            for conn in network.active_connections
            if conn.reputation != "trusted"
        ]
        self.containment.blocked_ips = list(dict.fromkeys(self.containment.blocked_ips + blocked_ips))
        trusted = [conn for conn in network.active_connections if conn.reputation == "trusted"]
        if not any(conn.remote_ip == CONTROLLER_PEER for conn in trusted):
            trusted.append(controller)
        dns = [
            query
            for query in network.dns_queries
            if not any(marker in query.lower() for marker in ("malicious", "exfil", "c2-", "dropzone"))
        ]
        return NetworkActivity(
            interface=network.interface,
            local_ip=network.local_ip,
            mac_address=network.mac_address,
            bytes_sent=network.bytes_sent,
            bytes_recv=network.bytes_recv,
            packets_sent=max(1, network.packets_sent // 4),
            packets_recv=max(1, network.packets_recv // 4),
            active_connections=trusted,
            dns_queries=dns or ["sentinelmesh.local"],
            unusual_ports=[],
        )

    def _controller_connection(self) -> NetworkConnection:
        return NetworkConnection(
            remote_ip=CONTROLLER_PEER,
            remote_port=8443,
            protocol="tls",
            direction="outbound",
            bytes_transferred=320,
            reputation="trusted",
            process="sentinelmesh_agent",
        )

    def _cap_power(self, power: PowerConsumption, baseline: float) -> PowerConsumption:
        watts = min(power.watts, max(0.8, baseline))
        voltage = power.voltage
        current = watts / voltage if voltage else 0.0
        deviation = ((watts - baseline) / baseline) * 100 if baseline else 0.0
        return PowerConsumption(
            watts=round(watts, 3),
            voltage=voltage,
            current_amps=round(current, 4),
            energy_wh=power.energy_wh,
            baseline_watts=power.baseline_watts,
            deviation_percent=round(deviation, 2),
        )

    def _enrich_telemetry(self, sensors: dict[str, Any], network: NetworkActivity) -> dict[str, Any]:
        enriched = dict(sensors)
        enriched["deep_telemetry"] = {
            "packet_capture": True,
            "dns_log": list(network.dns_queries),
            "connection_table": [conn.model_dump() for conn in network.active_connections],
            "unusual_ports": list(network.unusual_ports),
            "command_audit": [
                {"command": cmd.command, "actor": cmd.actor, "authorized": cmd.authorized, "result": cmd.result}
                for cmd in list(self.command_history)[-8:]
            ],
            "capture_window_seconds": 30,
        }
        return enriched

    def _containment_report(self) -> ContainmentReport:
        return ContainmentReport(
            response_state=self.containment.state.value,
            isolated=self.containment.isolated,
            safe_mode=self.containment.safe_mode,
            extra_telemetry=self.containment.extra_telemetry,
            blocked_ips=list(self.containment.blocked_ips),
            blocked_ports=list(self.containment.blocked_ports),
            revoked_permissions=list(self.containment.revoked_permissions),
            denied_commands=list(dict.fromkeys(self.containment.denied_commands)),
            allowed_peers=list(self.containment.allowed_peers),
            network_mode=self.containment.network_mode,
            detected_at=self.containment.detected_at,
            requested_at=self.containment.requested_at,
            applied_at=self.containment.applied_at,
            first_denied_at=self.containment.first_denied_at,
        )
