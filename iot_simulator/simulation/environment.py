from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from iot_simulator.config import settings
from iot_simulator.devices import SmartCamera, SmartLock, SmartPlug, SmartThermostat
from iot_simulator.devices.base import VirtualDevice
from iot_simulator.models.attacks import AttackRequest, AttackStopRequest, AttackType
from iot_simulator.models.devices import DeviceType
from iot_simulator.models.telemetry import (
    ActiveAttack,
    DeviceSnapshot,
    EnvironmentSnapshot,
    TelemetrySample,
    VerifiedContainment,
)
from iot_simulator.simulation.attack_injector import AttackInjector
from iot_simulator.simulation.verification import build_verified_containment, merge_incident
from security_engine.models.response import ContainmentApplyRequest, DefensiveAction
from security_engine.response.engine import ResponseEngine

DEMO_SEED = "sentinel-demo-42"
DEMO_HOUR = 12
DEMO_CLOCK = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)

DEVICE_ATTACK_AFFINITY: dict[AttackType, tuple[DeviceType, ...]] = {
    AttackType.ABNORMAL_NETWORK_TRAFFIC: (DeviceType.SMART_CAMERA, DeviceType.SMART_PLUG),
    AttackType.UNAUTHORIZED_COMMANDS: (DeviceType.SMART_LOCK, DeviceType.SMART_THERMOSTAT),
    AttackType.SUSPICIOUS_IP_CONNECTIONS: (
        DeviceType.SMART_CAMERA,
        DeviceType.SMART_LOCK,
        DeviceType.SMART_PLUG,
        DeviceType.SMART_THERMOSTAT,
    ),
    AttackType.FIRMWARE_MODIFICATION: (DeviceType.SMART_CAMERA, DeviceType.SMART_LOCK),
    AttackType.ABNORMAL_POWER_USAGE: (DeviceType.SMART_PLUG, DeviceType.SMART_CAMERA),
}


class IoTEnvironment:
    def __init__(self) -> None:
        self.tick_count = 0
        self.demo_mode = False
        self.injector = AttackInjector()
        self.devices: dict[str, VirtualDevice] = {}
        self.history: dict[str, deque[TelemetrySample]] = defaultdict(
            lambda: deque(maxlen=settings.history_limit)
        )
        self.latest: dict[str, TelemetrySample] = {}
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self.response_engine = ResponseEngine()
        self.incidents: dict[str, VerifiedContainment] = {}
        self._seed_home()

    def _seed_home(self) -> None:
        catalog: list[VirtualDevice] = [
            SmartCamera(
                device_id="cam-front-door",
                name="Front Door Camera",
                room="entryway",
                local_ip="192.168.1.21",
                mac_address="3c:22:fb:10:a1:01",
                firmware_version="2.4.11",
            ),
            SmartPlug(
                device_id="plug-living-lamp",
                name="Living Room Lamp Plug",
                room="living_room",
                local_ip="192.168.1.34",
                mac_address="3c:22:fb:10:a1:02",
                firmware_version="1.9.3",
            ),
            SmartThermostat(
                device_id="thermo-hallway",
                name="Hallway Thermostat",
                room="hallway",
                local_ip="192.168.1.40",
                mac_address="3c:22:fb:10:a1:03",
                firmware_version="5.1.0",
            ),
            SmartLock(
                device_id="lock-front-door",
                name="Front Door Lock",
                room="entryway",
                local_ip="192.168.1.55",
                mac_address="3c:22:fb:10:a1:04",
                firmware_version="3.2.8",
            ),
        ]
        for device in catalog:
            self.devices[device.device_id] = device

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while True:
            await self.step()
            await asyncio.sleep(settings.tick_interval_seconds)

    def _now(self) -> datetime:
        if not self.demo_mode:
            return datetime.now(UTC)
        elapsed = max(self.tick_count - 1, 0) * settings.tick_interval_seconds
        return DEMO_CLOCK + timedelta(seconds=elapsed)

    async def step(self) -> EnvironmentSnapshot:
        async with self._lock:
            self.tick_count += 1
            now = self._now()
            samples: list[TelemetrySample] = []
            for device in self.devices.values():
                sample = device.tick(now, self.injector.attacks_for(device.device_id))
                sample = self._with_verification(sample)
                self.latest[device.device_id] = sample
                self.history[device.device_id].append(sample)
                samples.append(sample)
            return EnvironmentSnapshot(
                generated_at=now,
                tick=self.tick_count,
                devices=samples,
                active_attacks=self.injector.active(),
            )

    def snapshot(self) -> EnvironmentSnapshot:
        return EnvironmentSnapshot(
            generated_at=self._now() if self.tick_count else datetime.now(UTC),
            tick=self.tick_count,
            devices=[self._with_verification(sample) for sample in self.latest.values()],
            active_attacks=self.injector.active(),
        )

    def list_devices(self) -> list[DeviceSnapshot]:
        snapshots: list[DeviceSnapshot] = []
        for device in self.devices.values():
            latest = self.latest.get(device.device_id)
            snapshots.append(
                DeviceSnapshot(
                    device_id=device.device_id,
                    device_type=device.device_type,
                    name=device.name,
                    room=device.room,
                    status=latest.status if latest else device.status,
                    firmware_version=device.firmware_version,
                    response_state=device.containment.state.value,
                    contained=device.containment.state.value != "normal",
                    latest_telemetry=latest,
                )
            )
        return snapshots

    def device_history(self, device_id: str, limit: int = 50) -> list[TelemetrySample]:
        if device_id not in self.devices:
            raise KeyError(device_id)
        records = list(self.history[device_id])
        return records[-limit:]

    def inject_attack(self, request: AttackRequest) -> ActiveAttack:
        device_id = request.device_id or self._choose_target(request.attack_type)
        if device_id not in self.devices:
            raise KeyError(device_id)
        return self.injector.inject(request, device_id)

    def stop_attack(self, request: AttackStopRequest) -> int:
        return self.injector.stop(
            attack_id=str(request.attack_id) if request.attack_id else None,
            device_id=request.device_id,
        )

    def reset(self, demo: bool = False) -> None:
        self.demo_mode = demo
        self.injector.stop()
        self.tick_count = 0
        self.latest.clear()
        self.history.clear()
        self.response_engine.reset()
        self.incidents.clear()
        for device in self.devices.values():
            device.reset(
                seed=f"{DEMO_SEED}:{device.device_id}" if demo else None,
                behavior_hour=DEMO_HOUR if demo else None,
            )

    def apply_defensive_action(self, action: DefensiveAction) -> DefensiveAction:
        device = self.devices.get(action.device_id)
        if device is None:
            raise KeyError(action.device_id)
        device.apply_response(action)
        action.enforced = True
        action.enforcement_target = "iot-simulator"
        if device.device_id in self.latest:
            self.latest[device.device_id] = self._with_verification(self.latest[device.device_id])
        return action

    def apply_containment(self, request: ContainmentApplyRequest) -> None:
        device = self.devices.get(request.device_id)
        if device is None:
            raise KeyError(request.device_id)
        device.apply_containment(request)
        if device.device_id in self.latest:
            self.latest[device.device_id] = self._with_verification(self.latest[device.device_id])

    def _choose_target(self, attack_type: AttackType) -> str:
        preferred = DEVICE_ATTACK_AFFINITY[attack_type]
        for device in self.devices.values():
            if device.device_type in preferred:
                return device.device_id
        return next(iter(self.devices))

    def _attack_for(self, device_id: str) -> ActiveAttack | None:
        attacks = [item for item in self.injector.active() if item.device_id == device_id]
        preferred = [item for item in attacks if item.attack_type == AttackType.UNAUTHORIZED_COMMANDS]
        pool = preferred or attacks
        return pool[0] if pool else None

    def _with_verification(self, sample: TelemetrySample) -> TelemetrySample:
        device = self.devices[sample.device_id]
        sample = sample.model_copy(update={"containment": device._containment_report()})
        status = self.response_engine.status(sample.device_id)
        evidence = build_verified_containment(
            sample,
            containment=device.containment,
            attack=self._attack_for(sample.device_id),
            action=status.last_action if status else None,
        )
        evidence = merge_incident(self.incidents.get(sample.device_id), evidence)
        self.incidents[sample.device_id] = evidence
        return sample.model_copy(update={"verified_containment": evidence})
