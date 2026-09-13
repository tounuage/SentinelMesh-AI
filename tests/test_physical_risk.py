from __future__ import annotations

import asyncio

from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.pipeline import AnalysisEngine


def _warmup(env: IoTEnvironment, engine: AnalysisEngine, ticks: int = 8) -> None:
    env.reset(demo=True)
    engine.reset()

    async def run() -> None:
        for _ in range(ticks):
            snapshot = await env.step()
            engine.analyze_snapshot(snapshot)

    asyncio.run(run())


def test_lock_attack_predicts_forced_entry() -> None:
    env = IoTEnvironment()
    engine = AnalysisEngine()
    _warmup(env, engine)
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    snapshot = asyncio.run(env.step())
    lock = next(sample for sample in snapshot.devices if sample.device_id == "lock-front-door")
    result = engine.analyze(lock)
    assert result.physical.score >= 50
    assert result.physical.hazard in {"forced_entry", "hostile_actuation"}
    assert result.physical.severity in {"high", "critical"}
    assert any("unlock" in item.lower() or "intruder" in item.lower() for item in result.physical.consequences)
    assert "lock" in result.physical.safe_mode.lower() or "deadbolt" in result.physical.safe_mode.lower()


def test_benign_camera_has_no_material_physical_hazard() -> None:
    env = IoTEnvironment()
    engine = AnalysisEngine()
    _warmup(env, engine)
    finding = engine.latest_for("cam-front-door")
    assert finding is not None
    assert finding.threat_type == "benign"
    assert finding.physical.score < 20
    assert finding.physical.hazard == "none"


def test_plug_power_anomaly_predicts_electrical_fire() -> None:
    env = IoTEnvironment()
    engine = AnalysisEngine()
    _warmup(env, engine)
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.ABNORMAL_POWER_USAGE,
            device_id="plug-living-lamp",
            duration_seconds=60,
            intensity="high",
        )
    )
    snapshot = asyncio.run(env.step())
    plug = next(sample for sample in snapshot.devices if sample.device_id == "plug-living-lamp")
    result = engine.analyze(plug)
    assert result.physical.score >= 40
    assert result.physical.hazard in {"electrical_fire", "energy_hazard", "unsafe_energize"}
    assert "relay" in result.physical.safe_mode.lower() or "power" in result.physical.safe_mode.lower()
