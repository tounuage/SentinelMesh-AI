import asyncio

from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.scoring.physical import PhysicalRiskPredictor


def step(env: IoTEnvironment):
    return asyncio.run(env.step())


def _lock(snapshot, device_id: str = "lock-front-door"):
    return next(sample for sample in snapshot.devices if sample.device_id == device_id)


def test_force_lock_does_not_close_an_ajar_door() -> None:
    env = IoTEnvironment()
    env.reset(demo=True)
    step(env)
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            intensity="high",
            duration_seconds=60,
        )
    )
    attacked = _lock(step(env))
    assert attacked.sensors["locked"] is False
    assert attacked.sensors["door_ajar"] is True

    action = env.response_engine.act(attacked.device_id, 86, "unauthorized_commands")
    env.apply_defensive_action(action)
    contained = _lock(step(env))
    assert contained.sensors["locked"] is True
    assert contained.sensors["door_ajar"] is True
    assert contained.sensors["remote_unlock_enabled"] is False
    assert any(cmd.result == "denied_by_containment" for cmd in contained.command_history)
    physical = PhysicalRiskPredictor().assess(contained, "unauthorized_commands", 86)
    assert any("ajar" in item.lower() for item in physical.consequences)
    assert all("intrusion prevented" not in item.lower() for item in physical.consequences)


def test_full_recovery_restores_door_sensor() -> None:
    env = IoTEnvironment()
    env.reset(demo=True)
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            intensity="high",
            duration_seconds=60,
        )
    )
    lock = _lock(step(env))
    env.apply_defensive_action(env.response_engine.act(lock.device_id, 86, "unauthorized_commands"))
    assert _lock(step(env)).sensors["door_ajar"] is True
    env.reset(demo=True)
    restored = _lock(step(env))
    assert restored.sensors["locked"] is True
    assert restored.sensors["door_ajar"] is False
    assert restored.containment.response_state == "normal"
