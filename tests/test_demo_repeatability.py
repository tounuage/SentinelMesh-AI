import asyncio
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from iot_simulator.api.main import app as simulator_app
from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.simulation.environment import DEMO_CLOCK, DEMO_HOUR, IoTEnvironment
from iot_simulator.config import settings as sim_settings
from security_engine.config import settings as engine_settings
from security_engine.pipeline import AnalysisEngine
from security_engine.scoring.physical import PhysicalRiskPredictor


def step(env):
    return asyncio.run(env.step())


def test_two_demo_runs_start_clean_and_detect_attack():
    env, engine = IoTEnvironment(), AnalysisEngine()
    baselines = []
    clocks = []
    for _ in range(2):
        env.reset(demo=True)
        engine.reset()
        observations = []
        timestamps = []
        for _ in range(16):
            snapshot = step(env)
            findings = engine.analyze_snapshot(snapshot)
            observations.append([(s.network.bytes_sent, s.power.watts, s.sensors) for s in snapshot.devices])
            timestamps.append([s.timestamp for s in snapshot.devices])
            assert all(not s.attack_signals and all(c.authorized for c in s.command_history) for s in snapshot.devices)
        baselines.append(observations)
        clocks.append(timestamps)
        assert all(p.baseline_ready for p in engine.profiles.all())
        assert all(f.threat_type == 'benign' for f in findings)
        env.inject_attack(AttackRequest(attack_type=AttackType.UNAUTHORIZED_COMMANDS,
                                      device_id='lock-front-door', intensity='high', duration_seconds=60))
        attacked = step(env)
        lock = next(s for s in attacked.devices if s.device_id == 'lock-front-door')
        finding = engine.analyze(lock)
        assert finding.risk_score >= 75
        action = engine.response.status(lock.device_id).last_action
        env.apply_defensive_action(action)
        contained = next(s for s in step(env).devices if s.device_id == lock.device_id)
        assert contained.sensors['locked'] is True
        assert any(c.result == 'denied_by_containment' for c in contained.command_history)
    assert baselines[0] == baselines[1]
    assert clocks[0] == clocks[1]


def test_demo_reset_clears_hostile_command_history():
    env, engine = IoTEnvironment(), AnalysisEngine()
    env.reset(demo=True)
    env.inject_attack(AttackRequest(
        attack_type=AttackType.UNAUTHORIZED_COMMANDS,
        device_id='lock-front-door',
        intensity='high',
        duration_seconds=60,
    ))
    attacked = step(env)
    lock = next(sample for sample in attacked.devices if sample.device_id == 'lock-front-door')
    finding = engine.analyze(lock)
    env.apply_defensive_action(engine.response.status(lock.device_id).last_action)
    contained = step(env)
    lock = next(sample for sample in contained.devices if sample.device_id == 'lock-front-door')
    assert any(not command.authorized for command in lock.command_history)
    assert any(command.result == 'denied_by_containment' for command in lock.command_history)
    assert finding.risk_score >= 75

    env.reset(demo=True)
    snapshot = step(env)
    for sample in snapshot.devices:
        assert all(command.authorized for command in sample.command_history)
        assert all(command.result != 'denied_by_containment' for command in sample.command_history)
        assert not sample.attack_signals
        assert sample.firmware_signed
        assert sample.containment.response_state == 'normal'
    lock = env.devices['lock-front-door']
    assert lock.locked is True
    assert lock.behavior_hour == DEMO_HOUR


def test_demo_clock_is_fixed_and_live_reset_restores_wall_clock():
    env = IoTEnvironment()
    env.reset(demo=True)
    first = step(env)
    assert first.generated_at == DEMO_CLOCK
    assert all(sample.timestamp == DEMO_CLOCK for sample in first.devices)
    second = step(env)
    assert (second.generated_at - DEMO_CLOCK).total_seconds() == sim_settings.tick_interval_seconds
    env.reset()
    assert env.demo_mode is False
    for device in env.devices.values():
        assert device.behavior_hour is None


def test_models_are_not_ready_before_warmup():
    env, engine = IoTEnvironment(), AnalysisEngine()
    env.reset(demo=True)
    engine.reset()
    snapshot = step(env)
    findings = engine.analyze_snapshot(snapshot)
    assert all(not profile.baseline_ready for profile in engine.profiles.all())
    assert all(finding.threat_type == 'benign' for finding in findings)
    for _ in range(engine_settings.warmup_samples - 1):
        engine.analyze_snapshot(step(env))
    assert all(profile.baseline_ready for profile in engine.profiles.all())


def test_duplicate_samples_do_not_train_or_advance_response():
    env, engine = IoTEnvironment(), AnalysisEngine()
    sample = step(env).devices[0]
    first = engine.analyze(sample)
    action_id = engine.response.status(sample.device_id).last_action.action_id
    for _ in range(20):
        assert engine.analyze(sample) is first
    assert engine.profiles.get(sample.device_id).sample_count == 1
    assert not engine.profiles.get(sample.device_id).baseline_ready
    assert engine.response.status(sample.device_id).last_action.action_id == action_id


@pytest.mark.parametrize('hour', [0, 12, 19, 23])
def test_normal_camera_recording_is_not_a_physical_hazard(hour):
    env = IoTEnvironment()
    camera = env.devices['cam-front-door']
    sample = camera.tick(datetime(2026, 9, 14, hour, tzinfo=UTC), {})
    predictor = PhysicalRiskPredictor()
    assert sample.sensors['privacy_shutter_open'] is True
    assessment = predictor.assess(sample, 'benign', 30)
    assert assessment.hazard == 'none'
    assert assessment.score < 20
    assert predictor.assess(sample, 'abnormal_network_traffic', 90).score >= 55


def test_benign_unlocked_lock_still_has_physical_hazard():
    env = IoTEnvironment()
    lock = env.devices['lock-front-door']
    lock.locked = False
    sample = lock.tick(datetime(2026, 9, 14, 12, tzinfo=UTC), {})
    assessment = PhysicalRiskPredictor().assess(sample, 'benign', 12)
    assert assessment.hazard == 'unsafe_physical_state'
    assert assessment.score >= 20


def test_plain_reset_restores_live_behavior_and_firmware():
    env = IoTEnvironment()
    env.reset(demo=True)
    env.inject_attack(AttackRequest(attack_type=AttackType.FIRMWARE_MODIFICATION,
                                  device_id='cam-front-door', intensity='high', duration_seconds=60))
    step(env)
    env.reset()
    assert not env.injector.active()
    assert not env.history and not env.latest
    assert env.demo_mode is False
    for device in env.devices.values():
        assert device.behavior_hour is None
        assert device.firmware_signed
        assert device.last_firmware_change is None
        assert all(c.authorized for c in device.command_history)
        assert device.containment.state.value == 'normal'


def test_demo_reset_api_clears_hostile_history_and_freezes_clock():
    with TestClient(simulator_app) as client:
        injected = client.post(
            '/api/v1/attacks',
            json={
                'attack_type': AttackType.UNAUTHORIZED_COMMANDS.value,
                'device_id': 'lock-front-door',
                'duration_seconds': 30,
                'intensity': 'high',
            },
        )
        assert injected.status_code == 201
        client.post('/api/v1/simulation/tick')
        dirty = client.get('/api/v1/telemetry').json()
        lock = next(device for device in dirty['devices'] if device['device_id'] == 'lock-front-door')
        assert any(not command['authorized'] for command in lock['command_history'])

        reset = client.post('/api/v1/simulation/reset?demo=true')
        assert reset.status_code == 200
        assert reset.json()['demo'] is True
        health = client.get('/api/v1/health').json()
        assert health['demo'] is True
        clean = client.get('/api/v1/telemetry').json()
        assert clean['generated_at'].startswith('2026-09-14T12:00')
        for device in clean['devices']:
            assert all(command['authorized'] for command in device['command_history'])
            assert not device['attack_signals']
            assert device['firmware_signed']
            assert device['containment']['response_state'] == 'normal'
            assert device['timestamp'].startswith('2026-09-14T12:00')
