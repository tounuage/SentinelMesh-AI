import asyncio
from datetime import UTC, datetime, timedelta

from iot_simulator.models.attacks import AttackRequest, AttackStopRequest, AttackType
from iot_simulator.models.devices import DeviceType
from iot_simulator.models.telemetry import CommandRecord, ContainmentReport, TelemetrySample
from iot_simulator.simulation.environment import IoTEnvironment
from iot_simulator.simulation.verification import build_verified_containment, latency_ms
from security_engine.config import settings as engine_settings
from security_engine.pipeline import AnalysisEngine


def step(env: IoTEnvironment):
    return asyncio.run(env.step())


def _lock(snapshot, device_id: str = "lock-front-door"):
    return next(sample for sample in snapshot.devices if sample.device_id == device_id)


def test_latency_uses_actual_timestamps() -> None:
    start = datetime(2026, 9, 14, 12, 0, 1, tzinfo=UTC)
    detected = datetime(2026, 9, 14, 12, 0, 2, 100000, tzinfo=UTC)
    denied = datetime(2026, 9, 14, 12, 0, 4, tzinfo=UTC)
    assert latency_ms(start, detected) == 1100.0
    assert latency_ms(detected, denied) == 1900.0


def test_builder_separates_intended_actions_from_observed_outcomes() -> None:
    detected = datetime(2026, 9, 14, 12, 0, 2, tzinfo=UTC)
    requested = detected + timedelta(milliseconds=350)
    acknowledged = requested + timedelta(milliseconds=40)
    denied = detected + timedelta(seconds=2)
    sample = TelemetrySample(
        timestamp=denied,
        device_id="lock-front-door",
        device_type=DeviceType.SMART_LOCK,
        name="Front Door Lock",
        room="entryway",
        status="restricted",
        firmware_version="3.2.8",
        firmware_signed=True,
        firmware_checksum="abc",
        network={
            "interface": "wlan0",
            "local_ip": "192.168.1.55",
            "mac_address": "3c:22:fb:10:a1:04",
            "bytes_sent": 1,
            "bytes_recv": 1,
            "packets_sent": 1,
            "packets_recv": 1,
            "active_connections": [],
            "dns_queries": [],
            "unusual_ports": [],
        },
        power={
            "watts": 1,
            "voltage": 120,
            "current_amps": 0.01,
            "energy_wh": 1,
            "baseline_watts": 1,
            "deviation_percent": 0,
        },
        sensors={"locked": True, "remote_unlock_enabled": False},
        command_history=[
            CommandRecord(
                timestamp=detected,
                command="unlock",
                actor="unknown_session",
                source_ip="203.0.113.66",
                authorized=False,
                result="accepted_without_authz",
            ),
            CommandRecord(
                timestamp=denied,
                command="unlock",
                actor="unknown_session",
                source_ip="203.0.113.66",
                authorized=False,
                result="denied_by_containment",
            ),
        ],
        containment=ContainmentReport(
            response_state="restricted",
            safe_mode=True,
            detected_at=detected,
            requested_at=requested,
            applied_at=acknowledged,
            first_denied_at=denied,
            denied_commands=["unlock"],
            revoked_permissions=["remote_unlock"],
        ),
    )
    evidence = build_verified_containment(sample)
    assert [item.label for item in evidence.sequence] == [
        "Unauthorized unlock detected",
        "Containment requested",
        "Simulator acknowledged",
        "Next unlock attempt: DENIED",
    ]
    assert evidence.sequence[1].kind == "intended"
    assert evidence.sequence[3].kind == "observed"
    assert evidence.verified
    assert evidence.containment_latency_ms == 2000.0
    denied_outcome = next(item for item in evidence.outcomes if item.label == "Follow-up command")
    assert denied_outcome.intended == "DENIED"
    assert denied_outcome.matched


def test_verified_containment_requires_denied_follow_up_while_attack_still_runs() -> None:
    env = IoTEnvironment()
    env.reset()
    step(env)
    attack = env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            intensity="high",
            duration_seconds=60,
        )
    )
    attacked = step(env)
    lock = _lock(attacked)
    assert any(cmd.result == "accepted_without_authz" for cmd in lock.command_history)
    assert lock.verified_containment is not None
    assert lock.verified_containment.verified is False
    assert lock.verified_containment.sequence[0].complete is True
    assert lock.verified_containment.sequence[3].complete is False

    action = env.response_engine.act(lock.device_id, 86, "unauthorized_commands")
    env.apply_defensive_action(action)
    assert any(item.device_id == "lock-front-door" for item in env.injector.active())

    contained = step(env)
    lock = _lock(contained)
    evidence = lock.verified_containment
    assert evidence is not None
    assert any(cmd.result == "denied_by_containment" and cmd.command == "unlock" for cmd in lock.command_history)
    assert lock.sensors["locked"] is True
    assert evidence.verified is True
    assert [item.label for item in evidence.sequence] == [
        "Unauthorized unlock detected",
        "Containment requested",
        "Simulator acknowledged",
        "Next unlock attempt: DENIED",
    ]
    assert all(item.complete and item.at is not None for item in evidence.sequence)
    assert evidence.sequence[0].at <= evidence.sequence[1].at <= evidence.sequence[2].at <= evidence.sequence[3].at
    assert evidence.detection_latency_ms == latency_ms(attack.started_at, evidence.sequence[0].at)
    assert evidence.containment_latency_ms == latency_ms(evidence.sequence[0].at, evidence.sequence[3].at)
    assert env.injector.active(), "attack must still be running when the follow-up unlock is denied"
    denied = next(item for item in evidence.outcomes if item.label == "Follow-up command")
    assert denied.intended == "DENIED"
    assert denied.observed != "still allowed / not attempted"
    lock_state = next(item for item in evidence.outcomes if item.label == "Door lock")
    assert lock_state.intended == "forced shut"
    assert lock_state.observed == "locked"
    original_detail = evidence.sequence[0].detail
    for _ in range(12):
        step(env)
    later = _lock(step(env)).verified_containment
    assert later is not None and later.verified
    assert later.sequence[0].detail == original_detail
    assert env.injector.active()


def test_stopping_the_attack_before_the_next_tick_is_not_verified_containment() -> None:
    env = IoTEnvironment()
    env.reset()
    step(env)
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            intensity="high",
            duration_seconds=60,
        )
    )
    lock = _lock(step(env))
    action = env.response_engine.act(lock.device_id, 86, "unauthorized_commands")
    env.apply_defensive_action(action)
    env.stop_attack(AttackStopRequest(device_id="lock-front-door"))
    lock = _lock(step(env))
    evidence = lock.verified_containment
    assert evidence is not None
    assert not any(cmd.result == "denied_by_containment" for cmd in lock.command_history)
    assert evidence.verified is False
    assert evidence.sequence[3].complete is False


def test_engine_loop_still_contains_and_records_verification() -> None:
    env, engine = IoTEnvironment(), AnalysisEngine()
    env.reset(demo=True)
    engine.reset()
    for _ in range(engine_settings.warmup_samples):
        engine.analyze_snapshot(step(env))
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            intensity="high",
            duration_seconds=60,
        )
    )
    lock = _lock(step(env))
    finding = engine.analyze(lock)
    assert finding.risk_score >= 75
    env.apply_defensive_action(engine.response.status(lock.device_id).last_action)
    lock = _lock(step(env))
    assert lock.verified_containment and lock.verified_containment.verified
    assert lock.sensors["locked"] is True
    assert any(command.result == "denied_by_containment" for command in lock.command_history)
