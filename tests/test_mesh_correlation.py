from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.models.devices import DeviceType
from iot_simulator.models.telemetry import CommandRecord, EnvironmentSnapshot, TelemetrySample
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.api.main import app as engine_app
from security_engine.api.routes import engine as api_engine
from security_engine.correlation.mesh import (
    CORRELATION_WINDOW_SECONDS,
    ENTRY_DETAIL,
    ENTRY_TITLE,
    correlate_entry_attempt,
)
from security_engine.pipeline import AnalysisEngine

SOURCE = "203.0.113.66"
CAMERA_AT = datetime(2026, 9, 14, 12, 0, 1, tzinfo=UTC)
LOCK_AT = datetime(2026, 9, 14, 12, 0, 4, tzinfo=UTC)


def _command(
    command: str,
    at: datetime,
    source_ip: str = SOURCE,
    authorized: bool = False,
    result: str = "accepted_without_authz",
) -> CommandRecord:
    return CommandRecord(
        timestamp=at,
        command=command,
        actor="unknown_session",
        source_ip=source_ip,
        authorized=authorized,
        result=result,
    )


def _sample(
    device_id: str,
    device_type: DeviceType,
    name: str,
    ip: str,
    commands: list[CommandRecord],
    attack_signals: list[str] | None = None,
) -> TelemetrySample:
    return TelemetrySample(
        timestamp=commands[-1].timestamp if commands else CAMERA_AT,
        device_id=device_id,
        device_type=device_type,
        name=name,
        room="entryway",
        status="online",
        firmware_version="1.0.0",
        firmware_signed=True,
        firmware_checksum="abc",
        network={
            "interface": "wlan0",
            "local_ip": ip,
            "mac_address": "3c:22:fb:10:a1:01",
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
        sensors={},
        command_history=commands,
        anomaly_indicators=[],
        attack_signals=attack_signals or [],
    )


def _camera(commands: list[CommandRecord], attack_signals: list[str] | None = None) -> TelemetrySample:
    return _sample("cam-front-door", DeviceType.SMART_CAMERA, "Front Door Camera", "192.168.1.21", commands, attack_signals)


def _lock(commands: list[CommandRecord], attack_signals: list[str] | None = None) -> TelemetrySample:
    return _sample("lock-front-door", DeviceType.SMART_LOCK, "Front Door Lock", "192.168.1.55", commands, attack_signals)


def test_shared_source_camera_then_lock_within_window_creates_incident() -> None:
    camera = _camera([_command("disable_recording", CAMERA_AT)])
    lock = _lock([_command("unlock", LOCK_AT)])
    incident = correlate_entry_attempt([camera, lock])
    assert incident is not None
    assert incident.title == ENTRY_TITLE
    assert incident.detail == ENTRY_DETAIL
    assert incident.method == "rule_based_correlation"
    assert incident.source_ip == SOURCE
    assert incident.device_ids == ["cam-front-door", "lock-front-door"]
    assert incident.delta_seconds == 3.0
    assert incident.window_seconds == CORRELATION_WINDOW_SECONDS
    assert [event.command for event in incident.sequence] == ["disable_recording", "unlock"]
    assert "rule-based" in incident.explanation.lower()
    assert "attack label" in incident.explanation.lower()


def test_correlation_ignores_simulator_attack_labels() -> None:
    labeled_only = correlate_entry_attempt(
        [
            _camera([_command("heartbeat", CAMERA_AT, source_ip="192.168.1.10", authorized=True, result="ok")], ["unauthorized_commands"]),
            _lock([_command("lock", LOCK_AT, source_ip="192.168.1.10", authorized=True, result="ok")], ["unauthorized_commands"]),
        ]
    )
    observed = correlate_entry_attempt(
        [
            _camera([_command("disable_recording", CAMERA_AT)], []),
            _lock([_command("unlock", LOCK_AT)], []),
        ]
    )
    assert labeled_only is None
    assert observed is not None
    source = inspect.getsource(correlate_entry_attempt)
    assert "attack_signals" not in source
    assert "ActiveAttack" not in source
    assert "attack_type" not in source


def test_different_sources_do_not_correlate() -> None:
    incident = correlate_entry_attempt(
        [
            _camera([_command("disable_recording", CAMERA_AT, source_ip="203.0.113.66")]),
            _lock([_command("unlock", LOCK_AT, source_ip="198.51.100.77")]),
        ]
    )
    assert incident is None


def test_window_boundary_and_reversed_order() -> None:
    inside = correlate_entry_attempt(
        [
            _camera([_command("disable_recording", CAMERA_AT)]),
            _lock([_command("unlock", CAMERA_AT + timedelta(seconds=10))]),
        ]
    )
    outside = correlate_entry_attempt(
        [
            _camera([_command("disable_recording", CAMERA_AT)]),
            _lock([_command("unlock", CAMERA_AT + timedelta(seconds=10, milliseconds=1))]),
        ]
    )
    reversed_order = correlate_entry_attempt(
        [
            _camera([_command("disable_recording", LOCK_AT)]),
            _lock([_command("unlock", CAMERA_AT)]),
        ]
    )
    lock_only = correlate_entry_attempt(
        [
            _camera([_command("heartbeat", CAMERA_AT, source_ip="192.168.1.10", authorized=True, result="ok")]),
            _lock([_command("unlock", LOCK_AT)]),
        ]
    )
    assert inside is not None
    assert inside.delta_seconds == 10.0
    assert outside is None
    assert reversed_order is None
    assert lock_only is None


def test_engine_analyze_snapshot_exposes_mesh_incident() -> None:
    engine = AnalysisEngine()
    snapshot = EnvironmentSnapshot(
        generated_at=LOCK_AT,
        tick=1,
        devices=[
            _camera([_command("disable_recording", CAMERA_AT)]),
            _lock([_command("unlock", LOCK_AT)]),
        ],
        active_attacks=[],
    )
    findings = engine.analyze_snapshot(snapshot)
    incidents = engine.latest_incidents()
    assert len(findings) == 2
    assert len(incidents) == 1
    assert incidents[0].title == ENTRY_TITLE
    engine.reset()
    assert engine.latest_incidents() == []


def test_live_camera_and_lock_attacks_share_source_and_correlate() -> None:
    import asyncio

    env = IoTEnvironment()
    engine = AnalysisEngine()
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="cam-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    snapshot = asyncio.run(env.step())
    camera = next(sample for sample in snapshot.devices if sample.device_id == "cam-front-door")
    lock = next(sample for sample in snapshot.devices if sample.device_id == "lock-front-door")
    camera_sources = {cmd.source_ip for cmd in camera.command_history if not cmd.authorized}
    lock_sources = {cmd.source_ip for cmd in lock.command_history if not cmd.authorized}
    assert camera_sources == {SOURCE}
    assert lock_sources == {SOURCE}
    engine.analyze_snapshot(snapshot)
    incidents = engine.latest_incidents()
    assert len(incidents) == 1
    assert incidents[0].device_ids == ["cam-front-door", "lock-front-door"]
    assert incidents[0].source_ip == SOURCE
    assert 0 <= incidents[0].delta_seconds <= CORRELATION_WINDOW_SECONDS


def test_lock_only_attack_is_not_a_mesh_incident() -> None:
    import asyncio

    env = IoTEnvironment()
    engine = AnalysisEngine()
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    snapshot = asyncio.run(env.step())
    engine.analyze_snapshot(snapshot)
    assert engine.latest_incidents() == []


def test_incidents_endpoint_returns_rule_based_card() -> None:
    api_engine.reset()
    camera = _camera([_command("disable_recording", CAMERA_AT)])
    lock = _lock([_command("unlock", LOCK_AT)])
    with TestClient(engine_app) as client:
        analyzed = client.post(
            "/api/v1/analyze/snapshot",
            json={
                "generated_at": LOCK_AT.isoformat(),
                "tick": 1,
                "devices": [camera.model_dump(mode="json"), lock.model_dump(mode="json")],
                "active_attacks": [],
            },
        )
        assert analyzed.status_code == 200
        assert {item["device"] for item in analyzed.json()} == {"cam-front-door", "lock-front-door"}
        payload = client.get("/api/v1/incidents").json()
        assert len(payload) == 1
        card = payload[0]
        assert card["title"] == ENTRY_TITLE
        assert card["detail"] == ENTRY_DETAIL
        assert card["method"] == "rule_based_correlation"
        assert card["device_ids"] == ["cam-front-door", "lock-front-door"]
        assert card["source_ip"] == SOURCE
    api_engine.reset()
