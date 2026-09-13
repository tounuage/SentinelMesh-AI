from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.models.telemetry import EnvironmentSnapshot
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.api.main import app as engine_app
from security_engine.api.routes import engine as api_engine
from security_engine.controller import ControllerWorker
from security_engine.models.response import DefensiveAction, ResponseState
from security_engine.pipeline import AnalysisEngine


class EnvironmentClient:
    def __init__(self, env: IoTEnvironment) -> None:
        self.env = env

    def latest(self) -> EnvironmentSnapshot:
        if not self.env.latest:
            asyncio.run(self.env.step())
        return self.env.snapshot()

    def history(self, device_id: str, limit: int = 100):
        return self.env.device_history(device_id, limit=limit)

    def devices(self) -> list[dict]:
        return [{"device_id": device_id} for device_id in self.env.devices]


class RecordingEnforcer:
    def __init__(self, env: IoTEnvironment) -> None:
        self.env = env
        self.applied: list[DefensiveAction] = []

    def apply(self, action: DefensiveAction) -> bool:
        self.env.apply_defensive_action(action)
        self.applied.append(action)
        return True


def _step(env: IoTEnvironment):
    return asyncio.run(env.step())


def _lock(env: IoTEnvironment):
    return env.devices["lock-front-door"]


def _warm_controller(ticks: int = 12) -> tuple[IoTEnvironment, ControllerWorker, RecordingEnforcer]:
    env = IoTEnvironment()
    engine = AnalysisEngine()
    enforcer = RecordingEnforcer(env)
    worker = ControllerWorker(
        engine=engine,
        enforcer=enforcer,
        simulator=EnvironmentClient(env),
        poll_interval_seconds=0.05,
        heartbeat_stale_seconds=0.4,
    )
    for _ in range(ticks):
        _step(env)
        worker.cycle(bootstrap_history=True)
    return env, worker, enforcer


def test_health_exposes_controller_heartbeat() -> None:
    api_engine.reset()
    with TestClient(engine_app) as client:
        health = client.get("/api/v1/health").json()
        assert "controller" in health
        heartbeat = health["controller"]
        assert heartbeat["active"] is False
        assert heartbeat["enforcement_enabled"] is True
        assert heartbeat["cycle_count"] == 0

        status = client.get("/api/v1/controller").json()
        assert status["fresh"] is False
        paused = client.post("/api/v1/controller", json={"enforcement_enabled": False}).json()
        assert paused["enforcement_enabled"] is False
        restored = client.post("/api/v1/controller", json={"enforcement_enabled": True}).json()
        assert restored["enforcement_enabled"] is True


def test_worker_heartbeat_is_fresh_only_while_loop_runs() -> None:
    env, worker, _enforcer = _warm_controller(ticks=2)
    assert worker.heartbeat().active is False
    assert worker.is_fresh() is False

    worker.start()
    deadline = time.time() + 2.0
    while time.time() < deadline and worker.heartbeat().cycle_count < 4:
        time.sleep(0.05)
    beat = worker.heartbeat()
    assert beat.active is True
    assert beat.fresh is True
    assert beat.last_beat_at is not None
    worker.stop()
    assert worker.heartbeat().active is False
    assert worker.is_fresh() is False

    worker.last_beat_at = datetime.now(UTC) - timedelta(seconds=2)
    worker._running = True
    worker._thread = type("Alive", (), {"is_alive": staticmethod(lambda: True)})()
    assert worker.is_fresh() is False
    worker._running = False
    worker._thread = None
    env.reset()


def test_controller_contains_without_a_dashboard() -> None:
    env, worker, enforcer = _warm_controller()
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    _step(env)
    findings = worker.cycle()

    lock = _lock(env)
    finding = next(item for item in findings if item.device == "lock-front-door")
    recorded = worker.engine.latest_for("lock-front-door")
    assert recorded is finding
    assert finding.risk_score >= 50
    assert finding.threat_type in {"unauthorized_commands", "multi_stage_compromise"}
    assert finding.response_state in {"restricted", "quarantine"}
    assert lock.containment.state in {ResponseState.RESTRICTED, ResponseState.QUARANTINE}
    assert any(action.device_id == "lock-front-door" for action in enforcer.applied)

    _step(env)
    follow_up = env.latest["lock-front-door"]
    denied = [cmd for cmd in follow_up.command_history if cmd.result == "denied_by_containment"]
    assert follow_up.sensors.get("locked") is True
    assert denied
    assert follow_up.verified_containment is not None
    assert follow_up.verified_containment.verified or follow_up.containment.response_state in {
        "restricted",
        "quarantine",
    }


def test_paused_enforcement_still_records_findings() -> None:
    env, worker, enforcer = _warm_controller()
    before_state = _lock(env).containment.state
    before = len(enforcer.applied)
    worker.set_enforcement(False)
    assert worker.enforcement_enabled is False
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    _step(env)
    findings = worker.cycle()
    lock = _lock(env)
    finding = next(item for item in findings if item.device == "lock-front-door")
    assert finding.risk_score >= 50
    assert finding.response_state in {"restricted", "quarantine"}
    assert len(enforcer.applied) == before
    assert lock.containment.state == before_state


def test_ingest_endpoint_does_not_require_the_dashboard_to_keep_state() -> None:
    env, worker, enforcer = _warm_controller()
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.UNAUTHORIZED_COMMANDS,
            device_id="lock-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    _step(env)
    worker.cycle()
    recorded = [item.model_dump() for item in worker.engine.latest()]
    assert any(item["device"] == "lock-front-door" and item["risk_score"] >= 50 for item in recorded)
    fleet = worker.engine.response.fleet()
    lock_status = next(item for item in fleet if item.device_id == "lock-front-door")
    assert lock_status.last_action is not None
    assert lock_status.last_action.enforced is True
    assert enforcer.applied
