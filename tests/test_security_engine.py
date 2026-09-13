from __future__ import annotations

import asyncio

import numpy as np
from fastapi.testclient import TestClient

from iot_simulator.api.main import app as simulator_app
from iot_simulator.models.attacks import AttackRequest, AttackType
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.api.main import app as engine_app
from security_engine.api.routes import engine as api_engine
from security_engine.detectors.base import AnomalyDetector, DetectorRegistry
from security_engine.models.findings import DetectorResult
from security_engine.pipeline import AnalysisEngine

REQUIRED_FIELDS = {
    "device",
    "risk_score",
    "threat_type",
    "explanation",
    "recommended_action",
}


def _warmup(env: IoTEnvironment, engine: AnalysisEngine, ticks: int = 12) -> None:
    async def run() -> None:
        for _ in range(ticks):
            snapshot = await env.step()
            engine.analyze_snapshot(snapshot)

    asyncio.run(run())


def test_health_exposes_detectors() -> None:
    api_engine.reset()
    with TestClient(engine_app) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        payload = health.json()
        assert payload["status"] == "ok"
        assert payload["models_ready"] is False
        assert payload["profile_count"] == 0
        assert "isolation_forest" in payload["detectors"]
        assert "statistical" in payload["detectors"]
        assert "cluster_distance" in payload["detectors"]


def test_analyze_endpoint_schema_and_benign_baseline() -> None:
    api_engine.reset()
    with TestClient(simulator_app) as sim, TestClient(engine_app) as engine_client:
        sim.post("/api/v1/simulation/reset")
        for _ in range(8):
            snapshot = sim.post("/api/v1/simulation/tick").json()
            findings = engine_client.post("/api/v1/analyze/snapshot", json=snapshot).json()
            assert findings
            assert REQUIRED_FIELDS <= set(findings[0])
        camera = next(item for item in findings if item["device"] == "cam-front-door")
        assert camera["risk_score"] < 40
        assert camera["threat_type"] == "benign"


def test_detects_unauthorized_commands_on_lock() -> None:
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

    async def attacked() -> None:
        return await env.step()

    snapshot = asyncio.run(attacked())
    lock = next(sample for sample in snapshot.devices if sample.device_id == "lock-front-door")
    result = engine.analyze(lock)
    payload = result.model_dump()
    assert REQUIRED_FIELDS <= set(payload)
    assert result.device == "lock-front-door"
    assert result.risk_score >= 50
    assert result.threat_type in {
        "unauthorized_commands",
        "multi_stage_compromise",
    }
    assert "unauthorized" in result.explanation.lower() or "lock" in result.explanation.lower()
    assert result.recommended_action


def test_detects_suspicious_network_and_firmware() -> None:
    env = IoTEnvironment()
    engine = AnalysisEngine()
    _warmup(env, engine)

    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.SUSPICIOUS_IP_CONNECTIONS,
            device_id="cam-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )
    env.inject_attack(
        AttackRequest(
            attack_type=AttackType.FIRMWARE_MODIFICATION,
            device_id="cam-front-door",
            duration_seconds=60,
            intensity="high",
        )
    )

    async def attacked() -> None:
        return await env.step()

    snapshot = asyncio.run(attacked())
    camera = next(sample for sample in snapshot.devices if sample.device_id == "cam-front-door")
    result = engine.analyze(camera)
    assert result.risk_score >= 70
    assert result.threat_type in {
        "firmware_modification",
        "suspicious_ip_connections",
        "multi_stage_compromise",
    }
    assert "cam-front-door" in result.recommended_action or "Quarantine" in result.recommended_action or "Isolate" in result.recommended_action


def test_registry_accepts_new_detector() -> None:
    class FlagDetector(AnomalyDetector):
        name = "flag"
        min_samples = 1

        def fit(self, device_id: str, X: np.ndarray, feature_names) -> None:
            self._ready.add(device_id)

        def score(self, device_id: str, x: np.ndarray, feature_names) -> DetectorResult:
            return DetectorResult(
                detector=self.name,
                anomaly_score=1.0,
                is_anomaly=True,
                details={"injected": True},
                contributing_features=["packets_sent"],
            )

    registry = DetectorRegistry()
    registry.register(FlagDetector())
    engine = AnalysisEngine(registry=registry)
    env = IoTEnvironment()
    _warmup(env, engine, ticks=6)
    finding = engine.latest_for("plug-living-lamp")
    assert finding is not None
    assert "flag" in engine.detector_names()
    assert finding.risk_score >= 40
    assert finding.threat_type != "benign"
