from fastapi.testclient import TestClient

from iot_simulator.api.main import app
from iot_simulator.models.attacks import AttackType


def test_health_and_attack_injection() -> None:
    with TestClient(app) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200

        tick = client.post("/api/v1/simulation/tick")
        assert tick.status_code == 200
        payload = tick.json()
        assert len(payload["devices"]) == 4

        camera = next(d for d in payload["devices"] if d["device_type"] == "smart_camera")
        assert "network" in camera
        assert "power" in camera
        assert "sensors" in camera
        assert "command_history" in camera

        injected = client.post(
            "/api/v1/attacks",
            json={
                "attack_type": AttackType.UNAUTHORIZED_COMMANDS.value,
                "device_id": "lock-front-door",
                "duration_seconds": 30,
                "intensity": "high",
            },
        )
        assert injected.status_code == 201

        attacked = client.post("/api/v1/simulation/tick").json()
        lock = next(d for d in attacked["devices"] if d["device_id"] == "lock-front-door")
        assert any(not cmd["authorized"] for cmd in lock["command_history"])
        assert "unauthorized_commands" in lock["attack_signals"]
