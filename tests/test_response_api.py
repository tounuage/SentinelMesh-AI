from fastapi.testclient import TestClient

from iot_simulator.api.main import app
from iot_simulator.models.attacks import AttackType
from security_engine.api.main import app as response_app


def test_device_action_api_quarantines_and_blocks_network() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/simulation/reset")
        injected = client.post(
            "/api/v1/attacks",
            json={
                "attack_type": AttackType.SUSPICIOUS_IP_CONNECTIONS.value,
                "device_id": "cam-front-door",
                "duration_seconds": 60,
                "intensity": "high",
            },
        )
        assert injected.status_code == 201
        before = client.post("/api/v1/simulation/tick").json()
        camera = next(d for d in before["devices"] if d["device_id"] == "cam-front-door")
        assert any(conn["reputation"] == "suspicious" for conn in camera["network"]["active_connections"])

        action = client.post(
            "/device/action",
            json={
                "device_id": "cam-front-door",
                "risk_score": 86,
                "threat_type": "suspicious_ip_connections",
            },
        )
        assert action.status_code == 200
        payload = action.json()
        assert payload["response_state"] == "quarantine"
        assert payload["enforced"] is True
        assert payload["effects"]["network_blocking"]["mode"] == "full_isolation"
        assert payload["effects"]["safe_operation_mode"]["applied"] is True

        after = client.post("/api/v1/simulation/tick").json()
        contained = next(d for d in after["devices"] if d["device_id"] == "cam-front-door")
        assert contained["status"] == "quarantined"
        assert contained["containment"]["isolated"] is True
        assert contained["sensors"]["privacy_shutter_open"] is False
        assert contained["sensors"]["recording"] is False
        peers = {conn["remote_ip"] for conn in contained["network"]["active_connections"]}
        assert peers == {"192.168.1.10"}
        assert contained["network"]["unusual_ports"] == []


def test_restricted_mode_denies_unauthorized_commands() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/simulation/reset")
        client.post(
            "/api/v1/attacks",
            json={
                "attack_type": AttackType.UNAUTHORIZED_COMMANDS.value,
                "device_id": "lock-front-door",
                "duration_seconds": 60,
                "intensity": "high",
            },
        )
        action = client.post(
            "/api/v1/device/action",
            json={
                "device_id": "lock-front-door",
                "risk_score": 64,
                "threat_type": "unauthorized_commands",
            },
        )
        assert action.status_code == 200
        assert action.json()["response_state"] == "restricted"

        tick = client.post("/api/v1/simulation/tick").json()
        lock = next(d for d in tick["devices"] if d["device_id"] == "lock-front-door")
        assert lock["status"] == "restricted"
        assert lock["sensors"]["locked"] is True
        denied = [cmd for cmd in lock["command_history"] if cmd["result"] == "denied_by_containment"]
        assert denied
        assert "deep_telemetry" in lock["sensors"]


def test_monitor_collects_additional_telemetry() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/simulation/reset")
        action = client.post(
            "/device/action",
            json={"device_id": "plug-living-lamp", "risk_score": 28, "threat_type": "unknown_anomaly"},
        )
        assert action.json()["response_state"] == "monitor"
        tick = client.post("/api/v1/simulation/tick").json()
        plug = next(d for d in tick["devices"] if d["device_id"] == "plug-living-lamp")
        assert plug["status"] == "monitoring"
        assert plug["containment"]["extra_telemetry"] is True
        assert "deep_telemetry" in plug["sensors"]


def test_recovery_restores_normal_operation() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/simulation/reset")
        client.post(
            "/device/action",
            json={"device_id": "thermo-hallway", "risk_score": 92, "threat_type": "firmware_modification"},
        )
        recovered = client.post("/device/recover", json={"device_id": "thermo-hallway", "force": True})
        assert recovered.status_code == 200
        assert recovered.json()["response_state"] == "normal"
        tick = client.post("/api/v1/simulation/tick").json()
        thermo = next(d for d in tick["devices"] if d["device_id"] == "thermo-hallway")
        assert thermo["containment"]["response_state"] == "normal"
        assert thermo["firmware_signed"] is True
        assert thermo["sensors"].get("controls_locked") is not True


def test_response_engine_service_device_action() -> None:
    with TestClient(response_app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        action = client.post(
            "/device/action",
            json={
                "device_id": "lock-front-door",
                "risk_score": 81,
                "threat_type": "unauthorized_commands",
            },
        )
        assert action.status_code == 200
        body = action.json()
        assert body["response_state"] == "quarantine"
        assert body["action"]
        assert body["steps_executed"]
