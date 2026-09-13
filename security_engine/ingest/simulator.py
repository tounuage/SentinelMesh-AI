from __future__ import annotations

import httpx

from iot_simulator.models.telemetry import EnvironmentSnapshot, TelemetrySample
from security_engine.config import settings


class SimulatorClient:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or settings.simulator_url).rstrip("/")

    def latest(self) -> EnvironmentSnapshot:
        response = httpx.get(f"{self.base_url}/api/v1/telemetry", timeout=5.0)
        response.raise_for_status()
        return EnvironmentSnapshot.model_validate(response.json())

    def history(self, device_id: str, limit: int = 100) -> list[TelemetrySample]:
        response = httpx.get(
            f"{self.base_url}/api/v1/telemetry/{device_id}/history",
            params={"limit": limit},
            timeout=5.0,
        )
        response.raise_for_status()
        return [TelemetrySample.model_validate(item) for item in response.json()]

    def devices(self) -> list[dict]:
        response = httpx.get(f"{self.base_url}/api/v1/devices", timeout=5.0)
        response.raise_for_status()
        return response.json()
