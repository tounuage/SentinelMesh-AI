from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from iot_simulator.models.attacks import AttackIntensity, AttackRequest, AttackType
from iot_simulator.models.telemetry import ActiveAttack


class AttackInjector:
    """Injects synthetic attack effects into the running environment."""

    def __init__(self) -> None:
        self._attacks: dict[str, ActiveAttack] = {}

    def inject(self, request: AttackRequest, device_id: str) -> ActiveAttack:
        now = datetime.now(UTC)
        attack = ActiveAttack(
            attack_id=uuid4(),
            attack_type=request.attack_type,
            device_id=device_id,
            intensity=request.intensity,
            started_at=now,
            expires_at=now + timedelta(seconds=request.duration_seconds),
        )
        self._attacks[str(attack.attack_id)] = attack
        return attack

    def stop(self, attack_id: str | None = None, device_id: str | None = None) -> int:
        removed = 0
        for key, attack in list(self._attacks.items()):
            if attack_id and str(attack.attack_id) != attack_id:
                continue
            if device_id and attack.device_id != device_id:
                continue
            if attack_id or device_id:
                del self._attacks[key]
                removed += 1
        if not attack_id and not device_id:
            removed = len(self._attacks)
            self._attacks.clear()
        return removed

    def active(self) -> list[ActiveAttack]:
        self._expire()
        return list(self._attacks.values())

    def attacks_for(self, device_id: str) -> dict[AttackType, AttackIntensity]:
        self._expire()
        return {
            attack.attack_type: attack.intensity
            for attack in self._attacks.values()
            if attack.device_id == device_id
        }

    def _expire(self) -> None:
        now = datetime.now(UTC)
        expired = [key for key, attack in self._attacks.items() if attack.expires_at <= now]
        for key in expired:
            del self._attacks[key]
