from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from security_engine.models.findings import ThreatType
from security_engine.models.response import DefensiveAction, DeviceResponseStatus, ResponseState
from security_engine.response.effects import build_effects, infer_device_kind, telemetry_policy_for

STATE_RANK = {
    ResponseState.NORMAL: 0,
    ResponseState.MONITOR: 1,
    ResponseState.RESTRICTED: 2,
    ResponseState.QUARANTINE: 3,
}

RECOVERY_NEXT = {
    ResponseState.QUARANTINE: ResponseState.MONITOR,
    ResponseState.RESTRICTED: ResponseState.MONITOR,
    ResponseState.MONITOR: ResponseState.NORMAL,
    ResponseState.NORMAL: ResponseState.NORMAL,
}

THREAT_FLOOR = {
    ThreatType.BENIGN: ResponseState.NORMAL,
    ThreatType.UNKNOWN_ANOMALY: ResponseState.MONITOR,
    ThreatType.ABNORMAL_POWER_USAGE: ResponseState.RESTRICTED,
    ThreatType.ABNORMAL_NETWORK_TRAFFIC: ResponseState.RESTRICTED,
    ThreatType.SUSPICIOUS_IP_CONNECTIONS: ResponseState.RESTRICTED,
    ThreatType.UNAUTHORIZED_COMMANDS: ResponseState.RESTRICTED,
    ThreatType.FIRMWARE_MODIFICATION: ResponseState.QUARANTINE,
    ThreatType.MULTI_STAGE_COMPROMISE: ResponseState.QUARANTINE,
}

THREAT_ALIASES = {
    "normal": ThreatType.BENIGN,
    "none": ThreatType.BENIGN,
    "ok": ThreatType.BENIGN,
    "clean": ThreatType.BENIGN,
    "restricted_mode": ThreatType.UNKNOWN_ANOMALY,
}


@dataclass
class DeviceResponseRecord:
    device_id: str
    state: ResponseState = ResponseState.NORMAL
    last_risk: float = 0.0
    last_threat: str = ThreatType.BENIGN.value
    consecutive_low: int = 0
    last_action: DefensiveAction | None = None
    history: list[DefensiveAction] = field(default_factory=list)


class ResponseEngine:
    """Autonomous cyber-defense policy: analysis in, containment state out."""

    LOW_RISK = 20.0
    MONITOR_RISK = 45.0
    QUARANTINE_RISK = 75.0
    FULL_RECOVERY_RISK = 12.0
    RECOVERY_STREAK = 2

    def __init__(self) -> None:
        self._devices: dict[str, DeviceResponseRecord] = {}

    def act(
        self,
        device_id: str,
        risk_score: float,
        threat_type: str,
        force_recovery: bool = False,
    ) -> DefensiveAction:
        threat = parse_threat_type(threat_type)
        score = float(max(0.0, min(100.0, risk_score)))
        record = self._devices.setdefault(device_id, DeviceResponseRecord(device_id=device_id))
        previous = record.state
        if score < self.LOW_RISK:
            record.consecutive_low += 1
        else:
            record.consecutive_low = 0

        desired = self.desired_state(score, threat)
        if force_recovery:
            new_state, transition = ResponseState.NORMAL, "forced_recovery"
            record.consecutive_low = 0
        else:
            new_state, transition = self._transition(previous, desired, score, record.consecutive_low)
        kind = infer_device_kind(device_id)
        effects = build_effects(
            state=new_state,
            previous=previous,
            transition=transition,
            threat_type=threat,
            device_kind=kind,
        )
        if transition in {"recovered", "forced_recovery"}:
            effects.recovery.in_progress = False
            effects.recovery.eligible = False
        elif transition == "recovering":
            effects.recovery.in_progress = True
            effects.recovery.restored = [
                "controller_channel_restored",
                "isolation_lifted",
                "firmware_reverified",
            ]

        rationale = self._rationale(score, threat, desired, new_state, transition)
        steps = self._steps(device_id, previous, new_state, effects, transition)
        action = DefensiveAction(
            action_id=uuid4(),
            timestamp=datetime.now(UTC),
            device_id=device_id,
            device_kind=kind,
            risk_score=round(score, 1),
            threat_type=threat.value,
            previous_state=previous,
            response_state=new_state,
            transition=transition,
            autonomous=True,
            action=self._action_text(device_id, new_state, threat, effects),
            rationale=rationale,
            steps_executed=steps,
            effects=effects,
            telemetry_policy=telemetry_policy_for(new_state),
        )
        record.state = new_state
        record.last_risk = score
        record.last_threat = threat.value
        record.last_action = action
        record.history.append(action)
        record.history = record.history[-50:]
        return action

    def recover(self, device_id: str, force: bool = False) -> DefensiveAction:
        record = self._devices.setdefault(device_id, DeviceResponseRecord(device_id=device_id))
        if force:
            return self.act(device_id, 0.0, ThreatType.BENIGN.value, force_recovery=True)

        record.consecutive_low = max(record.consecutive_low, self.RECOVERY_STREAK)
        return self.act(device_id, min(record.last_risk, self.FULL_RECOVERY_RISK), ThreatType.BENIGN.value)

    def status(self, device_id: str) -> DeviceResponseStatus | None:
        record = self._devices.get(device_id)
        if record is None:
            return None
        return DeviceResponseStatus(
            device_id=record.device_id,
            response_state=record.state,
            last_risk_score=record.last_risk,
            last_threat_type=record.last_threat,
            consecutive_low_scores=record.consecutive_low,
            last_action=record.last_action,
        )

    def fleet(self) -> list[DeviceResponseStatus]:
        return [status for device_id in self._devices if (status := self.status(device_id))]

    def reset(self) -> None:
        self._devices.clear()

    def desired_state(self, risk_score: float, threat_type: ThreatType | str) -> ResponseState:
        threat = threat_type if isinstance(threat_type, ThreatType) else parse_threat_type(threat_type)
        by_risk = self._state_from_risk(risk_score)
        floor = THREAT_FLOOR.get(threat, ResponseState.NORMAL)
        if threat == ThreatType.BENIGN:
            return by_risk
        if threat == ThreatType.UNKNOWN_ANOMALY and risk_score < self.LOW_RISK:
            return ResponseState.NORMAL
        return by_risk if STATE_RANK[by_risk] >= STATE_RANK[floor] else floor

    def _state_from_risk(self, risk_score: float) -> ResponseState:
        if risk_score >= self.QUARANTINE_RISK:
            return ResponseState.QUARANTINE
        if risk_score >= self.MONITOR_RISK:
            return ResponseState.RESTRICTED
        if risk_score >= self.LOW_RISK:
            return ResponseState.MONITOR
        return ResponseState.NORMAL

    def _transition(
        self,
        current: ResponseState,
        desired: ResponseState,
        risk_score: float,
        consecutive_low: int,
    ) -> tuple[ResponseState, str]:
        if STATE_RANK[desired] > STATE_RANK[current]:
            return desired, "escalated"
        if desired == current:
            return current, "hold"
        ready = risk_score < self.FULL_RECOVERY_RISK or consecutive_low >= self.RECOVERY_STREAK
        if not ready:
            return current, "hold"
        nxt = RECOVERY_NEXT[current]
        if nxt == ResponseState.NORMAL:
            return ResponseState.NORMAL, "recovered"
        return nxt, "recovering"

    def _action_text(
        self,
        device_id: str,
        state: ResponseState,
        threat: ThreatType,
        effects,
    ) -> str:
        labels = {
            ResponseState.NORMAL: "NORMAL: allow all activity",
            ResponseState.MONITOR: "MONITOR: collect additional telemetry",
            ResponseState.RESTRICTED: "RESTRICTED MODE: reduce permissions and block suspicious communication",
            ResponseState.QUARANTINE: "QUARANTINE: isolate device completely",
        }
        extra = ""
        if state == ResponseState.RESTRICTED:
            extra = f" Blocked peers: {', '.join(effects.network_blocking.blocked_peers[:3])}."
        if state == ResponseState.QUARANTINE:
            extra = f" Only controller {effects.network_blocking.allowed_peers[0]} remains reachable."
        if effects.recovery.in_progress:
            extra = " Recovery is in progress; the device is being restored to a monitored state."
        if effects.recovery.restored and state == ResponseState.NORMAL:
            extra = " Device recovered: network, permissions, and firmware restored."
        return (
            f"{labels[state]} on {device_id} "
            f"(threat={threat.value}).{extra}"
        )

    def _rationale(
        self,
        score: float,
        threat: ThreatType,
        desired: ResponseState,
        applied: ResponseState,
        transition: str,
    ) -> str:
        if transition == "hold" and applied != desired:
            return (
                f"Risk {score:.1f} and {threat.value} would allow {desired.value}, "
                f"but {applied.value} is held until consecutive low-risk analyses confirm recovery."
            )
        if transition == "recovering":
            return (
                f"Risk fell to {score:.1f}. Autonomous recovery stepped {applied.value} "
                f"toward normal rather than dropping containment in one move."
            )
        if transition == "recovered":
            return f"Risk {score:.1f} and no active threat. Device returned to normal operation."
        if transition == "forced_recovery":
            return "Operator-authorized recovery restored the device to NORMAL."
        if transition == "escalated":
            return (
                f"Autonomous defense selected {applied.value} because risk {score:.1f}/100 "
                f"and threat {threat.value} require that containment level."
            )
        return (
            f"Remaining in {applied.value}. Risk {score:.1f}/100, threat {threat.value}."
        )

    def _steps(self, device_id: str, previous: ResponseState, state: ResponseState, effects, transition: str) -> list[str]:
        steps = [
            f"received analysis for {device_id}",
            f"previous state {previous.value} → {state.value} ({transition})",
        ]
        policy = telemetry_policy_for(state)
        if policy.collect_additional:
            steps.append("enabled additional telemetry capture")
        if effects.network_blocking.applied:
            steps.append(f"network policy {effects.network_blocking.mode}")
        if effects.permission_reduction.applied:
            revoked = ", ".join(effects.permission_reduction.revoked[:4]) or "high-risk scopes"
            steps.append(f"revoked permissions: {revoked}")
        if effects.safe_operation_mode.applied:
            steps.append("engaged safe operation mode")
        if effects.recovery.in_progress:
            steps.append("started device recovery")
        if effects.recovery.restored and state == ResponseState.NORMAL:
            steps.append("completed device recovery")
        if state == ResponseState.NORMAL and transition == "hold":
            steps.append("allowed all activity")
        return steps


def parse_threat_type(value: str) -> ThreatType:
    normalized = value.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized in THREAT_ALIASES:
        return THREAT_ALIASES[normalized]
    try:
        return ThreatType(normalized)
    except ValueError:
        return ThreatType.UNKNOWN_ANOMALY
