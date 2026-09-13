from __future__ import annotations

from datetime import datetime

from iot_simulator.models.telemetry import (
    ActionOutcome,
    ActiveAttack,
    CommandRecord,
    IncidentStep,
    TelemetrySample,
    VerifiedContainment,
)
from iot_simulator.simulation.containment import DeviceContainment
from security_engine.models.response import DefensiveAction, ResponseState

UNLOCK_COMMANDS = {"unlock", "remote_unlock"}


def latency_ms(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return round(max(0.0, (end - start).total_seconds() * 1000.0), 1)


def _state_value(value: object) -> str:
    return value.value if isinstance(value, ResponseState) else str(value or "normal")


def _is_contained(state: object) -> bool:
    return _state_value(state) in {"restricted", "quarantine"}


def _device_kind(sample: TelemetrySample) -> str:
    device_type = sample.device_type
    return device_type.value if hasattr(device_type, "value") else str(device_type)


def _is_lock(sample: TelemetrySample) -> bool:
    return _device_kind(sample) == "smart_lock" or "lock" in sample.device_id


def _hostile_accepted(commands: list[CommandRecord]) -> CommandRecord | None:
    for command in commands:
        if not command.authorized and command.result != "denied_by_containment":
            return command
    return None


def _denied_unlock(commands: list[CommandRecord]) -> CommandRecord | None:
    for command in commands:
        if command.result != "denied_by_containment":
            continue
        if command.command in UNLOCK_COMMANDS or not command.authorized:
            return command
    return None


def build_verified_containment(
    sample: TelemetrySample,
    containment: DeviceContainment | None = None,
    attack: ActiveAttack | None = None,
    action: DefensiveAction | None = None,
) -> VerifiedContainment:
    """Separate intended policy from observed device behavior using real timestamps."""
    report = sample.containment
    commands = list(sample.command_history)
    detected_cmd = _hostile_accepted(commands)
    denied_cmd = _denied_unlock(commands)

    detected_at = (containment.detected_at if containment else None) or report.detected_at
    if detected_at is None and detected_cmd is not None:
        detected_at = detected_cmd.timestamp
    requested_at = (containment.requested_at if containment else None) or report.requested_at
    if requested_at is None and action is not None and _is_contained(action.response_state):
        requested_at = action.timestamp
    acknowledged_at = (containment.applied_at if containment else None) or report.applied_at
    denied_at = (containment.first_denied_at if containment else None) or report.first_denied_at
    if denied_at is None and denied_cmd is not None:
        denied_at = denied_cmd.timestamp

    attack_started = attack.started_at if attack is not None else None
    state = _state_value(containment.state if containment is not None else report.response_state)
    contained = _is_contained(state) or bool(report.safe_mode)
    lock_kind = _is_lock(sample)
    hostile_name = "unlock" if lock_kind or (detected_cmd and detected_cmd.command in UNLOCK_COMMANDS) else "command"
    denied_name = "unlock" if lock_kind or (denied_cmd and denied_cmd.command in UNLOCK_COMMANDS) else "command"

    intended, observed, outcomes = _intended_vs_observed(sample, action, contained, denied_cmd)
    sequence = [
        IncidentStep(
            id="detected",
            label=f"Unauthorized {hostile_name} detected",
            kind="observed",
            complete=detected_at is not None,
            at=detected_at,
            detail=(
                f"{detected_cmd.command} from {detected_cmd.source_ip} was accepted without authorization."
                if detected_cmd
                else "Hostile remote unlock was observed on this device."
                if detected_at
                else "Waiting for a hostile command on this device."
            ),
        ),
        IncidentStep(
            id="requested",
            label="Containment requested",
            kind="intended",
            complete=requested_at is not None and (action is not None or contained),
            at=requested_at,
            detail=(
                action.action
                if action is not None and _is_contained(getattr(action, "response_state", state))
                else f"Policy requested {state}."
                if contained
                else "No defensive action has been issued yet."
            ),
        ),
        IncidentStep(
            id="acknowledged",
            label="Simulator acknowledged",
            kind="observed",
            complete=bool(acknowledged_at and contained),
            at=acknowledged_at if contained else None,
            detail=(
                f"Enforcement plane entered {state}; safe mode={'on' if report.safe_mode else 'off'}."
                if contained
                else "Simulator has not applied a blocking policy yet."
            ),
        ),
        IncidentStep(
            id="denied",
            label=f"Next {denied_name} attempt: DENIED",
            kind="observed",
            complete=denied_at is not None and denied_cmd is not None,
            at=denied_at,
            detail=(
                f"{denied_cmd.command} from {denied_cmd.source_ip} returned {denied_cmd.result}."
                if denied_cmd
                else "Keep the attack running to prove the next attempt is blocked."
            ),
        ),
    ]
    return VerifiedContainment(
        device_id=sample.device_id,
        verified=all(step.complete for step in sequence),
        detection_latency_ms=latency_ms(attack_started, detected_at),
        containment_latency_ms=latency_ms(detected_at, denied_at or acknowledged_at),
        intended=intended,
        observed=observed,
        outcomes=outcomes,
        sequence=sequence,
    )


def _intended_vs_observed(
    sample: TelemetrySample,
    action: DefensiveAction | None,
    contained: bool,
    denied_cmd: CommandRecord | None,
) -> tuple[list[str], list[str], list[ActionOutcome]]:
    sensors = sample.sensors
    report = sample.containment
    intended_state = (
        _state_value(action.response_state)
        if action is not None and _is_contained(action.response_state)
        else (report.response_state if contained else "restricted")
    )
    safe_actions = list(action.effects.safe_operation_mode.actions) if action and action.effects else []
    revoked = (
        list(action.effects.permission_reduction.revoked)
        if action and action.effects
        else list(report.revoked_permissions)
    )
    want_lock = "force_lock" in safe_actions or _is_lock(sample)
    want_unlock_revoked = "disable_remote_unlock" in safe_actions or "remote_unlock" in revoked or want_lock
    locked = sensors.get("locked")
    remote_unlock = sensors.get("remote_unlock_enabled")

    outcomes = [
        ActionOutcome(
            label="Containment state",
            intended=intended_state,
            observed=report.response_state,
            matched=contained and (action is None or report.response_state == intended_state),
        ),
        ActionOutcome(
            label="Follow-up command",
            intended="DENIED",
            observed=denied_cmd.result.replace("_", " ").upper() if denied_cmd else "still allowed / not attempted",
            matched=denied_cmd is not None,
        ),
    ]
    if want_lock or locked is not None:
        outcomes.insert(
            1,
            ActionOutcome(
                label="Door lock",
                intended="forced shut",
                observed="locked" if locked else "unlocked",
                matched=locked is True,
            ),
        )
    if want_unlock_revoked:
        outcomes.insert(
            -1,
            ActionOutcome(
                label="Remote unlock",
                intended="revoked",
                observed="disabled" if remote_unlock is False or contained else "enabled",
                matched=contained and remote_unlock is not True,
            ),
        )
    return (
        [f"{item.label}: {item.intended}" for item in outcomes],
        [f"{item.label}: {item.observed}" for item in outcomes],
        outcomes,
    )


def merge_incident(previous: VerifiedContainment | None, current: VerifiedContainment) -> VerifiedContainment:
    if previous is None:
        return current
    if current.verified:
        return previous if previous.verified else current
    if previous.verified:
        current_detected = next((step.at for step in current.sequence if step.id == "detected" and step.at), None)
        previous_denied = next((step.at for step in previous.sequence if step.id == "denied" and step.at), None)
        if current_detected and previous_denied and current_detected > previous_denied:
            return current
        return previous
    if any(step.complete for step in current.sequence):
        return current
    return previous
