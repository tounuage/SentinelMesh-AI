"""Rule-based mesh correlation over observed device events.

This module does not read simulator attack labels (`attack_signals`,
`ActiveAttack`, or attack type enums). It only inspects command history
already present on telemetry samples.
"""

from __future__ import annotations

from iot_simulator.models.devices import DeviceType
from iot_simulator.models.telemetry import CommandRecord, TelemetrySample
from security_engine.models.findings import CorrelatedEvent, MeshIncident

CORRELATION_WINDOW_SECONDS = 10.0
ENTRY_TITLE = "Possible coordinated entry attempt"
ENTRY_DETAIL = "Shared source observed across camera and lock within 10 seconds."
ENTRY_RULE = "camera_then_lock_shared_source"
ENTRY_METHOD = "rule_based_correlation"
ENTRY_EXPLANATION = (
    "Rule-based correlation: an unauthorized camera command and an unauthorized "
    "lock command shared a source IP within 10 seconds. This is not a learned "
    "graph model, and it does not use simulator attack labels."
)
CAMERA_ID = "cam-front-door"
LOCK_ID = "lock-front-door"


def correlate_entry_attempt(
    samples: list[TelemetrySample],
    window_seconds: float = CORRELATION_WINDOW_SECONDS,
) -> MeshIncident | None:
    """Return one camera→lock incident when a shared source is observed in-window."""
    cameras = [sample for sample in samples if _is_camera(sample)]
    locks = [sample for sample in samples if _is_lock(sample)]
    if not cameras or not locks:
        return None

    best: tuple[float, CommandRecord, CommandRecord, TelemetrySample, TelemetrySample] | None = None
    for camera in cameras:
        for camera_event in _unauthorized_commands(camera):
            for lock in locks:
                for lock_event in _unauthorized_commands(lock):
                    if not _same_source(camera_event, lock_event):
                        continue
                    delta = (lock_event.timestamp - camera_event.timestamp).total_seconds()
                    if 0 <= delta <= window_seconds and (best is None or delta < best[0]):
                        best = (delta, camera_event, lock_event, camera, lock)

    if best is None:
        return None

    delta, camera_event, lock_event, camera, lock = best
    observed_at = lock_event.timestamp
    return MeshIncident(
        id=_incident_id(camera_event, lock_event),
        title=ENTRY_TITLE,
        detail=ENTRY_DETAIL,
        method=ENTRY_METHOD,
        rule=ENTRY_RULE,
        window_seconds=window_seconds,
        source_ip=camera_event.source_ip,
        device_ids=[camera.device_id, lock.device_id],
        sequence=[_as_event(camera, camera_event), _as_event(lock, lock_event)],
        observed_at=observed_at,
        delta_seconds=round(delta, 3),
        explanation=ENTRY_EXPLANATION,
    )


def _is_camera(sample: TelemetrySample) -> bool:
    return sample.device_type == DeviceType.SMART_CAMERA or sample.device_id == CAMERA_ID


def _is_lock(sample: TelemetrySample) -> bool:
    return sample.device_type == DeviceType.SMART_LOCK or sample.device_id == LOCK_ID


def _unauthorized_commands(sample: TelemetrySample) -> list[CommandRecord]:
    return [command for command in sample.command_history if not command.authorized]


def _same_source(left: CommandRecord, right: CommandRecord) -> bool:
    source = left.source_ip.strip() if left.source_ip else ""
    return bool(source) and source == right.source_ip


def _incident_id(camera_event: CommandRecord, lock_event: CommandRecord) -> str:
    camera_at = camera_event.timestamp.isoformat()
    lock_at = lock_event.timestamp.isoformat()
    return f"mesh-entry-{camera_event.source_ip}-{camera_at}-{lock_at}"


def _as_event(sample: TelemetrySample, command: CommandRecord) -> CorrelatedEvent:
    return CorrelatedEvent(
        device_id=sample.device_id,
        device_name=sample.name,
        device_type=sample.device_type.value if hasattr(sample.device_type, "value") else str(sample.device_type),
        command=command.command,
        source_ip=command.source_ip,
        timestamp=command.timestamp,
        authorized=command.authorized,
        result=command.result,
    )
