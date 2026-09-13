from __future__ import annotations

from security_engine.models.findings import ThreatType
from security_engine.models.response import (
    NetworkBlockingEffect,
    PermissionReductionEffect,
    RecoveryEffect,
    ResponseState,
    SafeOperationEffect,
    SimulatedEffects,
    TelemetryPolicy,
)

CONTROLLER_PEER = "192.168.1.10"

DEVICE_PERMISSIONS: dict[str, list[str]] = {
    "smart_camera": [
        "live_stream",
        "clip_upload",
        "motion_alerts",
        "privacy_shutter_override",
        "ota_update",
        "admin_api",
    ],
    "smart_plug": [
        "remote_on",
        "remote_off",
        "schedule_override",
        "energy_report",
        "ota_update",
        "admin_api",
    ],
    "smart_thermostat": [
        "set_setpoint",
        "remote_mode_change",
        "weather_sync",
        "ota_update",
        "admin_api",
    ],
    "smart_lock": [
        "remote_unlock",
        "remote_lock",
        "pin_manage",
        "status_poll",
        "ota_update",
        "admin_api",
    ],
    "iot_device": ["remote_control", "ota_update", "admin_api"],
}

RESTRICTED_REVOKE = {
    "smart_camera": ["live_stream", "clip_upload", "privacy_shutter_override", "ota_update", "admin_api"],
    "smart_plug": ["remote_on", "schedule_override", "ota_update", "admin_api"],
    "smart_thermostat": ["set_setpoint", "remote_mode_change", "ota_update", "admin_api"],
    "smart_lock": ["remote_unlock", "pin_manage", "ota_update", "admin_api"],
    "iot_device": ["remote_control", "ota_update", "admin_api"],
}

SAFE_MODE_ACTIONS = {
    "smart_camera": [
        "close_privacy_shutter",
        "stop_recording",
        "block_live_stream",
        "cap_bitrate",
    ],
    "smart_plug": ["force_relay_off", "lock_schedule", "cap_power_draw"],
    "smart_thermostat": ["enter_eco_setpoint", "lock_controls", "idle_hvac"],
    "smart_lock": ["force_lock", "disable_remote_unlock", "shorten_auto_relock"],
    "iot_device": ["enter_failsafe", "disable_remote_admin"],
}


def infer_device_kind(device_id: str) -> str:
    lowered = device_id.lower()
    if lowered.startswith("cam"):
        return "smart_camera"
    if lowered.startswith("plug"):
        return "smart_plug"
    if lowered.startswith("thermo"):
        return "smart_thermostat"
    if lowered.startswith("lock"):
        return "smart_lock"
    return "iot_device"


def telemetry_policy_for(state: ResponseState) -> TelemetryPolicy:
    if state == ResponseState.NORMAL:
        return TelemetryPolicy(
            collect_additional=False,
            packet_capture=False,
            dns_logging=False,
            command_audit="standard",
            sample_multiplier=1,
        )
    if state == ResponseState.MONITOR:
        return TelemetryPolicy(
            collect_additional=True,
            packet_capture=True,
            dns_logging=True,
            command_audit="verbose",
            sample_multiplier=4,
        )
    if state == ResponseState.RESTRICTED:
        return TelemetryPolicy(
            collect_additional=True,
            packet_capture=True,
            dns_logging=True,
            command_audit="deny_unsigned",
            sample_multiplier=2,
        )
    return TelemetryPolicy(
        collect_additional=True,
        packet_capture=True,
        dns_logging=True,
        command_audit="deny_all",
        sample_multiplier=1,
    )


def build_effects(
    *,
    state: ResponseState,
    previous: ResponseState,
    transition: str,
    threat_type: ThreatType,
    device_kind: str,
    suspicious_hint: str | None = None,
) -> SimulatedEffects:
    permissions = list(DEVICE_PERMISSIONS.get(device_kind, DEVICE_PERMISSIONS["iot_device"]))
    recovery_next = {
        ResponseState.QUARANTINE: ResponseState.MONITOR,
        ResponseState.RESTRICTED: ResponseState.MONITOR,
        ResponseState.MONITOR: ResponseState.NORMAL,
        ResponseState.NORMAL: None,
    }[state]

    if state == ResponseState.NORMAL:
        restored = []
        if transition in {"recovered", "forced_recovery"}:
            restored = [
                "network_allow_all",
                "permissions_restored",
                "safe_mode_cleared",
                "signed_firmware_restored",
            ]
        return SimulatedEffects(
            network_blocking=NetworkBlockingEffect(
                applied=False,
                mode="allow_all",
                allowed_peers=["*"],
                description="All device communication is permitted.",
            ),
            permission_reduction=PermissionReductionEffect(
                applied=False,
                remaining=permissions,
                description="Full device permissions are active.",
            ),
            safe_operation_mode=SafeOperationEffect(
                applied=False,
                description="Device operates with its normal control surface.",
            ),
            recovery=RecoveryEffect(
                eligible=False,
                in_progress=False,
                restored=restored,
                next_state=None,
                conditions="Remain in NORMAL while risk stays below 20.",
                description=(
                    "Device recovered to normal operation."
                    if restored
                    else "No recovery action required."
                ),
            ),
        )

    if state == ResponseState.MONITOR:
        restored = []
        if transition == "recovering":
            restored = ["lan_reconnected", "safe_mode_cleared", "controller_channel_open"]
        return SimulatedEffects(
            network_blocking=NetworkBlockingEffect(
                applied=False,
                mode="capture",
                allowed_peers=["*"],
                description="Traffic is allowed; packet, DNS, and command telemetry are expanded.",
            ),
            permission_reduction=PermissionReductionEffect(
                applied=False,
                remaining=permissions,
                description="Permissions stay intact while the device is watched more closely.",
            ),
            safe_operation_mode=SafeOperationEffect(
                applied=False,
                description="Safe mode is not engaged during monitoring.",
            ),
            recovery=RecoveryEffect(
                eligible=True,
                in_progress=transition == "recovering",
                restored=restored,
                next_state=ResponseState.NORMAL,
                conditions="Return to NORMAL after consecutive low-risk analyses (risk < 20).",
                description=(
                    "Stepping out of containment into heightened monitoring."
                    if transition == "recovering"
                    else "Collect additional evidence before any containment."
                ),
            ),
        )

    blocked_peers = ["untrusted_wan", "suspicious_destinations"]
    blocked_ports = [4444, 6667, 31337, 8089]
    if suspicious_hint:
        blocked_peers = [suspicious_hint, *blocked_peers]
    revoked = list(RESTRICTED_REVOKE.get(device_kind, RESTRICTED_REVOKE["iot_device"]))
    remaining = [perm for perm in permissions if perm not in revoked]
    safe_actions = list(SAFE_MODE_ACTIONS.get(device_kind, SAFE_MODE_ACTIONS["iot_device"]))

    if state == ResponseState.RESTRICTED:
        threat_blocks = _threat_network_extras(threat_type)
        blocked_peers = list(dict.fromkeys(blocked_peers + threat_blocks))
        return SimulatedEffects(
            network_blocking=NetworkBlockingEffect(
                applied=True,
                mode="trusted_only",
                blocked_peers=blocked_peers,
                blocked_ports=blocked_ports,
                allowed_peers=[CONTROLLER_PEER, "trusted_cloud"],
                description="Suspicious destinations and non-standard ports are blocked; only trusted peers remain.",
            ),
            permission_reduction=PermissionReductionEffect(
                applied=True,
                revoked=revoked,
                remaining=remaining,
                description="Remote admin, OTA, and high-risk commands are revoked.",
            ),
            safe_operation_mode=SafeOperationEffect(
                applied=True,
                actions=safe_actions,
                description="Device is forced into a known-good operating posture.",
            ),
            recovery=RecoveryEffect(
                eligible=True,
                in_progress=False,
                next_state=recovery_next,
                conditions="Step down to MONITOR after consecutive low-risk analyses.",
                description="Restricted mode holds until the risk score falls and stays low.",
            ),
        )

    all_revoked = list(permissions)
    return SimulatedEffects(
        network_blocking=NetworkBlockingEffect(
            applied=True,
            mode="full_isolation",
            blocked_peers=["*"],
            blocked_ports=blocked_ports,
            allowed_peers=[CONTROLLER_PEER],
            description="Device is isolated from the LAN/WAN except the SentinelMesh controller channel.",
        ),
        permission_reduction=PermissionReductionEffect(
            applied=True,
            revoked=all_revoked,
            remaining=["recovery_agent"],
            description="All device permissions are revoked except the recovery channel.",
        ),
        safe_operation_mode=SafeOperationEffect(
            applied=True,
            actions=safe_actions + ["isolate_from_mesh", "preserve_forensic_telemetry"],
            description="Device is frozen in failsafe and cut off from the rest of the home mesh.",
        ),
        recovery=RecoveryEffect(
            eligible=True,
            in_progress=False,
            next_state=ResponseState.MONITOR,
            conditions="Quarantine lifts to MONITOR only after risk < 20 on consecutive analyses, or an explicit recover.",
            description="Isolation remains until recovery is authorized.",
        ),
    )


def _threat_network_extras(threat_type: ThreatType) -> list[str]:
    if threat_type in {
        ThreatType.SUSPICIOUS_IP_CONNECTIONS,
        ThreatType.ABNORMAL_NETWORK_TRAFFIC,
        ThreatType.MULTI_STAGE_COMPROMISE,
    }:
        return ["203.0.113.0/24", "198.51.100.0/24"]
    if threat_type == ThreatType.FIRMWARE_MODIFICATION:
        return ["ota_sideload", "unsigned_updater"]
    if threat_type == ThreatType.UNAUTHORIZED_COMMANDS:
        return ["unknown_session_sources"]
    return []
