from __future__ import annotations

from dataclasses import dataclass

from iot_simulator.models.telemetry import TelemetrySample
from security_engine.models.findings import PhysicalAssessment, ThreatType
from security_engine.response.effects import SAFE_MODE_ACTIONS, infer_device_kind


@dataclass(frozen=True)
class HazardProfile:
    hazard: str
    consequence: str
    multiplier: float


DEVICE_CRITICALITY: dict[str, float] = {
    "smart_lock": 1.0,
    "smart_camera": 0.88,
    "smart_thermostat": 0.84,
    "smart_plug": 0.76,
    "iot_device": 0.6,
}

THREAT_HAZARDS: dict[tuple[str, str], HazardProfile] = {
    ("smart_lock", ThreatType.UNAUTHORIZED_COMMANDS.value): HazardProfile(
        "forced_entry",
        "A hostile session can unlock the door and admit an intruder.",
        1.15,
    ),
    ("smart_lock", ThreatType.FIRMWARE_MODIFICATION.value): HazardProfile(
        "lock_hijack",
        "Unsigned firmware can silently disable locking or ignore owner PINs.",
        1.12,
    ),
    ("smart_lock", ThreatType.SUSPICIOUS_IP_CONNECTIONS.value): HazardProfile(
        "remote_entry_channel",
        "An untrusted peer can reach the lock control plane from outside the home.",
        1.05,
    ),
    ("smart_camera", ThreatType.ABNORMAL_NETWORK_TRAFFIC.value): HazardProfile(
        "privacy_exfiltration",
        "Live video from the entryway may be leaving the home.",
        1.08,
    ),
    ("smart_camera", ThreatType.SUSPICIOUS_IP_CONNECTIONS.value): HazardProfile(
        "surveillance_hijack",
        "An attacker may be watching occupants and casing the property.",
        1.1,
    ),
    ("smart_camera", ThreatType.FIRMWARE_MODIFICATION.value): HazardProfile(
        "covert_recording",
        "A tampered camera can keep recording after the shutter appears closed.",
        1.06,
    ),
    ("smart_thermostat", ThreatType.UNAUTHORIZED_COMMANDS.value): HazardProfile(
        "climate_extremes",
        "HVAC can be driven to freeze pipes or overheat occupied rooms.",
        1.1,
    ),
    ("smart_thermostat", ThreatType.ABNORMAL_POWER_USAGE.value): HazardProfile(
        "hvac_stress",
        "Abnormal draw can damage HVAC equipment and create fire load.",
        1.0,
    ),
    ("smart_plug", ThreatType.ABNORMAL_POWER_USAGE.value): HazardProfile(
        "electrical_fire",
        "Sustained overload on a lamp circuit can ignite nearby furnishings.",
        1.18,
    ),
    ("smart_plug", ThreatType.UNAUTHORIZED_COMMANDS.value): HazardProfile(
        "unsafe_energize",
        "A hijacked relay can energize a load when nobody is home.",
        1.04,
    ),
    ("smart_lock", ThreatType.MULTI_STAGE_COMPROMISE.value): HazardProfile(
        "forced_entry",
        "A coordinated compromise of the lock can open the home to an intruder.",
        1.2,
    ),
    ("smart_camera", ThreatType.MULTI_STAGE_COMPROMISE.value): HazardProfile(
        "surveillance_hijack",
        "A coordinated camera compromise can watch the home and leak the feed.",
        1.16,
    ),
    ("smart_thermostat", ThreatType.MULTI_STAGE_COMPROMISE.value): HazardProfile(
        "climate_extremes",
        "A coordinated HVAC compromise can freeze pipes or overheat occupied rooms.",
        1.14,
    ),
    ("smart_plug", ThreatType.MULTI_STAGE_COMPROMISE.value): HazardProfile(
        "electrical_fire",
        "A coordinated plug compromise can overload a circuit and ignite furnishings.",
        1.18,
    ),
}

GENERIC_HAZARDS: dict[str, HazardProfile] = {
    ThreatType.MULTI_STAGE_COMPROMISE.value: HazardProfile(
        "coordinated_physical_compromise",
        "Multiple hostile behaviors at once raise the chance of a real-world incident.",
        1.2,
    ),
    ThreatType.FIRMWARE_MODIFICATION.value: HazardProfile(
        "untrusted_control",
        "The device can no longer be trusted to fail safe.",
        1.08,
    ),
    ThreatType.UNAUTHORIZED_COMMANDS.value: HazardProfile(
        "hostile_actuation",
        "Physical actuators may fire without the homeowner's consent.",
        1.06,
    ),
    ThreatType.ABNORMAL_NETWORK_TRAFFIC.value: HazardProfile(
        "data_and_control_leak",
        "Unexpected egress can carry sensor data or accept remote control.",
        0.95,
    ),
    ThreatType.SUSPICIOUS_IP_CONNECTIONS.value: HazardProfile(
        "external_command_channel",
        "An untrusted host can reach a device that moves or observes the home.",
        1.0,
    ),
    ThreatType.ABNORMAL_POWER_USAGE.value: HazardProfile(
        "energy_hazard",
        "Power anomalies often precede overheating, mining, or stuck actuators.",
        1.02,
    ),
    ThreatType.UNKNOWN_ANOMALY.value: HazardProfile(
        "uncharacterized_physical_risk",
        "Behavior left the learned envelope; physical side-effects are possible.",
        0.7,
    ),
}


class PhysicalRiskPredictor:
    """Maps cyber findings onto predicted physical harm in the home."""

    def assess(
        self,
        sample: TelemetrySample,
        threat_type: ThreatType | str,
        cyber_risk: float,
    ) -> PhysicalAssessment:
        kind = sample.device_type.value if hasattr(sample.device_type, "value") else str(sample.device_type)
        if kind not in DEVICE_CRITICALITY:
            kind = infer_device_kind(sample.device_id)
        threat = threat_type.value if isinstance(threat_type, ThreatType) else str(threat_type)
        profile = THREAT_HAZARDS.get((kind, threat)) or GENERIC_HAZARDS.get(threat)
        sensor_boost, sensor_notes = self._sensor_signals(kind, sample.sensors, threat)

        if threat in {ThreatType.BENIGN.value, "benign"}:
            # Recording, motion, and an open shutter are expected camera functions.
            if kind == "smart_camera" or sensor_boost < 8:
                return PhysicalAssessment(
                    score=round(min(12.0, cyber_risk * 0.15), 1),
                    hazard="none",
                    severity="none",
                    consequences=["No material physical hazard predicted from this tick."],
                    safe_mode="Device remains in its normal operating posture.",
                )
            return PhysicalAssessment(
                score=round(min(55.0, 20.0 + sensor_boost), 1),
                hazard="unsafe_physical_state",
                severity=_severity(20.0 + sensor_boost),
                consequences=sensor_notes or ["Sensors show an unsafe posture without a classified cyber attack."],
                safe_mode=_safe_mode_copy(kind, SAFE_MODE_ACTIONS.get(kind, SAFE_MODE_ACTIONS["iot_device"])),
            )

        if profile is None:
            profile = HazardProfile(
                "device_misuse",
                "Anomalous control of a cyber-physical device can affect the home.",
                0.8,
            )

        criticality = DEVICE_CRITICALITY.get(kind, 0.6)
        score = min(100.0, cyber_risk * criticality * profile.multiplier + sensor_boost)
        severity = _severity(score)
        consequences = [profile.consequence, *sensor_notes]
        actions = SAFE_MODE_ACTIONS.get(kind, SAFE_MODE_ACTIONS["iot_device"])
        safe_mode = _safe_mode_copy(kind, actions)
        return PhysicalAssessment(
            score=round(score, 1),
            hazard=profile.hazard if score >= 20 else "watch",
            severity=severity,
            consequences=consequences[:4],
            safe_mode=safe_mode,
        )

    def _sensor_signals(self, kind: str, sensors: dict, threat: str = "") -> tuple[float, list[str]]:
        notes: list[str] = []
        boost = 0.0
        benign = threat in {ThreatType.BENIGN.value, "benign", ""}
        if kind == "smart_lock":
            if sensors.get("locked") is False:
                boost += 22
                notes.append("The latch is currently unlocked.")
            if sensors.get("door_ajar"):
                boost += 16
                notes.append(
                    "The door sensor still reports ajar; locking the latch did not close the leaf."
                    if sensors.get("locked") is True
                    else "The door is ajar, so a remote unlock becomes physical entry."
                )
            if int(sensors.get("failed_pin_attempts") or 0) >= 3:
                boost += 10
                notes.append("Repeated PIN failures look like a physical bypass attempt.")
            if sensors.get("tamper_switch"):
                boost += 18
                notes.append("The lock tamper switch is active.")
        elif kind == "smart_camera" and not benign:
            if sensors.get("privacy_shutter_open") and sensors.get("recording"):
                boost += 8
                notes.append("The shutter is open and the camera is recording.")
            if float(sensors.get("motion_probability") or 0) >= 0.4:
                boost += 10
                notes.append("Motion at the entryway while the camera is hostile raises stalking risk.")
        elif kind == "smart_thermostat":
            setpoint = float(sensors.get("setpoint_c") or 21.0)
            if setpoint >= 30 or setpoint <= 12:
                boost += 20
                notes.append(f"Setpoint is {setpoint:.1f}°C, outside a safe occupied range.")
            if sensors.get("hvac_mode") in {"heat", "cool"} and sensors.get("controls_locked") is not True:
                boost += 6
        elif kind == "smart_plug":
            if sensors.get("relay_on") and sensors.get("in_rush_detected"):
                boost += 14
                notes.append("The relay is closed during an in-rush spike.")
            if sensors.get("relay_on"):
                boost += 4
        return boost, notes


def _severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "moderate"
    if score >= 15:
        return "low"
    return "none"


def _safe_mode_copy(kind: str, actions: list[str]) -> str:
    labels = {
        "smart_lock": "Force the deadbolt locked, disable remote unlock, and shorten auto-relock.",
        "smart_camera": "Close the privacy shutter, stop recording, and cut the live stream.",
        "smart_thermostat": "Hold an eco setpoint, idle HVAC, and lock climate controls.",
        "smart_plug": "Open the relay, cap power draw, and freeze the schedule.",
    }
    fallback = "Enter failsafe and disable remote admin: " + ", ".join(actions[:3])
    return labels.get(kind, fallback)
