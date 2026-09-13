from __future__ import annotations

from security_engine.features.extractor import BehavioralSignals
from security_engine.models.findings import ThreatType


class ActionRecommender:
    """Maps classified threats onto concrete defensive actions."""

    def recommend(
        self,
        device_id: str,
        threat_type: ThreatType,
        signals: BehavioralSignals,
        risk_score: float,
    ) -> str:
        ips = ", ".join(signals.suspicious_ips[:4]) or "the observed destinations"
        ports = ", ".join(str(port) for port in signals.unusual_ports[:6]) or "the unusual ports"
        commands = ", ".join(signals.unauthorized_commands[:4]) or "the unauthorized commands"

        if threat_type == ThreatType.BENIGN:
            return f"Continue monitoring {device_id}; no containment action required."

        if threat_type == ThreatType.FIRMWARE_MODIFICATION:
            return (
                f"Quarantine {device_id}, block OTA/update channels, roll back to the last signed "
                f"firmware image, and re-provision device credentials."
            )
        if threat_type == ThreatType.UNAUTHORIZED_COMMANDS:
            return (
                f"Revoke active sessions on {device_id}, rotate owner/API credentials, "
                f"deny {commands}, and force a known-good locked/safe state."
            )
        if threat_type == ThreatType.SUSPICIOUS_IP_CONNECTIONS:
            return (
                f"Isolate {device_id} from the LAN, block outbound traffic to {ips} "
                f"(ports {ports}), and capture DNS plus flow logs for incident response."
            )
        if threat_type == ThreatType.ABNORMAL_NETWORK_TRAFFIC:
            return (
                f"Rate-limit and isolate {device_id}, sinkhole suspicious DNS, "
                f"and inspect for data exfiltration or botnet beaconing."
            )
        if threat_type == ThreatType.ABNORMAL_POWER_USAGE:
            return (
                f"Cut or cap power on {device_id}, disable the load/relay if applicable, "
                f"and inspect for crypto-mining, stuck actuators, or hardware tampering."
            )
        if threat_type == ThreatType.MULTI_STAGE_COMPROMISE:
            return (
                f"Treat {device_id} as compromised: isolate at the access point, block {ips}, "
                f"revoke credentials, preserve telemetry for forensics, and rebuild from signed firmware."
            )

        severity = "high" if risk_score >= 70 else "elevated"
        return (
            f"Place {device_id} under {severity} watch, restrict outbound traffic, "
            f"and investigate the feature deviations in the latest telemetry tick."
        )
