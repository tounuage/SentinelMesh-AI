from __future__ import annotations

from security_engine.features.extractor import BehavioralSignals
from security_engine.models.findings import DetectorResult, ThreatType
from security_engine.scoring.risk import heuristic_risk


class ThreatClassifier:
    """Maps detector output and forensic signals onto a threat label."""

    def classify(
        self,
        signals: BehavioralSignals,
        detector_results: list[DetectorResult],
        risk_score: float,
    ) -> ThreatType:
        tags = self._tags(signals)
        if risk_score < 22 and not tags:
            return ThreatType.BENIGN
        if len(tags) >= 2 and risk_score >= 55:
            return ThreatType.MULTI_STAGE_COMPROMISE
        if "firmware" in tags:
            return ThreatType.FIRMWARE_MODIFICATION
        if "unauthorized" in tags:
            return ThreatType.UNAUTHORIZED_COMMANDS
        if "suspicious_ip" in tags:
            return ThreatType.SUSPICIOUS_IP_CONNECTIONS
        if "network_volume" in tags or "unusual_ports" in tags:
            return ThreatType.ABNORMAL_NETWORK_TRAFFIC
        if "power" in tags:
            return ThreatType.ABNORMAL_POWER_USAGE
        if risk_score >= 40:
            return ThreatType.UNKNOWN_ANOMALY
        if heuristic_risk(signals) >= 22:
            return ThreatType.UNKNOWN_ANOMALY
        return ThreatType.BENIGN

    @staticmethod
    def _tags(signals: BehavioralSignals) -> list[str]:
        tags: list[str] = []
        if signals.unsigned_firmware or signals.firmware_changed:
            tags.append("firmware")
        if signals.unauthorized_commands:
            tags.append("unauthorized")
        if signals.suspicious_ips:
            tags.append("suspicious_ip")
        if signals.unusual_ports:
            tags.append("unusual_ports")
        if abs(signals.power_deviation_percent) >= 80:
            tags.append("power")
        if signals.suspicious_dns:
            tags.append("network_volume")
        return tags
