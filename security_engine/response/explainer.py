from __future__ import annotations

from security_engine.features.extractor import BehavioralSignals, FeatureVector
from security_engine.models.findings import DetectorResult, ThreatType
from security_engine.profiles.baseline import DeviceBehaviorProfile


class Explainer:
    """Turns model output into an analyst-readable reason the device is suspicious."""

    def explain(
        self,
        vector: FeatureVector,
        profile: DeviceBehaviorProfile,
        detector_results: list[DetectorResult],
        threat_type: ThreatType,
        risk_score: float,
    ) -> str:
        signals = vector.signals
        flagged = [result.detector for result in detector_results if result.is_anomaly]
        ready = [result for result in detector_results if result.details.get("status") != "warmup"]
        evidence = self._evidence(signals, detector_results)
        baseline = (
            f"Baseline is built from {profile.sample_count} recent samples."
            if profile.baseline_ready
            else f"Baseline is still forming ({profile.sample_count} samples)."
        )

        if threat_type == ThreatType.BENIGN:
            return (
                f"{vector.name} ({vector.device_id}) matches its learned behavior. "
                f"Risk {risk_score:.1f}/100. {baseline}"
            )

        agreement = (
            f"{len(flagged)} of {len(ready)} anomaly models flagged this tick"
            if ready
            else "heuristic signals fired before the ML baseline was ready"
        )
        joined = "; ".join(evidence) if evidence else "behavior diverged from the device profile"
        return (
            f"{vector.name} ({vector.device_id}) is suspicious because {joined}. "
            f"{agreement}. Classified as {threat_type.value} with risk {risk_score:.1f}/100. "
            f"{baseline}"
        )

    def _evidence(
        self, signals: BehavioralSignals, detector_results: list[DetectorResult]
    ) -> list[str]:
        items: list[str] = []
        if signals.suspicious_ips:
            items.append(
                "outbound sessions to untrusted hosts "
                + ", ".join(signals.suspicious_ips[:4])
            )
        if signals.unusual_ports:
            ports = ", ".join(str(port) for port in signals.unusual_ports[:6])
            items.append(f"non-standard egress ports {ports}")
        if signals.suspicious_dns:
            items.append("DNS queries to " + ", ".join(signals.suspicious_dns[:3]))
        if signals.unauthorized_commands:
            cmds = ", ".join(signals.unauthorized_commands[:4])
            actors = ", ".join(signals.unauthorized_actors[:3]) or "unknown actors"
            items.append(f"unauthorized commands ({cmds}) from {actors}")
        if signals.unsigned_firmware or signals.firmware_changed:
            items.append(
                f"firmware changed to {signals.firmware_version} "
                f"({'unsigned' if signals.unsigned_firmware else 'unexpected version'})"
            )
        if abs(signals.power_deviation_percent) >= 40:
            items.append(
                f"power draw {signals.watts:.1f} W is {signals.power_deviation_percent:.1f}% off baseline"
            )
        if signals.new_remote_ips and not signals.suspicious_ips:
            items.append("new remote IPs " + ", ".join(signals.new_remote_ips[:4]))
        features = []
        for result in detector_results:
            for name in result.contributing_features:
                if name not in features:
                    features.append(name)
        if features:
            items.append("dominant feature shifts: " + ", ".join(features[:5]))
        return items
