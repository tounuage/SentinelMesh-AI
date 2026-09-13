from __future__ import annotations

import numpy as np

from security_engine.config import settings
from security_engine.features.extractor import BehavioralSignals
from security_engine.models.findings import DetectorResult


DEFAULT_WEIGHTS = {
    "isolation_forest": 0.45,
    "statistical": 0.30,
    "cluster_distance": 0.25,
}


def heuristic_risk(signals: BehavioralSignals) -> float:
    """Rule layer that catches high-signal IoT attacks even before models warm up."""
    score = 0.0
    if signals.suspicious_ips:
        score += min(55.0, 24.0 + 10.0 * len(signals.suspicious_ips))
    score += min(20.0, 8.0 * len(signals.unusual_ports))
    if signals.unsigned_firmware:
        score += 70.0
    elif signals.firmware_changed:
        score += 36.0
    events = max(len(signals.unauthorized_commands), signals.unauthorized_event_count)
    if events:
        score += min(75.0, 30.0 + 15.0 * events)
    deviation = abs(signals.power_deviation_percent)
    if deviation >= 80:
        score += 45.0
    elif deviation >= 40:
        score += 18.0
    score += min(15.0, 5.0 * len(signals.new_remote_ips))
    if signals.suspicious_dns:
        score += min(22.0, 10.0 * len(signals.suspicious_dns))
    return float(min(100.0, score))


class RiskScorer:
    """Blends detector scores with forensic heuristics into a 0-100 risk."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = dict(weights or DEFAULT_WEIGHTS)

    def score(
        self,
        detector_results: list[DetectorResult],
        signals: BehavioralSignals,
        models_ready: bool,
    ) -> float:
        heuristic = heuristic_risk(signals)
        ready = [result for result in detector_results if result.details.get("status") != "warmup"]
        if not models_ready or not ready:
            return round(heuristic, 1)

        weighted = 0.0
        total = 0.0
        peak = 0.0
        for result in ready:
            weight = self.weights.get(result.detector, 1.0)
            weighted += weight * result.anomaly_score
            total += weight
            peak = max(peak, result.anomaly_score)
        mean_ml = (weighted / total) if total else 0.0
        ml = (0.55 * mean_ml + 0.45 * peak) * 100.0
        blend = settings.heuristic_blend
        combined = (1.0 - blend) * ml + blend * heuristic
        risk = max(combined, heuristic)
        return round(float(np.clip(risk, 0.0, 100.0)), 1)
