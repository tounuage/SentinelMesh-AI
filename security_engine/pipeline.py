from __future__ import annotations

from datetime import datetime

from security_engine.config import settings
from security_engine.correlation.mesh import correlate_entry_attempt
from security_engine.detectors import build_default_registry
from security_engine.detectors.base import DetectorRegistry
from security_engine.features.extractor import FeatureExtractor
from security_engine.models.findings import AnalysisResult, DetectorResult, MeshIncident
from security_engine.profiles.store import ProfileStore
from security_engine.response.actions import ActionRecommender
from security_engine.response.engine import ResponseEngine
from security_engine.response.explainer import Explainer
from security_engine.scoring.classifier import ThreatClassifier
from security_engine.scoring.physical import PhysicalRiskPredictor
from security_engine.scoring.risk import RiskScorer
from iot_simulator.models.telemetry import EnvironmentSnapshot, TelemetrySample


class AnalysisEngine:
    """Orchestrates profiling, detection, scoring, classification, and response."""

    def __init__(self, registry: DetectorRegistry | None = None) -> None:
        self.registry = registry or build_default_registry()
        self.profiles = ProfileStore()
        self.extractor = FeatureExtractor()
        self.scorer = RiskScorer()
        self.classifier = ThreatClassifier()
        self.physical = PhysicalRiskPredictor()
        self.explainer = Explainer()
        self.actions = ActionRecommender()
        self.response = ResponseEngine()
        self.findings: dict[str, AnalysisResult] = {}
        self.last_observed: dict[str, datetime] = {}
        self.last_detector_results: dict[str, list[DetectorResult]] = {}
        self._latest_samples: dict[str, TelemetrySample] = {}
        self.incidents: list[MeshIncident] = []

    def analyze(self, sample: TelemetrySample) -> AnalysisResult:
        previous = self.last_observed.get(sample.device_id)
        if previous is not None and sample.timestamp <= previous:
            self._latest_samples[sample.device_id] = sample
            self.refresh_incidents()
            return self.findings[sample.device_id]
        profile = self.profiles.get_or_create(sample)
        vector = self.extractor.extract(sample, profile)
        matrix = profile.feature_matrix()

        detector_results: list[DetectorResult] = []
        ready_count = 0
        history_n = matrix.shape[0]
        for detector in self.registry.all():
            should_fit = history_n >= detector.min_samples and (
                not detector.is_ready(sample.device_id)
                or history_n == detector.min_samples
                or history_n % 5 == 0
            )
            if should_fit:
                detector.fit(sample.device_id, matrix, vector.names)
            result = detector.score(sample.device_id, vector.values, vector.names)
            detector_results.append(result)
            if detector.is_ready(sample.device_id):
                ready_count += 1

        models_ready = ready_count > 0
        risk_score = self.scorer.score(detector_results, vector.signals, models_ready)
        threat_type = self.classifier.classify(vector.signals, detector_results, risk_score)
        explanation = self.explainer.explain(
            vector, profile, detector_results, threat_type, risk_score
        )
        recommended_action = self.actions.recommend(
            sample.device_id, threat_type, vector.signals, risk_score
        )
        physical = self.physical.assess(sample, threat_type, risk_score)
        defensive = self.response.act(sample.device_id, risk_score, threat_type.value)
        finding = AnalysisResult(
            device=sample.device_id,
            risk_score=risk_score,
            threat_type=threat_type.value,
            explanation=explanation,
            recommended_action=recommended_action,
            response_state=defensive.response_state.value,
            defensive_action=defensive.action,
            physical=physical,
            source="engine",
        )
        self.last_observed[sample.device_id] = sample.timestamp
        self.findings[sample.device_id] = finding
        self.last_detector_results[sample.device_id] = detector_results
        self._latest_samples[sample.device_id] = sample
        self.refresh_incidents()
        if risk_score < settings.anomaly_update_threshold or not profile.baseline_ready:
            self.profiles.update_from_sample(sample, vector)
        return finding

    def analyze_many(self, samples: list[TelemetrySample]) -> list[AnalysisResult]:
        return [self.analyze(sample) for sample in samples]

    def analyze_snapshot(self, snapshot: EnvironmentSnapshot) -> list[AnalysisResult]:
        return self.analyze_many(snapshot.devices)

    def refresh_incidents(self) -> list[MeshIncident]:
        incident = correlate_entry_attempt(list(self._latest_samples.values()))
        self.incidents = [incident] if incident else []
        return self.incidents

    def latest(self) -> list[AnalysisResult]:
        return list(self.findings.values())

    def latest_for(self, device_id: str) -> AnalysisResult | None:
        return self.findings.get(device_id)

    def latest_incidents(self) -> list[MeshIncident]:
        return list(self.incidents)

    def detector_names(self) -> list[str]:
        return self.registry.names()

    def reset(self) -> None:
        self.last_observed.clear()
        self.profiles.clear()
        self.findings.clear()
        self.last_detector_results.clear()
        self._latest_samples.clear()
        self.incidents.clear()
        self.registry.reset()
        self.response.reset()
