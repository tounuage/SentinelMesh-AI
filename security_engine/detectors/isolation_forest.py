from __future__ import annotations

import os
from typing import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "2")

from security_engine.detectors.base import AnomalyDetector
from security_engine.models.findings import DetectorResult


class IsolationForestDetector(AnomalyDetector):
    """Unsupervised outlier model over a device's own behavioral history."""

    name = "isolation_forest"
    min_samples = 10

    def __init__(self) -> None:
        super().__init__()
        self._models: dict[str, IsolationForest] = {}
        self._scalers: dict[str, StandardScaler] = {}
        self._train_scores: dict[str, np.ndarray] = {}
        self._feature_names: dict[str, tuple[str, ...]] = {}

    def reset(self) -> None:
        super().reset()
        self._models.clear()
        self._scalers.clear()
        self._train_scores.clear()
        self._feature_names.clear()

    def fit(self, device_id: str, X: np.ndarray, feature_names: Sequence[str]) -> None:
        if X.shape[0] < self.min_samples:
            self._ready.discard(device_id)
            return
        scaler = StandardScaler()
        scaled = scaler.fit_transform(X)
        model = IsolationForest(
            n_estimators=40,
            contamination=0.08,
            max_samples=min(64, X.shape[0]),
            n_jobs=1,
            random_state=42,
        )
        model.fit(scaled)
        self._models[device_id] = model
        self._scalers[device_id] = scaler
        self._train_scores[device_id] = -model.score_samples(scaled)
        self._feature_names[device_id] = tuple(feature_names)
        self._ready.add(device_id)

    def score(
        self, device_id: str, x: np.ndarray, feature_names: Sequence[str]
    ) -> DetectorResult:
        if not self.is_ready(device_id):
            return DetectorResult(
                detector=self.name,
                anomaly_score=0.0,
                is_anomaly=False,
                details={"status": "warmup"},
            )
        scaler = self._scalers[device_id]
        model = self._models[device_id]
        scaled = scaler.transform(x.reshape(1, -1))
        raw = float(-model.score_samples(scaled)[0])
        train = self._train_scores[device_id]
        mu = float(np.mean(train))
        sigma = float(np.std(train)) or 1e-6
        z = (raw - mu) / sigma
        anomaly_score = float(np.clip(z / 3.0, 0.0, 1.0))
        predicted = int(model.predict(scaled)[0])
        is_anomaly = predicted == -1 or anomaly_score >= 0.55
        names = self._feature_names.get(device_id, tuple(feature_names))
        scaled_row = scaled.reshape(-1)
        top = np.argsort(np.abs(scaled_row))[::-1][:3]
        return DetectorResult(
            detector=self.name,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            details={
                "raw_score": round(raw, 4),
                "z_score": round(z, 3),
                "predicted_label": predicted,
            },
            contributing_features=[names[i] for i in top if abs(scaled_row[i]) >= 1.0],
        )
