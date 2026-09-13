from __future__ import annotations

from typing import Sequence

import numpy as np

from security_engine.detectors.base import AnomalyDetector
from security_engine.models.findings import DetectorResult


class StatisticalDetector(AnomalyDetector):
    """Per-feature z-score / robust-scale detector against the device baseline."""

    name = "statistical"
    min_samples = 5

    def __init__(self) -> None:
        super().__init__()
        self._mean: dict[str, np.ndarray] = {}
        self._std: dict[str, np.ndarray] = {}
        self._names: dict[str, tuple[str, ...]] = {}

    def reset(self) -> None:
        super().reset()
        self._mean.clear()
        self._std.clear()
        self._names.clear()

    def fit(self, device_id: str, X: np.ndarray, feature_names: Sequence[str]) -> None:
        if X.shape[0] < self.min_samples:
            self._ready.discard(device_id)
            return
        mean = np.mean(X, axis=0)
        std = np.std(X, axis=0)
        floor = np.maximum(0.08 * np.abs(mean), 0.05)
        self._mean[device_id] = mean
        self._std[device_id] = np.maximum(std, floor)
        self._names[device_id] = tuple(feature_names)
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
        z = np.abs((x - self._mean[device_id]) / self._std[device_id])
        names = self._names.get(device_id, tuple(feature_names))
        ranked = np.argsort(z)[::-1]
        top_features = [names[i] for i in ranked[:4] if z[i] >= 2.0]
        max_z = float(np.max(z))
        mean_z = float(np.mean(z))
        anomaly_score = float(np.clip(max(max_z / 6.0, mean_z / 3.0), 0.0, 1.0))
        return DetectorResult(
            detector=self.name,
            anomaly_score=anomaly_score,
            is_anomaly=max_z >= 3.0 or anomaly_score >= 0.5,
            details={
                "max_z": round(max_z, 3),
                "mean_z": round(mean_z, 3),
                "z_by_feature": {
                    names[i]: round(float(z[i]), 2) for i in ranked[:6] if z[i] >= 1.5
                },
            },
            contributing_features=top_features,
        )
