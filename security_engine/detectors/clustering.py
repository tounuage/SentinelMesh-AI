from __future__ import annotations

from typing import Sequence

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from security_engine.detectors.base import AnomalyDetector
from security_engine.models.findings import DetectorResult


class ClusterDistanceDetector(AnomalyDetector):
    """Flags points that sit far from the device's learned behavior clusters."""

    name = "cluster_distance"
    min_samples = 8

    def __init__(self) -> None:
        super().__init__()
        self._models: dict[str, KMeans] = {}
        self._scalers: dict[str, StandardScaler] = {}
        self._train_dist: dict[str, np.ndarray] = {}
        self._centers: dict[str, np.ndarray] = {}
        self._names: dict[str, tuple[str, ...]] = {}

    def reset(self) -> None:
        super().reset()
        self._models.clear()
        self._scalers.clear()
        self._train_dist.clear()
        self._centers.clear()
        self._names.clear()

    def fit(self, device_id: str, X: np.ndarray, feature_names: Sequence[str]) -> None:
        if X.shape[0] < self.min_samples:
            self._ready.discard(device_id)
            return
        scaler = StandardScaler()
        scaled = scaler.fit_transform(X)
        n_clusters = 2 if X.shape[0] >= 16 else 1
        model = KMeans(n_clusters=n_clusters, n_init=4, random_state=42)
        model.fit(scaled)
        distances = self._min_distances(scaled, model.cluster_centers_)
        self._models[device_id] = model
        self._scalers[device_id] = scaler
        self._train_dist[device_id] = distances
        self._centers[device_id] = model.cluster_centers_
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
        scaler = self._scalers[device_id]
        centers = self._centers[device_id]
        scaled = scaler.transform(x.reshape(1, -1))
        distance = float(self._min_distances(scaled, centers)[0])
        train = self._train_dist[device_id]
        median = float(np.median(train))
        mad = float(np.median(np.abs(train - median))) * 1.4826
        scale = mad if mad > 1e-6 else (float(np.std(train)) or 1e-6)
        scale = max(scale, 0.35)
        z = (distance - median) / scale
        anomaly_score = float(np.clip(z / 4.0, 0.0, 1.0))
        names = self._names.get(device_id, tuple(feature_names))
        nearest = centers[int(np.argmin(np.linalg.norm(centers - scaled, axis=1)))]
        delta = np.abs(scaled.reshape(-1) - nearest)
        top = np.argsort(delta)[::-1][:3]
        return DetectorResult(
            detector=self.name,
            anomaly_score=anomaly_score,
            is_anomaly=z >= 3.0 or anomaly_score >= 0.55,
            details={
                "distance": round(distance, 4),
                "robust_z": round(z, 3),
                "clusters": int(centers.shape[0]),
            },
            contributing_features=[names[i] for i in top if delta[i] >= 1.0],
        )

    @staticmethod
    def _min_distances(points: np.ndarray, centers: np.ndarray) -> np.ndarray:
        deltas = points[:, None, :] - centers[None, :, :]
        return np.min(np.linalg.norm(deltas, axis=2), axis=1)
