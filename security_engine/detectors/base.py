from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

import numpy as np

from security_engine.models.findings import DetectorResult


class AnomalyDetector(ABC):
    """Plug-in interface for anomaly models.

    To add a model later:
    1. Subclass AnomalyDetector and set a unique ``name``.
    2. Implement ``fit`` and ``score``.
    3. Call ``registry.register(MyDetector())``.
    """

    name: str
    min_samples: int = 8

    def __init__(self) -> None:
        self._ready: set[str] = set()

    @abstractmethod
    def fit(self, device_id: str, X: np.ndarray, feature_names: Sequence[str]) -> None:
        """Train or refresh the per-device model from baseline history."""

    @abstractmethod
    def score(
        self, device_id: str, x: np.ndarray, feature_names: Sequence[str]
    ) -> DetectorResult:
        """Return a 0-1 anomaly score for a single observation."""

    def is_ready(self, device_id: str) -> bool:
        return device_id in self._ready

    def reset(self) -> None:
        self._ready.clear()


class DetectorRegistry:
    """Name-keyed collection of detectors so new models can be dropped in."""

    def __init__(self) -> None:
        self._detectors: dict[str, AnomalyDetector] = {}

    def register(self, detector: AnomalyDetector) -> None:
        if not getattr(detector, "name", None):
            raise ValueError("Detector must define a unique name")
        self._detectors[detector.name] = detector

    def get(self, name: str) -> AnomalyDetector:
        return self._detectors[name]

    def all(self) -> list[AnomalyDetector]:
        return list(self._detectors.values())

    def names(self) -> list[str]:
        return list(self._detectors)

    def reset(self) -> None:
        for detector in self._detectors.values():
            detector.reset()

    def __contains__(self, name: str) -> bool:
        return name in self._detectors
