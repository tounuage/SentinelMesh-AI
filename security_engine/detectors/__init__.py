from security_engine.detectors.base import AnomalyDetector, DetectorRegistry
from security_engine.detectors.clustering import ClusterDistanceDetector
from security_engine.detectors.isolation_forest import IsolationForestDetector
from security_engine.detectors.statistical import StatisticalDetector


def build_default_registry() -> DetectorRegistry:
    """Built-in models. Register additional AnomalyDetector subclasses to extend."""
    registry = DetectorRegistry()
    registry.register(IsolationForestDetector())
    registry.register(StatisticalDetector())
    registry.register(ClusterDistanceDetector())
    return registry


__all__ = [
    "AnomalyDetector",
    "ClusterDistanceDetector",
    "DetectorRegistry",
    "IsolationForestDetector",
    "StatisticalDetector",
    "build_default_registry",
]
