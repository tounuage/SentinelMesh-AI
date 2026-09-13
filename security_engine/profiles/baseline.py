from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

import numpy as np

from security_engine.config import settings
from security_engine.features.extractor import FeatureVector


@dataclass
class DeviceBehaviorProfile:
    """Rolling behavioral baseline for a single device."""

    device_id: str
    device_type: str
    name: str
    sample_count: int = 0
    mean: np.ndarray | None = None
    m2: np.ndarray | None = None
    history: deque[np.ndarray] = field(default_factory=lambda: deque(maxlen=settings.history_size))
    trusted_remote_ips: set[str] = field(default_factory=set)
    typical_ports: set[int] = field(default_factory=set)
    typical_dns: set[str] = field(default_factory=set)
    typical_commands: Counter[str] = field(default_factory=Counter)
    typical_firmware: str = ""
    last_bytes_sent: int = 0
    last_updated: datetime | None = None

    @property
    def baseline_ready(self) -> bool:
        return self.sample_count >= settings.warmup_samples

    @property
    def std(self) -> np.ndarray | None:
        if self.mean is None or self.m2 is None or self.sample_count < 2:
            return None
        variance = self.m2 / max(self.sample_count - 1, 1)
        return np.sqrt(np.maximum(variance, 0.0))

    def update(self, vector: FeatureVector, sample_ips: list[str], sample_ports: list[int], dns: list[str], commands: list[str], firmware: str, bytes_sent: int) -> None:
        values = vector.values
        if self.mean is None:
            self.mean = values.astype(np.float64).copy()
            self.m2 = np.zeros_like(self.mean)
            self.sample_count = 1
        else:
            self.sample_count += 1
            delta = values - self.mean
            self.mean += delta / self.sample_count
            self.m2 += delta * (values - self.mean)
        self.history.append(values.copy())
        self.trusted_remote_ips.update(sample_ips)
        self.typical_ports.update(sample_ports)
        self.typical_dns.update(dns)
        self.typical_commands.update(commands)
        if not self.typical_firmware:
            self.typical_firmware = firmware
        self.last_bytes_sent = bytes_sent
        self.last_updated = datetime.now(UTC)

    def feature_matrix(self) -> np.ndarray:
        if not self.history:
            return np.empty((0, 0))
        return np.vstack(self.history)

    def summary(self, feature_names: tuple[str, ...]) -> dict[str, object]:
        means = {}
        stds = {}
        if self.mean is not None:
            means = {name: round(float(value), 4) for name, value in zip(feature_names, self.mean, strict=True)}
        if self.std is not None:
            stds = {name: round(float(value), 4) for name, value in zip(feature_names, self.std, strict=True)}
        return {
            "device": self.device_id,
            "device_type": self.device_type,
            "name": self.name,
            "sample_count": self.sample_count,
            "baseline_ready": self.baseline_ready,
            "feature_means": means,
            "feature_stds": stds,
            "trusted_remote_ips": sorted(self.trusted_remote_ips),
            "typical_firmware": self.typical_firmware,
            "typical_commands": [name for name, _ in self.typical_commands.most_common(8)],
        }
