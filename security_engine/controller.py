from __future__ import annotations

import threading
from datetime import UTC, datetime

import httpx

from security_engine.config import settings
from security_engine.ingest.simulator import SimulatorClient
from security_engine.models.findings import AnalysisResult
from security_engine.models.response import ControllerHeartbeat, DefensiveAction
from security_engine.pipeline import AnalysisEngine
from security_engine.response.enforcer import SimulatorEnforcer

ENFORCE_TRANSITIONS = {"escalated", "recovering", "recovered", "forced_recovery"}


class ControllerWorker:
    """Backend loop: ingest telemetry, execute policy, enforce containment.

    The dashboard is an observer. Closing it must not pause defense.
    """

    def __init__(
        self,
        engine: AnalysisEngine | None = None,
        enforcer: SimulatorEnforcer | None = None,
        simulator: SimulatorClient | None = None,
        poll_interval_seconds: float | None = None,
        heartbeat_stale_seconds: float | None = None,
    ) -> None:
        self.engine = engine or AnalysisEngine()
        self.enforcer = enforcer or SimulatorEnforcer()
        self.simulator = simulator or SimulatorClient()
        self.poll_interval_seconds = (
            settings.poll_interval_seconds if poll_interval_seconds is None else poll_interval_seconds
        )
        self.heartbeat_stale_seconds = (
            settings.heartbeat_stale_seconds if heartbeat_stale_seconds is None else heartbeat_stale_seconds
        )
        self.enforcement_enabled = True
        self.cycle_count = 0
        self.last_ingest_count = 0
        self.last_beat_at: datetime | None = None
        self.last_enforced_at: datetime | None = None
        self.last_error: str | None = None
        self._bootstrapped = False
        self._enforced_state: dict[str, str] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False

    @property
    def active(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def heartbeat(self, now: datetime | None = None) -> ControllerHeartbeat:
        stamp = now or datetime.now(UTC)
        return ControllerHeartbeat(
            active=self.active,
            fresh=self.is_fresh(stamp),
            last_beat_at=self.last_beat_at,
            cycle_count=self.cycle_count,
            last_error=self.last_error,
            poll_interval_seconds=self.poll_interval_seconds,
            heartbeat_stale_seconds=self.heartbeat_stale_seconds,
            enforcement_enabled=self.enforcement_enabled,
            last_enforced_at=self.last_enforced_at,
            last_ingest_count=self.last_ingest_count,
            bootstrapped=self._bootstrapped,
        )

    def is_fresh(self, now: datetime | None = None) -> bool:
        if not self.active or self.last_beat_at is None:
            return False
        age = (now or datetime.now(UTC)) - self.last_beat_at
        return age.total_seconds() <= self.heartbeat_stale_seconds

    def start(self) -> None:
        with self._lock:
            if self.active:
                return
            self._stop.clear()
            self._running = True
            self._beat(self.last_ingest_count)
            self._thread = threading.Thread(
                target=self._loop,
                name="sentinelmesh-controller",
                daemon=True,
            )
            thread = self._thread
        thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._running = False
        self._thread = None

    def reset(self) -> None:
        with self._lock:
            self.engine.reset()
            self._bootstrapped = False
            self._enforced_state.clear()
            self.last_error = None
            self.cycle_count = 0
            self.last_ingest_count = 0
            self.last_enforced_at = None

    def set_enforcement(self, enabled: bool) -> ControllerHeartbeat:
        with self._lock:
            self.enforcement_enabled = bool(enabled)
            return self.heartbeat()

    def ingest(self, bootstrap_history: bool = False) -> list[AnalysisResult]:
        """Pull telemetry and run policy. Used by the HTTP fallback path."""
        with self._lock:
            return self._run_ingest(bootstrap_history=bootstrap_history, enforce=False)

    def cycle(self, bootstrap_history: bool = False) -> list[AnalysisResult]:
        """Worker tick: ingest, execute policy, and push containment."""
        with self._lock:
            return self._run_ingest(bootstrap_history=bootstrap_history, enforce=True)

    def _run_ingest(self, bootstrap_history: bool, enforce: bool) -> list[AnalysisResult]:
        try:
            findings = self._ingest_and_analyze(bootstrap_history=bootstrap_history)
            if enforce and self.enforcement_enabled:
                self._enforce_latest()
            self.last_error = None
            if enforce:
                self._beat(len(findings))
            return findings
        except Exception as exc:
            self.last_error = str(exc)
            if enforce:
                self._beat(0)
            raise

    def act(self, device_id: str, risk_score: float, threat_type: str) -> DefensiveAction:
        with self._lock:
            action = self.engine.response.act(device_id, risk_score, threat_type)
            return self._apply(action, force=True)

    def recover(self, device_id: str, force: bool = False) -> DefensiveAction:
        with self._lock:
            action = self.engine.response.recover(device_id, force=force)
            return self._apply(action, force=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.cycle(bootstrap_history=not self._bootstrapped)
            except Exception:
                pass
            if self._stop.wait(self.poll_interval_seconds):
                break
        self._running = False

    def _ingest_and_analyze(self, bootstrap_history: bool) -> list[AnalysisResult]:
        if bootstrap_history or not self._bootstrapped:
            devices = self.simulator.devices()
            for device in devices:
                device_id = device["device_id"]
                if self.engine.profiles.get(device_id) is None:
                    history = self.simulator.history(device_id, limit=settings.history_size)
                    if history:
                        self.engine.analyze_many(history)
            self._bootstrapped = True
        snapshot = self.simulator.latest()
        return self.engine.analyze_snapshot(snapshot)

    def _enforce_latest(self) -> None:
        for status in self.engine.response.fleet():
            action = status.last_action
            if action is None:
                continue
            self._apply(action, force=False)

    def _apply(self, action: DefensiveAction, force: bool) -> DefensiveAction:
        target = action.response_state.value
        already = self._enforced_state.get(action.device_id) == target
        if not force and action.transition not in ENFORCE_TRANSITIONS and already:
            return action
        applied = self.enforcer.apply(action)
        action.enforced = applied
        action.enforcement_target = "iot-simulator" if applied else None
        if applied:
            self._enforced_state[action.device_id] = target
            self.last_enforced_at = datetime.now(UTC)
        return action

    def _beat(self, ingest_count: int) -> None:
        self.cycle_count += 1
        self.last_ingest_count = ingest_count
        self.last_beat_at = datetime.now(UTC)


controller = ControllerWorker()


def ingest_error_detail(exc: BaseException) -> str:
    if isinstance(exc, httpx.HTTPError):
        return f"Simulator unreachable at {settings.simulator_url}"
    return str(exc)
