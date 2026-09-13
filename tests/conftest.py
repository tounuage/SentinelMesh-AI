from __future__ import annotations

import pytest

from security_engine.config import settings
from security_engine.controller import controller


@pytest.fixture(autouse=True)
def _isolate_controller() -> None:
    previous = settings.poll_simulator
    settings.poll_simulator = False
    controller.stop()
    controller.reset()
    controller.enforcement_enabled = True
    yield
    controller.stop()
    controller.reset()
    controller.enforcement_enabled = True
    settings.poll_simulator = previous
