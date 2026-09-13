from security_engine.models.findings import ThreatType
from security_engine.models.response import ResponseState
from security_engine.response.engine import ResponseEngine, parse_threat_type


def test_four_response_states() -> None:
    engine = ResponseEngine()
    normal = engine.act("lock-front-door", 8, "benign")
    assert normal.response_state == ResponseState.NORMAL
    assert normal.effects.network_blocking.mode == "allow_all"
    assert not normal.effects.permission_reduction.applied

    monitor = engine.act("cam-front-door", 32, "unknown_anomaly")
    assert monitor.response_state == ResponseState.MONITOR
    assert monitor.telemetry_policy.collect_additional
    assert monitor.telemetry_policy.packet_capture

    restricted = engine.act("cam-front-door", 61, "suspicious_ip_connections")
    assert restricted.response_state == ResponseState.RESTRICTED
    assert restricted.effects.network_blocking.applied
    assert restricted.effects.permission_reduction.applied
    assert restricted.effects.safe_operation_mode.applied
    assert "ota_update" in restricted.effects.permission_reduction.revoked

    quarantined = engine.act("lock-front-door", 91, "unauthorized_commands")
    assert quarantined.response_state == ResponseState.QUARANTINE
    assert quarantined.effects.network_blocking.mode == "full_isolation"
    assert quarantined.effects.permission_reduction.remaining == ["recovery_agent"]


def test_threat_floor_escalates_firmware_to_quarantine() -> None:
    engine = ResponseEngine()
    action = engine.act("cam-front-door", 40, "firmware_modification")
    assert action.response_state == ResponseState.QUARANTINE
    assert action.transition == "escalated"


def test_recovery_steps_down_instead_of_dropping_containment() -> None:
    engine = ResponseEngine()
    engine.act("plug-living-lamp", 88, "multi_stage_compromise")
    recovering = engine.act("plug-living-lamp", 6, "benign")
    assert recovering.response_state == ResponseState.MONITOR
    assert recovering.transition == "recovering"
    assert recovering.effects.recovery.in_progress

    recovered = engine.act("plug-living-lamp", 4, "benign")
    assert recovered.response_state == ResponseState.NORMAL
    assert recovered.transition == "recovered"
    assert recovered.effects.recovery.restored


def test_forced_recovery_returns_to_normal() -> None:
    engine = ResponseEngine()
    engine.act("thermo-hallway", 95, "firmware_modification")
    restored = engine.recover("thermo-hallway", force=True)
    assert restored.response_state == ResponseState.NORMAL
    assert restored.transition == "forced_recovery"


def test_parse_threat_aliases() -> None:
    assert parse_threat_type("Unauthorized Commands") == ThreatType.UNAUTHORIZED_COMMANDS
    assert parse_threat_type("normal") == ThreatType.BENIGN
    assert parse_threat_type("something-new") == ThreatType.UNKNOWN_ANOMALY
