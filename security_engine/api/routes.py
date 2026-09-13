from fastapi import APIRouter, HTTPException, Query
import httpx

from iot_simulator.models.telemetry import EnvironmentSnapshot, TelemetrySample
from security_engine.controller import controller, ingest_error_detail
from security_engine.models.findings import AnalysisResult, MeshIncident
from security_engine.models.response import (
    ControllerHeartbeat,
    ControllerUpdate,
    DefensiveAction,
    DeviceActionRequest,
    DeviceResponseStatus,
    RecoverRequest,
)

router = APIRouter()
action_router = APIRouter()
engine = controller.engine


def _health_payload() -> dict[str, object]:
    profiles = list(engine.profiles.all())
    return {
        "status": "ok",
        "service": "sentinelmesh-security-engine",
        "detectors": engine.detector_names(),
        "models_ready": bool(profiles) and all(profile.baseline_ready for profile in profiles),
        "profile_count": len(profiles),
        "controller": controller.heartbeat().model_dump(mode="json"),
    }


@router.get("/health")
@action_router.get("/health")
def health() -> dict[str, object]:
    return _health_payload()


@router.get("/controller", response_model=ControllerHeartbeat)
def controller_status() -> ControllerHeartbeat:
    return controller.heartbeat()


@router.post("/controller", response_model=ControllerHeartbeat)
def update_controller(request: ControllerUpdate) -> ControllerHeartbeat:
    if request.enforcement_enabled is not None:
        return controller.set_enforcement(request.enforcement_enabled)
    return controller.heartbeat()


@router.post("/analyze", response_model=AnalysisResult)
def analyze_sample(sample: TelemetrySample) -> AnalysisResult:
    return engine.analyze(sample)


@router.post("/analyze/snapshot", response_model=list[AnalysisResult])
def analyze_snapshot(snapshot: EnvironmentSnapshot) -> list[AnalysisResult]:
    return engine.analyze_snapshot(snapshot)


@router.post("/analyze/batch", response_model=list[AnalysisResult])
def analyze_batch(samples: list[TelemetrySample]) -> list[AnalysisResult]:
    return engine.analyze_many(samples)


@router.get("/detectors")
def list_detectors() -> dict[str, list[str]]:
    return {"detectors": engine.detector_names()}


@router.get("/findings", response_model=list[AnalysisResult])
@router.get("/analysis", response_model=list[AnalysisResult])
def list_findings() -> list[AnalysisResult]:
    return engine.latest()


@router.get("/incidents", response_model=list[MeshIncident])
def list_incidents() -> list[MeshIncident]:
    return engine.latest_incidents()


@router.get("/findings/{device_id}", response_model=AnalysisResult)
@router.get("/analysis/{device_id}", response_model=AnalysisResult)
def get_finding(device_id: str) -> AnalysisResult:
    finding = engine.latest_for(device_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="No finding for device")
    return finding


@router.get("/profiles")
def list_profiles() -> list[dict]:
    return [profile.summary(engine.extractor.names) for profile in engine.profiles.all()]


@router.get("/profiles/{device_id}")
def get_profile(device_id: str) -> dict:
    profile = engine.profiles.get(device_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="No profile for device")
    return profile.summary(engine.extractor.names)


@router.post("/ingest/simulator", response_model=list[AnalysisResult])
def ingest_simulator(
    bootstrap_history: bool = Query(default=True),
) -> list[AnalysisResult]:
    try:
        return controller.ingest(bootstrap_history=bootstrap_history)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=ingest_error_detail(exc),
        ) from exc


@router.post("/reset")
def reset_engine() -> dict[str, str]:
    controller.reset()
    return {"status": "reset"}


@action_router.post("/device/action", response_model=DefensiveAction)
@router.post("/device/action", response_model=DefensiveAction)
def device_action(request: DeviceActionRequest) -> DefensiveAction:
    return controller.act(request.device_id, request.risk_score, request.threat_type)


@action_router.post("/device/recover", response_model=DefensiveAction)
@router.post("/device/recover", response_model=DefensiveAction)
def device_recover(request: RecoverRequest) -> DefensiveAction:
    return controller.recover(request.device_id, force=request.force)


@action_router.get("/device/{device_id}/response", response_model=DeviceResponseStatus)
@router.get("/device/{device_id}/response", response_model=DeviceResponseStatus)
def device_response(device_id: str) -> DeviceResponseStatus:
    status = engine.response.status(device_id)
    if status is None:
        raise HTTPException(status_code=404, detail="No response state for device")
    return status


@router.get("/devices/responses", response_model=list[DeviceResponseStatus])
def fleet_responses() -> list[DeviceResponseStatus]:
    return engine.response.fleet()
