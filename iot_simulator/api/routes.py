from fastapi import APIRouter, HTTPException, Query

from iot_simulator.models.attacks import AttackRequest, AttackStopRequest
from iot_simulator.models.telemetry import ActiveAttack, DeviceSnapshot, EnvironmentSnapshot, TelemetrySample
from iot_simulator.simulation.environment import IoTEnvironment
from security_engine.models.response import (
    ContainmentApplyRequest,
    DefensiveAction,
    DeviceActionRequest,
    DeviceResponseStatus,
    RecoverRequest,
)

router = APIRouter()
action_router = APIRouter()
environment = IoTEnvironment()


@router.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "iot-simulator",
        "demo": environment.demo_mode,
    }


@router.get("/devices", response_model=list[DeviceSnapshot])
def list_devices() -> list[DeviceSnapshot]:
    return environment.list_devices()


@router.get("/devices/{device_id}", response_model=DeviceSnapshot)
def get_device(device_id: str) -> DeviceSnapshot:
    for device in environment.list_devices():
        if device.device_id == device_id:
            return device
    raise HTTPException(status_code=404, detail="Device not found")


@router.get("/telemetry", response_model=EnvironmentSnapshot)
def latest_telemetry() -> EnvironmentSnapshot:
    snapshot = environment.snapshot()
    if not snapshot.devices:
        raise HTTPException(status_code=503, detail="Simulator has not produced a tick yet")
    return snapshot


@router.get("/telemetry/{device_id}", response_model=TelemetrySample)
def device_telemetry(device_id: str) -> TelemetrySample:
    sample = environment.latest.get(device_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="No telemetry for device")
    return sample


@router.get("/telemetry/{device_id}/history", response_model=list[TelemetrySample])
def device_history(
    device_id: str, limit: int = Query(default=50, ge=1, le=300)
) -> list[TelemetrySample]:
    try:
        return environment.device_history(device_id, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Device not found") from exc


@router.post("/attacks", response_model=ActiveAttack, status_code=201)
def inject_attack(request: AttackRequest) -> ActiveAttack:
    try:
        return environment.inject_attack(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Device not found") from exc


@router.get("/attacks", response_model=list[ActiveAttack])
def list_attacks() -> list[ActiveAttack]:
    return environment.injector.active()


@router.post("/attacks/stop")
def stop_attack(request: AttackStopRequest) -> dict[str, int]:
    stopped = environment.stop_attack(request)
    return {"stopped": stopped}


@router.post("/simulation/tick", response_model=EnvironmentSnapshot)
async def force_tick() -> EnvironmentSnapshot:
    return await environment.step()


@router.post("/simulation/reset")
async def reset_simulation(demo: bool = Query(False)) -> dict[str, str | bool]:
    async with environment._lock:
        environment.reset(demo=demo)
    await environment.step()
    return {"status": "reset", "demo": demo}


@action_router.post("/device/action", response_model=DefensiveAction)
@router.post("/device/action", response_model=DefensiveAction)
def device_action(request: DeviceActionRequest) -> DefensiveAction:
    if request.device_id not in environment.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    action = environment.response_engine.act(
        request.device_id, request.risk_score, request.threat_type
    )
    return environment.apply_defensive_action(action)


@action_router.post("/device/recover", response_model=DefensiveAction)
@router.post("/device/recover", response_model=DefensiveAction)
def device_recover(request: RecoverRequest) -> DefensiveAction:
    if request.device_id not in environment.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    action = environment.response_engine.recover(request.device_id, force=request.force)
    return environment.apply_defensive_action(action)


@action_router.get("/device/{device_id}/response", response_model=DeviceResponseStatus)
@router.get("/device/{device_id}/response", response_model=DeviceResponseStatus)
def device_response(device_id: str) -> DeviceResponseStatus:
    if device_id not in environment.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    status = environment.response_engine.status(device_id)
    if status is None:
        device = environment.devices[device_id]
        return DeviceResponseStatus(
            device_id=device_id,
            response_state=device.containment.state,
            last_risk_score=0.0,
            last_threat_type="benign",
            consecutive_low_scores=0,
        )
    return status


@router.post("/containment/apply")
def apply_containment(request: ContainmentApplyRequest) -> dict[str, str]:
    try:
        environment.apply_containment(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Device not found") from exc
    return {"status": "applied", "device_id": request.device_id, "state": request.response_state.value}
