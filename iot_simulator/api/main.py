from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from iot_simulator.api.routes import action_router, environment, router


@asynccontextmanager
async def lifespan(_: FastAPI):
    await environment.start()
    yield
    await environment.stop()


app = FastAPI(
    title="SentinelMesh IoT Simulator",
    description="Virtual smart-home telemetry feed and autonomous containment plane for SentinelMesh AI.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router, prefix="/api/v1")
app.include_router(action_router)
