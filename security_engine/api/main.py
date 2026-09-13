from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from security_engine.api.routes import action_router, router
from security_engine.config import settings
from security_engine.controller import controller


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.poll_simulator:
        controller.start()
    yield
    controller.stop()


app = FastAPI(
    title="SentinelMesh Security Engine",
    description="Behavioral analysis and autonomous cyber-defense for the SentinelMesh IoT mesh.",
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
