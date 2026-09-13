import uvicorn

from iot_simulator.config import settings


def main() -> None:
    uvicorn.run(
        "iot_simulator.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
