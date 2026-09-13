import uvicorn

from security_engine.config import settings


def main() -> None:
    uvicorn.run(
        "security_engine.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
