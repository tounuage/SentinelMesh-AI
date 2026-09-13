from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ENGINE_")

    host: str = "0.0.0.0"
    port: int = 8081
    simulator_url: str = "http://127.0.0.1:8080"
    poll_simulator: bool = True
    poll_interval_seconds: float = 2.0
    heartbeat_stale_seconds: float = 6.0
    warmup_samples: int = 12
    history_size: int = 180
    anomaly_update_threshold: float = 60.0
    heuristic_blend: float = 0.4


settings = Settings()
