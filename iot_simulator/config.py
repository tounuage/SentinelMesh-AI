from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IOT_SIM_")

    tick_interval_seconds: float = 2.0
    history_limit: int = 300
    command_history_limit: int = 25
    host: str = "0.0.0.0"
    port: int = 8080


settings = Settings()
