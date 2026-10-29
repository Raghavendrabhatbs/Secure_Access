from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Nokia AI Assistant"
    app_env: str = "development"
    app_port: int = 8000
    app_timezone: str = "UTC"

    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str

    valkey_host: str
    valkey_port: int

    ollama_host: str
    ollama_model: str
    ollama_timeout_seconds: float = 45.0
    warpgate_url: str = "https://localhost:8888"
    warpgate_ca_bundle: str | None = None

    qdrant_host: str
    qdrant_port: int

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
