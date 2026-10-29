from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    groq_api_key: str
    groq_model: str
    groq_timeout_seconds: float
    secure_access_timeout_seconds: float
    secure_access_api_url: str
    warpgate_url: str
    warpgate_ca_bundle: str | None
    app_timezone: str
    audit_database_url: str | None
    audit_query_timeout_seconds: float
    groq_api_keys: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "Settings":
        api_keys = _groq_api_keys_from_env()
        return cls(
            groq_api_key=api_keys[0] if api_keys else "",
            groq_model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip(),
            groq_timeout_seconds=_positive_float("GROQ_TIMEOUT_SECONDS", 90.0),
            secure_access_timeout_seconds=_positive_float(
                "SECURE_ACCESS_TIMEOUT_SECONDS", 15.0
            ),
            secure_access_api_url=os.getenv(
                "SECURE_ACCESS_API_URL", "http://127.0.0.1:8765"
            ).rstrip("/"),
            warpgate_url=os.getenv(
                "WARPGATE_URL", "https://localhost:8888"
            ).rstrip("/"),
            warpgate_ca_bundle=os.getenv("WARPGATE_CA_BUNDLE") or None,
            app_timezone=os.getenv("APP_TIMEZONE", "UTC"),
            audit_database_url=os.getenv("AUDIT_DATABASE_URL") or None,
            audit_query_timeout_seconds=_positive_float(
                "AUDIT_QUERY_TIMEOUT_SECONDS", 5.0
            ),
            groq_api_keys=api_keys,
        )

    def validate(self) -> None:
        if not self.groq_model:
            raise ConfigurationError("GROQ_MODEL must not be empty.")
        if not self.secure_access_api_url.startswith(("http://", "https://")):
            raise ConfigurationError("SECURE_ACCESS_API_URL must be an HTTP(S) URL.")
        if not self.warpgate_url.startswith("https://"):
            raise ConfigurationError("WARPGATE_URL must use HTTPS.")
        if self.warpgate_ca_bundle and not Path(self.warpgate_ca_bundle).is_file():
            raise ConfigurationError("WARPGATE_CA_BUNDLE does not name a readable file.")
        if self.audit_database_url and not self.audit_database_url.startswith(
            ("postgresql://", "postgres://")
        ):
            raise ConfigurationError("AUDIT_DATABASE_URL must be a PostgreSQL URL.")


def _positive_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive number.") from exc
    if parsed <= 0:
        raise ConfigurationError(f"{name} must be a positive number.")
    return parsed


def _groq_api_keys_from_env() -> tuple[str, ...]:
    configured_keys = os.getenv("GROQ_API_KEYS", "")
    if configured_keys.strip():
        return tuple(dict.fromkeys(
            key.strip()
            for key in configured_keys.replace(";", ",").split(",")
            if key.strip()
        ))

    legacy_key = os.getenv("GROQ_API_KEY", "").strip()
    return (legacy_key,) if legacy_key else ()
