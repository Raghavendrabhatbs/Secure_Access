from __future__ import annotations

from dataclasses import dataclass
from http.cookies import SimpleCookie
import re
from typing import Any

import httpx

from backend.config import Settings


ALLOWED_ROLES = {"admin", "developer", "auditor_viewer"}
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|authorization|cookie|private.?key|api.?key|recording.?path)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_FLAG = re.compile(
    r"(?i)(--?(?:password|passwd|token|secret|api-key|access-key)\s+)([^\s]+)"
)
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
_GROQ_KEY = re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


class AuthenticationError(RuntimeError):
    pass


class IdentityServiceError(RuntimeError):
    pass


@dataclass(frozen=True)
class AssistantIdentity:
    username: str
    role: str

    @property
    def is_developer(self) -> bool:
        return self.role == "developer"


def parse_session_cookie(cookie_header: str | None) -> str:
    parsed = SimpleCookie()
    try:
        parsed.load(cookie_header or "")
    except (TypeError, ValueError) as exc:
        raise AuthenticationError("A valid Secure Access login is required.") from exc
    cookie = parsed.get("warpgate-http-session")
    if cookie is None or not cookie.value:
        raise AuthenticationError("A valid Secure Access login is required.")
    return cookie.OutputString()


def authenticate_cookie(cookie_header: str | None, settings: Settings) -> tuple[str, AssistantIdentity]:
    cookie = parse_session_cookie(cookie_header)
    verify: bool | str = settings.warpgate_ca_bundle or True
    try:
        response = httpx.get(
            f"{settings.warpgate_url}/@warpgate/api/info",
            headers={"Cookie": cookie},
            timeout=5.0,
            verify=verify,
            follow_redirects=False,
        )
    except httpx.RequestError as exc:
        raise IdentityServiceError("The Secure Access identity service is unavailable.") from exc
    if response.status_code in {401, 403}:
        raise AuthenticationError("A valid Secure Access login is required.")
    if response.status_code != 200:
        raise IdentityServiceError("The Secure Access identity service returned an error.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise IdentityServiceError("The identity service returned invalid data.") from exc
    username = payload.get("username") if isinstance(payload, dict) else None
    role = payload.get("application_role") if isinstance(payload, dict) else None
    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(role, str)
        or role not in ALLOWED_ROLES
    ):
        raise AuthenticationError("This account cannot access session intelligence.")
    return cookie, AssistantIdentity(username=username.strip(), role=role)


def safe_session_id(value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ValueError("Invalid session ID.")
    return value


def sanitize_for_llm(value: Any) -> Any:
    """Remove sensitive fields and common inline credential forms before model use."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else sanitize_for_llm(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_for_llm(item) for item in value[:100]]
    if isinstance(value, str):
        text = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", value)
        text = _BEARER.sub("Bearer [REDACTED]", text)
        text = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
        text = _SECRET_FLAG.sub(r"\1[REDACTED]", text)
        text = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)
        text = _GROQ_KEY.sub("[REDACTED API KEY]", text)
        return text[:4000]
    return value
