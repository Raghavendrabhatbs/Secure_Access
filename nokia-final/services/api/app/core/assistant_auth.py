from dataclasses import dataclass
from http.cookies import SimpleCookie
import os

import httpx
from fastapi import HTTPException, Request

from app.core.config import settings


ALLOWED_ROLES = {"admin", "developer", "auditor_viewer"}


@dataclass(frozen=True)
class AssistantUser:
    username: str
    role: str


def require_assistant_user(request: Request) -> AssistantUser:
    cookies = SimpleCookie()
    cookies.load(request.headers.get("cookie", ""))
    session_cookie = cookies.get("warpgate-http-session")
    warpgate_url = (os.getenv("WARPGATE_URL") or settings.warpgate_url).rstrip("/")
    if session_cookie is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not warpgate_url:
        raise HTTPException(status_code=503, detail="Identity service is unavailable.")

    verify: bool | str = os.getenv("WARPGATE_CA_BUNDLE") or settings.warpgate_ca_bundle or True
    try:
        response = httpx.get(
            f"{warpgate_url}/@warpgate/api/info",
            headers={"Cookie": session_cookie.OutputString()},
            timeout=5.0,
            verify=verify,
            follow_redirects=False,
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail="Identity service is unavailable.",
        ) from exc

    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        identity = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Identity service is unavailable.") from exc

    username = identity.get("username") if isinstance(identity, dict) else None
    role = identity.get("application_role") if isinstance(identity, dict) else None
    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(role, str)
        or role not in ALLOWED_ROLES
    ):
        raise HTTPException(status_code=403, detail="This account cannot access session intelligence.")

    return AssistantUser(username=username.strip(), role=role)
