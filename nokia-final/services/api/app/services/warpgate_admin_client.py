from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx

from app.core.config import settings


class WarpgateAdminError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class WarpgateAdminClient:
    """Calls the authenticated Warpgate admin API on behalf of an app operator."""

    PAGE_SIZE = 100
    MAX_SESSIONS = 5000

    def __init__(
        self,
        base_url: str | None = None,
        ca_bundle: str | None = None,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base_url = (
            (base_url or settings.warpgate_url).rstrip("/")
            + "/@warpgate/admin/api"
        )
        self.verify: bool | str = (
            ca_bundle or settings.warpgate_ca_bundle or True
        )
        self.timeout = timeout
        self.transport = transport

    def _client(self, cookie_header: str) -> httpx.Client:
        if not cookie_header:
            raise WarpgateAdminError("Authentication with Warpgate is required.", 401)
        return httpx.Client(
            headers={"Cookie": cookie_header},
            timeout=self.timeout,
            verify=self.verify,
            transport=self.transport,
            follow_redirects=False,
        )

    @staticmethod
    def _check_response(response: httpx.Response) -> None:
        if response.is_success:
            return
        if response.status_code in (401, 403, 404):
            message = {
                401: "Warpgate authentication has expired.",
                403: "This operator is not authorized for the Warpgate session action.",
                404: "The Warpgate session was not found or is no longer active.",
            }[response.status_code]
            raise WarpgateAdminError(message, response.status_code)
        raise WarpgateAdminError(
            f"Warpgate returned HTTP {response.status_code}.",
            502,
        )

    def _request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        try:
            response = client.request(method, f"{self.base_url}{path}", **kwargs)
        except httpx.TimeoutException as exc:
            raise WarpgateAdminError("Warpgate did not respond before the request timed out.", 503) from exc
        except httpx.RequestError as exc:
            raise WarpgateAdminError("Warpgate is unavailable from the application backend.", 503) from exc
        self._check_response(response)
        return response

    @staticmethod
    def _session_summary(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise WarpgateAdminError("Warpgate returned an invalid session record.")
        try:
            session_id = str(UUID(str(payload["id"])))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise WarpgateAdminError("Warpgate returned an invalid session identifier.") from exc

        username = payload.get("username")
        protocol = payload.get("protocol")
        started = payload.get("started")
        ended = payload.get("ended")
        if (
            (username is not None and not isinstance(username, str))
            or not isinstance(protocol, str)
            or not isinstance(started, str)
            or (ended is not None and not isinstance(ended, str))
        ):
            raise WarpgateAdminError("Warpgate returned an invalid session record.")

        target = payload.get("target")
        if isinstance(target, dict):
            target = target.get("name")
        if target is not None and not isinstance(target, str):
            target = None

        node_hostname = payload.get("node_hostname")
        if node_hostname is not None and not isinstance(node_hostname, str):
            node_hostname = None

        return {
            "id": session_id,
            "username": username,
            "target": target,
            "protocol": protocol,
            "started": started,
            "ended": ended,
            "node_hostname": node_hostname,
        }

    def _get_session(self, client: httpx.Client, session_id: str) -> dict[str, Any]:
        response = self._request(client, "GET", f"/sessions/{session_id}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise WarpgateAdminError("Warpgate returned an invalid session response.") from exc
        session = self._session_summary(payload)
        if session["id"] != session_id:
            raise WarpgateAdminError("Warpgate returned a mismatched session identifier.")
        return session

    def list_active_sessions(self, cookie_header: str) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        offset = 0
        total: int | None = None
        with self._client(cookie_header) as client:
            while total is None or offset < total:
                response = self._request(
                    client,
                    "GET",
                    "/sessions",
                    params={
                        "active_only": "true",
                        "logged_in_only": "true",
                        "limit": self.PAGE_SIZE,
                        "offset": offset,
                    },
                )
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise WarpgateAdminError("Warpgate returned an invalid sessions response.") from exc

                if not isinstance(payload, dict):
                    raise WarpgateAdminError("Warpgate returned an invalid sessions response.")
                items = payload.get("items")
                page_total = payload.get("total")
                if (
                    not isinstance(items, list)
                    or not isinstance(page_total, int)
                    or page_total < 0
                ):
                    raise WarpgateAdminError("Warpgate returned an invalid sessions response.")
                total = page_total
                if total > self.MAX_SESSIONS:
                    raise WarpgateAdminError(
                        "The active-session list exceeds the supported safe limit."
                    )

                for raw_session in items:
                    session = self._session_summary(raw_session)
                    if session["ended"] is None:
                        sessions.append(session)
                if not items:
                    break
                offset += len(items)

        return sessions

    def terminate_session(self, cookie_header: str, session_id: str) -> dict[str, Any]:
        try:
            normalized_id = str(UUID(session_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise WarpgateAdminError("The selected session identifier is invalid.", 422) from exc

        with self._client(cookie_header) as client:
            session = self._get_session(client, normalized_id)
            if session["ended"] is not None:
                return {"status": "already_ended", "session": session}

            try:
                response = client.post(f"{self.base_url}/sessions/{normalized_id}/close")
            except httpx.RequestError:
                return {"status": "unverified", "session": session}

            if response.status_code not in (201, 404):
                if response.status_code in (401, 403):
                    self._check_response(response)
                return {"status": "unverified", "session": session}

            try:
                verified = self._get_session(client, normalized_id)
            except WarpgateAdminError:
                return {"status": "unverified", "session": session}

            if verified["ended"] is not None:
                return {
                    "status": "confirmed",
                    "session": verified,
                }
            return {"status": "unverified", "session": verified}
