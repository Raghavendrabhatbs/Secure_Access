from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timezone
import json
from typing import Any
from urllib.parse import quote
from urllib.parse import urlsplit

import httpx

from backend.config import Settings
from backend.security import AssistantIdentity, safe_session_id
from backend.time_ranges import is_after_cutoff


class DataSourceError(RuntimeError):
    def __init__(self, source: str, message: str):
        super().__init__(message)
        self.source = source


class SecureAccessClient:
    PAGE_SIZE = 1000
    MAX_SESSION_ROWS = 10000
    MAX_WEB_ROWS = 10000
    MAX_WEB_RECORDING_BYTES = 32 * 1024 * 1024
    MAX_WEB_RECORDING_EVENTS = 50000
    MAX_TARGET_LOOKUPS = 250
    MAX_AUDIT_ROWS = 500

    def __init__(
        self,
        settings: Settings,
        cookie: str,
        identity: AssistantIdentity,
        transport: Any = httpx,
    ):
        self._settings = settings
        self._cookie = cookie
        self._identity = identity
        self._transport = transport

    def _get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        try:
            response = self._transport.get(
                f"{self._settings.secure_access_api_url}{path}",
                headers={"Cookie": self._cookie},
                params=params,
                timeout=self._settings.secure_access_timeout_seconds,
                verify=self._settings.warpgate_ca_bundle or True,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise DataSourceError("Secure Access API", "The Secure Access API is unavailable.") from exc
        if response.status_code in {401, 403}:
            raise DataSourceError("Secure Access API", "The Secure Access API rejected this identity.")
        if response.status_code != 200:
            raise DataSourceError("Secure Access API", f"The Secure Access API returned HTTP {response.status_code}.")
        try:
            return response.json()
        except ValueError as exc:
            raise DataSourceError("Secure Access API", "The Secure Access API returned invalid data.") from exc

    def list_ssh_sessions(
        self,
        *,
        username: str | None = None,
        target: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        before: datetime | None = None,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        live_records: list[dict[str, Any]] = []
        live_complete = False
        warnings: list[str] = []
        try:
            live_records, live_complete = self._list_live_warpgate_sessions()
            if not live_complete:
                warnings.append(
                    "The live Warpgate session feed reached its 500-session visibility cap."
                )
        except DataSourceError as exc:
            warnings.append(str(exc))

        records: list[dict[str, Any]] = []
        archive_complete = False
        try:
            for offset in range(0, self.MAX_SESSION_ROWS, self.PAGE_SIZE):
                page = self._get_json(
                    "/sessions",
                    params={"limit": self.PAGE_SIZE, "offset": offset},
                )
                if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                    raise DataSourceError("SSH sessions", "The session API returned invalid records.")
                records.extend(page)
                if len(page) < self.PAGE_SIZE:
                    archive_complete = True
                    break
        except DataSourceError as exc:
            warnings.append(str(exc))

        records_by_id: dict[str, dict[str, Any]] = {}
        for item in records:
            session_id = item.get("session_id") or item.get("unique_id")
            if not isinstance(session_id, str) or not session_id:
                raise DataSourceError("SSH sessions", "A session record has no logical ID.")
            records_by_id.setdefault(session_id, item)
        for item in live_records:
            session_id = item["session_id"]
            archived = records_by_id.get(session_id, {})
            records_by_id[session_id] = {
                **archived,
                **{key: value for key, value in item.items() if value is not None},
            }
        records = list(records_by_id.values())
        filtered = [
            item for item in records
            if self._authorized_session(item)
            and (
                not item.get("protocol")
                or str(item.get("protocol")).upper() == "SSH"
            )
            and (username is None or _same(item.get("username"), username))
            and _date_matches(
                item.get("started_at") or item.get("login_time"),
                start_date,
                end_date,
                self._settings.app_timezone,
            )
            and not is_after_cutoff(item.get("started_at") or item.get("login_time"), before)
            and _is_at_or_after(item.get("started_at") or item.get("login_time"), since)
        ]
        if target:
            matched: list[dict[str, Any]] = []
            target_candidates = filtered
            candidates = target_candidates[: self.MAX_TARGET_LOOKUPS]
            for item in candidates:
                session_target = item.get("target")
                if session_target is None and item.get("live_source") != "Warpgate":
                    detail = self._fetch_ssh_detail(item)
                    session_target = detail.get("target")
                if target.casefold() in str(session_target or "").casefold():
                    matched.append({**item, "target": session_target})
                elif item.get("live_source") == "Warpgate" and session_target is None:
                    live_complete = False
                    warnings.append(
                        "Some live Warpgate sessions have no target metadata and could not be matched."
                    )
            filtered = matched
            archive_complete = archive_complete and len(candidates) == len(target_candidates)
        filtered.sort(
            key=lambda item: _timestamp(item.get("started_at") or item.get("login_time")),
            reverse=True,
        )
        return {
            "items": filtered,
            "total": len(filtered),
            "complete": archive_complete and live_complete,
            "warnings": list(dict.fromkeys(warnings)),
            "source": "authenticated live Warpgate sessions and PostgreSQL archive",
        }

    def _list_live_warpgate_sessions(self) -> tuple[list[dict[str, Any]], bool]:
        sessions = self._get_warpgate_json(
            "/@warpgate/rrweb/api/warpgate/sessions",
            source="sessions",
        )
        normalized: list[dict[str, Any]] = []
        for item in sessions:
            session_id = item.get("id") or item.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise DataSourceError(
                    "Warpgate sessions",
                    "A live session record has no session ID.",
                )
            protocol = str(item.get("protocol") or "").upper()
            if protocol != "SSH":
                continue
            target = item.get("target")
            if isinstance(target, dict):
                target = target.get("name")
            normalized.append(
                {
                    "session_id": session_id,
                    "unique_id": session_id,
                    "username": item.get("username"),
                    "target": target,
                    "protocol": protocol,
                    "started_at": item.get("started") or item.get("started_at"),
                    "ended_at": item.get("ended") or item.get("ended_at"),
                    "remote_address": item.get("remote_address"),
                    "live_source": "Warpgate",
                }
            )
        return normalized, len(sessions) < 500

    def list_web_sessions(
        self,
        *,
        username: str | None = None,
        target: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        limit: int = 25,
        offset: int = 0,
        since: datetime | None = None,
        before: datetime | None = None,
    ) -> dict[str, Any]:
        filters = {
            "username": self._identity.username if self._identity.is_developer else username,
            "target": target,
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
        }
        params: dict[str, Any] = {
            key: value for key, value in filters.items() if value is not None
        }
        records: list[dict[str, Any]] = []
        total: int | None = None
        while (
            (total is None or len(records) < total)
            and len(records) < self.MAX_WEB_ROWS
        ):
            page_offset = len(records)
            payload = self._get_json(
                "/web-sessions",
                params={**params, "limit": 100, "offset": page_offset},
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise DataSourceError("Web sessions", "The Web session API returned invalid records.")
            page = payload["items"]
            if any(not isinstance(item, dict) for item in page):
                raise DataSourceError("Web sessions", "The Web session API returned invalid records.")
            total = payload.get("total")
            if not isinstance(total, int) or total < 0:
                raise DataSourceError("Web sessions", "The Web session API returned an invalid count.")
            records.extend(page)
            if not page:
                break
        complete = total is not None and len(records) >= total
        visible = [
            item for item in records
            if (username is None or _same(item.get("username"), username))
            and (target is None or target.casefold() in str(item.get("target") or "").casefold())
            and _date_matches(
                item.get("startedAt"),
                start_date,
                end_date,
                self._settings.app_timezone,
            )
            and _is_at_or_after(item.get("startedAt"), since)
            and not is_after_cutoff(item.get("startedAt"), before)
        ]
        unique: dict[str, dict[str, Any]] = {}
        for item in visible:
            session_id = item.get("sessionId")
            if not isinstance(session_id, str) or not session_id:
                raise DataSourceError("Web sessions", "A Web session record has no session ID.")
            unique.setdefault(session_id, item)
        visible = list(unique.values())
        visible.sort(key=lambda item: _timestamp(item.get("startedAt")), reverse=True)
        return {
            "items": visible[offset : offset + limit],
            "total": len(visible),
            "complete": complete,
            "source": "Warpgate rrweb metadata via authenticated Secure Access API",
        }

    def get_session_detail(self, session_id: str) -> dict[str, Any]:
        authorized = self._find_authorized_ssh_session(session_id)
        if authorized.get("live_source") == "Warpgate":
            return authorized
        return self._fetch_ssh_detail(authorized)

    def enrich_ssh_sessions(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched = []
        for session in sessions:
            if session.get("target") is not None:
                enriched.append(session)
                continue
            detail = self._fetch_ssh_detail(session)
            enriched.append({**session, "target": detail.get("target")})
        return enriched

    def _fetch_ssh_detail(self, session: dict[str, Any]) -> dict[str, Any]:
        unique_id = session.get("unique_id") or session.get("session_id")
        payload = self._get_json(f"/sessions/{quote(str(unique_id), safe='')}")
        if not isinstance(payload, dict):
            raise DataSourceError("SSH sessions", "The session detail API returned invalid data.")
        if (
            self._identity.is_developer
            and not _same(payload.get("username"), self._identity.username)
        ):
            raise DataSourceError("SSH sessions", "The requested SSH session is not available.")
        return payload

    def get_session_related(self, session_id: str, kind: str) -> list[dict[str, Any]]:
        if kind not in {"commands", "events"}:
            raise ValueError("Unsupported session record type.")
        authorized = self._find_authorized_ssh_session(session_id)
        unique_id = authorized.get("unique_id") or authorized.get("session_id")
        payload = self._get_json(
            f"/sessions/{quote(str(unique_id), safe='')}/{kind}"
        )
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise DataSourceError("SSH session records", f"The session {kind} API returned invalid data.")
        return payload if kind == "commands" else payload[:500]

    def get_session_command_log(
        self,
        session_id: str,
        *,
        limit: int = 5,
        offset: int = 0,
        output_offset: int = 0,
        output_limit: int = 4000,
    ) -> dict[str, Any]:
        safe_session_id(session_id)
        authorized = self._find_authorized_ssh_session(session_id)
        unique_id = authorized.get("unique_id") or authorized.get("session_id")
        payload = self._get_json(
            f"/sessions/{quote(str(unique_id), safe='')}/command-log",
            params={
                "limit": limit,
                "offset": offset,
                "output_offset": output_offset,
                "output_limit": output_limit,
            },
        )
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("commands"), list)
            or any(not isinstance(item, dict) for item in payload["commands"])
            or not isinstance(payload.get("total"), int)
            or not isinstance(payload.get("complete"), bool)
        ):
            raise DataSourceError(
                "SSH command log",
                "The session command-log API returned invalid data.",
            )
        return payload

    def analyze_ssh_command_archive(
        self,
        *,
        search: str | None = None,
        risky_only: bool = False,
        limit: int = 25,
        offset: int = 0,
        session_limit: int = 25,
        session_offset: int = 0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "risky_only": risky_only,
            "limit": limit,
            "offset": offset,
            "session_limit": session_limit,
            "session_offset": session_offset,
        }
        if search:
            params["search"] = search
        payload = self._get_json("/sessions/command-analysis", params=params)
        if not isinstance(payload, dict) or not isinstance(payload.get("matches"), list):
            raise DataSourceError(
                "SSH command archive",
                "The command-analysis API returned invalid data.",
            )
        return payload

    def get_web_session(self, session_id: str) -> dict[str, Any]:
        safe_session_id(session_id)
        payload = self._get_json(f"/web-sessions/{quote(session_id, safe='')}")
        if not isinstance(payload, dict):
            raise DataSourceError("Web sessions", "The Web session API returned invalid data.")
        if (
            self._identity.is_developer
            and not _same(payload.get("username"), self._identity.username)
        ):
            raise DataSourceError("Web sessions", "The requested Web session is not available.")
        return payload

    def get_web_recording_activity(self, session_id: str) -> dict[str, Any]:
        safe_session_id(session_id)
        metadata = self.get_web_session(session_id)
        path = f"/@warpgate/rrweb/api/sessions/{quote(session_id + '.json', safe='')}"
        content = bytearray()
        try:
            with self._transport.stream(
                "GET",
                f"{self._settings.warpgate_url}{path}",
                headers={"Cookie": self._cookie},
                timeout=self._settings.secure_access_timeout_seconds,
                verify=self._settings.warpgate_ca_bundle or True,
                follow_redirects=False,
            ) as response:
                if response.status_code in {401, 403}:
                    raise DataSourceError(
                        "Web recordings",
                        "Warpgate denied access to this recording.",
                    )
                if response.status_code == 404:
                    raise DataSourceError(
                        "Web recordings",
                        "The authorized Web recording is not available.",
                    )
                if response.status_code == 409:
                    raise DataSourceError(
                        "Web recordings",
                        "The Web recording is still in progress and is not replayable yet.",
                    )
                if response.status_code != 200:
                    raise DataSourceError(
                        "Web recordings",
                        f"The recording service returned HTTP {response.status_code}.",
                    )
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        oversized = int(content_length) > self.MAX_WEB_RECORDING_BYTES
                    except ValueError as exc:
                        raise DataSourceError(
                            "Web recordings",
                            "The recording service returned an invalid content length.",
                        ) from exc
                    if oversized:
                        raise DataSourceError(
                            "Web recordings",
                            "The recording exceeds the assistant's bounded retrieval size.",
                        )
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    content.extend(chunk)
                    if len(content) > self.MAX_WEB_RECORDING_BYTES:
                        raise DataSourceError(
                            "Web recordings",
                            "The recording exceeds the assistant's bounded retrieval size.",
                        )
        except httpx.RequestError as exc:
            raise DataSourceError(
                "Web recordings",
                "The Warpgate recording service is unavailable.",
            ) from exc
        try:
            events = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DataSourceError(
                "Web recordings",
                "The recording service returned invalid event data.",
            ) from exc
        if not isinstance(events, list) or any(not isinstance(item, dict) for item in events):
            raise DataSourceError(
                "Web recordings",
                "The recording service returned invalid event data.",
            )

        analyzed = events[: self.MAX_WEB_RECORDING_EVENTS]
        event_types: Counter[str] = Counter()
        activity_types: Counter[str] = Counter()
        page_origins: set[str] = set()
        timestamps: list[float] = []
        source_names = {
            0: "dom_mutations",
            1: "mouse_moves",
            2: "mouse_interactions",
            3: "scrolls",
            4: "viewport_resizes",
            5: "input_events",
            6: "touch_moves",
            7: "media_interactions",
            8: "stylesheet_changes",
            9: "canvas_mutations",
            10: "font_events",
        }
        type_names = {
            1: "metadata",
            2: "full_snapshots",
            3: "incremental_snapshots",
            4: "custom_events",
            5: "plugin_events",
        }
        for event in analyzed:
            event_type = event.get("type")
            if isinstance(event_type, int) and not isinstance(event_type, bool):
                event_types[type_names.get(event_type, "other_events")] += 1
            timestamp = event.get("timestamp")
            if (
                isinstance(timestamp, (int, float))
                and not isinstance(timestamp, bool)
                and 0 <= timestamp <= 253402300799999
            ):
                timestamps.append(float(timestamp))
            data = event.get("data")
            if not isinstance(data, dict):
                continue
            if event_type == 1:
                href = data.get("href")
                if isinstance(href, str):
                    try:
                        parsed = urlsplit(href)
                        if parsed.scheme in {"http", "https"} and parsed.hostname:
                            page_origins.add(f"{parsed.scheme}://{parsed.hostname}")
                    except ValueError:
                        pass
            if event_type == 3:
                source = data.get("source")
                if isinstance(source, int) and not isinstance(source, bool):
                    name = source_names.get(source)
                    if name:
                        activity_types[name] += 1

        activity: dict[str, Any] = {
            "event_count": len(events),
            "analyzed_event_count": len(analyzed),
            "truncated": len(events) > len(analyzed),
            "event_types": dict(event_types),
            "activity_types": dict(activity_types),
            "page_origins": sorted(page_origins)[:20],
            "dom_text_included": False,
            "input_values_included": False,
        }
        if timestamps:
            activity["first_event_at"] = datetime.fromtimestamp(
                min(timestamps) / 1000, timezone.utc
            ).isoformat()
            activity["last_event_at"] = datetime.fromtimestamp(
                max(timestamps) / 1000, timezone.utc
            ).isoformat()
        return {
            "session_id": session_id,
            "username": metadata.get("username"),
            "target": metadata.get("target"),
            "started_at": metadata.get("startedAt"),
            "activity": activity,
            "source": "authorized live rrweb recording",
        }

    def list_audit_logs(
        self,
        *,
        search: str | None = None,
        limit: int = MAX_AUDIT_ROWS,
    ) -> dict[str, Any]:
        if self._identity.role not in {"admin", "auditor_viewer"}:
            raise DataSourceError(
                "Audit logs",
                "Audit-log access is restricted to admin and auditor accounts.",
            )
        bounded_limit = min(max(limit, 1), self.MAX_AUDIT_ROWS)
        params: dict[str, Any] = {"limit": bounded_limit}
        if search:
            params["search"] = search[:200]
        routes = {
            "secure_access_events": "/@warpgate/rrweb/api/audit/events",
            "warpgate_events": "/@warpgate/rrweb/api/audit/warpgate-events",
        }
        sources: dict[str, list[dict[str, Any]]] = {}
        for source, path in routes.items():
            sources[source] = self._get_warpgate_json(path, params=params)
        return {
            **sources,
            "limit_per_source": bounded_limit,
            "complete": all(
                len(events) < bounded_limit for events in sources.values()
            ),
            "note": (
                "Each audit source returns at most 500 most recent matching events."
            ),
        }

    def _get_warpgate_json(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        source: str = "Audit logs",
    ) -> list[dict[str, Any]]:
        try:
            response = self._transport.get(
                f"{self._settings.warpgate_url}{path}",
                headers={"Cookie": self._cookie},
                params=params,
                timeout=self._settings.secure_access_timeout_seconds,
                verify=self._settings.warpgate_ca_bundle or True,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise DataSourceError(
                source,
                (
                    "The Warpgate audit-log service is unavailable."
                    if source == "Audit logs"
                    else f"The Warpgate {source.casefold()} service is unavailable."
                ),
            ) from exc
        if response.status_code in {401, 403}:
            raise DataSourceError(
                source,
                (
                    "Warpgate denied access to audit logs for this account."
                    if source == "Audit logs"
                    else f"Warpgate denied access to {source.casefold()} for this account."
                ),
            )
        if response.status_code != 200:
            raise DataSourceError(
                source,
                (
                    f"The Warpgate audit-log service returned HTTP {response.status_code}."
                    if source == "Audit logs"
                    else f"The Warpgate {source.casefold()} service returned HTTP {response.status_code}."
                ),
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise DataSourceError(
                source,
                (
                    "The Warpgate audit-log service returned invalid data."
                    if source == "Audit logs"
                    else f"The Warpgate {source.casefold()} service returned invalid data."
                ),
            ) from exc
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise DataSourceError(
                source,
                (
                    "The Warpgate audit-log service returned invalid records."
                    if source == "Audit logs"
                    else f"The Warpgate {source.casefold()} service returned invalid records."
                ),
            )
        return payload

    def _find_authorized_ssh_session(self, session_id: str) -> dict[str, Any]:
        safe_session_id(session_id)
        listing = self.list_ssh_sessions()
        for item in listing["items"]:
            if session_id in {item.get("session_id"), item.get("unique_id")}:
                return item
        raise DataSourceError("SSH sessions", "The requested SSH session is not available.")

    def _authorized_session(self, item: dict[str, Any]) -> bool:
        return (
            not self._identity.is_developer
            or _same(item.get("username"), self._identity.username)
        )


def _same(left: Any, right: str) -> bool:
    return isinstance(left, str) and left.casefold() == right.casefold()


def _timestamp(value: Any) -> float:
    if not isinstance(value, str):
        return float("-inf")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return float("-inf")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _date_matches(
    value: Any,
    start_date: date | None,
    end_date: date | None,
    timezone_name: str,
) -> bool:
    if start_date is None and end_date is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    from zoneinfo import ZoneInfo

    local_date = parsed.astimezone(ZoneInfo(timezone_name)).date()
    return (start_date is None or local_date >= start_date) and (
        end_date is None or local_date <= end_date
    )


def _is_at_or_after(value: Any, since: datetime | None) -> bool:
    if since is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    threshold = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc) >= threshold.astimezone(timezone.utc)
