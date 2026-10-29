from __future__ import annotations

import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import re
from typing import Any

from backend.config import ConfigurationError, Settings


logger = logging.getLogger(__name__)


class GroqProviderError(RuntimeError):
    pass


class GroqPayloadTooLargeError(GroqProviderError):
    pass


class GroqRateLimitError(GroqProviderError):
    def __init__(self, message: str, retry_after_seconds: int | None = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class GroqProvider:
    def __init__(
        self,
        settings: Settings,
        client: Any = None,
        client_factory: Any = None,
    ):
        configured_keys = settings.groq_api_keys or (
            (settings.groq_api_key,) if settings.groq_api_key else ()
        )
        api_keys = tuple(dict.fromkeys(
            key.strip() for key in configured_keys if key.strip()
        ))
        if not api_keys:
            raise ConfigurationError(
                "Groq is not configured. Set GROQ_API_KEY or GROQ_API_KEYS in the addon environment."
            )
        if client is not None:
            self._clients = (client,)
        else:
            try:
                from groq import Groq
            except ImportError as exc:
                raise ConfigurationError(
                    "The Groq SDK is missing. Install groq_ai_addon/requirements-addon.txt."
                ) from exc
            make_client = client_factory or (
                lambda api_key: Groq(
                    api_key=api_key,
                    timeout=settings.groq_timeout_seconds,
                    max_retries=2,
                )
            )
            self._clients = tuple(make_client(api_key) for api_key in api_keys)
        self._active_client_index = 0
        self._model = settings.groq_model
        logger.info("Groq provider configured with %d API key(s).", len(self._clients))

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        tool_choice: str | None = None,
    ):
        completion_arguments = {
            "model": self._model,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice or ("auto" if tools else "none"),
            "temperature": 0.1,
        }
        if tools:
            completion_arguments["parallel_tool_calls"] = False

        last_rate_limit: Exception | None = None
        auth_failures = 0
        for offset in range(len(self._clients)):
            client_index = (self._active_client_index + offset) % len(self._clients)
            try:
                response = self._clients[client_index].chat.completions.create(
                    **completion_arguments
                )
                self._active_client_index = client_index
                return response
            except Exception as exc:
                status_code = getattr(exc, "status_code", None)
                if status_code in {401, 403} and len(self._clients) > 1:
                    auth_failures += 1
                    logger.warning(
                        "Groq API key %d returned HTTP %d; trying the next configured key.",
                        client_index + 1,
                        status_code,
                    )
                    continue
                if status_code == 429 and len(self._clients) > 1:
                    last_rate_limit = exc
                    logger.warning(
                        "Groq API key %d was rate-limited; trying the next configured key.",
                        client_index + 1,
                    )
                    continue
                if status_code == 429:
                    last_rate_limit = exc
                else:
                    self._raise_provider_error(exc)

        if last_rate_limit is not None:
            self._raise_provider_error(last_rate_limit)
        if auth_failures == len(self._clients):
            raise GroqProviderError(
                "All configured Groq API keys were rejected or lack access to the "
                "configured model. Replace invalid keys in groq_ai_addon\\.env and "
                "restart the add-on."
            )
        raise GroqProviderError("Groq could not complete the request.")

    def _raise_provider_error(self, exc: Exception) -> None:
        status_code = getattr(exc, "status_code", None)
        error_name = type(exc).__name__
        logger.warning(
            "Groq request failed (%s, HTTP %s)",
            error_name,
            status_code if isinstance(status_code, int) else "unknown",
        )
        if error_name in {"APITimeoutError", "TimeoutError"}:
            detail = "The Groq request timed out. Try again or increase GROQ_TIMEOUT_SECONDS."
        elif status_code in {401, 403}:
            detail = "Groq rejected the configured API key or model permissions."
        elif status_code == 404:
            detail = f"The configured Groq model '{self._model}' is unavailable."
        elif status_code == 429:
            retry_after_seconds = _retry_after_seconds(exc)
            if retry_after_seconds is None:
                detail = (
                    "Groq is currently rate-limited. Wait for the provider's "
                    "quota window to reset before trying again."
                )
            else:
                detail = (
                    "Groq is currently rate-limited. Retry in about "
                    f"{retry_after_seconds} seconds."
                )
            raise GroqRateLimitError(detail, retry_after_seconds) from exc
        elif status_code == 413:
            raise GroqPayloadTooLargeError(
                "Groq rejected the request because its payload exceeded the provider limit."
            ) from exc
        elif status_code == 400:
            detail = (
                "Groq rejected the request format. Check model tool-calling support "
                "and the configured tool schema."
            )
        elif isinstance(status_code, int) and status_code >= 500:
            detail = "Groq is temporarily unavailable. Try again shortly."
        elif error_name in {"APIConnectionError", "ConnectionError"}:
            detail = "The Groq API could not be reached. Check network connectivity."
        else:
            detail = "Groq could not complete the request. Check provider availability."
        raise GroqProviderError(detail) from exc


def _retry_after_seconds(exc: Exception) -> int | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        headers = getattr(exc, "headers", None)
    if not headers:
        return None

    retry_after = _header_value(headers, "retry-after")
    if retry_after:
        try:
            seconds = float(retry_after)
        except (TypeError, ValueError):
            try:
                reset_at = parsedate_to_datetime(str(retry_after))
                if reset_at.tzinfo is None:
                    reset_at = reset_at.replace(tzinfo=timezone.utc)
                seconds = (reset_at - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                seconds = None
        if seconds is not None:
            return _bounded_retry_delay(seconds)

    for header_name in ("x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        reset_value = _header_value(headers, header_name)
        if not reset_value:
            continue
        seconds = _parse_reset_duration(str(reset_value))
        if seconds is not None:
            return _bounded_retry_delay(seconds)
    return None


def _header_value(headers: Any, name: str) -> Any:
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is not None:
            return value
        return headers.get(name.title())
    return None


def _parse_reset_duration(value: str) -> float | None:
    text = value.strip().lower()
    try:
        return float(text)
    except ValueError:
        pass

    matches = list(re.finditer(r"(\d+(?:\.\d+)?)(ms|s|m|h)", text))
    if not matches or "".join(match.group(0) for match in matches) != text:
        return None
    units = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
    return sum(float(match.group(1)) * units[match.group(2)] for match in matches)


def _bounded_retry_delay(seconds: float) -> int | None:
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return min(math.ceil(seconds), 86400)
