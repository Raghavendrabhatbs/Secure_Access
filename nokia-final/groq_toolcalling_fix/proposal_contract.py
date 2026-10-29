"""Isolated validation contract proposed for a future Groq integration."""

from __future__ import annotations

import json
import re
from typing import Any


MAX_GROQ_FUNCTIONS = 128
SUPPORTED_TOOL_CHOICES = {"auto", "none", "required"}
SUPPORTED_SCHEMA_KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "description",
    "default",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
}
SUPPORTED_JSON_TYPES = {
    "object",
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "null",
}
GPT_OSS_120B_CAPABILITIES = {
    "local_tool_use": True,
    "parallel_tool_use": False,
    "json_mode": True,
}


class ContractError(ValueError):
    pass


def classify_provider_error(
    *,
    status_code: int | None,
    error_code: str | None = None,
    error_type: str | None = None,
    message: str | None = None,
) -> tuple[str, str]:
    """Map provider errors to safe user-facing categories, never raw body text."""
    code = (error_code or "").lower()
    kind = (error_type or "").lower()
    text = (message or "").lower()
    if "timeout" in kind:
        return "timeout", "The Groq request timed out. Try again shortly."
    if "connection" in kind:
        return "connection", "The Groq API could not be reached. Check connectivity."
    if status_code in {401, 403}:
        return "authentication", "Groq rejected the configured credentials or permissions."
    if status_code == 404 or "model_not_found" in code or "model not found" in text:
        return "unsupported_model", "The configured Groq model is unavailable."
    if status_code == 413:
        return "payload_too_large", "The Groq request exceeded the provider payload limit."
    if status_code == 429:
        return "rate_limit", "Groq rate-limited the request. Wait briefly and try again."
    if status_code == 400:
        if "context" in code or "context length" in text or "context_length" in text:
            return "context_length", "The request exceeds the model context limit."
        if "tool" in code or "tool" in text and ("schema" in text or "choice" in text):
            return "tool_request", "Groq could not accept the configured tool request."
        if "model" in code or "model" in text and "support" in text:
            return "unsupported_model_feature", "The model does not support a requested feature."
        return "malformed_request", "Groq could not accept the request format."
    if isinstance(status_code, int) and status_code >= 500:
        return "temporary_provider_error", "Groq is temporarily unavailable. Try again shortly."
    return "provider_error", "Groq could not complete the request."


def validate_tools(tools: Any) -> int:
    if not isinstance(tools, list):
        raise ContractError("Tools must be a list.")
    if len(tools) > MAX_GROQ_FUNCTIONS:
        raise ContractError("Tool count exceeds Groq's documented limit.")

    names: set[str] = set()
    for index, tool in enumerate(tools):
        location = f"tools[{index}]"
        if (
            not isinstance(tool, dict)
            or set(tool) != {"type", "function"}
            or tool.get("type") != "function"
        ):
            raise ContractError(f"{location} has an invalid function-tool envelope.")

        function = tool["function"]
        if (
            not isinstance(function, dict)
            or set(function) != {"name", "description", "parameters"}
        ):
            raise ContractError(f"{location} has invalid function fields.")

        name = function["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
            or name in names
        ):
            raise ContractError(f"{location} has an invalid or duplicate function name.")
        names.add(name)
        if not isinstance(function["description"], str) or not function["description"].strip():
            raise ContractError(f"{location} is missing its description.")
        _validate_schema(function["parameters"], f"{location}.parameters")
        if function["parameters"].get("type") != "object":
            raise ContractError(f"{location}.parameters must have object type.")

    return len(json.dumps(tools, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def validate_tool_choice(
    value: Any,
    *,
    tool_names: set[str],
    tools_present: bool,
) -> None:
    if isinstance(value, str) and value in SUPPORTED_TOOL_CHOICES:
        if value != "none" and not tools_present:
            raise ContractError("Tool choice requires tools.")
        return
    if (
        isinstance(value, dict)
        and tools_present
        and set(value) == {"type", "function"}
        and value.get("type") == "function"
        and isinstance(value.get("function"), dict)
        and set(value["function"]) == {"name"}
        and value["function"]["name"] in tool_names
    ):
        return
    raise ContractError("Unsupported tool_choice value.")


def validate_model_features(
    model: str,
    *,
    tools_present: bool,
    parallel_tool_calls: bool,
    response_format: str | None,
    stream: bool,
) -> None:
    if model != "openai/gpt-oss-120b":
        raise ContractError(f"Model capabilities are not verified for {model!r}.")
    capabilities = GPT_OSS_120B_CAPABILITIES
    if tools_present and not capabilities["local_tool_use"]:
        raise ContractError("The configured model does not support local tool use.")
    if tools_present and parallel_tool_calls and not capabilities["parallel_tool_use"]:
        raise ContractError("The configured model does not support parallel tool use.")
    if response_format == "json_object" and not capabilities["json_mode"]:
        raise ContractError("The configured model does not support JSON mode.")
    if response_format not in {None, "json_object"}:
        raise ContractError("Response format is not verified for the configured model.")
    if not isinstance(stream, bool):
        raise ContractError("stream must be a boolean.")


def validate_tool_history(messages: Any) -> None:
    if not isinstance(messages, list):
        raise ContractError("Messages must be a list.")

    seen_ids: set[str] = set()
    index = 0
    while index < len(messages):
        message = messages[index]
        if not isinstance(message, dict):
            raise ContractError(f"messages[{index}] must be an object.")
        if message.get("role") != "assistant" or "tool_calls" not in message:
            if message.get("role") == "tool":
                raise ContractError("Orphan tool result message.")
            index += 1
            continue

        calls = message["tool_calls"]
        if not isinstance(calls, list) or not calls:
            raise ContractError(f"messages[{index}].tool_calls must be a nonempty list.")
        expected: list[tuple[str, str]] = []
        for call in calls:
            if not isinstance(call, dict):
                raise ContractError("Tool call must be an object.")
            call_id = call.get("id")
            function = call.get("function")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in seen_ids
                or not isinstance(function, dict)
                or not isinstance(function.get("name"), str)
                or not isinstance(function.get("arguments"), str)
            ):
                raise ContractError("Tool call has invalid or duplicate ID/function fields.")
            try:
                arguments = json.loads(function["arguments"])
            except json.JSONDecodeError as exc:
                raise ContractError("Tool call arguments are not valid JSON.") from exc
            if not isinstance(arguments, dict):
                raise ContractError("Tool call arguments must be a JSON object.")
            seen_ids.add(call_id)
            expected.append((call_id, function["name"]))

        index += 1
        for call_id, name in expected:
            if index >= len(messages):
                raise ContractError("Assistant tool call has no result message.")
            result = messages[index]
            if (
                not isinstance(result, dict)
                or result.get("role") != "tool"
                or result.get("tool_call_id") != call_id
                or result.get("name") != name
                or not isinstance(result.get("content"), str)
            ):
                raise ContractError("Tool result does not match its assistant call.")
            index += 1


def _validate_schema(schema: Any, location: str) -> None:
    if not isinstance(schema, dict):
        raise ContractError(f"{location} must be a JSON Schema object.")
    unsupported = set(schema) - SUPPORTED_SCHEMA_KEYS
    if unsupported:
        raise ContractError(
            f"{location} contains unsupported schema keyword(s): "
            + ", ".join(sorted(unsupported))
        )

    schema_type = schema.get("type")
    types = schema_type if isinstance(schema_type, list) else [schema_type]
    if not types or any(
        not isinstance(item, str) or item not in SUPPORTED_JSON_TYPES
        for item in types
    ):
        raise ContractError(f"{location} has an invalid JSON Schema type.")
    if isinstance(schema_type, list) and len(schema_type) != len(set(schema_type)):
        raise ContractError(f"{location} has duplicate union types.")

    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or any(
        not isinstance(name, str) for name in properties
    ):
        raise ContractError(f"{location}.properties must be an object.")
    required = schema.get("required", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(item, str) for item in required)
        or len(required) != len(set(required))
        or any(item not in properties for item in required)
    ):
        raise ContractError(f"{location}.required must name declared properties.")
    if "additionalProperties" in schema and not isinstance(
        schema["additionalProperties"], bool
    ):
        raise ContractError(f"{location}.additionalProperties must be boolean.")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not enum:
            raise ContractError(f"{location}.enum must be a nonempty array.")
        if any(
            not any(_matches_type(value, item) for item in types)
            for value in enum
        ):
            raise ContractError(f"{location}.enum contains a value of the wrong type.")

    for bound in ("minimum", "maximum", "minLength", "maxLength"):
        if bound in schema and (
            isinstance(schema[bound], bool)
            or not isinstance(schema[bound], (int, float))
            or schema[bound] < 0
        ):
            raise ContractError(f"{location}.{bound} must be a nonnegative number.")
    for bound in ("minLength", "maxLength"):
        if bound in schema and (
            isinstance(schema[bound], bool) or not isinstance(schema[bound], int)
        ):
            raise ContractError(f"{location}.{bound} must be an integer.")
    if (
        "minimum" in schema
        and "maximum" in schema
        and schema["minimum"] > schema["maximum"]
    ):
        raise ContractError(f"{location} has inverted numeric bounds.")
    if (
        "minLength" in schema
        and "maxLength" in schema
        and schema["minLength"] > schema["maxLength"]
    ):
        raise ContractError(f"{location} has inverted string-length bounds.")

    for name, child in properties.items():
        _validate_schema(child, f"{location}.properties.{name}")


def _matches_type(value: Any, schema_type: str) -> bool:
    if schema_type == "null":
        return value is None
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "object":
        return isinstance(value, dict)
    return False
