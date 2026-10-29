"""Isolated Groq request compatibility prototype for GPT-OSS tool calling."""

from __future__ import annotations

from typing import Any


def build_completion_parameters(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    tool_choice: str | None = None,
    temperature: float = 0.1,
) -> dict[str, Any]:
    """Create completion arguments with parallel calls disabled when tools are present."""
    parameters: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": tool_choice or ("auto" if tools else "none"),
        "temperature": temperature,
    }
    if tools:
        parameters["parallel_tool_calls"] = False
    return parameters


def validate_tool_batch(tool_calls: list[Any]) -> None:
    """Reject multi-call responses when the configured model is sequential-only."""
    if len(tool_calls) > 1:
        raise ValueError(
            "The configured Groq model returned multiple tool calls although "
            "parallel tool calls are disabled."
        )
