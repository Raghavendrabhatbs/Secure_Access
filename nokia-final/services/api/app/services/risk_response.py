from __future__ import annotations

from typing import Any, Mapping, Sequence

SEVERITY_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}


def format_risk_summary(
    summary: Mapping[str, Any] | None,
    findings: Sequence[Mapping[str, Any]] | None,
    commands: Sequence[Mapping[str, Any]] | None,
) -> str:
    """Format deterministic session risk evidence for chatbot responses."""
    summary_data = summary or {}
    findings_list = list(findings or [])
    commands_list = list(commands or [])

    overall_severity = str(summary_data.get("overall_severity", "NONE"))
    finding_count = _as_int(summary_data.get("finding_count", len(findings_list)))
    high_count = _as_int(summary_data.get("high_count", _count_findings(findings_list, "HIGH")))
    medium_count = _as_int(summary_data.get("medium_count", _count_findings(findings_list, "MEDIUM")))
    low_count = _as_int(summary_data.get("low_count", _count_findings(findings_list, "LOW")))
    categories = _sorted_unique_strings(summary_data.get("categories", _extract_categories(findings_list)))

    has_findings = bool(finding_count or high_count or medium_count or low_count or findings_list)
    if not has_findings:
        return "Overall risk: NONE\n\nNo risk findings were identified in the retrieved session evidence."

    lines = [
        f"Overall risk: {overall_severity}",
        "",
        f"Findings: {finding_count}",
        f"HIGH: {high_count}",
        f"MEDIUM: {medium_count}",
        f"LOW: {low_count}",
        "",
        "Risk categories:",
    ]

    if categories:
        lines.extend(f"- {category}" for category in categories)
    else:
        lines.append("- None")

    command_lines = _format_command_lines(commands_list)
    if command_lines:
        lines.extend(["", "Risky commands:"])
        lines.extend(command_lines)

    return "\n".join(lines)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _count_findings(findings: Sequence[Mapping[str, Any]], severity: str) -> int:
    return sum(1 for finding in findings if str(finding.get("severity", "")).upper() == severity)


def _extract_categories(findings: Sequence[Mapping[str, Any]]) -> list[str]:
    categories = []
    for finding in findings:
        category = str(finding.get("category", "")).strip()
        if category:
            categories.append(category)
    return categories


def _sorted_unique_strings(values: Any) -> list[str]:
    unique_values = []
    seen = set()
    for value in values or []:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            unique_values.append(text)
    return sorted(unique_values)


def _format_command_lines(commands: Sequence[Mapping[str, Any]]) -> list[str]:
    risky_commands = [
        command for command in commands if command.get("risk_findings")
    ]
    risky_commands.sort(key=_command_sort_key)

    lines: list[str] = []
    for command in risky_commands:
        command_text = str(command.get("command", "")).strip()
        if not command_text:
            continue
        labels = [
            f"{finding_label.get('category')} ({str(finding_label.get('severity', '')).upper()})"
            for finding_label in sorted(
                command.get("risk_findings", []),
                key=_finding_sort_key,
            )
            if finding_label.get("category")
        ]
        if labels:
            lines.append(f"- {command_text}: {', '.join(labels)}")
        else:
            lines.append(f"- {command_text}")
    return lines


def _command_sort_key(command: Mapping[str, Any]) -> tuple[int, str, str]:
    sequence_number = command.get("sequence_number")
    if isinstance(sequence_number, int):
        return (sequence_number, str(command.get("command", "")), str(command.get("output", "")))
    return (10**9, str(command.get("command", "")), str(command.get("output", "")))


def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[int, str, str]:
    severity = str(finding.get("severity", "")).upper()
    return (
        SEVERITY_ORDER.get(severity, len(SEVERITY_ORDER)),
        str(finding.get("category", "")),
        str(finding.get("rule", "")),
    )
