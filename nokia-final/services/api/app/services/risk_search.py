from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SEVERITY_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
    "NONE": 3,
}

RISK_CATEGORY_PHRASES = (
    ("privilege escalation", "PRIVILEGE_ESCALATION"),
    ("account modification", "ACCOUNT_MODIFICATION"),
    ("permission modification", "PERMISSION_MODIFICATION"),
    ("credential operation", "CREDENTIAL_OPERATION"),
    ("credential file access", "CREDENTIAL_FILE_ACCESS"),
    ("destructive operation", "DESTRUCTIVE_OPERATION"),
    ("anti-forensics", "ANTI_FORENSICS"),
    ("log tampering", "ANTI_FORENSICS"),
    ("network transfer", "NETWORK_TRANSFER"),
    ("data exfiltration", "NETWORK_TRANSFER"),
)


def extract_risk_categories(question: str) -> list[str]:
    question_lower = (question or "").strip().lower()
    if not question_lower:
        return []

    categories: list[str] = []
    for phrase, category in RISK_CATEGORY_PHRASES:
        if phrase in question_lower and category not in categories:
            categories.append(category)
    return categories


def extract_risk_severity(question: str) -> str | None:
    question_lower = (question or "").lower()

    if "high-risk" in question_lower or "high risk" in question_lower:
        return "HIGH"

    if "medium-risk" in question_lower or "medium risk" in question_lower:
        return "MEDIUM"

    if "low-risk" in question_lower or "low risk" in question_lower:
        return "LOW"

    return None


def is_risk_domain_query(question: str) -> bool:
    question_lower = (question or "").lower()

    return (
        "risky" in question_lower
        or "risk findings" in question_lower
        or "flagged commands" in question_lower
        or "risky commands" in question_lower
    )


def format_cross_session_risk_search(
    matched_sessions: Sequence[Mapping[str, Any]] | None,
    risk_categories: Sequence[str] | None,
) -> str:
    sessions = list(matched_sessions or [])
    categories = _sorted_unique_strings(risk_categories)

    if not sessions:
        if categories:
            return (
                f"No sessions with {', '.join(categories)} were found in the retrieved session evidence."
            )
        return "No sessions with the requested risk categories were found in the retrieved session evidence."

    sessions.sort(key=_session_sort_key)

    heading = "Sessions with " + ", ".join(categories) if categories else "Matching sessions"
    lines = [heading + ":", ""]

    for i, session in enumerate(sessions, start=1):
        risk_summary = session.get("risk_summary", {})
        severity = str(risk_summary.get("overall_severity", "NONE")).upper()
        session_id = str(session.get("session_id", ""))

        lines.append(f"{i}. {session_id}")
        lines.append(f"   Risk: {severity}")
        lines.append("")

        matching_commands = sorted(
            [c for c in session.get("matching_commands", []) if c.get("command")],
            key=_command_sort_key,
        )

        if matching_commands:
            lines.append("   Commands:")
            for command in matching_commands[:5]:
                lines.append(f"   - {command['command']}")
            lines.append("")

            all_findings: list[tuple[str, str]] = []
            seen_findings: set[tuple[str, str]] = set()
            for command in matching_commands:
                for finding in sorted(command.get("risk_findings", []), key=_finding_sort_key):
                    category = str(finding.get("category", "")).strip()
                    sev = str(finding.get("severity", "")).upper()
                    key = (category, sev)
                    if category and key not in seen_findings:
                        seen_findings.add(key)
                        all_findings.append(key)

            if all_findings:
                all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f[1], len(SEVERITY_ORDER)), f[0]))
                lines.append("   Findings:")
                for category, sev in all_findings:
                    lines.append(f"   - {category} / {sev}")

    return "\n".join(lines)


def _format_findings(findings: Sequence[Mapping[str, Any]] | None) -> str:
    entries = []
    for finding in sorted(findings or [], key=_finding_sort_key):
        category = finding.get("category")
        severity = str(finding.get("severity", "")).upper()
        if category:
            entries.append(f"{category} ({severity})")
    return ", ".join(entries)


def _sorted_unique_strings(values: Sequence[str] | None) -> list[str]:
    unique_values: list[str] = []
    for value in values or []:
        text = str(value).strip().upper()
        if text and text not in unique_values:
            unique_values.append(text)
    return sorted(unique_values)


def _session_sort_key(session: Mapping[str, Any]) -> tuple[int, str]:
    summary = session.get("risk_summary", {})
    severity = str(summary.get("overall_severity", "NONE")).upper()
    return (SEVERITY_ORDER.get(severity, len(SEVERITY_ORDER)), str(session.get("session_id", "")))


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


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
