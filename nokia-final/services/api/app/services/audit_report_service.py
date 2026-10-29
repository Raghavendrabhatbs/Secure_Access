from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone

from app.services.analytics_query_service import (
    AnalyticsQueryService,
    CommandFrequency,
    DailySummary,
    UserRiskScore,
)
from app.services.risk_aggregator import aggregate_session_risks
from app.services.session_query_service import SessionQueryService


@dataclass
class RiskySessionRecord:
    session_id: str
    username: str | None
    started_at: str | None
    overall_severity: str
    risky_commands: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    title: str
    period_start: str
    period_end: str
    generated_at: str
    session_count: int
    command_count: int
    user_count: int
    high_risk_sessions: int
    medium_risk_sessions: int
    low_risk_sessions: int
    top_commands: list[CommandFrequency] = field(default_factory=list)
    top_users: list[UserRiskScore] = field(default_factory=list)
    risky_sessions: list[RiskySessionRecord] = field(default_factory=list)
    daily_summaries: list[DailySummary] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


class AuditReportService:
    def __init__(self, session_query_service: SessionQueryService):
        self._sessions = session_query_service
        self._analytics = AnalyticsQueryService(session_query_service)

    def build_report(self, start_date: date, end_date: date) -> AuditReport:
        sessions = self._analytics.list_sessions_between(start_date, end_date, limit=10000)
        users = sorted({session.username or "unknown" for session in sessions})
        command_counter: dict[str, int] = {}
        high_risk = medium_risk = low_risk = 0
        risky_sessions: list[RiskySessionRecord] = []

        for session in sessions:
            session_id = session.session_id or session.unique_id
            commands = self._sessions.get_command_evidence(session_id)
            findings = [finding for cmd in commands for finding in cmd.risk_findings]
            summary = aggregate_session_risks(findings)

            if summary.overall_severity == "HIGH":
                high_risk += 1
            elif summary.overall_severity == "MEDIUM":
                medium_risk += 1
            elif summary.overall_severity == "LOW":
                low_risk += 1

            for item in commands:
                if item.command:
                    command_counter[item.command.strip()] = command_counter.get(item.command.strip(), 0) + 1

            if summary.overall_severity in {"HIGH", "MEDIUM"}:
                risky_commands = [
                    item.command
                    for item in commands
                    if item.risk_findings and item.command
                ]
                risky_sessions.append(
                    RiskySessionRecord(
                        session_id=session_id,
                        username=session.username,
                        started_at=session.started_at.isoformat() if session.started_at else None,
                        overall_severity=summary.overall_severity,
                        risky_commands=risky_commands[:10],
                    )
                )

        top_commands = [
            CommandFrequency(command=command, count=count)
            for command, count in sorted(command_counter.items(), key=lambda item: (-item[1], item[0]))[:10]
        ]
        top_users = self._analytics.rank_users_by_risk(start_date, end_date, limit=5)

        daily_summaries: list[DailySummary] = []
        cursor = start_date
        while cursor <= end_date:
            daily_summaries.append(self._analytics.build_daily_summary(cursor))
            cursor = date.fromordinal(cursor.toordinal() + 1)

        period_label = (
            start_date.isoformat()
            if start_date == end_date
            else f"{start_date.isoformat()} to {end_date.isoformat()}"
        )
        findings = self._build_findings(
            period_label=period_label,
            session_count=len(sessions),
            high_risk=high_risk,
            medium_risk=medium_risk,
            top_users=top_users,
            risky_sessions=risky_sessions,
        )

        return AuditReport(
            title=f"SSH Security Audit Report — {period_label}",
            period_start=start_date.isoformat(),
            period_end=end_date.isoformat(),
            generated_at=datetime.now(timezone.utc).isoformat(),
            session_count=len(sessions),
            command_count=sum(command_counter.values()),
            user_count=len(users),
            high_risk_sessions=high_risk,
            medium_risk_sessions=medium_risk,
            low_risk_sessions=low_risk,
            top_commands=top_commands,
            top_users=top_users,
            risky_sessions=risky_sessions,
            daily_summaries=daily_summaries,
            findings=findings,
        )

    def format_markdown(self, report: AuditReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            f"Generated: {report.generated_at}",
            f"Period: {report.period_start} to {report.period_end}",
            "",
            "## Executive Summary",
            f"- Sessions: {report.session_count}",
            f"- Users: {report.user_count}",
            f"- Commands: {report.command_count}",
            f"- HIGH-risk sessions: {report.high_risk_sessions}",
            f"- MEDIUM-risk sessions: {report.medium_risk_sessions}",
            f"- LOW-risk sessions: {report.low_risk_sessions}",
            "",
            "## Key Findings",
        ]
        if report.findings:
            lines.extend(f"- {finding}" for finding in report.findings)
        else:
            lines.append("- No notable security findings for this period.")

        if report.top_users:
            lines.extend(["", "## Top Users by Risk Score"])
            for index, user in enumerate(report.top_users, start=1):
                lines.append(
                    f"{index}. `{user.username}` — score {user.score} "
                    f"({user.high_findings} HIGH, {user.medium_findings} MEDIUM)"
                )

        if report.top_commands:
            lines.extend(["", "## Most Executed Commands"])
            for index, item in enumerate(report.top_commands, start=1):
                lines.append(f"{index}. `{item.command}` — {item.count}")

        if report.risky_sessions:
            lines.extend(["", "## Risky Sessions"])
            for index, session in enumerate(report.risky_sessions[:10], start=1):
                commands = ", ".join(f"`{cmd}`" for cmd in session.risky_commands[:5]) or "none"
                lines.append(
                    f"{index}. `{session.session_id}` | {session.username or 'unknown'} | "
                    f"{session.overall_severity} | risky commands: {commands}"
                )

        return "\n".join(lines)

    def format_json(self, report: AuditReport) -> dict:
        return asdict(report)

    def _build_findings(
        self,
        *,
        period_label: str,
        session_count: int,
        high_risk: int,
        medium_risk: int,
        top_users: list[UserRiskScore],
        risky_sessions: list[RiskySessionRecord],
    ) -> list[str]:
        findings: list[str] = []
        if session_count == 0:
            findings.append(f"No SSH sessions were recorded during {period_label}.")
            return findings

        if high_risk:
            findings.append(f"{high_risk} HIGH-risk session(s) detected during {period_label}.")
        if medium_risk:
            findings.append(f"{medium_risk} MEDIUM-risk session(s) detected during {period_label}.")
        if top_users:
            findings.append(
                f"Highest-risk user: `{top_users[0].username}` with score {top_users[0].score}."
            )
        if risky_sessions:
            findings.append(
                f"{len(risky_sessions)} session(s) contained MEDIUM or HIGH risk command activity."
            )
        return findings
