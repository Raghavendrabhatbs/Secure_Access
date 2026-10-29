from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

from app.services.analytics_query_service import AnalyticsQueryService
from app.services.risk_classifier import classify_command_risks
from app.services.session_query_service import SessionQueryService

OFF_HOURS_START = 22
OFF_HOURS_END = 6
BASELINE_WINDOW_DAYS = 7


@dataclass
class BaselineMetrics:
    window_start: str
    window_end: str
    days_with_data: int
    avg_sessions_per_day: float
    avg_commands_per_day: float
    avg_high_risk_sessions: float
    active_hours: list[int] = field(default_factory=list)
    known_users: list[str] = field(default_factory=list)


@dataclass
class AnomalyFinding:
    rule: str
    severity: str
    description: str
    session_id: str | None = None
    username: str | None = None
    evidence: str = ""


class AnomalyDetectionService:
    def __init__(self, session_query_service: SessionQueryService):
        self._sessions = session_query_service
        self._analytics = AnalyticsQueryService(session_query_service)

    def build_baseline(self, end_date: date, window_days: int = BASELINE_WINDOW_DAYS) -> BaselineMetrics:
        start_date = end_date - timedelta(days=window_days - 1)
        daily_sessions: list[int] = []
        daily_commands: list[int] = []
        daily_high_risk: list[int] = []
        hour_counter: dict[int, int] = {}
        known_users: set[str] = set()

        cursor = start_date
        days_with_data = 0
        while cursor <= end_date:
            summary = self._analytics.build_daily_summary(cursor)
            if summary.session_count > 0:
                days_with_data += 1
            daily_sessions.append(summary.session_count)
            daily_commands.append(summary.command_count)
            daily_high_risk.append(summary.high_risk_sessions)
            for session in self._analytics.list_sessions_between(cursor, cursor, limit=10000):
                known_users.add(session.username or "unknown")
                if session.started_at is not None:
                    hour_counter[session.started_at.hour] = hour_counter.get(session.started_at.hour, 0) + 1
            cursor = date.fromordinal(cursor.toordinal() + 1)

        divisor = max(days_with_data, 1)
        active_hours = [
            hour
            for hour, _count in sorted(hour_counter.items(), key=lambda item: (-item[1], item[0]))[:8]
        ]

        return BaselineMetrics(
            window_start=start_date.isoformat(),
            window_end=end_date.isoformat(),
            days_with_data=days_with_data,
            avg_sessions_per_day=round(sum(daily_sessions) / divisor, 2),
            avg_commands_per_day=round(sum(daily_commands) / divisor, 2),
            avg_high_risk_sessions=round(sum(daily_high_risk) / divisor, 2),
            active_hours=active_hours,
            known_users=sorted(known_users),
        )

    def detect_anomalies(
        self,
        target_date: date,
        baseline: BaselineMetrics | None = None,
    ) -> list[AnomalyFinding]:
        if baseline is None:
            baseline = self.build_baseline(target_date - timedelta(days=1))

        findings: list[AnomalyFinding] = []
        summary = self._analytics.build_daily_summary(target_date)
        sessions = self._analytics.list_sessions_between(target_date, target_date, limit=10000)

        if summary.session_count == 0:
            return findings

        if baseline.avg_sessions_per_day and summary.session_count > max(
            baseline.avg_sessions_per_day * 2, baseline.avg_sessions_per_day + 2
        ):
            findings.append(
                AnomalyFinding(
                    rule="SESSION_VOLUME_SPIKE",
                    severity="MEDIUM",
                    description=(
                        f"Session volume on {target_date.isoformat()} "
                        f"({summary.session_count}) exceeds the baseline average "
                        f"({baseline.avg_sessions_per_day})."
                    ),
                    evidence=f"{summary.session_count} sessions vs baseline {baseline.avg_sessions_per_day}",
                )
            )

        if baseline.avg_commands_per_day and summary.command_count > max(
            baseline.avg_commands_per_day * 2, baseline.avg_commands_per_day + 3
        ):
            findings.append(
                AnomalyFinding(
                    rule="COMMAND_VOLUME_SPIKE",
                    severity="MEDIUM",
                    description=(
                        f"Command volume on {target_date.isoformat()} "
                        f"({summary.command_count}) exceeds the baseline average "
                        f"({baseline.avg_commands_per_day})."
                    ),
                    evidence=f"{summary.command_count} commands vs baseline {baseline.avg_commands_per_day}",
                )
            )

        if summary.high_risk_sessions > max(baseline.avg_high_risk_sessions + 1, 1):
            findings.append(
                AnomalyFinding(
                    rule="HIGH_RISK_SPIKE",
                    severity="HIGH",
                    description=(
                        f"HIGH-risk session count on {target_date.isoformat()} "
                        f"({summary.high_risk_sessions}) exceeds baseline "
                        f"({baseline.avg_high_risk_sessions})."
                    ),
                    evidence=f"{summary.high_risk_sessions} HIGH-risk sessions",
                )
            )

        baseline_users = set(baseline.known_users)
        for session in sessions:
            session_id = session.session_id or session.unique_id
            username = session.username or "unknown"
            started = session.started_at
            if started is not None:
                hour = started.hour
                is_off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
                in_active_hours = bool(baseline.active_hours) and hour not in baseline.active_hours
                if is_off_hours or in_active_hours:
                    findings.append(
                        AnomalyFinding(
                            rule="OFF_HOURS_ACCESS",
                            severity="MEDIUM",
                            description=(
                                f"Session by `{username}` started at {started.isoformat()} "
                                f"outside typical activity hours."
                            ),
                            session_id=session_id,
                            username=username,
                            evidence=f"Hour {hour:02d}:00 UTC",
                        )
                    )

            commands = self._sessions.get_command_evidence(session_id)
            ran_sudo = False
            for item in commands:
                command_text = item.command or ""
                for risk in classify_command_risks(command_text):
                    if risk.rule in {"RM_RF", "HISTORY_CLEAR"}:
                        findings.append(
                            AnomalyFinding(
                                rule="DESTRUCTIVE_COMMAND",
                                severity="HIGH",
                                description=(
                                    f"Destructive or anti-forensics command `{command_text}` "
                                    f"was executed by `{username}`."
                                ),
                                session_id=session_id,
                                username=username,
                                evidence=f"{risk.category} / {risk.severity}",
                            )
                        )
                    if risk.category == "PRIVILEGE_ESCALATION":
                        ran_sudo = True

            if ran_sudo and username not in baseline_users:
                findings.append(
                    AnomalyFinding(
                        rule="NEW_USER_SUDO",
                        severity="HIGH",
                        description=(
                            f"User `{username}` ran privilege-escalation commands but was not "
                            f"seen in the baseline window ({baseline.window_start} to {baseline.window_end})."
                        ),
                        session_id=session_id,
                        username=username,
                        evidence="PRIVILEGE_ESCALATION",
                    )
                )

        return self._dedupe_findings(findings)

    def compare_to_baseline(self, target_date: date, baseline: BaselineMetrics | None = None) -> dict:
        if baseline is None:
            baseline = self.build_baseline(target_date - timedelta(days=1))
        summary = self._analytics.build_daily_summary(target_date)
        return {
            "target_date": target_date.isoformat(),
            "baseline_window": f"{baseline.window_start} to {baseline.window_end}",
            "sessions": {
                "actual": summary.session_count,
                "baseline_avg": baseline.avg_sessions_per_day,
            },
            "commands": {
                "actual": summary.command_count,
                "baseline_avg": baseline.avg_commands_per_day,
            },
            "high_risk_sessions": {
                "actual": summary.high_risk_sessions,
                "baseline_avg": baseline.avg_high_risk_sessions,
            },
            "anomalies": [
                {
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "description": finding.description,
                    "session_id": finding.session_id,
                    "username": finding.username,
                    "evidence": finding.evidence,
                }
                for finding in self.detect_anomalies(target_date, baseline)
            ],
        }

    def _dedupe_findings(self, findings: list[AnomalyFinding]) -> list[AnomalyFinding]:
        seen: set[tuple[str, str | None, str | None]] = set()
        unique: list[AnomalyFinding] = []
        for finding in findings:
            key = (finding.rule, finding.session_id, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
