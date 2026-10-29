from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

from app.services.risk_aggregator import aggregate_session_risks
from app.services.session_query_service import SessionCommandEvidence, SessionQueryService
from app.services.query_understanding_service import configured_timezone, configured_today
from shared.models.session import Session as SessionModel

SEVERITY_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class UserLoginRecord:
    username: str
    session_id: str
    started_at: datetime | None
    ended_at: datetime | None


@dataclass
class CommandFrequency:
    command: str
    count: int


@dataclass
class DailySummary:
    date_label: str
    session_count: int
    users: list[str] = field(default_factory=list)
    command_count: int = 0
    high_risk_sessions: int = 0
    medium_risk_sessions: int = 0
    low_risk_sessions: int = 0
    top_commands: list[CommandFrequency] = field(default_factory=list)
    risky_commands: list[str] = field(default_factory=list)


@dataclass
class UserRiskScore:
    username: str
    score: int
    high_findings: int
    medium_findings: int
    low_findings: int
    session_count: int


@dataclass
class RiskFindingRecord:
    category: str
    severity: str
    command: str
    executed_at: datetime | None
    session_id: str
    username: str | None


@dataclass
class DailyComparison:
    date_a: str
    date_b: str
    summary_a: DailySummary
    summary_b: DailySummary


class AnalyticsQueryService:
    def __init__(self, session_query_service: SessionQueryService):
        self._sessions = session_query_service

    @staticmethod
    def _unique_sessions(sessions: list[SessionModel]) -> list[SessionModel]:
        unique: list[SessionModel] = []
        positions: dict[str, int] = {}
        for session in sessions:
            logical_id = session.session_id or session.unique_id
            existing_position = positions.get(logical_id)
            if existing_position is not None:
                existing = unique[existing_position]
                if existing.ended_at is not None and session.ended_at is None:
                    unique[existing_position] = session
                continue
            positions[logical_id] = len(unique)
            unique.append(session)
        return unique

    def count_sessions_between(self, start_date: date, end_date: date) -> int:
        return self._sessions.count_sessions_started_between(start_date, end_date)

    def list_sessions_between(self, start_date: date, end_date: date, limit: int = 100) -> list[SessionModel]:
        return self._sessions.list_sessions_started_between(start_date, end_date, limit=limit)

    def list_user_sessions(self, username: str, limit: int = 10000) -> list[SessionModel]:
        normalized_username = (username or "").strip().lower()
        return self._unique_sessions([
            session
            for session in self._sessions.list_sessions(limit=limit)
            if (session.username or "").strip().lower() == normalized_username
        ])

    def list_user_sessions_between(
        self,
        username: str,
        start_date: date,
        end_date: date,
        limit: int = 10000,
    ) -> list[SessionModel]:
        normalized_username = (username or "").strip().lower()
        return self._unique_sessions([
            session
            for session in self.list_sessions_between(start_date, end_date, limit=limit)
            if (session.username or "").strip().lower() == normalized_username
        ])

    def session_counts_by_user(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for session in self._unique_sessions(self._sessions.list_sessions(limit=10000)):
            counts[(session.username or "unknown").strip() or "unknown"] += 1
        return dict(counts)

    def latest_user_login(self) -> SessionModel | None:
        sessions = self._unique_sessions(self._sessions.list_sessions(limit=10000))
        sessions = [
            session
            for session in sessions
            if session.started_at is not None or session.login_time is not None
        ]
        return max(
            sessions,
            key=lambda session: (session.started_at or session.login_time).isoformat(),
            default=None,
        )

    def sessions_with_risk_category(self, category: str) -> list[SessionModel]:
        normalized_category = (category or "").strip().upper()
        matches: list[SessionModel] = []
        for session in self._unique_sessions(self._sessions.list_sessions(limit=10000)):
            session_id = session.session_id or session.unique_id
            commands = self._sessions.get_command_evidence(session_id)
            if any(
                finding.category == normalized_category
                for command in commands
                for finding in command.risk_findings
            ):
                matches.append(session)
        return matches

    def highest_risk_session(self) -> tuple[SessionModel, object] | None:
        ranked: list[tuple[SessionModel, object]] = []
        severity_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        for session in self._unique_sessions(self._sessions.list_sessions(limit=10000)):
            session_id = session.session_id or session.unique_id
            commands = self._sessions.get_command_evidence(session_id)
            findings = [finding for command in commands for finding in command.risk_findings]
            summary = aggregate_session_risks(findings)
            if summary.finding_count:
                ranked.append((session, summary))
        if not ranked:
            return None
        return max(
            ranked,
            key=lambda item: (
                severity_score[item[1].overall_severity],
                item[1].finding_count,
                item[1].high_count,
                item[1].medium_count,
            ),
        )

    def session_status_counts(self) -> tuple[int, int]:
        sessions = self._unique_sessions(self._sessions.list_sessions(limit=10000))
        active = sum(
            1
            for session in sessions
            if session.ended_at is None
            and session.logout_time is None
            and (session.started_at is not None or session.login_time is not None)
        )
        return active, len(sessions) - active

    def busiest_date(self) -> tuple[date, int] | None:
        counts: Counter[date] = Counter()
        for session in self._unique_sessions(self._sessions.list_sessions(limit=10000)):
            timestamp = session.started_at or session.login_time
            if timestamp is not None:
                counts[timestamp.astimezone(configured_timezone()).date()] += 1
        return counts.most_common(1)[0] if counts else None

    def duration_extreme(self, longest: bool) -> SessionModel | None:
        sessions = self._unique_sessions(self._sessions.list_sessions(limit=10000))
        sessions = [
            session
            for session in sessions
            if self._duration_seconds(session) is not None
            and self._has_recorded_commands(session)
        ]
        if not longest:
            sessions = [session for session in sessions if (self._duration_seconds(session) or 0) > 0]
        if not sessions:
            return None
        return max(sessions, key=lambda session: self._duration_seconds(session) or 0) if longest else min(
            sessions, key=lambda session: self._duration_seconds(session) or 0
        )

    def _has_recorded_commands(self, session: SessionModel) -> bool:
        session_id = session.session_id or session.unique_id
        return bool(self._sessions.get_command_evidence(session_id))

    def average_duration_seconds(self) -> float | None:
        durations = [
            self._duration_seconds(session)
            for session in self._unique_sessions(self._sessions.list_sessions(limit=10000))
            if self._duration_seconds(session) is not None
        ]
        return sum(durations) / len(durations) if durations else None

    def all_unique_sessions(self) -> list[SessionModel]:
        return self._unique_sessions(self._sessions.list_sessions(limit=10000))

    def sessions_for_dates(self, start_date: date, end_date: date) -> list[SessionModel]:
        return [
            session
            for session in self.all_unique_sessions()
            if (session.started_at or session.login_time)
            and start_date <= (session.started_at or session.login_time).astimezone(configured_timezone()).date() <= end_date
        ]

    def command_count(self, session: SessionModel) -> int:
        return len(self._sessions.get_command_evidence(session.session_id or session.unique_id))

    def format_duration(self, session: SessionModel) -> str | None:
        seconds = self._duration_seconds(session)
        if seconds is None:
            return None
        total_seconds = int(round(seconds))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds_remainder = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds_remainder}s"
        if minutes:
            return f"{minutes}m {seconds_remainder}s"
        return f"{seconds_remainder}s"

    @staticmethod
    def _duration_seconds(session: SessionModel) -> float | None:
        if session.duration_seconds is not None:
            return float(session.duration_seconds)
        started = session.started_at or session.login_time
        ended = session.ended_at or session.logout_time
        if started is None or ended is None:
            return None
        return max((ended - started).total_seconds(), 0.0)

    def last_n_users(self, limit: int = 5) -> list[UserLoginRecord]:
        sessions = self._sessions.list_sessions(limit=max(limit * 5, limit))
        records: list[UserLoginRecord] = []
        seen_users: set[str] = set()

        for session in sessions:
            username = (session.username or "unknown").strip()
            if username in seen_users:
                continue
            seen_users.add(username)
            records.append(
                UserLoginRecord(
                    username=username,
                    session_id=session.session_id or session.unique_id,
                    started_at=session.started_at,
                    ended_at=session.ended_at,
                )
            )
            if len(records) >= limit:
                break
        return records

    def sessions_in_last_hours(self, hours: float = 1.0) -> list[SessionModel]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        sessions = self._sessions.list_sessions(limit=10000)
        return [
            session
            for session in sessions
            if session.started_at is not None and session.started_at >= cutoff
        ]

    def command_frequency_between(
        self,
        start_date: date,
        end_date: date,
        limit: int = 10,
    ) -> list[CommandFrequency]:
        counter: Counter[str] = Counter()
        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                if item.command:
                    counter[item.command.strip()] += 1
        return [
            CommandFrequency(command=command, count=count)
            for command, count in counter.most_common(limit)
        ]

    def command_frequency_all(self, limit: int = 50) -> list[CommandFrequency]:
        counter: Counter[str] = Counter()
        for session in self._sessions.list_sessions(limit=10000):
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                if item.command:
                    counter[item.command.strip()] += 1
        return [
            CommandFrequency(command=command, count=count)
            for command, count in counter.most_common(limit)
        ]

    def most_frequent_user_between(self, start_date: date, end_date: date) -> tuple[str, int] | None:
        counter: Counter[str] = Counter()
        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            counter[session.username or "unknown"] += 1
        if not counter:
            return None
        username, count = counter.most_common(1)[0]
        return username, count

    def count_sessions_by_risk_between(
        self,
        start_date: date,
        end_date: date,
        severity: str,
    ) -> int:
        return len(self._risk_sessions_between(start_date, end_date, severity))

    def high_risk_percentage_between(self, start_date: date, end_date: date) -> tuple[int, int, float]:
        sessions = self.list_sessions_between(start_date, end_date, limit=10000)
        if not sessions:
            return 0, 0, 0.0
        high_risk = len(self._risk_sessions_between(start_date, end_date, "HIGH"))
        total = len(sessions)
        return high_risk, total, round((high_risk / total) * 100, 1)

    def busiest_hour_between(self, start_date: date, end_date: date) -> tuple[int, int] | None:
        counter: Counter[int] = Counter()
        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            if session.started_at is None:
                continue
            counter[session.started_at.hour] += 1
        if not counter:
            return None
        hour, count = counter.most_common(1)[0]
        return hour, count

    def build_daily_summary(self, target_date: date) -> DailySummary:
        sessions = self.list_sessions_between(target_date, target_date, limit=10000)
        users = sorted({session.username or "unknown" for session in sessions})
        command_counter: Counter[str] = Counter()
        risky_commands: list[str] = []
        high_risk = medium_risk = low_risk = 0

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
                if not item.command:
                    continue
                command_counter[item.command.strip()] += 1
                if item.risk_findings and item.command not in risky_commands:
                    risky_commands.append(item.command)

        return DailySummary(
            date_label=target_date.isoformat(),
            session_count=len(sessions),
            users=users,
            command_count=sum(command_counter.values()),
            high_risk_sessions=high_risk,
            medium_risk_sessions=medium_risk,
            low_risk_sessions=low_risk,
            top_commands=[
                CommandFrequency(command=command, count=count)
                for command, count in command_counter.most_common(5)
            ],
            risky_commands=risky_commands[:10],
        )

    def find_command_usages_between(
        self,
        command_term: str,
        start_date: date,
        end_date: date,
        username: str | None = None,
    ) -> list[tuple[SessionModel, SessionCommandEvidence]]:
        normalized_term = (command_term or "").strip().lower()
        results: list[tuple[SessionModel, SessionCommandEvidence]] = []

        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            if username and (session.username or "").lower() != username.lower():
                continue
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                if normalized_term in (item.command or "").lower():
                    results.append((session, item))
        return results

    def find_command_usages_recent(
        self,
        command_term: str,
        username: str | None = None,
        limit: int = 20,
    ) -> list[tuple[SessionModel, SessionCommandEvidence]]:
        normalized_term = (command_term or "").strip().lower()
        exact_results: list[tuple[SessionModel, SessionCommandEvidence]] = []
        partial_results: list[tuple[SessionModel, SessionCommandEvidence]] = []

        for session in self._sessions.list_sessions(limit=10000):
            if username and (session.username or "").lower() != username.lower():
                continue
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                command_text = (item.command or "").strip().lower()
                if command_text == normalized_term:
                    exact_results.append((session, item))
                elif normalized_term in command_text:
                    partial_results.append((session, item))

        results = exact_results or partial_results

        results.sort(
            key=lambda pair: pair[1].executed_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return self._dedupe_command_usages(results)[:limit]

    def _dedupe_command_usages(
        self,
        usages: list[tuple[SessionModel, SessionCommandEvidence]],
    ) -> list[tuple[SessionModel, SessionCommandEvidence]]:
        seen: set[tuple[str, str | None, str]] = set()
        unique: list[tuple[SessionModel, SessionCommandEvidence]] = []
        for session, item in usages:
            session_id = session.session_id or session.unique_id
            executed_at = item.executed_at.isoformat() if item.executed_at else None
            command_text = (item.command or "").strip().lower()
            key = (session_id, executed_at, command_text)
            if key in seen:
                continue
            seen.add(key)
            unique.append((session, item))
        return unique

    def format_session_timing(self, session: SessionModel) -> str:
        started = session.started_at or session.login_time
        ended = session.ended_at or session.logout_time
        started_label = started.isoformat() if started else "unknown"
        ended_label = ended.isoformat() if ended else "unknown"
        duration_label = session.duration
        if not duration_label and session.duration_seconds is not None:
            duration_label = f"{int(session.duration_seconds)}s"
        if not duration_label and started and ended:
            duration_label = str(ended - started)
        parts = [f"Login/start: {started_label}", f"Logout/end: {ended_label}"]
        if duration_label:
            parts.append(f"Duration: {duration_label}")
        return "; ".join(parts)

    def first_command(self, session_id: str) -> SessionCommandEvidence | None:
        commands = self._sessions.get_command_evidence(session_id)
        return commands[0] if commands else None

    def last_command(self, session_id: str) -> SessionCommandEvidence | None:
        commands = self._sessions.get_command_evidence(session_id)
        return commands[-1] if commands else None

    def first_command_after_login(self, session_id: str) -> SessionCommandEvidence | None:
        return self.first_command(session_id)

    def sessions_in_hour_window(
        self,
        target_date: date,
        start_hour: int,
        end_hour: int,
    ) -> list[SessionModel]:
        sessions = self.list_sessions_between(target_date, target_date, limit=10000)
        matched: list[SessionModel] = []
        for session in sessions:
            started = session.started_at
            if started is None:
                continue
            if started.astimezone(configured_timezone()).date() != target_date:
                continue
            if start_hour <= started.hour <= end_hour:
                matched.append(session)
        return matched

    def commands_in_hour_window(
        self,
        target_date: date,
        start_hour: int,
        end_hour: int,
    ) -> list[tuple[SessionModel, SessionCommandEvidence]]:
        results: list[tuple[SessionModel, SessionCommandEvidence]] = []
        for session in self.list_sessions_between(target_date, target_date, limit=10000):
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                executed_at = item.executed_at
                if executed_at is None:
                    continue
                if executed_at.astimezone(configured_timezone()).date() != target_date:
                    continue
                if start_hour <= executed_at.hour <= end_hour:
                    results.append((session, item))
        results.sort(
            key=lambda pair: pair[1].executed_at or datetime.min.replace(tzinfo=timezone.utc)
        )
        return results

    def first_risk_finding_on_date(
        self,
        target_date: date,
        category: str,
    ) -> RiskFindingRecord | None:
        normalized_category = (category or "").strip().upper()
        if not normalized_category:
            return None

        earliest: RiskFindingRecord | None = None
        for session in self.list_sessions_between(target_date, target_date, limit=10000):
            session_id = session.session_id or session.unique_id
            for item in self._sessions.get_command_evidence(session_id):
                for finding in item.risk_findings:
                    if finding.category != normalized_category:
                        continue
                    record = RiskFindingRecord(
                        category=finding.category,
                        severity=finding.severity,
                        command=item.command or "",
                        executed_at=item.executed_at,
                        session_id=session_id,
                        username=session.username,
                    )
                    if earliest is None:
                        earliest = record
                        continue
                    if record.executed_at and earliest.executed_at:
                        if record.executed_at < earliest.executed_at:
                            earliest = record
                    elif record.executed_at and not earliest.executed_at:
                        earliest = record
        return earliest

    def rank_users_by_risk(
        self,
        start_date: date,
        end_date: date,
        limit: int = 10,
    ) -> list[UserRiskScore]:
        scores: dict[str, UserRiskScore] = {}
        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            username = (session.username or "unknown").strip()
            session_id = session.session_id or session.unique_id
            if username not in scores:
                scores[username] = UserRiskScore(
                    username=username,
                    score=0,
                    high_findings=0,
                    medium_findings=0,
                    low_findings=0,
                    session_count=0,
                )
            entry = scores[username]
            entry.session_count += 1
            for item in self._sessions.get_command_evidence(session_id):
                for finding in item.risk_findings:
                    entry.score += SEVERITY_SCORE.get(finding.severity, 0)
                    if finding.severity == "HIGH":
                        entry.high_findings += 1
                    elif finding.severity == "MEDIUM":
                        entry.medium_findings += 1
                    elif finding.severity == "LOW":
                        entry.low_findings += 1

        ranked = sorted(
            scores.values(),
            key=lambda item: (-item.score, -item.high_findings, item.username),
        )
        return [item for item in ranked if item.score > 0][:limit]

    def compare_daily_summaries(self, date_a: date, date_b: date) -> DailyComparison:
        return DailyComparison(
            date_a=date_a.isoformat(),
            date_b=date_b.isoformat(),
            summary_a=self.build_daily_summary(date_a),
            summary_b=self.build_daily_summary(date_b),
        )

    def _risk_sessions_between(self, start_date: date, end_date: date, severity: str) -> list[SessionModel]:
        normalized = severity.strip().upper()
        matched: list[SessionModel] = []
        for session in self.list_sessions_between(start_date, end_date, limit=10000):
            session_id = session.session_id or session.unique_id
            commands = self._sessions.get_command_evidence(session_id)
            findings = [finding for cmd in commands for finding in cmd.risk_findings]
            summary = aggregate_session_risks(findings)
            if summary.overall_severity == normalized:
                matched.append(session)
        return matched
