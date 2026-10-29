from __future__ import annotations

import json
import re
from datetime import date, timedelta
from typing import Any

from app.services.anomaly_detection_service import AnomalyDetectionService
from app.services.audit_report_service import AuditReportService
from app.services.query_understanding_service import (
    classify_current_datetime_question,
    configured_timezone,
    configured_today,
    extract_date_range,
    format_current_datetime_answer,
    is_current_datetime_question,
)
from app.services.ssh_knowledge_service import SSHKnowledgeService
from app.services.session_query_service import SessionQueryService

SESSION_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


class Phase3QueryService:
    """Deterministic handlers for Phase 3 audit export, anomaly detection, and knowledge."""

    def __init__(self, session_query_service: SessionQueryService):
        self._sessions = session_query_service
        self._audit = AuditReportService(session_query_service)
        self._anomaly = AnomalyDetectionService(session_query_service)
        self._knowledge = SSHKnowledgeService()

    def try_answer(self, question: str, session_id: str | None = None) -> dict[str, Any] | None:
        question_text = (question or "").strip()
        if not question_text:
            return None

        question_lower = question_text.lower()
        date_range = extract_date_range(question_text)

        handlers = (
            self._try_current_datetime,
            self._try_export_audit_report,
            self._try_list_anomalies,
            self._try_baseline_comparison,
            self._try_weekly_audit_report,
            self._try_ssh_knowledge,
        )

        for handler in handlers:
            result = handler(
                question_text=question_text,
                question_lower=question_lower,
                session_id=session_id,
                date_range=date_range,
            )
            if result is not None:
                return result
        return None

    def _try_current_datetime(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not is_current_datetime_question(question_text):
            return None
        kind = classify_current_datetime_question(question_text) or "both"
        summaries = {
            "date": "Answered with the current local date and day.",
            "time": "Answered with the current local time.",
            "both": "Answered with the current local date and time.",
        }
        return self._result(
            format_current_datetime_answer(question_text),
            intent="GENERAL_KNOWLEDGE",
            evidence_available=True,
            evidence_summary=summaries[kind],
        )

    def _try_export_audit_report(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "export audit",
                "generate audit",
                "generate security report",
                "security audit report",
                "audit report for",
                "download audit",
                "full audit",
                "audit export",
            )
        ):
            return None
        if "weekly" in question_lower:
            return None

        if not date_range:
            if "today" in question_lower:
                date_range = (configured_today(), configured_today())
            else:
                return None

        start_date, end_date = date_range
        report = self._audit.build_report(start_date, end_date)
        wants_json = any(term in question_lower for term in ("json", "as json", "export json"))
        if wants_json:
            answer = json.dumps(self._audit.format_json(report), indent=2)
        else:
            answer = self._audit.format_markdown(report)

        return self._result(
            answer,
            intent="AUDIT_EXPORT",
            evidence_available=report.session_count > 0,
            evidence_summary=(
                f"Generated audit report for {report.period_start} to {report.period_end} "
                f"with {report.session_count} session(s)."
            ),
        )

    def _try_weekly_audit_report(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in ("weekly audit", "weekly security report", "this week's audit")
        ):
            return None

        if not date_range:
            date_range = extract_date_range("this week")
        start_date, end_date = date_range or (configured_today(), configured_today())
        report = self._audit.build_report(start_date, end_date)
        answer = self._audit.format_markdown(report)
        return self._result(
            answer,
            intent="AUDIT_EXPORT",
            evidence_available=report.session_count > 0,
            evidence_summary=(
                f"Weekly audit report for {report.period_start} to {report.period_end}."
            ),
        )

    def _try_list_anomalies(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "anomaly",
                "anomalies",
                "anomalous",
                "unusual",
                "abnormal",
                "suspicious pattern",
                "off-hours",
                "off hours",
                "detect anomaly",
            )
        ):
            return None

        target_date = None
        if date_range is not None:
            start_date, end_date = date_range
            if start_date == end_date:
                target_date = start_date
        if target_date is None:
            if "today" in question_lower:
                    target_date = configured_today()
            else:
                latest = self._sessions.list_sessions(limit=1)
                if latest and latest[0].started_at is not None:
                    target_date = latest[0].started_at.astimezone(configured_timezone()).date()

        if target_date is None:
            return self._result(
                "Specify a date to scan for anomalies, for example: "
                "`Detect anomalies on 2026-08-20`.",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary="No target date for anomaly scan.",
            )

        baseline_end = target_date - timedelta(days=1)
        baseline = self._anomaly.build_baseline(baseline_end)
        findings = self._anomaly.detect_anomalies(target_date, baseline)
        label = target_date.isoformat()

        if not findings:
            return self._result(
                f"No anomalies were detected on {label} against the baseline "
                f"({baseline.window_start} to {baseline.window_end}).",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"0 anomalies on {label}.",
            )

        lines = [f"Anomalies detected on {label}:"]
        for index, finding in enumerate(findings, start=1):
            lines.append(f"{index}. [{finding.severity}] {finding.rule}: {finding.description}")
            if finding.evidence:
                lines.append(f"   Evidence: {finding.evidence}")
        return self._result(
            "\n".join(lines),
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Detected {len(findings)} anomalie(s) on {label}.",
        )

    def _try_baseline_comparison(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "baseline",
                "compared to normal",
                "vs last 7 days",
                "versus last 7 days",
                "against baseline",
                "normal activity",
            )
        ):
            return None

        target_date = None
        if date_range is not None:
            start_date, end_date = date_range
            if start_date == end_date:
                target_date = start_date
        if target_date is None:
            if "today" in question_lower:
                target_date = configured_today()
            else:
                return None

        baseline = self._anomaly.build_baseline(target_date - timedelta(days=1))
        comparison = self._anomaly.compare_to_baseline(target_date, baseline)
        lines = [
            f"Baseline comparison for {comparison['target_date']}:",
            f"Baseline window: {comparison['baseline_window']}",
            "",
            (
                f"- Sessions: {comparison['sessions']['actual']} "
                f"(baseline avg {comparison['sessions']['baseline_avg']})"
            ),
            (
                f"- Commands: {comparison['commands']['actual']} "
                f"(baseline avg {comparison['commands']['baseline_avg']})"
            ),
            (
                f"- HIGH-risk sessions: {comparison['high_risk_sessions']['actual']} "
                f"(baseline avg {comparison['high_risk_sessions']['baseline_avg']})"
            ),
        ]
        anomalies = comparison.get("anomalies", [])
        if anomalies:
            lines.extend(["", "Anomalies:"])
            for index, finding in enumerate(anomalies, start=1):
                lines.append(f"{index}. [{finding['severity']}] {finding['description']}")
        else:
            lines.append("")
            lines.append("No anomalies detected against the baseline.")

        has_evidence = (
            comparison["sessions"]["actual"] > 0
            or comparison["commands"]["actual"] > 0
            or bool(anomalies)
        )
        return self._result(
            "\n".join(lines),
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=has_evidence,
            evidence_summary=f"Baseline comparison for {comparison['target_date']}.",
        )

    def _try_ssh_knowledge(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if SESSION_ID_RE.search(question_text):
            return None
        if any(
            term in question_lower
            for term in (
                "session", "postgresql", "warpgate", "risky session",
                "who accessed", "accessed the system", "user activity",
                "logged in", "log in", "logging in",
                "logged out", "log out", "logging out",
                "login", "logout",
            )
        ):
            return None
        # Actor audit questions ("who executed X", "which user ran X") should be answered
        # by the audit handler, not the offline knowledge base.
        if any(
            marker in question_lower
            for marker in (
                "who executed", "who ran", "who used",
                "which user ran", "which user executed", "which user used",
                "what user ran", "what user executed",
                "who has executed", "who has run",
            )
        ):
            return None

        answer = self._knowledge.answer_question(question_text)
        if answer is None:
            return None

        command = self._knowledge.extract_command_from_question(question_text) or "command"
        return self._result(
            answer,
            intent="COMMAND_EXPLANATION",
            evidence_available=True,
            evidence_summary=f"SSH knowledge lookup for `{command}`.",
        )

    def _result(
        self,
        answer: str,
        *,
        intent: str,
        evidence_available: bool,
        evidence_summary: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "answer": answer,
            "intent": intent,
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": evidence_available,
            "evidence_summary": evidence_summary,
        }
