from __future__ import annotations

from typing import Any

from app.services.evidence_retrieval_service import RetrievedEvidence
from app.services.risk_aggregator import aggregate_session_risks
from app.services.ssh_knowledge_service import SSHKnowledgeService


class EvidenceContextService:
    def build_context(self, retrieved: RetrievedEvidence) -> dict[str, Any]:
        plan = retrieved.plan
        start_date = plan.date_range[0].isoformat() if plan.date_range else None
        end_date = plan.date_range[1].isoformat() if plan.date_range else None

        sessions = []
        all_findings = []
        command_count = 0
        risk_command_only = self._is_risky_command_question(plan.question)
        knowledge = SSHKnowledgeService()

        for session in retrieved.sessions:
            session_identifier = session.session_id or session.unique_id
            commands = retrieved.commands_by_session.get(session_identifier, [])
            events = retrieved.events_by_session.get(session_identifier, [])
            included_commands = self._select_commands(commands, risk_command_only)
            if plan.risk_categories:
                included_commands = self._filter_commands_by_categories(included_commands, plan.risk_categories)
            if risk_command_only and not included_commands:
                continue
            command_count += len(included_commands)

            findings = [
                {
                    "session_id": session_identifier,
                    "sequence_number": command.sequence_number,
                    "command": command.command,
                    "category": finding.category,
                    "severity": finding.severity,
                    "rule": finding.rule,
                }
                for command in included_commands
                for finding in self._findings_for_command(command, plan.risk_categories)
            ]
            all_findings.extend(findings)
            risk_summary = aggregate_session_risks(
                [
                    finding
                    for command in included_commands
                    for finding in self._findings_for_command(command, plan.risk_categories)
                ]
            )

            if risk_command_only:
                sessions.append(
                    {
                        "session_id": session_identifier,
                        "username": session.username,
                        "started_at": session.started_at,
                        "ended_at": session.ended_at,
                        "risk": session.risk or risk_summary.overall_severity,
                        "commands": [
                            {
                                "sequence_number": command.sequence_number,
                                "command": command.command,
                                "description": knowledge.lookup(command.command.split()[0] if command.command else None),
                                "executed_at": command.executed_at,
                                "output": self._compact_output(command.output),
                                "risk_findings": [
                                    {
                                        "category": finding.category,
                                        "severity": finding.severity,
                                    }
                                    for finding in self._findings_for_command(command, plan.risk_categories)
                                ],
                            }
                            for command in included_commands[:20]
                        ],
                    }
                )
                continue

            sessions.append(
                {
                    "session_id": session_identifier,
                    "username": session.username,
                    "protocol": session.protocol,
                    "target": session.target,
                    "remote_address": session.remote_address,
                    "started_at": session.started_at,
                    "ended_at": session.ended_at,
                    "risk": session.risk or risk_summary.overall_severity,
                    "command_count": len(commands),
                    "event_count": len(events),
                    "commands": [
                        {
                            "sequence_number": command.sequence_number,
                            "command": command.command,
                            "description": knowledge.lookup(command.command.split()[0] if command.command else None),
                            "output": self._compact_output(command.output),
                            "executed_at": command.executed_at,
                            "risk_findings": [
                                {
                                    "category": finding.category,
                                    "severity": finding.severity,
                                    "rule": finding.rule,
                                }
                                for finding in self._findings_for_command(command, plan.risk_categories)
                            ],
                        }
                                for command in included_commands[:20]
                    ],
                    "events": [
                        {
                            "event_type": event.event_type,
                            "timestamp": event.timestamp,
                            "severity": event.severity,
                            "message": event.message,
                        }
                        for event in events[:20]
                    ],
                    "risk_summary": {
                        "overall_severity": risk_summary.overall_severity,
                        "finding_count": risk_summary.finding_count,
                        "high_count": risk_summary.high_count,
                        "medium_count": risk_summary.medium_count,
                        "low_count": risk_summary.low_count,
                        "categories": risk_summary.categories,
                    },
                }
            )

        return {
            "intent": "GROUNDED_ANALYSIS",
            "question": plan.question,
            "query_scope": {
                "date_from": start_date,
                "date_to": end_date,
                "users": plan.users,
                "session_id": plan.session_id,
                "scope": plan.scope,
                "risk_domain": plan.risk_domain_query or bool(plan.risk_categories or plan.risk_severity),
                "needs": sorted(plan.needs),
                "analysis": plan.analysis,
            },
            "summary": {
                "session_count": len(sessions),
                "command_count": command_count,
                "risk_finding_count": len(all_findings),
                "risk_categories": sorted({finding["category"] for finding in all_findings}),
            },
            "sessions": sessions,
            "findings": all_findings,
        }

    def _compact_output(self, output: str | None, limit: int = 300) -> str | None:
        if output is None:
            return None
        compacted = output.strip()
        if len(compacted) <= limit:
            return compacted
        return compacted[:limit].rstrip() + "..."

    def _is_risky_command_question(self, question: str) -> bool:
        question_lower = (question or "").lower()
        return any(
            phrase in question_lower
            for phrase in (
                "risky command",
                "risky commands",
                "dangerous command",
                "dangerous commands",
                "which commands were risky",
                "what commands were risky",
                "suspicious activity",
                "dangerous activity",
                "risky session",
                "risky sessions",
                "risk session",
                "risk sessions",
                "risk findings",
                "high risk",
                "high-risk",
            )
        )

    def _select_commands(self, commands: list[Any], risk_command_only: bool) -> list[Any]:
        if not risk_command_only:
            return commands
        return [
            command
            for command in commands
            if getattr(command, "risk_findings", [])
        ]

    def _filter_commands_by_categories(self, commands: list[Any], risk_categories: list[str]) -> list[Any]:
        category_set = {category.upper() for category in risk_categories}
        return [
            command
            for command in commands
            if any(
                finding.category in category_set
                for finding in getattr(command, "risk_findings", [])
            )
        ]

    def _findings_for_command(self, command: Any, risk_categories: list[str]) -> list[Any]:
        findings = list(getattr(command, "risk_findings", []) or [])
        if not risk_categories:
            return findings
        category_set = {category.upper() for category in risk_categories}
        return [finding for finding in findings if finding.category in category_set]