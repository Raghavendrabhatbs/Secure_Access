from __future__ import annotations

from dataclasses import dataclass

from shared.risk.classifier import RiskFinding


@dataclass(frozen=True)
class SessionRiskSummary:
    """Aggregated risk summary for an entire SSH session."""
    overall_severity: str
    finding_count: int
    high_count: int
    medium_count: int
    low_count: int
    categories: list[str]


def aggregate_session_risks(findings: list[RiskFinding]) -> SessionRiskSummary:
    """
    Deterministically aggregate risk findings into a session-level summary.
    
    Severity calculation:
    - If any HIGH finding exists → overall_severity = HIGH
    - Else if any MEDIUM finding exists → overall_severity = MEDIUM
    - Else if any LOW finding exists → overall_severity = LOW
    - Else → overall_severity = NONE
    
    Args:
        findings: List of RiskFinding objects from all commands in the session
        
    Returns:
        SessionRiskSummary with overall severity, counts, and categories
    """
    if not findings:
        return SessionRiskSummary(
            overall_severity="NONE",
            finding_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            categories=[],
        )

    # Count severity levels
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    # Determine overall severity (deterministic rule)
    if high_count > 0:
        overall_severity = "HIGH"
    elif medium_count > 0:
        overall_severity = "MEDIUM"
    elif low_count > 0:
        overall_severity = "LOW"
    else:
        overall_severity = "NONE"

    # Collect unique categories
    categories = sorted(set(f.category for f in findings))

    return SessionRiskSummary(
        overall_severity=overall_severity,
        finding_count=len(findings),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        categories=categories,
    )
