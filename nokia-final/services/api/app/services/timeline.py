from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Sequence

from app.services.risk_classifier import RiskFinding


@dataclass(frozen=True, order=True)
class TimelineEntry:
    """Normalized chronological timeline item for SSH evidence."""

    _timestamp_sort: str = field(init=False, repr=False, compare=True)
    _sequence_sort: int = field(init=False, repr=False, compare=True)

    timestamp: str | None = field(compare=False)
    sequence_number: int | None = field(compare=False)
    event_type: str = field(compare=False)
    command: str = field(compare=False)
    output: str = field(default="", compare=False)
    risk_findings: tuple[RiskFinding, ...] = field(default_factory=tuple, compare=False)

    def __post_init__(self) -> None:
        # Keep original timestamp value for evidence fidelity; use dedicated sort fields.
        timestamp_sort = "" if self.timestamp is None else str(self.timestamp)
        object.__setattr__(self, "_timestamp_sort", timestamp_sort)

        sequence = self.sequence_number if isinstance(self.sequence_number, int) else 10**9
        object.__setattr__(self, "_sequence_sort", sequence)

        normalized_event_type = str(self.event_type or "").strip()
        normalized_command = str(self.command or "").strip()
        normalized_output = "" if self.output is None else str(self.output)

        object.__setattr__(self, "event_type", normalized_event_type)
        object.__setattr__(self, "command", normalized_command)
        object.__setattr__(self, "output", normalized_output)

        findings = tuple(self.risk_findings or ())
        object.__setattr__(self, "risk_findings", findings)


def sort_timeline_entries(entries: Sequence[TimelineEntry] | None) -> list[TimelineEntry]:
    """Return a deterministic chronological ordering of timeline entries."""
    return sorted(entries or [])
