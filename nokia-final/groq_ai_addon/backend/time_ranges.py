from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DATE_PATTERN = re.compile(r"\b(\d{4}-\d{2}-\d{2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})\b")


def local_today(timezone_name: str, now: datetime | None = None) -> date:
    return (now or datetime.now(timezone.utc)).astimezone(_zone(timezone_name)).date()


def date_range_from_question(
    question: str,
    timezone_name: str,
    now: datetime | None = None,
) -> tuple[date, date] | None:
    normalized = (question or "").casefold()
    zone = _zone(timezone_name)
    current = (now or datetime.now(timezone.utc)).astimezone(zone)
    today = current.date()

    if re.search(r"\blast\s+24\s+hours?\b", normalized):
        return (current - timedelta(hours=24)).date(), today
    if re.search(r"\b(?:today|this morning|since midnight)\b", normalized):
        return today, today
    if re.search(r"\b(?:yesterday|previous day)\b", normalized):
        yesterday = today - timedelta(days=1)
        return yesterday, yesterday
    if re.search(r"\bthis week\b", normalized):
        return today - timedelta(days=today.weekday()), today
    if re.search(r"\b(?:last|previous) week\b", normalized):
        start = today - timedelta(days=today.weekday() + 7)
        return start, start + timedelta(days=6)
    if re.search(r"\bthis month\b", normalized):
        return today.replace(day=1), today
    if re.search(r"\b(?:from the )?beginning of (?:this )?month\b", normalized):
        return today.replace(day=1), today
    if re.search(r"\b(?:last|previous) month\b", normalized):
        end = today.replace(day=1) - timedelta(days=1)
        return end.replace(day=1), end
    since_midnight = re.search(r"\bsince\s+midnight\b", normalized)
    if since_midnight:
        return today, today

    found: list[date] = []
    for match in DATE_PATTERN.finditer(normalized):
        token = match.group(1)
        try:
            if "-" in token and len(token.split("-")[0]) == 4:
                parsed = date.fromisoformat(token)
            else:
                parsed = datetime.strptime(token.replace("/", "-").replace(".", "-"), "%d-%m-%Y").date()
        except ValueError:
            continue
        found.append(parsed)
    if not found:
        return None
    if len(found) > 1 and re.search(r"\b(?:between|from|through|until|to)\b", normalized):
        return min(found[0], found[1]), max(found[0], found[1])
    return found[0], found[0]


def time_bounds_from_question(
    question: str,
    timezone_name: str,
    now: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    normalized = (question or "").casefold()
    zone = _zone(timezone_name)
    current = (now or datetime.now(timezone.utc)).astimezone(zone)
    if re.search(r"\blast\s+24\s+hours?\b", normalized):
        return (
            (current - timedelta(hours=24)).astimezone(timezone.utc),
            current.astimezone(timezone.utc),
        )
    if re.search(r"\bsince\s+midnight\b", normalized):
        start = datetime.combine(current.date(), time.min, tzinfo=zone)
        return start.astimezone(timezone.utc), current.astimezone(timezone.utc)
    if re.search(r"\bthis morning\b", normalized):
        start = datetime.combine(current.date(), time.min, tzinfo=zone)
        noon = datetime.combine(current.date(), time(hour=12), tzinfo=zone)
        return start.astimezone(timezone.utc), min(noon, current).astimezone(timezone.utc)
    return None, None


def is_after_cutoff(value: str | None, cutoff: datetime | None = None) -> bool:
    parsed = _parse_datetime(value)
    if parsed is None:
        return False
    threshold = cutoff or datetime.now(timezone.utc)
    if threshold.tzinfo is None:
        threshold = threshold.replace(tzinfo=timezone.utc)
    return parsed > threshold.astimezone(timezone.utc)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Invalid application timezone: {name}") from exc
