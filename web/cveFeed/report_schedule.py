"""When an email report is due: the schedule arithmetic of cveFeed.report_digests, pure functions with no database.

A subscription says a weekday (weekly) or a day of the month from 1 to 28 (monthly), a time of day and an IANA time zone. A slot is that moment in
that zone, kept in UTC. Building a slot from the local date and time through ``zoneinfo`` keeps "Monday 08:00 in London" at 08:00 local on both sides
of a daylight saving change; a time that does not exist on a spring-forward day resolves the way ``zoneinfo`` resolves it (the first reading, fold 0),
which is the hour after the gap.
"""
import calendar
from datetime import datetime, time, timedelta, timezone as dt_timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = dt_timezone.utc
WEEKDAYS = ("Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays", "Sundays")


def zone(name):
    """The ZoneInfo of an IANA name; a ValueError for anything else (an empty name, a path, an unknown zone)."""
    text = str(name or '')
    if not text or len(text) > 64 or text.startswith(('/', '.')) or '..' in text:
        raise ValueError('that is not a time zone name')
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise ValueError('that is not a time zone name') from exc


def _slot(day, at, tz):
    return datetime.combine(day, at, tzinfo=tz).astimezone(UTC)


def _add_months(day, months):
    index = day.year * 12 + day.month - 1 + months
    year, month = divmod(index, 12)
    return day.replace(year=year, month=month + 1, day=min(day.day, calendar.monthrange(year, month + 1)[1]))


def next_slot(sub, after):
    """The first slot of ``sub`` strictly after ``after`` (an aware datetime), in UTC."""
    tz = zone(sub.timezone)
    local = after.astimezone(tz)
    at = sub.send_time if isinstance(sub.send_time, time) else time.fromisoformat(str(sub.send_time))
    if sub.cadence == 'monthly':
        first = local.date().replace(day=1)
        for step in range(0, 3):
            slot = _slot(_add_months(first, step).replace(day=sub.day_of_month), at, tz)
            if slot > after:
                return slot
        raise ValueError('no slot found')
    day = local.date() + timedelta(days=(sub.weekday - local.weekday()) % 7)
    for step in range(0, 3):
        slot = _slot(day + timedelta(days=7 * step), at, tz)
        if slot > after:
            return slot
    raise ValueError('no slot found')


def previous_slot(sub, slot):
    """The slot before ``slot``: a week earlier in local wall time (weekly), or the same day of the previous month (monthly)."""
    tz = zone(sub.timezone)
    local = slot.astimezone(tz)
    at = sub.send_time if isinstance(sub.send_time, time) else time.fromisoformat(str(sub.send_time))
    if sub.cadence == 'monthly':
        return _slot(_add_months(local.date().replace(day=1), -1).replace(day=min(sub.day_of_month, 28)), at, tz)
    return _slot(local.date() - timedelta(days=7), at, tz)


def _day(value, tz):
    local = value.astimezone(tz)
    return f"{local:%b} {local.day}"


def period_label(start, end, tz, monthly=False):
    """"Nov 14 to Nov 21, 2026", "October 2026" (a monthly period from the 1st to the 1st), "Oct 15 to Nov 15, 2026"."""
    tz = zone(tz) if isinstance(tz, str) else tz
    first, last = start.astimezone(tz), end.astimezone(tz)
    if monthly and first.day == 1 and last.day == 1 and first.time() == last.time() and _add_months(first.date(), 1) == last.date():
        return f"{first:%B} {first.year}"
    if first.year == last.year:
        return f"{_day(start, tz)} to {_day(end, tz)}, {last.year}"
    return f"{_day(start, tz)}, {first.year} to {_day(end, tz)}, {last.year}"


def summary(sub):
    """"Weekly, Mondays 08:00 (Europe/London)" or "Monthly, day 1 at 08:00 (UTC)": the same words as ``static/cve/reports-logic.js`` ``scheduleSummary``."""
    at = sub.send_time if isinstance(sub.send_time, time) else time.fromisoformat(str(sub.send_time))
    stamp = f"{at:%H:%M}"
    if sub.cadence == 'monthly':
        return f"Monthly, day {sub.day_of_month} at {stamp} ({sub.timezone})"
    return f"Weekly, {WEEKDAYS[sub.weekday]} {stamp} ({sub.timezone})"


def short_label(start, end, tz):
    """"Nov 14 to Nov 21": a period without its year, for a subject line."""
    tz = zone(tz) if isinstance(tz, str) else tz
    return f"{_day(start, tz)} to {_day(end, tz)}"


def trailing(sub, end):
    """The start of the period that ends at ``end`` when ``end`` is not a slot (a test send, a preview): a week or a month earlier on the same local clock."""
    tz = zone(sub.timezone)
    local = end.astimezone(tz)
    if sub.cadence == 'monthly':
        return datetime.combine(_add_months(local.date(), -1), local.time(), tzinfo=tz).astimezone(UTC)
    return datetime.combine(local.date() - timedelta(days=7), local.time(), tzinfo=tz).astimezone(UTC)
