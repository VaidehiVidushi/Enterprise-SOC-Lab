
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress
import json


@dataclass
class CorrelationAlert:
    rule_id: str
    title: str
    severity: str
    source_ip: str
    host: str
    failed_attempts: int
    first_seen: str
    last_seen: str


def parse_time(value: str) -> datetime:
    """
    Parse an ISO 8601 timestamp.

    Timezone-aware timestamps are normalized to UTC.
    Timezone-naive timestamps retain their original local clock time.
    No timezone is invented for recorded dataset events.
    """
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if dt.tzinfo is None:
        return dt

    return dt.astimezone(timezone.utc)


def is_loopback_address(value: str) -> bool:
    """Return True if the source is an IPv4 or IPv6 loopback address."""
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def correlate_failed_logins(
    events: list[dict],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[CorrelationAlert]:
    """
    Correlate repeated Windows Event ID 4625 authentication failures.

    Events are grouped by source IP, host, and timestamp context.

    Timezone-naive and timezone-aware events are kept separate to
    avoid invalid datetime comparisons.

    Correlation indicates repeated authentication failures.
    It does not independently prove malicious activity.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    groups = defaultdict(list)

    for event in events:
        if str(event.get("event_id")) != "4625":
            continue

        ip = event.get("source_ip")
        host = event.get("host")
        timestamp = event.get("timestamp")

        if not all([ip, host, timestamp]):
            continue

        if not isinstance(ip, str) or not isinstance(host, str):
            continue

        ip = ip.strip()
        host = host.strip()

        if not ip or not host:
            continue

        try:
            event_time = parse_time(timestamp)
        except (ValueError, TypeError, AttributeError):
            continue

        time_context = (
            "unknown_local"
            if event_time.tzinfo is None
            else "utc"
        )

        groups[(ip, host, time_context)].append(event_time)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (ip, host, time_context), times in groups.items():
        times.sort()

        left = 0
        best = None

        for right, current in enumerate(times):
            while current - times[left] > window:
                left += 1

            count = right - left + 1

            if count >= threshold:
                if best is None or count > best[0]:
                    best = (count, times[left], current)

        if best is None:
            continue

        count, first, last = best

        if is_loopback_address(ip):
            title = "Repeated Local Authentication Failures"
            severity = "low"
        else:
            title = "Repeated Failed Authentication"
            severity = "high" if count >= 10 else "medium"

        alerts.append(
            CorrelationAlert(
                rule_id="SOC-003",
                title=title,
                severity=severity,
                source_ip=ip,
                host=host,
                failed_attempts=count,
                first_seen=first.isoformat(),
                last_seen=last.isoformat(),
            )
        )

    return alerts


def main():
    path = Path("datasets/correlation_events.json")

    events = json.loads(
        path.read_text(encoding="utf-8")
    )

    alerts = correlate_failed_logins(events)

    if not alerts:
        print("No correlated authentication alerts detected.")

    for alert in alerts:
        print(json.dumps(asdict(alert), indent=2))


if __name__ == "__main__":
    main()
