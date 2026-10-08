
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return dt.astimezone(timezone.utc)


def correlate_failed_logins(
    events: list[dict],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[CorrelationAlert]:
    """Detect clusters of failed logins by source IP and host."""
    groups = defaultdict(list)

    for event in events:
        if str(event.get("event_id")) != "4625":
            continue

        ip = event.get("source_ip")
        host = event.get("host")
        timestamp = event.get("timestamp")

        if not all([ip, host, timestamp]):
            continue

        try:
            event_time = parse_time(timestamp)
        except (ValueError, TypeError):
            continue

        groups[(ip, host)].append(event_time)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (ip, host), times in groups.items():
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

        if best:
            count, first, last = best
            alerts.append(
                CorrelationAlert(
                    rule_id="SOC-003",
                    title="Repeated Failed Authentication",
                    severity="high" if count >= 10 else "medium",
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
    events = json.loads(path.read_text(encoding="utf-8"))

    alerts = correlate_failed_logins(events)

    if not alerts:
        print("No correlated threats detected.")

    for alert in alerts:
        print(json.dumps(asdict(alert), indent=2))


if __name__ == "__main__":
    main()
