
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from src.correlation_engine import correlate_failed_logins


@dataclass
class Incident:
    case_id: str
    created_at: str
    title: str
    severity: str
    status: str
    host: str
    source_ip: str
    event_count: int
    mitre_attack: list[str]
    recommended_actions: list[str]
    evidence: dict


def build_incidents(events: list[dict]) -> list[Incident]:
    alerts = correlate_failed_logins(events)
    incidents = []

    for alert in alerts:
        identity = (
            f"{alert.rule_id}|{alert.host}|"
            f"{alert.source_ip}|{alert.first_seen}"
        )
        case_id = "INC-" + hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()[:12].upper()

        incidents.append(
            Incident(
                case_id=case_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                title=alert.title,
                severity=alert.severity,
                status="Open",
                host=alert.host,
                source_ip=alert.source_ip,
                event_count=alert.failed_attempts,
                mitre_attack=["T1110 - Brute Force"],
                recommended_actions=[
                    "Review authentication logs for the source IP.",
                    "Check whether successful logins followed failures.",
                    "Validate whether the activity was authorized.",
                    "Escalate confirmed suspicious activity.",
                ],
                evidence={
                    "rule_id": alert.rule_id,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "failed_attempts": alert.failed_attempts,
                },
            )
        )

    return incidents


def main():
    dataset = Path("datasets/correlation_events.json")
    events = json.loads(dataset.read_text(encoding="utf-8"))

    incidents = build_incidents(events)

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    for incident in incidents:
        report_path = output_dir / f"{incident.case_id}.json"

        report_path.write_text(
            json.dumps(asdict(incident), indent=2),
            encoding="utf-8",
        )

        print(f"Incident created: {incident.case_id}")
        print(f"Severity: {incident.severity}")
        print(f"Report saved: {report_path}")


if __name__ == "__main__":
    main()
