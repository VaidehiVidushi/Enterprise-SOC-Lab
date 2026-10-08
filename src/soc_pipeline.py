
import json
from dataclasses import asdict
from pathlib import Path

from src.detection_engine import analyze_event
from src.correlation_engine import correlate_failed_logins
from src.incident_manager import build_incidents


def run_pipeline(events: list[dict]) -> dict:
    """Process security events through the SOC components."""

    detections = [
        asdict(detection)
        for event in events
        for detection in analyze_event(event)
    ]

    correlations = [
        asdict(alert)
        for alert in correlate_failed_logins(events)
    ]

    incidents = [
        asdict(incident)
        for incident in build_incidents(events)
    ]

    return {
        "events_processed": len(events),
        "detections": detections,
        "correlations": correlations,
        "incidents": incidents,
    }


def main():
    dataset = Path("datasets/correlation_events.json")

    events = json.loads(dataset.read_text(encoding="utf-8"))

    if not isinstance(events, list) or not all(
        isinstance(event, dict) for event in events
    ):
        raise ValueError("Dataset must contain a list of event objects")

    result = run_pipeline(events)

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "soc_pipeline_report.json"

    output_file.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    print(f"Events processed: {result['events_processed']}")
    print(f"Detections: {len(result['detections'])}")
    print(f"Correlations: {len(result['correlations'])}")
    print(f"Incidents: {len(result['incidents'])}")
    print(f"Report saved: {output_file}")


if __name__ == "__main__":
    main()
