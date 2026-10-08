
import json
from pathlib import Path

from src.auth_event_parser import parse_failed_login
from src.log_normalizer import load_windows_events
from src.soc_pipeline import run_pipeline


DATASET_FILES = {
    "PC1": Path("datasets/raw/_PC1.csv"),
    "PC2": Path("datasets/raw/_PC2.csv"),
    "PC3": Path("datasets/raw/_PC3.csv"),
}


def load_real_events() -> list[dict]:
    """Load and enrich recorded Windows security events."""

    events = []

    for host, file_path in DATASET_FILES.items():
        if not file_path.is_file():
            raise FileNotFoundError(
                f"Missing dataset for {host}: {file_path}"
            )

        host_events = load_windows_events(
            file_path=file_path,
            host=host,
        )

        enriched_events = [
            parse_failed_login(event)
            for event in host_events
        ]

        events.extend(enriched_events)

        print(f"{host}: loaded {len(enriched_events)} events")

    return events


def main():
    events = load_real_events()

    print(f"\nTotal events loaded: {len(events)}")
    print("Running SOC detection and correlation pipeline...")

    result = run_pipeline(events)

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "real_windows_soc_report.json"

    output_file.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    print("\nSOC Analysis Results")
    print("--------------------")
    print(f"Events processed: {result['events_processed']}")
    print(f"Detections: {len(result['detections'])}")
    print(f"Correlations: {len(result['correlations'])}")
    print(f"Incidents: {len(result['incidents'])}")
    print(f"Report saved: {output_file}")


if __name__ == "__main__":
    main()

