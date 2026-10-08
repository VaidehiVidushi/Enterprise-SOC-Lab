
from dataclasses import dataclass, asdict
import json
from pathlib import Path


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    evidence: dict


def analyze_event(event: dict) -> list[Detection]:
    detections = []

    event_id = int(event.get("event_id", 0))
    image = str(event.get("image", "")).lower()

    if event_id == 4625:
        detections.append(
            Detection(
                rule_id="SOC-001",
                title="Failed Windows Authentication",
                severity="low",
                evidence={
                    "user": event.get("user"),
                    "source_ip": event.get("source_ip"),
                },
            )
        )

    if event_id == 1 and image.endswith(
        ("powershell.exe", "pwsh.exe")
    ):
        detections.append(
            Detection(
                rule_id="SOC-002",
                title="PowerShell Process Execution",
                severity="informational",
                evidence={
                    "image": image,
                    "command_line": event.get("command_line"),
                },
            )
        )

    return detections


def main():
    path = Path("datasets/sample_events.json")

    if not path.exists():
        print("Sample dataset not found.")
        return

    events = json.loads(path.read_text(encoding="utf-8"))

    for event in events:
        detections = analyze_event(event)

        for detection in detections:
            print(json.dumps(asdict(detection), indent=2))


if __name__ == "__main__":
    main()
