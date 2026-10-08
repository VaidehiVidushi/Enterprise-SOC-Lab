
from dataclasses import dataclass, asdict
import json
import re
from pathlib import Path


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    evidence: dict


def analyze_event(event: dict) -> list[Detection]:
    detections = []

    try:
        event_id = int(event.get("event_id", 0))
    except (ValueError, TypeError):
        return detections

    source = str(event.get("source", "")).lower()
    image = str(event.get("image") or "").lower()
    command_line = str(event.get("command_line") or "").lower()

    # Backward compatibility with our original sample events:
    # Event 1 without a source is treated as Sysmon.
    is_sysmon = source in ("sysmon", "microsoft-windows-sysmon") or (
        not source and event_id in (1, 3, 11)
    )
    is_windows = source in (
        "", "windows", "windows-security", "security"
    )

    # SOC-001: Windows failed authentication
    if is_windows and event_id == 4625:
        detections.append(Detection(
            rule_id="SOC-001",
            title="Failed Windows Authentication",
            severity="low",
            evidence={
                "user": event.get("user"),
                "source_ip": event.get("source_ip"),
            },
        ))

    # SOC-002: PowerShell execution
    is_process_event = (
        (is_sysmon and event_id == 1)
        or (is_windows and event_id == 4688)
    )

    is_powershell = image.replace("/", "\\").endswith(
        ("\\powershell.exe", "\\pwsh.exe")
    ) or image in ("powershell.exe", "pwsh.exe")

    if is_process_event and is_powershell:
        detections.append(Detection(
            rule_id="SOC-002",
            title="PowerShell Process Execution",
            severity="informational",
            evidence={
                "image": image,
                "command_line": event.get("command_line"),
            },
        ))

        suspicious_patterns = {
            "encoded_command": r"(?<!\w)-(?:enc|encodedcommand)\b",
            "download_cradle": r"\b(?:downloadstring|downloadfile)\s*\(",
            "invoke_expression": r"\b(?:invoke-expression|iex)\b",
            "execution_policy_bypass": r"(?<!\w)-(?:executionpolicy|ep)\s+bypass\b",
        }

        indicators = [
            name for name, pattern in suspicious_patterns.items()
            if re.search(pattern, command_line)
        ]

        if indicators:
            detections.append(Detection(
                rule_id="SOC-004",
                title="Suspicious PowerShell Command",
                severity="high",
                evidence={
                    "image": image,
                    "command_line": event.get("command_line"),
                    "indicators": indicators,
                },
            ))

    # SOC-005: New local or domain user account
    if is_windows and event_id == 4720:
        detections.append(Detection(
            rule_id="SOC-005",
            title="Windows User Account Created",
            severity="medium",
            evidence={
                "user": event.get("user"),
                "target_user": event.get("target_user"),
                "host": event.get("host"),
            },
        ))

    # SOC-006: Membership added to a security-enabled local group
    if is_windows and event_id == 4732:
        group = str(event.get("group") or "").lower()
        privileged = any(
            name in group for name in ("administrators", "remote desktop users")
        )
        detections.append(Detection(
            rule_id="SOC-006",
            title="Local Security Group Membership Changed",
            severity="high" if privileged else "medium",
            evidence={
                "group": event.get("group"),
                "member": event.get("member"),
                "host": event.get("host"),
                "privileged_group_indicator": privileged,
            },
        ))

    # SOC-007: Process creation from suspicious Windows directories
    if is_windows and event_id == 4688:
        normalized = image.replace("/", "\\")
        suspicious_locations = (
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\users\\public\\",
        )

        if any(location in normalized for location in suspicious_locations):
            detections.append(Detection(
                rule_id="SOC-007",
                title="Process Executed from Suspicious Directory",
                severity="medium",
                evidence={
                    "image": event.get("image"),
                    "command_line": event.get("command_line"),
                    "host": event.get("host"),
                },
            ))

    # SOC-008: Sysmon network connection to a public IP.
    # Observation only: a public IP is not inherently malicious.
    if is_sysmon and event_id == 3:
        from ipaddress import ip_address

        destination = str(event.get("destination_ip") or "")
        try:
            address = ip_address(destination)
            if address.is_global:
                detections.append(Detection(
                    rule_id="SOC-008",
                    title="Outbound Connection to Globally Routable IP",
                    severity="informational",
                    evidence={
                        "destination_ip": destination,
                        "destination_port": event.get("destination_port"),
                        "image": event.get("image"),
                    },
                ))
        except ValueError:
            pass

    # SOC-009: Sysmon file creation in a startup directory
    if is_sysmon and event_id == 11:
        target = str(event.get("target_filename") or "").lower()
        normalized = target.replace("/", "\\")

        if "\\start menu\\programs\\startup\\" in normalized:
            detections.append(Detection(
                rule_id="SOC-009",
                title="File Created in Windows Startup Directory",
                severity="medium",
                evidence={
                    "target_filename": event.get("target_filename"),
                    "image": event.get("image"),
                    "host": event.get("host"),
                },
            ))

    return detections


def main():
    path = Path("datasets/sample_events.json")

    if not path.exists():
        print("Sample dataset not found.")
        return

    try:
        events = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Unable to load sample events: {exc}")
        return

    if not isinstance(events, list):
        print("Sample dataset must contain a JSON array.")
        return

    for event in events:
        if not isinstance(event, dict):
            continue

        for detection in analyze_event(event):
            print(json.dumps(asdict(detection), indent=2))


if __name__ == "__main__":
    main()
