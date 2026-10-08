
from dataclasses import dataclass, asdict
from ipaddress import ip_address
from pathlib import Path
import json
import re


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    evidence: dict


def analyze_event(event: dict) -> list[Detection]:
    """Analyze a normalized security event against SOC detection rules."""

    detections = []

    try:
        event_id = int(event.get("event_id", 0))
    except (ValueError, TypeError):
        return detections

    source = str(event.get("source") or "").lower()
    image = str(event.get("image") or "").lower()
    command_line = str(event.get("command_line") or "").lower()

    # Backward compatibility with original synthetic events.
    # Event IDs 1, 3, and 11 without a source are treated as Sysmon.
    is_sysmon = source in (
        "sysmon",
        "microsoft-windows-sysmon",
    ) or (
        not source and event_id in (1, 3, 11)
    )

    is_windows = source in (
        "",
        "windows",
        "windows-security",
        "security",
    )

    # --------------------------------------------------
    # SOC-001: Windows failed authentication
    # --------------------------------------------------
    if is_windows and event_id == 4625:
        account_name = (
            event.get("account_name")
            or event.get("user")
        )

        source_ip = event.get("source_ip")
        if source_ip in (None, "", "-"):
            source_ip = None

        detections.append(
            Detection(
                rule_id="SOC-001",
                title="Failed Windows Authentication",
                severity="low",
                evidence={
                    "event_id": event_id,
                    "timestamp": event.get("timestamp"),
                    "host": event.get("host"),
                    "user": account_name,
                    "source_ip": source_ip,
                    "workstation": event.get("workstation"),
                    "logon_type": event.get("logon_type"),
                    "failure_reason": event.get("failure_reason"),
                    "status": event.get("status"),
                    "sub_status": event.get("sub_status"),
                    "caller_process": event.get("caller_process"),
                },
            )
        )

    # --------------------------------------------------
    # SOC-002: PowerShell process execution
    # SOC-004: Suspicious PowerShell command
    # --------------------------------------------------
    is_process_event = (
        (is_sysmon and event_id == 1)
        or (is_windows and event_id == 4688)
    )

    normalized_image = image.replace("/", "\\")

    is_powershell = normalized_image.endswith(
        ("\\powershell.exe", "\\pwsh.exe")
    ) or normalized_image in (
        "powershell.exe",
        "pwsh.exe",
    )

    if is_process_event and is_powershell:
        detections.append(
            Detection(
                rule_id="SOC-002",
                title="PowerShell Process Execution",
                severity="informational",
                evidence={
                    "image": event.get("image"),
                    "command_line": event.get("command_line"),
                },
            )
        )

        suspicious_patterns = {
            "encoded_command": (
                r"(?<!\w)-(?:enc|encodedcommand)\b"
            ),
            "download_cradle": (
                r"\b(?:downloadstring|downloadfile)\s*\("
            ),
            "invoke_expression": (
                r"\b(?:invoke-expression|iex)\b"
            ),
            "execution_policy_bypass": (
                r"(?<!\w)-(?:executionpolicy|ep)\s+bypass\b"
            ),
        }

        indicators = [
            name
            for name, pattern in suspicious_patterns.items()
            if re.search(pattern, command_line)
        ]

        if indicators:
            detections.append(
                Detection(
                    rule_id="SOC-004",
                    title="Suspicious PowerShell Command",
                    severity="high",
                    evidence={
                        "image": event.get("image"),
                        "command_line": event.get("command_line"),
                        "indicators": indicators,
                    },
                )
            )

    # --------------------------------------------------
    # SOC-005: Windows user account creation
    # --------------------------------------------------
    if is_windows and event_id == 4720:
        detections.append(
            Detection(
                rule_id="SOC-005",
                title="Windows User Account Created",
                severity="medium",
                evidence={
                    "user": event.get("user"),
                    "target_user": event.get("target_user"),
                    "host": event.get("host"),
                },
            )
        )

    # --------------------------------------------------
    # SOC-006: Local security group membership change
    # --------------------------------------------------
    if is_windows and event_id == 4732:
        group = str(event.get("group") or "").lower()

        privileged = any(
            name in group
            for name in (
                "administrators",
                "remote desktop users",
            )
        )

        detections.append(
            Detection(
                rule_id="SOC-006",
                title="Local Security Group Membership Changed",
                severity="high" if privileged else "medium",
                evidence={
                    "group": event.get("group"),
                    "member": event.get("member"),
                    "host": event.get("host"),
                    "privileged_group_indicator": privileged,
                },
            )
        )

    # --------------------------------------------------
    # SOC-007: Process execution from unusual directories
    # --------------------------------------------------
    if is_windows and event_id == 4688:
        suspicious_locations = (
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\users\\public\\",
        )

        if any(
            location in normalized_image
            for location in suspicious_locations
        ):
            detections.append(
                Detection(
                    rule_id="SOC-007",
                    title="Process Executed from Suspicious Directory",
                    severity="medium",
                    evidence={
                        "image": event.get("image"),
                        "command_line": event.get("command_line"),
                        "host": event.get("host"),
                    },
                )
            )

    # --------------------------------------------------
    # SOC-008: Sysmon outbound connection to global IP
    # --------------------------------------------------
    if is_sysmon and event_id == 3:
        destination = str(
            event.get("destination_ip") or ""
        ).strip()

        try:
            address = ip_address(destination)

            if address.is_global:
                detections.append(
                    Detection(
                        rule_id="SOC-008",
                        title=(
                            "Outbound Connection to "
                            "Globally Routable IP"
                        ),
                        severity="informational",
                        evidence={
                            "destination_ip": destination,
                            "destination_port": event.get(
                                "destination_port"
                            ),
                            "image": event.get("image"),
                        },
                    )
                )
        except ValueError:
            pass

    # --------------------------------------------------
    # SOC-009: Sysmon file creation in startup directory
    # --------------------------------------------------
    if is_sysmon and event_id == 11:
        target = str(
            event.get("target_filename") or ""
        ).lower()

        normalized_target = target.replace("/", "\\")

        if (
            "\\start menu\\programs\\startup\\"
            in normalized_target
        ):
            detections.append(
                Detection(
                    rule_id="SOC-009",
                    title="File Created in Windows Startup Directory",
                    severity="medium",
                    evidence={
                        "target_filename": event.get(
                            "target_filename"
                        ),
                        "image": event.get("image"),
                        "host": event.get("host"),
                    },
                )
            )

    return detections


def main():
    """Run the detection engine against the sample dataset."""

    path = Path("datasets/sample_events.json")

    if not path.exists():
        print("Sample dataset not found.")
        return

    try:
        events = json.loads(
            path.read_text(encoding="utf-8")
        )
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
            print(
                json.dumps(
                    asdict(detection),
                    indent=2,
                )
            )


if __name__ == "__main__":
    main()
