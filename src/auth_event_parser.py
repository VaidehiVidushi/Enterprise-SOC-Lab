
import re


def extract_field(description: str, field_name: str) -> str | None:
    """Extract a field from a Windows event description."""
    pattern = rf"^\s*{re.escape(field_name)}:[ \t]*(.*?)[ \t]*$"

    match = re.search(
        pattern,
        description,
        flags=re.MULTILINE | re.IGNORECASE,
    )

    return match.group(1).strip() or None if match else None


def extract_section(description: str, section_name: str) -> str | None:
    """Extract fields belonging to a named Windows event section."""
    lines = description.splitlines()
    target = section_name.strip().casefold() + ":"

    for index, line in enumerate(lines):
        if line.strip().casefold() != target:
            continue

        section_lines = []

        for next_line in lines[index + 1:]:
            if not next_line.strip():
                if section_lines:
                    break
                continue

            section_lines.append(next_line)

        return "\n".join(section_lines) if section_lines else None

    return None


def parse_failed_login(event: dict) -> dict:
    """Enrich a normalized Windows failed-login event."""
    enriched = event.copy()

    if event.get("event_id") != 4625:
        return enriched

    description = event.get("description", "")

    failed_account = extract_section(
        description, "Account For Which Logon Failed"
    )
    network = extract_section(description, "Network Information")
    failure = extract_section(description, "Failure Information")
    process = extract_section(description, "Process Information")

    enriched["account_name"] = (
        extract_field(failed_account, "Account Name")
        if failed_account else None
    )
    enriched["source_ip"] = (
        extract_field(network, "Source Network Address")
        if network else None
    )
    enriched["workstation"] = (
        extract_field(network, "Workstation Name")
        if network else None
    )
    enriched["failure_reason"] = (
        extract_field(failure, "Failure Reason")
        if failure else None
    )
    enriched["status"] = (
        extract_field(failure, "Status")
        if failure else None
    )
    enriched["sub_status"] = (
        extract_field(failure, "Sub Status")
        if failure else None
    )
    enriched["caller_process"] = (
        extract_field(process, "Caller Process Name")
        if process else None
    )

    logon_type = extract_field(description, "Logon Type")
    enriched["logon_type"] = (
        int(logon_type)
        if logon_type and logon_type.isdigit()
        else None
    )

    return enriched
