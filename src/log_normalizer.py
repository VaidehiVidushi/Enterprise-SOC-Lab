

import csv
from datetime import datetime
from pathlib import Path


COMMON_COLUMNS = [
    "Date and Time",
    "Source",
    "Event ID",
    "Task Category",
]

SUPPORTED_TIMESTAMP_COLUMNS = {"Keywords", "Level"}


def normalize_event(row: dict, host: str) -> dict:
    """Convert a Kaggle Windows Security event into our SOC schema."""

    timestamp_column = next(
        (column for column in ("Keywords", "Level") if column in row),
        None,
    )

    if timestamp_column is None:
        raise ValueError("Missing timestamp column")

    timestamp = datetime.strptime(
        row[timestamp_column].strip(),
        "%d.%m.%Y. %H:%M:%S",
    ).isoformat()

    event_id = int(row["Source"].strip())

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "host": host,
        "provider": row["Date and Time"].strip(),
        "category": row["Event ID"].strip(),
        "description": row["Task Category"].strip(),
    }


def load_windows_events(
    file_path: str | Path,
    host: str,
    limit: int | None = None,
) -> list[dict]:
    """Read and normalize Windows Security events from CSV."""

    if limit is not None and limit < 0:
        raise ValueError("limit cannot be negative")

    events = []

    with Path(file_path).open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        reader = csv.DictReader(file)

        if (
            reader.fieldnames is None
            or len(reader.fieldnames) != 5
            or reader.fieldnames[0] not in SUPPORTED_TIMESTAMP_COLUMNS
            or reader.fieldnames[1:] != COMMON_COLUMNS
        ):
            raise ValueError(
                f"Unexpected CSV columns: {reader.fieldnames}"
            )

        for row_number, row in enumerate(reader, start=2):
            if limit is not None and len(events) >= limit:
                break

            try:
                event = normalize_event(row, host)
            except (ValueError, KeyError, AttributeError) as error:
                raise ValueError(
                    f"Invalid event at CSV row {row_number}: {error}"
                ) from error

            events.append(event)

    return events
