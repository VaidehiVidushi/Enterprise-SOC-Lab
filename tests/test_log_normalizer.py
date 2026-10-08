
import unittest
from src.log_normalizer import normalize_event, load_windows_events


class TestLogNormalizer(unittest.TestCase):

    def setUp(self):
        self.sample_row = {
            "Keywords": "24.11.2024. 16:49:48",
            "Date and Time": "Microsoft-Windows-Security-Auditing",
            "Source": "4798",
            "Event ID": "User Account Management",
            "Task Category": "A user's local group membership was enumerated.",
        }

    def test_event_id_conversion(self):
        event = normalize_event(self.sample_row, "PC1")
        self.assertEqual(event["event_id"], 4798)

    def test_timestamp_conversion(self):
        event = normalize_event(self.sample_row, "PC1")
        self.assertEqual(
            event["timestamp"],
            "2024-11-24T16:49:48",
        )

    def test_host_assignment(self):
        event = normalize_event(self.sample_row, "PC1")
        self.assertEqual(event["host"], "PC1")

    def test_description_preserved(self):
        event = normalize_event(self.sample_row, "PC1")
        self.assertIn(
            "local group membership",
            event["description"],
        )

    def test_invalid_event_id(self):
        self.sample_row["Source"] = "INVALID"

        with self.assertRaises(ValueError):
            normalize_event(self.sample_row, "PC1")

    def test_invalid_timestamp(self):
        self.sample_row["Keywords"] = "INVALID"

        with self.assertRaises(ValueError):
            normalize_event(self.sample_row, "PC1")

    def test_negative_limit(self):
        with self.assertRaises(ValueError):
            load_windows_events(
                "unused.csv",
                "PC1",
                limit=-1,
            )

    def test_pc2_timestamp_column(self):
        """Verify PC2's Level column is supported."""

        pc2_row = self.sample_row.copy()
        pc2_row["Level"] = pc2_row.pop("Keywords")

        event = normalize_event(pc2_row, "PC2")

        self.assertEqual(
            event["timestamp"],
            "2024-11-24T16:49:48",
        )
        self.assertEqual(event["host"], "PC2")
        self.assertEqual(event["event_id"], 4798)

    def test_missing_timestamp_column(self):
        """Reject events without a supported timestamp column."""

        self.sample_row.pop("Keywords")

        with self.assertRaises(ValueError):
            normalize_event(self.sample_row, "PC1")


if __name__ == "__main__":
    unittest.main()
