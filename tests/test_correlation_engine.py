
import unittest
from datetime import datetime, timedelta, timezone

from src.correlation_engine import correlate_failed_logins


class TestCorrelationEngine(unittest.TestCase):

    def make_events(self, count, spacing_seconds=30):
        start = datetime(2026, 10, 9, tzinfo=timezone.utc)

        return [
            {
                "event_id": 4625,
                "host": "WIN-LAB-01",
                "source_ip": "192.0.2.15",
                "timestamp": (
                    start + timedelta(seconds=i * spacing_seconds)
                ).isoformat(),
            }
            for i in range(count)
        ]

    def test_threshold_reached(self):
        alerts = correlate_failed_logins(self.make_events(5))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SOC-003")

    def test_below_threshold(self):
        alerts = correlate_failed_logins(self.make_events(4))
        self.assertEqual(alerts, [])

    def test_outside_time_window(self):
        alerts = correlate_failed_logins(
            self.make_events(5, spacing_seconds=120)
        )
        self.assertEqual(alerts, [])

    def test_high_severity(self):
        alerts = correlate_failed_logins(
            self.make_events(10, spacing_seconds=20)
        )
        self.assertEqual(alerts[0].severity, "high")


if __name__ == "__main__":
    unittest.main()
