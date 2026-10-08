
import unittest

from src.correlation_engine import correlate_failed_logins


class TestRealLogCorrelation(unittest.TestCase):

    def test_naive_timestamps_from_recorded_dataset(self):
        """Recorded local timestamps should support correlation."""
        events = [
            {
                "event_id": 4625,
                "host": "PC3",
                "source_ip": "127.0.0.1",
                "timestamp": f"2024-11-24T14:{minute:02d}:00",
            }
            for minute in range(50, 55)
        ]

        alerts = correlate_failed_logins(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failed_attempts, 5)
        self.assertEqual(alerts[0].host, "PC3")
        self.assertEqual(alerts[0].source_ip, "127.0.0.1")

    def test_missing_source_ip_does_not_correlate(self):
        """Missing source addresses must not create false groups."""
        events = [
            {
                "event_id": 4625,
                "host": "PC3",
                "source_ip": None,
                "timestamp": "2024-11-24T14:50:00",
            }
            for _ in range(6)
        ]

        self.assertEqual(correlate_failed_logins(events), [])

    def test_non_authentication_events_are_ignored(self):
        events = [
            {
                "event_id": 4624,
                "host": "PC3",
                "source_ip": "127.0.0.1",
                "timestamp": "2024-11-24T14:50:00",
            }
            for _ in range(6)
        ]

        self.assertEqual(correlate_failed_logins(events), [])


if __name__ == "__main__":
    unittest.main()
