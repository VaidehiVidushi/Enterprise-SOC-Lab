
import unittest
from datetime import datetime, timedelta, timezone

from src.incident_manager import build_incidents


class TestIncidentManager(unittest.TestCase):

    def make_events(self, count=5):
        start = datetime(2026, 10, 9, tzinfo=timezone.utc)

        return [
            {
                "event_id": 4625,
                "host": "WIN-LAB-01",
                "source_ip": "192.0.2.15",
                "timestamp": (
                    start + timedelta(seconds=i * 30)
                ).isoformat(),
            }
            for i in range(count)
        ]

    def test_incident_created(self):
        incidents = build_incidents(self.make_events())

        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0].case_id.startswith("INC-"))

    def test_incident_contains_evidence(self):
        incident = build_incidents(self.make_events())[0]

        self.assertEqual(incident.event_count, 5)
        self.assertEqual(
            incident.evidence["rule_id"], "SOC-003"
        )

    def test_incident_has_mitre_mapping(self):
        incident = build_incidents(self.make_events())[0]

        self.assertIn(
            "T1110 - Brute Force",
            incident.mitre_attack
        )

    def test_no_incident_below_threshold(self):
        incidents = build_incidents(self.make_events(3))

        self.assertEqual(incidents, [])

    def test_case_id_is_deterministic(self):
        events = self.make_events()

        first = build_incidents(events)[0]
        second = build_incidents(events)[0]

        self.assertEqual(first.case_id, second.case_id)


if __name__ == "__main__":
    unittest.main()
