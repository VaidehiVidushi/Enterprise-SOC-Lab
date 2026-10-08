
import unittest

from src.soc_pipeline import run_pipeline


class TestSOCPipeline(unittest.TestCase):

    def setUp(self):
        self.events = [
            {
                "event_id": 4625,
                "host": "WIN-LAB-01",
                "source_ip": "192.0.2.15",
                "timestamp": f"2026-10-09T10:00:{i:02d}Z",
            }
            for i in range(5)
        ]

    def test_events_processed(self):
        result = run_pipeline(self.events)
        self.assertEqual(result["events_processed"], 5)

    def test_detections_generated(self):
        result = run_pipeline(self.events)
        self.assertEqual(len(result["detections"]), 5)

    def test_correlation_generated(self):
        result = run_pipeline(self.events)
        self.assertEqual(len(result["correlations"]), 1)

    def test_incident_generated(self):
        result = run_pipeline(self.events)
        self.assertEqual(len(result["incidents"]), 1)


if __name__ == "__main__":
    unittest.main()
