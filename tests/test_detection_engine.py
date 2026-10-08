
import unittest

from src.detection_engine import analyze_event


class TestDetectionEngine(unittest.TestCase):

    def test_failed_login(self):
        event = {
            "event_id": 4625,
            "user": "testuser",
            "source_ip": "192.0.2.15"
        }

        detections = analyze_event(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "SOC-001")

    def test_powershell_execution(self):
        event = {
            "event_id": 1,
            "image": r"C:\Windows\System32\powershell.exe",
            "command_line": "powershell.exe Get-Date"
        }

        detections = analyze_event(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "SOC-002")

    def test_normal_login(self):
        event = {
            "event_id": 4624,
            "user": "testuser"
        }

        detections = analyze_event(event)

        self.assertEqual(detections, [])

    def test_unrelated_process(self):
        event = {
            "event_id": 1,
            "image": r"C:\Windows\System32\notepad.exe"
        }

        detections = analyze_event(event)

        self.assertEqual(detections, [])


if __name__ == "__main__":
    unittest.main()
