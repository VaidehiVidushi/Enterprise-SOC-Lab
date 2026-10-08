
import unittest

from src.detection_engine import analyze_event


class TestDetectionEvidence(unittest.TestCase):

    def test_failed_login_preserves_authentication_evidence(self):
        event = {
            "event_id": 4625,
            "timestamp": "2024-11-24T14:50:31",
            "host": "PC3",
            "account_name": "ANON_USERS_1",
            "source_ip": "127.0.0.1",
            "workstation": "ANON_MACHINES_1",
            "logon_type": 2,
            "failure_reason": "Unknown user name or bad password.",
            "status": "0xC000006D",
            "sub_status": "0xC000006A",
            "caller_process": r"C:\Windows\System32\svchost.exe",
        }

        detections = analyze_event(event)

        self.assertEqual(len(detections), 1)

        detection = detections[0]

        self.assertEqual(detection.rule_id, "SOC-001")
        self.assertEqual(detection.evidence["user"], "ANON_USERS_1")
        self.assertEqual(detection.evidence["source_ip"], "127.0.0.1")
        self.assertEqual(detection.evidence["host"], "PC3")
        self.assertEqual(detection.evidence["logon_type"], 2)
        self.assertEqual(
            detection.evidence["failure_reason"],
            "Unknown user name or bad password.",
        )
        self.assertEqual(
            detection.evidence["caller_process"],
            r"C:\Windows\System32\svchost.exe",
        )

    def test_legacy_user_field_remains_supported(self):
        event = {
            "event_id": 4625,
            "user": "legacy_user",
            "source_ip": "192.0.2.10",
        }

        detections = analyze_event(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(
            detections[0].evidence["user"],
            "legacy_user",
        )

    def test_missing_source_ip_is_not_invented(self):
        event = {
            "event_id": 4625,
            "account_name": "test_user",
            "source_ip": "-",
        }

        detections = analyze_event(event)

        self.assertEqual(len(detections), 1)
        self.assertIsNone(
            detections[0].evidence["source_ip"]
        )


if __name__ == "__main__":
    unittest.main()
