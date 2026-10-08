
import unittest

from src.detection_engine import analyze_event


class TestAdvancedDetection(unittest.TestCase):

    def test_failed_login(self):
        result = analyze_event({
            "source": "windows-security",
            "event_id": 4625,
            "user": "testuser",
        })
        self.assertIn("SOC-001", [r.rule_id for r in result])

    def test_encoded_powershell(self):
        result = analyze_event({
            "source": "sysmon",
            "event_id": 1,
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand PLACEHOLDER",
        })
        ids = [r.rule_id for r in result]
        self.assertIn("SOC-002", ids)
        self.assertIn("SOC-004", ids)

    def test_account_creation(self):
        result = analyze_event({
            "source": "windows-security",
            "event_id": 4720,
            "target_user": "newuser",
        })
        self.assertEqual(result[0].rule_id, "SOC-005")

    def test_privileged_group_change(self):
        result = analyze_event({
            "source": "windows-security",
            "event_id": 4732,
            "group": "Administrators",
            "member": "newuser",
        })
        self.assertEqual(result[0].severity, "high")

    def test_process_from_public_folder(self):
        result = analyze_event({
            "source": "windows-security",
            "event_id": 4688,
            "image": "C:\\Users\\Public\\example.exe",
        })
        self.assertIn("SOC-007", [r.rule_id for r in result])

    def test_global_ip_connection(self):
        result = analyze_event({
            "source": "sysmon",
            "event_id": 3,
            "destination_ip": "8.8.8.8",
        })
        self.assertIn("SOC-008", [r.rule_id for r in result])

    def test_private_ip_not_flagged(self):
        result = analyze_event({
            "source": "sysmon",
            "event_id": 3,
            "destination_ip": "192.168.1.5",
        })
        self.assertEqual(result, [])

    def test_startup_file(self):
        result = analyze_event({
            "source": "sysmon",
            "event_id": 11,
            "target_filename": (
                "C:\\Users\\testuser\\AppData\\Roaming\\Microsoft\\Windows"
                "\\Start Menu\\Programs\\Startup\\example.lnk"
            ),
        })
        self.assertIn("SOC-009", [r.rule_id for r in result])

    def test_unrelated_event(self):
        self.assertEqual(analyze_event({
            "source": "windows-security",
            "event_id": 4624,
            "user": "testuser",
        }), [])


if __name__ == "__main__":
    unittest.main()
