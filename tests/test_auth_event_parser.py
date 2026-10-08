
import unittest

from src.auth_event_parser import parse_failed_login


SAMPLE_DESCRIPTION = """
An account failed to log on.

Subject:
    Account Name: SYSTEM

Logon Type: 2

Account For Which Logon Failed:
    Account Name: ANON_USERS_1
    Account Domain: ANON_DOMAINS_1

Failure Information:
    Failure Reason: Unknown user name or bad password.
    Status: 0xC000006D
    Sub Status: 0xC000006A

Process Information:
    Caller Process Name: C:\\Windows\\System32\\svchost.exe

Network Information:
    Workstation Name: ANON_MACHINES_1
    Source Network Address: 127.0.0.1
    Source Port: 0
"""


class TestAuthEventParser(unittest.TestCase):

    def setUp(self):
        self.event = {
            "timestamp": "2024-11-24T14:50:31",
            "event_id": 4625,
            "host": "PC3",
            "description": SAMPLE_DESCRIPTION,
        }

    def test_failed_account_is_extracted(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(parsed["account_name"], "ANON_USERS_1")

    def test_source_ip_is_extracted(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(parsed["source_ip"], "127.0.0.1")

    def test_logon_type_is_integer(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(parsed["logon_type"], 2)

    def test_failure_reason_is_extracted(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(
            parsed["failure_reason"],
            "Unknown user name or bad password.",
        )

    def test_status_codes_are_extracted(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(parsed["status"], "0xC000006D")
        self.assertEqual(parsed["sub_status"], "0xC000006A")

    def test_caller_process_is_extracted(self):
        parsed = parse_failed_login(self.event)
        self.assertEqual(
            parsed["caller_process"],
            "C:\\Windows\\System32\\svchost.exe",
        )

    def test_subject_account_is_not_confused_with_failed_account(self):
        parsed = parse_failed_login(self.event)
        self.assertNotEqual(parsed["account_name"], "SYSTEM")

    def test_non_4625_event_remains_unchanged(self):
        event = {
            "event_id": 4624,
            "description": "Successful logon",
        }
        self.assertEqual(parse_failed_login(event), event)

    def test_missing_fields_are_handled(self):
        event = {
            "event_id": 4625,
            "description": "An account failed to log on.",
        }
        parsed = parse_failed_login(event)
        self.assertIsNone(parsed["source_ip"])
        self.assertIsNone(parsed["account_name"])
        self.assertIsNone(parsed["logon_type"])

    def test_original_event_is_not_modified(self):
        original = self.event.copy()
        parse_failed_login(self.event)
        self.assertEqual(self.event, original)


if __name__ == "__main__":
    unittest.main()
