import unittest
from analyser import parse_events,detect_bruteforce
class TestParser(unittest.TestCase):
    def test_failed_login(self):
        logs = [
            "Aug 14 08:21:33 kali sshd-session[1234]: Failed password for kali from 192.168.1.50 port 50000 ssh2"
        ]
        events = parse_events(logs)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "failed_login")
        self.assertEqual(events[0]["username"], "kali")
        self.assertEqual(events[0]["source_ip"], "192.168.1.50")
        self.assertEqual(events[0]["source_port"], 50000)
    def test_successful_login(self):
        logs = [
            "Aug 14 08:22:00 kali sshd-session[1234]: Accepted password for kali from 192.168.1.50 port 50001 ssh2"
        ]
        events = parse_events(logs)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "successful_login")
        self.assertEqual(events[0]["username"], "kali")
        self.assertEqual(events[0]["source_ip"], "192.168.1.50")
        self.assertEqual(events[0]["source_port"], 50001)
        self.assertEqual(events[0]["auth_method"], "password")
    def test_irrelevant_log(self):
        logs = [
            "-- Boot abc123 --",
            "Aug 14 08:30:00 kali systemd[1]: Started something.service"
        ]
        events = parse_events(logs)
        self.assertEqual(len(events), 0)
    def test_bruteforce_detection(self):
        logs = [
            "Aug 14 08:21:33 kali sshd-session[1234]: Failed password for kali from 192.168.1.50 port 50000 ssh2",
            "Aug 14 08:21:40 kali sshd-session[1235]: Failed password for kali from 192.168.1.50 port 50001 ssh2",
            "Aug 14 08:21:47 kali sshd-session[1236]: Failed password for kali from 192.168.1.50 port 50002 ssh2"
        ]
        events = parse_events(logs)
        alerts = detect_bruteforce(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["rule"], "SSH_BRUTE_FORCE")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.50")
    def test_no_bruteforce_with_two_failures(self):
        logs = [
            "Aug 14 09:21:33 kali sshd-session[1234]: Failed password for kali from 192.168.1.50 port 50000 ssh2",
            "Aug 14 09:21:40 kali sshd-session[1235]: Failed password for kali from 192.168.1.50 port 50001 ssh2"
        ]
        events = parse_events(logs)
        alerts = detect_bruteforce(events)
        self.assertEqual(len(alerts), 0)
    def test_different_ips_do_not_trigger(self):
        logs = [
            "Aug 14 10:21:33 kali sshd-session[1234]: Failed password for kali from 192.168.1.10 port 50000 ssh2",
            "Aug 14 10:21:40 kali sshd-session[1235]: Failed password for kali from 192.168.1.20 port 50001 ssh2",
            "Aug 14 10:21:47 kali sshd-session[1236]: Failed password for kali from 192.168.1.30 port 50002 ssh2"
        ]
        events = parse_events(logs)
        alerts = detect_bruteforce(events)
        self.assertEqual(len(alerts), 0)
if __name__ == "__main__":
    unittest.main()
