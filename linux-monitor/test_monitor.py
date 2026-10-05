import json
import tempfile
import unittest
import os
import stat
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from pathlib import Path
from monitor_core import control_request, parse_snapshot, read_snapshot, describe, UNIT, MAX_BYTES, upstream_state


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.value = {"schemaVersion": 1, "emittedAtUtc": self.now.isoformat(), "processId": 123,
                      "startedAtUtc": self.now.isoformat(), "events": [],
                      "status": {"implementation": "HostsGuardian.DnsEngine", "udpState": "Listening",
                                 "tcpState": "Listening", "managementState": "Listening", "filteringEnabled": True,
                                 "emergencySafeMode": False, "policyLoaded": True, "policyRevision": 4, "committedRuleCount": 3,
                                 "activeRuleCount": 3, "lastUpstreamOutcome": "NotObserved"}}

    def raw(self):
        return json.dumps(self.value).encode()

    def test_fixed_unit_and_only_three_controls(self):
        for verb, method in (("start", "StartUnit"), ("stop", "StopUnit"), ("restart", "RestartUnit")):
            self.assertEqual(control_request(verb), (method, (UNIT, "replace")))
        for verb in ("enable", "reload", "stop other.service", "", "kill"):
            with self.assertRaises(ValueError):
                control_request(verb)

    def test_snapshot_freshness_schema_and_process_binding(self):
        self.assertEqual(parse_snapshot(self.raw(), 123, self.now)["status"]["policyRevision"], 4)
        for pid in (0, 124):
            with self.assertRaises(ValueError):
                parse_snapshot(self.raw(), pid, self.now)
        for age in (11, -3):
            with self.assertRaises(ValueError):
                parse_snapshot(self.raw(), 123, self.now + timedelta(seconds=age))
        self.value["schemaVersion"] = 2
        with self.assertRaises(ValueError):
            parse_snapshot(self.raw(), 123, self.now)

    def test_size_duplicate_and_event_bounds(self):
        for raw in (b"x" * (MAX_BYTES + 1), b'{"schemaVersion":1,"schemaVersion":1}'):
            with self.assertRaises(ValueError):
                parse_snapshot(raw, 123, self.now)
        self.value["events"] = [{"level": "WARN", "component": "DNS", "message": "x" * 241}]
        with self.assertRaises(ValueError):
            parse_snapshot(self.raw(), 123, self.now)
        self.value["events"] = [{}] * 65
        with self.assertRaises(ValueError):
            parse_snapshot(self.raw(), 123, self.now)

    def test_missing_stale_and_stopped_are_not_false_running(self):
        self.assertIn("Stopped", describe({"ActiveState": "inactive"}, None))
        self.assertIn("Failed", describe({"ActiveState": "failed"}, None))
        self.assertIn("Unknown", describe({}, None))
        text = describe({"ActiveState": "active"}, self.value)
        self.assertIn("Policy revision: 4", text)
        self.assertIn("NotObserved", text)

    def test_bounded_file_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_bytes(self.raw())
            # Windows cannot express POSIX mode bits. Inject each mode into the real bounded reader.
            actual_fstat = os.fstat
            def metadata(fd, mode=stat.S_IFREG | 0o644, owner=123):
                original = actual_fstat(fd)
                return SimpleNamespace(st_mode=mode, st_uid=owner)
            with patch("monitor_core.os.fstat", side_effect=metadata):
                self.assertEqual(read_snapshot(path, 123, self.now, expected_uid=123)["processId"], 123)
            for mode, owner in ((stat.S_IFREG | 0o664, 123), (stat.S_IFREG | 0o646, 123), (stat.S_IFIFO | 0o644, 123), (stat.S_IFREG | 0o644, 999)):
                with patch("monitor_core.os.fstat", side_effect=lambda fd, mode=mode, owner=owner: metadata(fd, mode, owner)):
                    with self.assertRaises(ValueError):
                        read_snapshot(path, 123, self.now, expected_uid=123)
            path.write_bytes(b"x" * (MAX_BYTES + 1))
            with patch("monitor_core.os.fstat", side_effect=metadata):
                with self.assertRaises(ValueError):
                    read_snapshot(path, 123, self.now)

    def test_upstream_evidence_expires_and_fallback_is_degraded(self):
        evidence = {"lastUpstreamOutcome": "Response", "lastUpstreamSuccessUtc": self.now.isoformat()}
        self.assertEqual(upstream_state(evidence, self.now), "Healthy")
        evidence["lastUpstreamRequestUsedFallback"] = True
        self.assertIn("Degraded", upstream_state(evidence, self.now))
        self.assertIn("Unknown", upstream_state(evidence, self.now + timedelta(seconds=31)))
        self.assertIn("Unknown", upstream_state({}, self.now))

    def test_gui_has_no_policy_credential_or_engine_process_control(self):
        source = Path(__file__).with_name("monitor.py").read_text(encoding="utf-8-sig")
        for forbidden in ("subprocess", "os.system", "requests.", "safe-mode/", "rules/blocked", "ApiToken", "Popen"):
            self.assertNotIn(forbidden, source)
        shutdown = source[source.index("    def shutdown_monitor"):source.index('if __name__')]
        self.assertNotIn("self.client.control", shutdown)
        self.assertIn("os.geteuid() == 0", source)


if __name__ == "__main__":
    unittest.main()
