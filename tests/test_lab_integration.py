"""Pure test doubles: no live host, Docker container or MySQL is used."""
import json
import unittest
from unittest.mock import patch

from db.lab_repository import make_observation
from scanner.scope import ScopePolicy
from verification.lab_runner import execute


PORT = {"host_ip": "127.0.0.1", "port": 21, "port_id": 10, "scan_id": 5,
        "asset_uid": "8b6822df-c9e7-4126-8c81-32516f06ea03", "service": "ftp"}
POLICY = ScopePolicy.from_dict({
    "scope_uid": "local-lab", "name": "Local", "authorization_ref": "LOCAL-001",
    "approved_by": "operator", "valid_from": "2020-01-01T00:00:00+00:00",
    "valid_until": "2030-01-01T00:00:00+00:00", "allowed_targets": ["127.0.0.1"],
    "max_targets": 2, "max_workers": 2, "max_ports_per_target": 4
})


class LabIntegrationTests(unittest.TestCase):
    def test_execution_error_remains_inconclusive(self):
        observation = make_observation(port=PORT, environment="LOCAL_BASELINE",
            check_name="FTP_ANONYMOUS", scope=POLICY,
            result={"status": "ERROR", "checker": "FTPChecker", "reason": "timeout",
                    "details": {"finding_status": "CONFIRMED"}})
        self.assertEqual((observation["execution_status"], observation["finding_status"]),
                         ("ERROR", "INCONCLUSIVE"))
        self.assertEqual(json.loads(observation["evidence_json"])["finding_status"], "INCONCLUSIVE")

    def test_redacts_auth_secrets_recursively(self):
        observation = make_observation(port=PORT, environment="EC2_LAB",
            check_name="FTP_ANONYMOUS", scope=POLICY,
            result={"status": "POTENTIAL", "checker": "FTPChecker", "reason": "seen",
                    "details": {"finding_status": "CONFIRMED", "cookie": "private",
                                "nested": {"Authorization": "private"}}})
        data = json.loads(observation["evidence_json"])
        self.assertEqual(data["details"]["cookie"], "[REDACTED]")
        self.assertEqual(data["details"]["nested"]["Authorization"], "[REDACTED]")

    @patch("verification.lab_runner.get_all_ports", return_value=[PORT])
    @patch("verification.lab_runner.insert_observation", return_value=7)
    @patch("verification.lab_runner.FTPChecker")
    def test_explicit_approved_ftp_is_saved(self, checker, save, get_ports):
        checker.return_value.run_check.return_value = {
            "status": "POTENTIAL", "checker": "FTPChecker",
            "reason": "anonymous accepted", "details": {"finding_status": "CONFIRMED"}}
        result = execute(policy=POLICY, environment="EC2_LAB", scan_id=5,
                         allow_ftp_anonymous=True)
        self.assertEqual(result[0]["finding_status"], "CONFIRMED")
        self.assertEqual(result[0]["execution_status"], "SUCCESS")
        self.assertEqual(save.call_count, 1)
        self.assertEqual(checker.call_args.kwargs["approved_endpoints"], (("127.0.0.1", 21),))

    @patch("verification.lab_runner.get_all_ports", return_value=[PORT])
    @patch("verification.lab_runner.insert_observation")
    @patch("verification.lab_runner.FTPChecker")
    def test_dry_run_makes_no_network_requests_or_writes(self, checker, save, get_ports):
        result = execute(policy=POLICY, environment="LOCAL_BASELINE", scan_id=5, dry_run=True)
        self.assertEqual(result[0]["action"], "DRY_RUN")
        checker.assert_not_called()
        save.assert_not_called()

    @patch("verification.lab_runner.get_all_ports", return_value=[{**PORT, "host_ip": "203.0.113.1"}])
    @patch("verification.lab_runner.FTPChecker")
    def test_scope_denied_before_probe(self, checker, get_ports):
        with self.assertRaises(ValueError):
            execute(policy=POLICY, environment="EC2_LAB", scan_id=5)
        checker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
