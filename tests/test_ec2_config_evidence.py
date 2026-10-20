"""No AWS/Windows access: strict imports, failure semantics and concurrent-safe storage."""
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from db.lab_repository import insert_observation, make_observation
from scripts.collect_ec2_config_evidence import collect
from scripts.import_ec2_config_evidence import import_evidence, parse_evidence
from scripts.generate_lab_comparison import build_comparison
from test_import_ec2_dvwa_evidence import SCOPE, PORT


class ConfigImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config.json"
        self.data = {"schema_version": 1, "environment": "EC2_LAB", "check": "FTP_ANONYMOUS",
                     "tested_at": "2026-10-20T12:00:00Z", "target": {"host": "127.0.0.1", "port": 21},
                     "execution_status": "SUCCESS", "details": {"reply_code": 230}}
        self.port = {**PORT, "port": 21, "service": "ftp"}

    def save(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def run_import(self, **changes):
        args = dict(evidence_path=self.path, expected_sha256=self.save(), scope=SCOPE,
                    scan_id=7, port_id=PORT["port_id"], expected_host="127.0.0.1")
        args.update(changes)
        return import_evidence(**args)

    @patch("scripts.import_ec2_config_evidence.insert_observation")
    @patch("scripts.import_ec2_config_evidence.get_all_ports")
    def test_dry_run_no_writes(self, ports, insert):
        ports.return_value = [self.port]
        result = self.run_import()
        self.assertEqual((result["execution_status"], result["finding_status"]), ("SUCCESS", "CONFIRMED"))
        insert.assert_not_called()

    @patch("scripts.import_ec2_config_evidence.insert_observation", return_value=42)
    @patch("scripts.import_ec2_config_evidence.get_all_ports")
    def test_commit_preserves_source_and_uses_deduplication(self, ports, insert):
        ports.return_value = [self.port]
        self.assertEqual(self.run_import(dry_run=False)["observation_id"], 42)
        self.assertTrue(insert.call_args.kwargs["deduplicate"])
        obs = insert.call_args.args[0]
        evidence = json.loads(obs["evidence_json"])
        self.assertFalse(evidence["details"]["remote_attestation"])
        self.assertEqual(evidence["scan_id"], 7)
        self.assertEqual(build_comparison([obs])["environments"]["EC2_LAB"]["observations"][0]["evidence_integrity"], "MATCH")

    def test_source_hash_mismatch_rejected(self):
        self.save()
        with self.assertRaises(ValueError): parse_evidence(self.path, "0" * 64)

    def test_secret_and_duplicate_fields_rejected(self):
        self.data["cookie"] = "test-only"
        with self.assertRaises(ValueError): parse_evidence(self.path, self.save())
        raw = '{"check":"FTP_ANONYMOUS","check":"SSH_AUTH_POLICY"}'
        self.path.write_text(raw)
        with self.assertRaises(ValueError): parse_evidence(self.path, hashlib.sha256(raw.encode()).hexdigest())

    def test_false_success_invalid_values_rejected(self):
        for details in ({"reply_code": True}, {"reply_code": 220}, {"reply_code": 230, "password": "test"}):
            with self.subTest(details=details):
                self.data["details"] = details
                with self.assertRaises(ValueError): parse_evidence(self.path, self.save())

    def test_timestamp_timezone_future_rejected(self):
        for timestamp in ("2026-10-20", "2999-01-01T00:00:00Z"):
            self.data["tested_at"] = timestamp
            with self.assertRaises(ValueError): parse_evidence(self.path, self.save())

    @patch("scripts.import_ec2_config_evidence.get_all_ports")
    def test_wrong_scan_host_port_service_rejected(self, ports):
        for key, value in (("scan_id", 8), ("host_ip", "192.0.2.1"), ("port", 2121), ("service", "ssh")):
            ports.return_value = [{**self.port, key: value}]
            with self.subTest(key=key), self.assertRaises(ValueError): self.run_import()

    @patch("scripts.import_ec2_config_evidence.get_all_ports")
    def test_scope_checked_at_collection_and_import(self, ports):
        ports.return_value = [self.port]
        with self.assertRaises(ValueError):
            self.run_import(scope=__import__('dataclasses').replace(SCOPE, valid_from=SCOPE.valid_until - timedelta(days=1)))

    def test_http_four_missing_headers_potential(self):
        self.data.update(check="HTTP_SECURITY_HEADERS", target={"host": "127.0.0.1", "port": 80},
                         details={"http_status": 200, "nosniff": False, "referrer_policy_present": False,
                                  "csp_present": False, "frame_protection_present": False})
        parsed = parse_evidence(self.path, self.save())
        self.assertEqual(parsed[3], "POTENTIAL")
        self.assertEqual(len(parsed[4]), 4)
        self.data["details"]["csp_present"] = "false"
        with self.assertRaises(ValueError): parse_evidence(self.path, self.save())

    def test_ssh_disabled_policy_not_detected(self):
        self.data.update(check="SSH_AUTH_POLICY", target={"host": "127.0.0.1", "port": 22},
                         details={"pubkeyauthentication": True, "passwordauthentication": False,
                                  "policy_source": "sshd_T_default_config"})
        self.assertEqual(parse_evidence(self.path, self.save())[3], "NOT_DETECTED")
        self.data["details"]["policy_source"] = "banner"
        with self.assertRaises(ValueError): parse_evidence(self.path, self.save())

    @patch("scripts.import_ec2_config_evidence.get_all_ports")
    def test_error_is_not_a_secure_verdict(self, ports):
        ports.return_value = [self.port]
        self.data.update(execution_status="ERROR", details={"error_type": "TimeoutError"})
        result = self.run_import()
        self.assertEqual((result["execution_status"], result["finding_status"]), ("ERROR", "INCONCLUSIVE"))

    @patch("scripts.collect_ec2_config_evidence.ftplib.FTP")
    def test_collector_failure_retains_error_no_credentials(self, ftp):
        ftp.return_value.__enter__.return_value.connect.side_effect = TimeoutError("sensitive-data")
        result = collect("FTP_ANONYMOUS")
        self.assertEqual(result["execution_status"], "ERROR")
        self.assertNotIn("sensitive-data", json.dumps(result))

    @patch("scripts.collect_ec2_config_evidence.subprocess.run")
    def test_ssh_collector_only_reads_two_flags(self, run):
        run.return_value.stdout = "pubkeyauthentication yes\npasswordauthentication no\nother secret\n"
        result = collect("SSH_AUTH_POLICY")
        self.assertFalse(result["details"]["passwordauthentication"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(run.call_args.args[0], ["sudo", "-n", "/usr/sbin/sshd", "-T"])

    def test_duplicate_source_no_insert_and_lock_released(self):
        self.check_storage(existing=True)

    def test_new_source_append_only(self):
        self.check_storage(existing=False)

    def check_storage(self, existing):
        obs = make_observation(port=self.port, environment="EC2_LAB", check_name="FTP_ANONYMOUS", scope=SCOPE,
            result={"status": "POTENTIAL", "details": {"finding_status": "CONFIRMED", "source_file_sha256": "a" * 64}})
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(1,), (81, obs["evidence_sha256"]) if existing else None, (1,)]
        cursor.lastrowid = 82
        result = insert_observation(obs, connect=lambda: connection, deduplicate=True)
        self.assertEqual(result, 81 if existing else 82)
        sqls = [c.args[0] for c in cursor.execute.call_args_list]
        self.assertEqual(any(q.startswith("INSERT") for q in sqls), not existing)
        self.assertIn("RELEASE_LOCK", sqls[-1])
        connection.close.assert_called_once()
        if existing: connection.commit.assert_not_called()

    def test_integrated_pdf_renders_config_evidence_risk_and_peer_scope(self):
        from api.report_pdf import render_report_pdf
        from test_generate_report import pdf_drawn_text
        obs = make_observation(port=self.port, environment="EC2_LAB", check_name="FTP_ANONYMOUS", scope=SCOPE,
            result={"status": "POTENTIAL", "checker": "OperatorCollectedEC2ConfigImport",
                    "details": {"finding_status": "CONFIRMED", "source_file_sha256": "a" * 64}})
        comparison = build_comparison([obs])
        path = Path(self.tmp.name) / "fixture.pdf"
        render_report_pdf({"assets": [], "scans": [], "lab_comparison": comparison,
                           "peer_report": {"assets": [], "scans": [{"scan_id": 7, "scope": {"scope_uid": "approved-ec2-fixture"}}]}}, path)
        text = pdf_drawn_text(path.read_bytes())
        for value in ("CONFIRMED", "MEDIUM", "Disable anonymous", "OperatorCollectedEC2ConfigImport",
                      "approved-ec2-fixture", "NOT_TESTED", "different applications", obs["evidence_sha256"]):
            self.assertIn(value, text)

    def test_lock_timeout_never_inserts(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (0,)
        with self.assertRaises(RuntimeError):
            insert_observation({"scan_id": 7, "port_id": 1, "check_name": "FTP_ANONYMOUS", "environment_label": "EC2_LAB"}, connect=lambda: connection, deduplicate=True)
        self.assertFalse(any(c.args[0].startswith("INSERT") for c in cursor.execute.call_args_list))
        connection.rollback.assert_called_once()


if __name__ == "__main__": unittest.main()
