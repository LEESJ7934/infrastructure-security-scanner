"""Offline validation of owner-supplied evidence; no AWS, Docker, DB, HTTP calls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scanner.scope import ScopePolicy
from scripts.import_ec2_dvwa_evidence import import_evidence, parse_dvwa_evidence


PORT = {
    "port_id": 19, "scan_id": 7, "asset_uid": "8b6822df-c9e7-4126-8c81-32516f06ea03",
    "host_ip": "127.0.0.1", "port": 4280, "service": "http"
}
SCOPE = ScopePolicy.from_dict({
    "scope_uid": "local-approved", "name": "Lab", "authorization_ref": "SELF-OWNED",
    "approved_by": "operator", "valid_from": "2020-01-01T00:00:00+00:00",
    "valid_until": "2030-01-01T00:00:00+00:00", "allowed_targets": ["127.0.0.1"],
    "max_targets": 4, "max_workers": 4, "max_ports_per_target": 8,
})


class EC2EvidenceImportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.file = Path(self.directory.name) / "dvwa.json"
        self.data = {
            "tested_at": "2026-10-20T12:38:30+00:00",
            "check": "DVWA_SQLI", "method": "Read-only row comparison",
            "baseline": {"http_status": 200, "result_rows": 1,
                         "response_sha256": "a" * 64},
            "injection": {"http_status": 200, "result_rows": 5,
                          "response_sha256": "b" * 64},
            "finding_status": "CONFIRMED", "cve_confirmed": False,
        }
        self.save()

    def save(self):
        self.file.write_text(json.dumps(self.data), encoding="utf-8")

    def test_valid_dvwa_evidence_parses_without_exposing_raw_data(self):
        evidence, digest, when = parse_dvwa_evidence(self.file)
        self.assertEqual(evidence["baseline"]["result_rows"], 1)
        self.assertEqual(evidence["injection"]["result_rows"], 5)
        self.assertEqual(digest, hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(when.year, 2026)

    @patch("scripts.import_ec2_dvwa_evidence.insert_observation")
    @patch("scripts.import_ec2_dvwa_evidence.get_all_ports", return_value=[PORT])
    def test_dry_run_leaves_db_unchanged(self, get_ports, save):
        response = import_evidence(evidence_path=self.file, scope=SCOPE,
                                   scan_id=7, port_id=19, dry_run=True)
        self.assertEqual(response["status"], "DRY_RUN")
        self.assertEqual(response["finding_status"], "CONFIRMED")
        save.assert_not_called()

    @patch("scripts.import_ec2_dvwa_evidence.insert_observation", return_value=101)
    @patch("scripts.import_ec2_dvwa_evidence.get_all_ports", return_value=[PORT])
    def test_explicit_commit_persists_user_source_flag(self, get_ports, save):
        response = import_evidence(evidence_path=self.file, scope=SCOPE,
                                   scan_id=7, port_id=19, dry_run=False)
        self.assertEqual(response["observation_id"], 101)
        self.assertFalse(response["remote_attestation"])
        entry = save.call_args.args[0]
        self.assertEqual(entry["execution_status"], "SUCCESS")
        self.assertEqual(entry["finding_status"], "CONFIRMED")
        self.assertIn("operator_supplied_ec2_local_file", entry["evidence_json"])
        self.assertEqual(entry["scan_id"], 7)

    def test_injection_without_row_expansion_rejected(self):
        self.data["injection"]["result_rows"] = 1
        self.save()
        with self.assertRaises(ValueError):
            parse_dvwa_evidence(self.file)

    def test_secret_field_rejected(self):
        self.data["cookie"] = "php-abcdef"
        self.save()
        with self.assertRaises(ValueError):
            parse_dvwa_evidence(self.file)

    def test_malformed_hash_rejected(self):
        self.data["injection"]["response_sha256"] = "wrong"
        self.save()
        with self.assertRaises(ValueError):
            parse_dvwa_evidence(self.file)

    def test_cve_confirmation_rejected(self):
        self.data["cve_confirmed"] = True
        self.save()
        with self.assertRaises(ValueError):
            parse_dvwa_evidence(self.file)

    @patch("scripts.import_ec2_dvwa_evidence.insert_observation")
    @patch("scripts.import_ec2_dvwa_evidence.get_all_ports", return_value=[{
        **PORT, "host_ip": "192.0.2.44"}])
    def test_out_of_scope_rejected_before_storage(self, get_ports, save):
        with self.assertRaises(ValueError):
            import_evidence(evidence_path=self.file, scope=SCOPE,
                            scan_id=7, port_id=19, dry_run=False)
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
