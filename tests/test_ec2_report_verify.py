import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.ec2_lab_tunnel_run import _write_manifest
from scripts.ec2_report_verify import EvidenceValidationError, verify_report

INSTANCE = "i-036b5556c800856e0"


def _row(check, port, status):
    return {
        "check": check, "execution_status": "SUCCESS",
        "finding_status": status, "evidence_integrity": "MATCH",
        "evidence": {"port": port},
    }


def _comparison():
    local = [
        _row("FTP_ANONYMOUS", 2121, "NOT_DETECTED"),
        _row("SSH_AUTH_POLICY", 2222, "NOT_DETECTED"),
        _row("HTTP_SECURITY_HEADERS", 8081, "NOT_DETECTED"),
    ]
    remote = [
        _row("FTP_ANONYMOUS", 2122, "CONFIRMED"),
        _row("SSH_AUTH_POLICY", 2223, "POTENTIAL"),
        _row("HTTP_SECURITY_HEADERS", 8082, "POTENTIAL"),
        _row("DVWA_SQLI", 4280, "CONFIRMED"),
        _row("NUCLEI", 8082, "POTENTIAL"),
        _row("HTTP_SECURITY_HEADERS", 8082, "NOT_DETECTED"),
    ]
    return {
        "lab_comparison": {"scan_ids": {"LOCAL_BASELINE": 11, "EC2_LAB": 22},
                           "environments": {
                               "LOCAL_BASELINE": {"observations": local, "by_check": {
                                   name: [r for r in local if r["check"] == name]
                                   for name in {r["check"] for r in local}}},
                               "EC2_LAB": {"observations": remote, "by_check": {
                                   name: [r for r in remote if r["check"] == name]
                                   for name in {r["check"] for r in remote}}},
                           }}
    }


class EC2ReportVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.before = _write_manifest(
            output_dir=root, instance_id=INSTANCE, region="ap-northeast-2",
            local_id=11, ec2_id=22, phase="before", results=[], report={})
        self.after = _write_manifest(
            output_dir=root, instance_id=INSTANCE, region="ap-northeast-2",
            local_id=11, ec2_id=22, phase="after", results=[], report={})
        self.path = root / "combined.json"
        self.data = _comparison()
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")

    def verify(self):
        return verify_report(before_manifest=self.before, after_manifest=self.after,
                             report_json=self.path)

    def test_valid_distinct_scans_with_actual_before_after(self):
        out = self.verify()
        self.assertEqual(out["result"], "RECORDED_EVIDENCE_CONSISTENT")
        self.assertEqual(out["http_retest"], "POTENTIAL_TO_NOT_DETECTED")

    def test_inconclusive_not_treated_as_success(self):
        group = self.data["lab_comparison"]["environments"]["EC2_LAB"]
        for record in group["observations"]:
            if record["check"] == "DVWA_SQLI":
                record["finding_status"] = "INCONCLUSIVE"
        self.save()
        with self.assertRaises(EvidenceValidationError):
            self.verify()

    def test_tampered_evidence_hash_rejected(self):
        self.data["lab_comparison"]["environments"]["LOCAL_BASELINE"]["observations"][0]["evidence_integrity"] = "MISMATCH"
        self.save()
        with self.assertRaises(EvidenceValidationError):
            self.verify()

    def test_manifest_modified_after_signing_rejected(self):
        item = json.loads(Path(self.before).read_text())
        item["ec2_scan_id"] = 99
        Path(self.before).write_text(json.dumps(item))
        with self.assertRaises(EvidenceValidationError):
            self.verify()

    def test_retest_cannot_replace_original_observation(self):
        remote = self.data["lab_comparison"]["environments"]["EC2_LAB"]
        remote["by_check"]["HTTP_SECURITY_HEADERS"] = [
            _row("HTTP_SECURITY_HEADERS", 8082, "NOT_DETECTED")]
        self.save()
        with self.assertRaises(EvidenceValidationError):
            self.verify()

    @unittest.skipUnless(shutil.which("bash"), "Bash not installed on this platform")
    def test_ec2_owner_deployment_script_syntax(self):
        root = Path(__file__).resolve().parents[1]
        finished = subprocess.run(["bash", "-n", str(root / "lab/ec2_resource_gate.sh")],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(finished.returncode, 0, finished.stderr)


if __name__ == "__main__":
    unittest.main()
