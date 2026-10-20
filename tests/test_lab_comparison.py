import hashlib
import json
import unittest
from scripts.generate_lab_comparison import build_comparison


class LabComparisonTests(unittest.TestCase):
    def test_missing_environment_never_marked_safe(self):
        report = build_comparison([])
        for data in report["environments"].values():
            self.assertTrue(all(status == "NOT_TESTED" for status in data["coverage"].values()))

    def test_evidence_integrity_and_findings_are_separate(self):
        evidence = {"finding_status": "CONFIRMED", "execution_status": "SUCCESS"}
        encoded = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        sha = hashlib.sha256(encoded.encode()).hexdigest()
        item = {"environment_label": "EC2_LAB", "check_name": "FTP_ANONYMOUS",
                "asset_uid": "a", "execution_status": "SUCCESS", "finding_status": "CONFIRMED",
                "observed_at": "2026-10-20", "evidence_json": encoded,
                "evidence_sha256": sha}
        report = build_comparison([item])
        record = report["environments"]["EC2_LAB"]["by_check"]["FTP_ANONYMOUS"][0]
        self.assertEqual(record["evidence_integrity"], "MATCH")
        self.assertEqual(report["environments"]["LOCAL_BASELINE"]["coverage"]["FTP_ANONYMOUS"], "NOT_TESTED")
        item["evidence_sha256"] = "0"*64
        self.assertEqual(build_comparison([item])["environments"]["EC2_LAB"]["observations"][0]["evidence_integrity"], "MISMATCH")

    def test_error_and_tampered_metadata_have_no_verified_coverage(self):
        evidence = {"finding_status": "INCONCLUSIVE", "execution_status": "ERROR"}
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        row = {"environment_label": "EC2_LAB", "check_name": "SSH_AUTH_POLICY",
               "asset_uid": "a", "execution_status": "ERROR", "finding_status": "INCONCLUSIVE",
               "observed_at": "2026-10-20", "evidence_json": encoded,
               "evidence_sha256": hashlib.sha256(encoded.encode()).hexdigest()}
        report = build_comparison([row])
        group = report["environments"]["EC2_LAB"]
        self.assertEqual(group["coverage"]["SSH_AUTH_POLICY"], "NOT_TESTED")
        self.assertEqual(group["observations"][0]["risk"], "UNASSESSED")
        row.update(execution_status="SUCCESS", finding_status="NOT_DETECTED")
        self.assertEqual(build_comparison([row])["environments"]["EC2_LAB"]["observations"][0]["evidence_integrity"], "MISMATCH")

    def test_comparison_explains_independent_applications(self):
        report = build_comparison([])
        self.assertEqual(report["comparison_type"], "INDEPENDENT_ENVIRONMENTS_NOT_BEFORE_AFTER")
        self.assertIn("different applications", report["disclaimer"])


if __name__ == "__main__":
    unittest.main()
