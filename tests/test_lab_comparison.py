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


if __name__ == "__main__":
    unittest.main()
