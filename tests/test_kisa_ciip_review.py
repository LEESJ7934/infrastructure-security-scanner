import json
import tempfile
import unittest
from pathlib import Path

from config_audit.kisa_ciip_review import KisaReviewInputError, review, review_linux, review_windows
from scripts.compare_kisa_ciip import main


def linux(mode=0o640, status="PASS", source="local_container_readonly"):
    return {
        "mode": "LAB", "origin": source,
        "results": [{"check_id": "LINUX-LAB-003", "status": status,
                     "observed_value": [{"path": "/etc/shadow", "mode": mode, "uid": 0, "regular": True, "symlink": False},
                                        {"path": "/etc/ssh/sshd_config", "mode": 0o600, "uid": 0, "regular": True, "symlink": False}],
                     "evidence_reference": "sha256:synthetic"}],
    }


def windows(threshold=10, duration=30, reset=30, status="PASS"):
    return {"mode": "LAB", "results": [{"check_id": "WIN-LAB-004", "status": status,
        "assessment_basis": "user_powershell_confirmation",
        "after_values": {"lockout_threshold": threshold, "lockout_duration": duration, "reset_minutes": reset}}]}


class KisaReassessmentTests(unittest.TestCase):
    def test_existing_lab_values_fail_selected_kisa_recommendations(self):
        linux_report, windows_report = linux(), windows()
        result = review(linux=linux_report, windows=windows_report)
        self.assertEqual([(x["kisa_id"], x["kisa_recommendation_result"]) for x in result["results"]],
                         [("U-18", "FAIL"), ("W-04", "FAIL"), ("W-08", "FAIL")])
        self.assertEqual(result["summary"], {"FAIL": 3})
        self.assertEqual(linux_report["results"][0]["status"], "PASS")
        self.assertEqual(windows_report["results"][0]["status"], "PASS")

    def test_recommended_values_pass(self):
        x = review(linux=linux(0o400), windows=windows(5, 60, 60))
        self.assertEqual(x["summary"], {"PASS": 3})

    def test_numeric_0044_world_read_is_never_approved(self):
        self.assertEqual(review_linux(linux(0o044))[0]["kisa_recommendation_result"], "FAIL")

    def test_shadow_owner_and_symlink_rejected(self):
        x = linux(0o400)
        x["results"][0]["observed_value"][0]["uid"] = 1000
        self.assertEqual(review_linux(x)[0]["kisa_recommendation_result"], "FAIL")
        x["results"][0]["observed_value"][0]["uid"] = 0
        x["results"][0]["observed_value"][0]["symlink"] = True
        self.assertEqual(review_linux(x)[0]["kisa_recommendation_result"], "FAIL")

    def test_disabled_lockout_does_not_pass(self):
        self.assertEqual(review_windows(windows(threshold=0))[0]["kisa_recommendation_result"], "FAIL")

    def test_partial_windows_policy_is_review(self):
        x = windows()
        del x["results"][0]["after_values"]["reset_minutes"]
        self.assertEqual(review_windows(x)[1]["kisa_recommendation_result"], "NEEDS_REVIEW")
        self.assertEqual(review_windows(x)[0]["kisa_recommendation_result"], "FAIL")

    def test_missing_check_does_not_get_pass(self):
        x = {"mode": "LAB", "results": []}
        self.assertEqual(review_linux(x)[0]["kisa_recommendation_result"], "NOT_TESTED")
        self.assertEqual([y["kisa_recommendation_result"] for y in review_windows(x)], ["NOT_TESTED", "NOT_TESTED"])

    def test_error_stays_error(self):
        self.assertEqual(review_linux(linux(status="ERROR"))[0]["kisa_recommendation_result"], "ERROR")
        self.assertEqual(review_windows(windows(status="ERROR"))[0]["kisa_recommendation_result"], "ERROR")

    def test_duplicate_check_rejected(self):
        x = linux()
        x["results"].append(x["results"][0])
        with self.assertRaises(KisaReviewInputError): review_linux(x)

    def test_cli_prints_json_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps(linux()), encoding="utf-8")
            self.assertEqual(main(["--linux-report", str(path)]), 0)
            self.assertEqual([x.name for x in Path(directory).iterdir()], ["source.json"])


if __name__ == "__main__":
    unittest.main()
