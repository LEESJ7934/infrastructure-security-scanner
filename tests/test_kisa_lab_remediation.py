"""KISA-aligned replay settings, separate from historical LAB baselines."""

import json
import unittest
from pathlib import Path

from config_audit.collectors.linux_mysql_lab import predicate as linux_predicate
from config_audit.kisa_ciip_review import review, review_linux
from config_audit.windows_lab import load_lab_criteria, predicate as windows_predicate

ROOT = Path(__file__).resolve().parents[1]


def linux_row(mode):
    return {
        "mode": "LAB", "results": [
            {"check_id": "LINUX-LAB-003", "status": "PASS",
             "observed_value": [
                 {"path": "/etc/shadow", "mode": mode, "uid": 0, "regular": True,
                  "symlink": False, "group_approved": True},
                 {"path": "/etc/ssh/sshd_config", "mode": 0o600, "uid": 0,
                  "regular": True, "symlink": False, "group_approved": True}
             ]}
        ]
    }


class KisaRemediationConfigurationTests(unittest.TestCase):
    def test_hardened_linux_replay_sets_0400_shadow(self):
        src = (ROOT / "lab/linux-mysql-retest/start-linux.py").read_text(encoding="utf-8")
        self.assertIn("stage == 'before' else 0o400", src)
        self.assertTrue(linux_predicate("LINUX-LAB-003", linux_row(0o400)["results"][0]["observed_value"]))
        self.assertEqual(review_linux(linux_row(0o400))[0]["kisa_recommendation_result"], "PASS")

    def test_historic_0640_is_not_kisa_pass(self):
        self.assertTrue(linux_predicate("LINUX-LAB-003", linux_row(0o640)["results"][0]["observed_value"]))
        self.assertEqual(review_linux(linux_row(0o640))[0]["kisa_recommendation_result"], "FAIL")

    def test_windows_kisa_criteria_profile_is_valid(self):
        criteria = load_lab_criteria(ROOT / "rules/windows-server-kisa-2025-lab.json")
        self.assertEqual(criteria["password"]["lockout_threshold"], 5)
        self.assertEqual(criteria["password"]["duration_minutes"], 60)
        self.assertEqual(criteria["password"]["reset_minutes"], 60)
        self.assertTrue(windows_predicate("WIN-LAB-004",
            {"lockout_threshold": 5, "lockout_duration": 60, "reset_minutes": 60}, criteria))
        self.assertFalse(windows_predicate("WIN-LAB-004",
            {"lockout_threshold": 10, "lockout_duration": 30, "reset_minutes": 30}, criteria))

    def test_synthetic_kisa_values_pass_only_when_measured(self):
        linux = linux_row(0o400)
        windows = {"mode": "LAB", "results": [{"check_id": "WIN-LAB-004",
            "status": "NEEDS_REVIEW", "after_values": {
                "lockout_threshold": 5, "lockout_duration": 60, "reset_minutes": 60
            }}]}
        result = review(linux=linux, windows=windows)
        self.assertEqual(result["summary"], {"PASS": 3})
        self.assertTrue(all(row["comparison_only_not_a_live_check"] for row in result["results"]))

    def test_windows_apply_script_has_explicit_lab_guards(self):
        script = (ROOT / "scripts/apply_windows_kisa_lab.ps1").read_text(encoding="utf-8")
        for guard in ("AcknowledgeIsolatedLab", "ExpectedComputerName", "PartOfDomain", "DomainRole",
                      "ProductType", "VIRTUAL_MACHINE_REQUIRED", "CreateNew", "/lockoutthreshold:5",
                      "/lockoutduration:60", "/lockoutwindow:60", "secedit.exe"):
            self.assertIn(guard, script)


if __name__ == "__main__":
    unittest.main()
