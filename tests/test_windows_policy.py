"""Synthetic policy/evidence fixtures; no approvals or server results invented."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from pypdf import PdfReader

from tests import test_windows_audit as fixtures
from config_audit.collectors import windows_server as windows
from config_audit.windows_policy import load_policy, DEFAULT_POLICY, WindowsPolicyError, AUDIT_GUIDS, parse_audit
from config_audit.windows_report import build_windows_report, write_windows_report
from config_audit.windows_comparison import compare_windows_snapshots
from config_audit.comparison import SnapshotRelation
from config_audit.reporting import OfflineReport


class WindowsPolicyTests(unittest.TestCase):
    setUp = fixtures.WindowsAuditTests.setUp
    bundle = fixtures.WindowsAuditTests.bundle
    results = fixtures.WindowsAuditTests.results

    def policy_file(self, document=None, *, acknowledge=True):
        path = Path(self.temp.name) / "policy.json"
        if document is not None:
            path.write_text(json.dumps(document), encoding="utf-8")
        return load_policy(path, project_root=self.temp.name, acknowledge_approval=acknowledge)

    def test_approved_internal_baseline_14_complexity_10(self):
        rows = self.results()
        self.assertEqual([rows[key]["status"] for key in ("WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004")], ["PASS"] * 3)
        self.assertEqual(rows["WIN-LAB-002"]["rule_version"], "0.3")

    def test_length13_fails_approved14(self):
        doc = fixtures.synthetic_document()
        doc["sections"]["security_policy"]["values"]["minimum_length"] = 13
        self.assertEqual(self.results(doc)["WIN-LAB-002"]["status"], "FAIL")

    def test_threshold_must_equal10_not_just_be_positive(self):
        doc = fixtures.synthetic_document()
        doc["sections"]["security_policy"]["values"]["lockout_threshold"] = 9
        self.assertEqual(self.results(doc)["WIN-LAB-004"]["status"], "FAIL")

    def test_lockout_duration_and_reset_match_approved_values(self):
        for key in ("lockout_duration", "reset_minutes"):
            doc = fixtures.synthetic_document()
            doc["sections"]["security_policy"]["values"][key] = 30
            self.assertEqual(self.results(doc)["WIN-LAB-004"]["status"], "FAIL")

    def test_draft_cannot_create_pass_or_fail(self):
        self.policy = load_policy()
        rows = self.results()
        self.assertTrue(all(rows[key]["status"] == "NEEDS_REVIEW" for key in ("WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004")))

    def test_approval_hash_does_not_replace_human_attestation(self):
        self.policy = self.policy_file(acknowledge=False)
        self.assertEqual(self.policy.approval_integrity, "VERIFIED")
        self.assertEqual(self.results()["WIN-LAB-002"]["status"], "NEEDS_REVIEW")

    def test_approval_missing_authority_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["authority"] = None
        with self.assertRaises(WindowsPolicyError): self.policy_file(doc)

    def test_approval_missing_evidence_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["evidence"]["path"] = "missing.txt"
        with self.assertRaises(WindowsPolicyError): self.policy_file(doc)

    def test_approval_hash_mismatch_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["evidence"]["sha256"] = "0" * 64
        with self.assertRaises(WindowsPolicyError): self.policy_file(doc)

    def test_approval_path_escape_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["evidence"]["path"] = "../other.txt"
        with self.assertRaises(WindowsPolicyError): self.policy_file(doc)

    def test_future_approval_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["approved_at"] = "2999-01-01T00:00:00Z"
        with self.assertRaises(WindowsPolicyError): self.policy_file(doc)

    def test_approved_scope_asset_missing_blocks_verdict(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["scope"]["asset_ids"] = ["DIFFERENT-SYNTHETIC"]
        self.policy = self.policy_file(doc)
        self.assertEqual(self.results()["WIN-LAB-002"]["status"], "NEEDS_REVIEW")

    def test_duration_reset_not_approved_blocks_lockout(self):
        doc = deepcopy(self.policy.document)
        doc["password"].update(duration_minutes=None, reset_minutes=None)
        self.policy = self.policy_file(doc)
        self.assertEqual(self.results()["WIN-LAB-004"]["status"], "NEEDS_REVIEW")

    def test_setting_missing_cannot_use_user_claim_as_value(self):
        doc = fixtures.synthetic_document()
        doc["sections"]["security_policy"]["values"] = {"merged_policy": True}
        rows = self.results(doc)
        self.assertTrue(all(rows[key]["status"] == "NEEDS_REVIEW" for key in ("WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004")))
        self.assertIn("missing_minimum_length", rows["WIN-LAB-002"]["unmet_conditions"])

    def test_domain_and_build_mismatch_block_password_pass(self):
        for update in ({"domain_role":3, "part_of_domain":True}, {"build_number":"99999"}):
            doc = fixtures.synthetic_document()
            doc["system"].update(update)
            self.assertEqual(self.results(doc)["WIN-LAB-002"]["status"], "NEEDS_REVIEW")

    def audit_doc(self):
        doc = fixtures.synthetic_document()
        doc["sections"]["audit"]["values"] = {"parser_verified":True, "method":"AuditQuerySystemPolicy",
            "subcategories":[{"guid":guid.upper(), "mask":3} for guid in AUDIT_GUIDS]}
        return doc

    def test_audit_guid_masks_pass_only_with_approved_criteria(self):
        self.assertEqual(self.results(self.audit_doc())["WIN-LAB-009"]["status"], "PASS")

    def test_audit_success_missing_is_fail_with_approval(self):
        doc = self.audit_doc()
        doc["sections"]["audit"]["values"]["subcategories"][0]["mask"] = 2
        self.assertEqual(self.results(doc)["WIN-LAB-009"]["status"], "FAIL")

    def test_audit_missing_guid_needs_review(self):
        doc = self.audit_doc()
        doc["sections"]["audit"]["values"]["subcategories"].pop()
        self.assertEqual(self.results(doc)["WIN-LAB-009"]["status"], "NEEDS_REVIEW")

    def test_audit_malformed_masks_and_duplicate_ids_rejected(self):
        for value in ("Success and Failure", True, 5, -1):
            doc = self.audit_doc()
            doc["sections"]["audit"]["values"]["subcategories"][0]["mask"] = value
            with self.assertRaises(windows.WindowsInputError): self.bundle(doc)
        doc = self.audit_doc()
        rows = doc["sections"]["audit"]["values"]["subcategories"]
        rows[-1] = deepcopy(rows[0])
        with self.assertRaises(windows.WindowsInputError): self.bundle(doc)

    def test_localized_audit_labels_not_accepted_as_evidence(self):
        doc = self.audit_doc()
        doc["sections"]["audit"]["values"]["method"] = "localized_csv"
        with self.assertRaises(windows.WindowsInputError): self.bundle(doc)

    def test_legacy_audit_input_remains_review(self):
        self.assertEqual(self.results()["WIN-LAB-009"]["status"], "NEEDS_REVIEW")
        doc = self.audit_doc()
        doc["sections"]["audit"]["values"]["parser_verified"] = False
        with self.assertRaises(windows.WindowsInputError): self.bundle(doc)

    def source_files(self, *, reversed_time=False, different_build=False):
        result = []
        for side in ("before", "after"):
            doc = fixtures.synthetic_document()
            doc["origin"] = "local_server_readonly"  # mocked file format; no actual VM
            doc["system"].update(build_number="20348", os_version="10.0.20348")
            doc["collected_at"] = "2020-01-02T00:00:00Z" if side == "before" else "2020-01-03T00:00:00Z"
            if side == "before":
                doc["sections"]["security_policy"]["values"].update(minimum_length=0, lockout_threshold=0)
                if reversed_time: doc["collected_at"] = "2020-01-04T00:00:00Z"
            elif different_build: doc["system"]["build_number"] = "99999"
            path = Path(self.temp.name) / (side + ".json")
            raw = json.dumps(doc).encode(); path.write_bytes(raw)
            result.append((path, hashlib.sha256(raw).hexdigest()))
        return result

    def report(self, *, reversed_time=False, different_build=False, omit_before_hash=False):
        (before, a), (after, b) = self.source_files(reversed_time=reversed_time, different_build=different_build)
        return build_windows_report(before, after, before_sha256=None if omit_before_hash else a, after_sha256=b, policy=self.policy)

    def test_normal_mocked_pair_two_improvements_one_unchanged(self):
        report = self.report()
        rows = {row["check_id"]:row for row in report["changes"]}
        self.assertEqual(rows["WIN-LAB-002"]["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(rows["WIN-LAB-004"]["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(rows["WIN-LAB-003"]["comparison_result"], "UNCHANGED_PASS")
        self.assertEqual(rows["WIN-LAB-002"]["before_values"]["minimum_length"], 0)

    def test_clock_reversal_preserves_observation_not_improvement(self):
        report = self.report(reversed_time=True)
        row = next(row for row in report["comparison"]["pairs"][0]["results"] if row["check_id"] == "WIN-LAB-002")
        self.assertEqual(row["comparison_result"], "INCOMPARABLE")
        self.assertEqual(row["recorded_status_transition"], "FAIL_TO_PASS")

    def test_product_build_mismatch_incomparable(self):
        rows = self.report(different_build=True)["changes"]
        self.assertTrue(all(row["comparison_result"] == "INCOMPARABLE" for row in rows))

    def test_missing_independent_before_hash_not_self_verified(self):
        report = self.report(omit_before_hash=True)
        self.assertEqual(report["source_results"][0]["integrity"], "NOT_VERIFIED")
        self.assertIsNone(report["source_results"][0]["expected_sha256"])
        self.assertEqual(report["comparison"]["summary"]["IMPROVED_OBSERVED"], 0)

    def test_tampered_or_missing_source_not_replaced(self):
        (before,a),(after,b) = self.source_files()
        before.write_bytes(before.read_bytes()+b' ')
        with self.assertRaises(windows.WindowsInputError):
            build_windows_report(before,after,before_sha256=a,after_sha256=b,policy=self.policy)
        before.unlink()
        with self.assertRaises(windows.WindowsInputError):
            build_windows_report(before,after,after_sha256=b,policy=self.policy)

    def test_rule_method_mismatch_not_comparable(self):
        report = self.report()
        from config_audit.collectors.windows_server import to_report_snapshot
        a,b = (to_report_snapshot(value,snapshot_id=side) for value,side in zip(report["source_results"],("before","after")))
        b.results[0].automatic["verification_method"] = "DIFFERENT"
        result = compare_windows_snapshots(OfflineReport(report["generated_at"],(a,b)),[SnapshotRelation("before","after")])
        row = next(row for row in result["pairs"][0]["results"] if row["check_id"] == "WIN-LAB-001")
        self.assertEqual(row["comparison_result"], "INCOMPARABLE")

    def test_json_pdf_separate_output_and_no_overwrite(self):
        report = self.report()
        directory = Path(self.temp.name)/"reports"
        json_path,pdf_path = write_windows_report(report,directory)
        self.assertEqual(json.loads(json_path.read_text())["mode"],"offline_windows_reanalysis_only")
        pdf = PdfReader(pdf_path)
        self.assertGreaterEqual(len(pdf.pages),3)
        text = "".join(page.extract_text() for page in pdf.pages)
        self.assertIn("Not a KISA certification",text)
        self.assertIn("minimum_length",text)
        with self.assertRaises(windows.WindowsInputError): write_windows_report(report,directory)

    def test_sensitive_approval_metadata_rejected(self):
        doc = deepcopy(self.policy.document)
        doc["approval"]["authority"] = "api_secret"
        with self.assertRaises(WindowsPolicyError) as error: self.policy_file(doc)
        self.assertNotIn("api_secret",str(error.exception))


if __name__ == "__main__": unittest.main()
