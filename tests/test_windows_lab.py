"""LAB mode uses explicit synthetic fixtures; never collects or changes Windows."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pypdf import PdfReader

from tests import test_windows_audit as fixtures
from config_audit.collectors.windows_server import load_bundle, WindowsInputError
from config_audit.windows_lab import build_lab_view, load_lab_criteria, load_lab_manual, predicate
from config_audit.windows_policy import AUDIT_GUIDS, WindowsPolicyError
from scripts.run_windows_audit import main


class WindowsLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.criteria = load_lab_criteria()

    def pair(self, missing_password=False):
        bundles = []
        for side in ("before", "after"):
            doc = fixtures.synthetic_document()
            doc["origin"] = "local_server_readonly"  # mocked format, not an actual VM
            doc["system"].update(build_number="20348", os_version="10.0.20348")
            doc["collected_at"] = "2020-01-01T00:00:00Z" if side == "before" else "2020-01-02T00:00:00Z"
            doc["sections"]["security_policy"]["values"].update(minimum_length=0 if side == "before" else 14,
                lockout_threshold=0 if side == "before" else 10, lockout_duration=30, reset_minutes=30)
            if missing_password: doc["sections"]["security_policy"]["values"] = {"merged_policy": True}
            doc["sections"]["spooler"]["values"] = {"present":False, "native_error_code":1060,
                "required":None, "running":None, "disabled":None, "feature_query_state":"COLLECTED",
                "print_services_installed":False, "print_server_installed":False}
            path = self.root / (side+".json")
            path.write_text(json.dumps(doc),encoding="utf-8")
            bundles.append(load_bundle(path))
        return bundles

    def manual(self):
        def record(before,after,changed=True):
            return {"scenario_id":"SYNTHETIC-LAB-CASE", "before":before, "after":after,
                    "verified_at":None,"remediation_performed":changed,"retested":True,"sequence_confirmed":True}
        doc = {"schema_version":1,"asset_id":"WIN-LAB-SERVER","server_release":"2022","build_number":"20348",
               "source_kind":"user_powershell_confirmation","source_reference":"synthetic:unit-test-only",
               "checks":{
                   "WIN-LAB-002":record({"minimum_length":0},{"minimum_length":14}),
                   "WIN-LAB-003":record({"complexity":True},{"complexity":True},False),
                   "WIN-LAB-004":record({"lockout_threshold":0,"lockout_duration":None,"reset_minutes":None},
                                        {"lockout_threshold":10,"lockout_duration":30,"reset_minutes":30}),
                   "WIN-LAB-005":record({},{"required":False},False),
                   "WIN-LAB-008":record({"require_signing":False},{"require_signing":True})}}
        path = self.root/"manual.json"
        path.write_text(json.dumps(doc),encoding="utf-8")
        return load_lab_manual(path)

    def rows(self, **kwargs):
        return {row["check_id"]:row for row in build_lab_view(*self.pair(),criteria=self.criteria,**kwargs)["results"]}

    def test_lab_no_organization_approval_or_independent_hash_required(self):
        rows = self.rows()
        self.assertEqual(rows["WIN-LAB-002"]["status"],"PASS")
        self.assertEqual(rows["WIN-LAB-004"]["status"],"PASS")
        self.assertEqual(self.pair()[0].integrity,"NOT_VERIFIED")

    def test_known_bad_values_fail(self):
        rows = self.rows()
        self.assertEqual(rows["WIN-LAB-002"]["before_status"],"FAIL")
        self.assertEqual(rows["WIN-LAB-004"]["before_status"],"FAIL")

    def test_manual_confirmations_eight_pass_and_three_completed(self):
        report = build_lab_view(*self.pair(True),criteria=self.criteria,manual=self.manual())
        self.assertEqual(report["summary"],{"PASS":8,"NEEDS_REVIEW":1})
        self.assertEqual(report["remediation_completed_count"],3)

    def test_missing_values_without_manual_are_not_pass(self):
        report = build_lab_view(*self.pair(True),criteria=self.criteria)
        rows={row["check_id"]:row for row in report["results"]}
        for check in ("WIN-LAB-002","WIN-LAB-003","WIN-LAB-004"):
            self.assertEqual(rows[check]["status"],"NEEDS_REVIEW")

    def test_manual_values_never_written_into_automatic_or_source(self):
        bundles=self.pair(True)
        originals=[deepcopy(bundle.document) for bundle in bundles]
        rows={row["check_id"]:row for row in build_lab_view(*bundles,manual=self.manual())["results"]}
        self.assertNotIn("minimum_length",rows["WIN-LAB-002"]["automatic"]["after"]["values"])
        self.assertEqual(rows["WIN-LAB-002"]["manual"]["after"]["values"]["minimum_length"],14)
        self.assertEqual([bundle.document for bundle in bundles], originals)

    def test_manual_smb_baseline_separate_from_newer_json_baseline(self):
        row=self.rows(manual=self.manual())["WIN-LAB-008"]
        self.assertTrue(row["automatic"]["before"]["values"]["require_signing"])
        self.assertFalse(row["manual"]["before"]["values"]["require_signing"])
        self.assertTrue(row["remediation_complete"])
        self.assertTrue(row["manual_baseline_separate_from_json_baseline"])

    def test_no_test_time_or_transcript_fabrication(self):
        row=self.rows(manual=self.manual())["WIN-LAB-002"]
        self.assertIsNone(row["manual"]["verified_at"])
        self.assertFalse(row["manual"]["original_transcript_attached"])

    def test_spooler_absent_without_need_confirmation_stays_review(self):
        self.assertEqual(self.rows()["WIN-LAB-005"]["status"],"NEEDS_REVIEW")

    def test_spooler_unneeded_confirmation_combines_explicit_sources(self):
        row=self.rows(manual=self.manual())["WIN-LAB-005"]
        self.assertEqual(row["status"],"PASS")
        self.assertEqual(row["after_value_sources"]["present"],"automatic_saved_json")
        self.assertEqual(row["after_value_sources"]["required"],"user_powershell_confirmation")
        self.assertFalse(row["remediation_complete"])

    def test_lockout_requires_all_30_minute_values_for_pass(self):
        self.assertIsNone(predicate("WIN-LAB-004",{"lockout_threshold":10},self.criteria))
        self.assertFalse(predicate("WIN-LAB-004",{"lockout_threshold":10,"lockout_duration":30,"reset_minutes":15},self.criteria))
        self.assertTrue(predicate("WIN-LAB-004",{"lockout_threshold":10,"lockout_duration":30,"reset_minutes":30},self.criteria))

    def test_conflicting_current_auto_manual_values_block_pass(self):
        before,after=self.pair()
        after.document["sections"]["security_policy"]["values"]["minimum_length"]=13
        rows={row["check_id"]:row for row in build_lab_view(before,after,manual=self.manual())["results"]}
        self.assertEqual(rows["WIN-LAB-002"]["status"],"NEEDS_REVIEW")
        self.assertEqual(rows["WIN-LAB-002"]["conflicting_fields"],["minimum_length"])
        self.assertEqual(rows["WIN-LAB-002"]["automatic"]["after"]["status"],"FAIL")

    def test_no_action_claim_means_no_completed_remediation(self):
        manual=self.manual()
        manual["document"]["checks"]["WIN-LAB-002"]["remediation_performed"]=False
        self.assertFalse(self.rows(manual=manual)["WIN-LAB-002"]["remediation_complete"])

    def test_legacy_audit_remains_unverified_with_five_missing_rows(self):
        row=self.rows()["WIN-LAB-009"]
        self.assertEqual(row["status"],"NEEDS_REVIEW")
        self.assertEqual([item["status"] for item in row["audit_subcategories"]],["NOT_TESTED"]*5)

    def test_audit_identifies_each_fail_and_becomes_pass_on_retest(self):
        before,after=self.pair()
        after.document["sections"]["audit"]["values"]={"parser_verified":True,"method":"AuditQuerySystemPolicy",
            "subcategories":[{"guid":guid,"mask":3} for guid in AUDIT_GUIDS]}
        after.document["sections"]["audit"]["values"]["subcategories"][0]["mask"]=2
        row=build_lab_view(before,after)["results"][-1]
        self.assertEqual(row["status"],"FAIL")
        self.assertEqual(row["audit_subcategories"][0]["name"],"Logon")
        after.document["sections"]["audit"]["values"]["subcategories"][0]["mask"]=3
        self.assertEqual(build_lab_view(before,after)["results"][-1]["status"],"PASS")

    def test_selected_firewall_profiles_define_scope(self):
        criteria=deepcopy(self.criteria);criteria["firewall_profiles"]=["domain"]
        self.assertTrue(predicate("WIN-LAB-006",{"domain":True},criteria))
        self.assertIsNone(predicate("WIN-LAB-006",{},criteria))

    def test_manual_asset_mismatch_rejected(self):
        manual=self.manual();manual["document"]["asset_id"]="DIFFERENT"
        with self.assertRaises(WindowsPolicyError):self.rows(manual=manual)

    def test_domain_local_policy_not_confused(self):
        before,after=self.pair()
        for bundle in (before,after):bundle.document["system"].update(domain_role=3,part_of_domain=True)
        self.assertEqual(build_lab_view(before,after)["results"][1]["status"],"NEEDS_REVIEW")

    def test_manual_invalid_json_and_secret_fields_rejected(self):
        path=self.root/"invalid.json"
        for content in ('not json','{"schema_version":1,"api_secret":"CANARY"}'):
            path.write_text(content,encoding="utf-8")
            with self.assertRaises((WindowsInputError,WindowsPolicyError)) as failure:load_lab_manual(path)
            self.assertNotIn("CANARY",str(failure.exception))

    def test_cli_lab_pdf_and_strict_view_both_preserved(self):
        self.pair(True);self.manual()
        output=io.StringIO();directory=self.root/"lab-report"
        with redirect_stdout(output):
            result=main(["--mode","LAB","--before-json",str(self.root/"before.json"),"--input-json",str(self.root/"after.json"),
                "--lab-manual",str(self.root/"manual.json"),"--output-dir",str(directory)])
        self.assertEqual(result,0)
        report=json.loads((directory/"windows-report.json").read_text())
        self.assertEqual(report["summary"]["PASS"],8)
        self.assertEqual(report["advanced_validation"]["comparison"]["summary"]["UNVERIFIABLE"],9)
        text="".join(page.extract_text() for page in PdfReader(directory/"windows-report.pdf").pages)
        self.assertIn("PERSONAL LAB",text)
        self.assertIn("ADVANCED VERIFICATION",text)

    def test_lab_options_require_explicit_lab_mode(self):
        output=io.StringIO()
        with redirect_stdout(output):self.assertEqual(main(["--lab-manual","unused.json"]),2)
        self.assertIn("lab_arguments_require_lab_mode",output.getvalue())

    def test_missing_organization_policy_blocks_only_advanced_view(self):
        self.pair(True);self.manual()
        output=io.StringIO()
        with redirect_stdout(output):
            result=main(["--mode","LAB","--input-json",str(self.root/"after.json"),
                "--lab-manual",str(self.root/"manual.json"),"--policy",str(self.root/"unavailable-policy.json")])
        self.assertEqual(result,0)
        report=json.loads(output.getvalue())
        self.assertEqual(report["summary"]["PASS"],8)
        self.assertEqual(report["advanced_validation"]["status"],"ERROR")


if __name__=="__main__":unittest.main()
