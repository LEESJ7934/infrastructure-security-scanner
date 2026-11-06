"""Synthetic tests only; no Windows commands, VM, network or policy changes."""

from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config_audit.collectors import windows_server as windows
from config_audit.models import AuditAsset
from config_audit.comparison import ComparisonInputError, SnapshotRelation, compare_snapshots
from config_audit.reporting import OfflineReport, ReportResult, SourceSnapshot
from config_audit.windows_comparison import assess_collection_time, compare_windows_snapshots
from config_audit.windows_policy import load_policy, DEFAULT_POLICY
from scripts.run_windows_audit import main


def synthetic_document():
    values = {
        "guest": {"enabled": False, "matching_accounts": 1},
        "security_policy": {"minimum_length": 14, "complexity": True, "lockout_threshold": 10,
                            "lockout_duration": 15, "reset_minutes": 15, "merged_policy": True},
        "spooler": {"required": False, "role_approval": "LAB-ROLE-01", "running": False, "disabled": True},
        "firewall": {"policy_store": "ActiveStore", "domain": True, "private": True, "public": True, "service_running": True},
        "smb": {"smb1_enabled": False, "require_signing": True},
        "audit": {"parser_verified": False},
    }
    return {"schema_version": 1, "origin": "synthetic", "asset_id": "WIN-LAB-SERVER",
            "collected_at": "2026-11-06T08:00:00+09:00",
            "system": {"server_release": "2022", "product_type": 3, "domain_role": 2,
                       "part_of_domain": False, "is_64bit": True},
            "sections": {key: {"state": "COLLECTED", "values": value} for key, value in values.items()}}


class WindowsAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic.json"
        # Synthetic approval fixture only; never an operational approval.
        root = Path(self.temp.name)
        proof = root / "evidence/phase2-windows/approvals/synthetic.txt"
        proof.parent.mkdir(parents=True)
        proof.write_bytes(b'SYNTHETIC UNIT TEST APPROVAL - NOT OPERATIONAL')
        document = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        document["approval"].update(status="APPROVED", authority="SYNTHETIC-TEST", basis="SYNTHETIC-ONLY",
                                     approved_at="2020-01-01T00:00:00Z", evidence={"path":"synthetic.txt", "sha256":hashlib.sha256(proof.read_bytes()).hexdigest()})
        document["approval"]["scope"]["asset_ids"] = ["WIN-LAB-SERVER"]
        document["password"].update(duration_minutes=15, reset_minutes=15)
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(document), encoding="utf-8")
        self.policy = load_policy(policy_path, project_root=root, acknowledge_approval=True)

    def bundle(self, doc=None, *, verified=True):
        raw = json.dumps(doc if doc is not None else synthetic_document()).encode()
        self.path.write_bytes(raw)
        return windows.load_bundle(self.path, expected_sha256=hashlib.sha256(raw).hexdigest() if verified else None)

    def results(self, doc=None, *, verified=True):
        doc = deepcopy(doc if doc is not None else synthetic_document())
        doc["system"].setdefault("build_number", "20348")
        output = windows.audit(self.bundle(doc, verified=verified), asset_id="WIN-LAB-SERVER", synthetic=True, policy=self.policy)
        self.assertEqual(output["results"], [])
        return {row["check_id"]: row for row in output["synthetic_results"]}

    def test_good_internal_settings_and_pending_audit(self):
        rows = self.results()
        self.assertEqual([rows[f"WIN-LAB-{i:03}"]["status"] for i in range(1, 9)], ["PASS"] * 8)
        self.assertEqual(rows["WIN-LAB-009"]["status"], "NEEDS_REVIEW")

    def test_each_vulnerable_setting(self):
        changes = [("guest", "enabled", True, 1), ("security_policy", "minimum_length", 8, 2),
                   ("security_policy", "complexity", False, 3), ("security_policy", "lockout_threshold", 0, 4),
                   ("spooler", "running", True, 5), ("firewall", "public", False, 6),
                   ("smb", "smb1_enabled", True, 7), ("smb", "require_signing", False, 8)]
        for section, key, value, number in changes:
            with self.subTest(check=number):
                doc = synthetic_document()
                doc["sections"][section]["values"][key] = value
                self.assertEqual(self.results(doc)[f"WIN-LAB-{number:03}"]["status"], "FAIL")

    def test_missing_sections_not_tested(self):
        doc = synthetic_document()
        doc["sections"] = {}
        self.assertTrue(all(row["status"] == "NOT_TESTED" for row in self.results(doc).values()))

    def test_collected_missing_fields_needs_review(self):
        doc = synthetic_document()
        for section in doc["sections"].values():
            section["values"] = {}
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(doc).values()))

    def test_permission_denied_is_error(self):
        doc = synthetic_document()
        doc["sections"]["smb"] = {"state": "ERROR", "error_code": "permission_denied"}
        self.assertEqual(self.results(doc)["WIN-LAB-007"]["status"], "ERROR")

    def test_unavailable_command_is_error(self):
        doc = synthetic_document()
        doc["sections"]["firewall"] = {"state": "ERROR", "error_code": "command_unavailable"}
        self.assertEqual(self.results(doc)["WIN-LAB-006"]["status"], "ERROR")

    def test_unsupported_version_not_applicable(self):
        doc = synthetic_document()
        doc["system"]["server_release"] = "2016"
        self.assertTrue(all(row["status"] == "NOT_APPLICABLE" for row in self.results(doc).values()))

    def test_candidate_versions_not_claimed_as_vm_validation(self):
        for version in ("2019", "2022", "2025"):
            doc = synthetic_document()
            doc["system"]["server_release"] = version
            output = windows.audit(self.bundle(doc), asset_id=doc["asset_id"], synthetic=True)
            self.assertIn("2019_2025_not_vm_validated_2022_build20348_lab_only", output["limitations"])

    def test_workstation_is_not_server(self):
        doc = synthetic_document()
        doc["system"].update(product_type=1, domain_role=0)
        self.assertTrue(all(row["status"] == "NOT_APPLICABLE" for row in self.results(doc).values()))

    def test_unknown_version_needs_review(self):
        doc = synthetic_document()
        doc["system"]["server_release"] = None
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(doc).values()))

    def test_unknown_product_type_needs_review(self):
        doc = synthetic_document()
        doc["system"]["product_type"] = None
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(doc).values()))

    def test_numeric_product_build_metadata_only(self):
        doc = synthetic_document()
        doc["system"].update(os_version="10.0.20348", build_number="20348")
        self.assertEqual(self.results(doc)["WIN-LAB-001"]["build_number"], "20348")
        doc["system"]["os_version"] = "SECRET_CANARY"
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)

    def test_inconsistent_domain_context_needs_review(self):
        doc = synthetic_document()
        doc["system"]["part_of_domain"] = True
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(doc).values()))

    def test_domain_member_password_values_not_effective_domain_proof(self):
        doc = synthetic_document()
        doc["system"].update(domain_role=3, part_of_domain=True)
        rows = self.results(doc)
        for number in (2, 3, 4):
            row = rows[f"WIN-LAB-{number:03}"]
            self.assertEqual(row["status"], "NEEDS_REVIEW")
            self.assertIn("domain_or_role_effective_policy_not_verified", row["unmet_conditions"])
        self.assertEqual(rows["WIN-LAB-001"]["status"], "PASS")

    def test_dc_local_guest_not_applicable(self):
        doc = synthetic_document()
        doc["system"].update(product_type=2, domain_role=5, part_of_domain=True)
        rows = self.results(doc)
        self.assertEqual(rows["WIN-LAB-001"]["status"], "NOT_APPLICABLE")
        self.assertEqual(rows["WIN-LAB-002"]["status"], "NEEDS_REVIEW")

    def test_no_64bit_claim_needs_review(self):
        doc = synthetic_document()
        doc["system"]["is_64bit"] = False
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(doc).values()))

    def test_guest_duplicate_not_arbitrarily_selected(self):
        doc = synthetic_document()
        doc["sections"]["guest"]["values"]["matching_accounts"] = 2
        self.assertEqual(self.results(doc)["WIN-LAB-001"]["status"], "NEEDS_REVIEW")

    def test_no_merged_policy_no_password_pass(self):
        doc = synthetic_document()
        doc["sections"]["security_policy"]["values"]["merged_policy"] = False
        for number in (2, 3, 4):
            self.assertEqual(self.results(doc)[f"WIN-LAB-{number:03}"]["status"], "NEEDS_REVIEW")

    def test_lockout_reset_greater_than_duration_fails(self):
        doc = synthetic_document()
        doc["sections"]["security_policy"]["values"]["reset_minutes"] = 30
        self.assertEqual(self.results(doc)["WIN-LAB-004"]["status"], "FAIL")

    def test_spooler_role_not_assumed(self):
        doc = synthetic_document()
        doc["sections"]["spooler"]["values"].update(required=None, role_approval=None)
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_approved_required_spooler_not_applicable(self):
        doc = synthetic_document()
        doc["sections"]["spooler"]["values"]["required"] = True
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NOT_APPLICABLE")

    def test_unapproved_required_spooler_not_na(self):
        doc = synthetic_document()
        doc["sections"]["spooler"]["values"].update(required=True, role_approval=None)
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_unconfirmed_approval_marker_not_accepted(self):
        doc = synthetic_document()
        doc["sections"]["spooler"]["values"]["role_approval"] = "UNCONFIRMED"
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def absent_spooler(self):
        doc = synthetic_document()
        doc["sections"]["spooler"]["values"] = {
            "present": False, "native_error_code": 1060,
            "required": False, "role_approval": "LAB-ROLE-01",
            "feature_query_state": "COLLECTED", "print_services_installed": False,
            "print_server_installed": False,
        }
        return doc

    def test_confirmed_absence_and_approved_role_is_na_never_pass(self):
        row = self.results(self.absent_spooler())["WIN-LAB-005"]
        self.assertEqual(row["status"], "NOT_APPLICABLE")
        self.assertEqual(row["rule_version"], "0.2")
        self.assertEqual(self.results()["WIN-LAB-008"]["rule_version"], "0.1")

    def test_absence_without_approval_remains_review(self):
        doc = self.absent_spooler()
        doc["sections"]["spooler"]["values"].pop("role_approval")
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_absence_of_required_service_needs_review(self):
        doc = self.absent_spooler()
        doc["sections"]["spooler"]["values"]["required"] = True
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_absence_without_feature_or_native_evidence_needs_review(self):
        for field in ("feature_query_state", "native_error_code", "print_services_installed", "print_server_installed"):
            doc = self.absent_spooler()
            if field == "feature_query_state":
                doc["sections"]["spooler"]["values"].pop("print_services_installed")
                doc["sections"]["spooler"]["values"].pop("print_server_installed")
            doc["sections"]["spooler"]["values"].pop(field)
            self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_feature_lookup_error_is_separate_from_confirmed_absence(self):
        doc = self.absent_spooler()
        values = doc["sections"]["spooler"]["values"]
        values.pop("print_services_installed")
        values.pop("print_server_installed")
        values.update(feature_query_state="ERROR", feature_error_code="permission_denied")
        row = self.results(doc)["WIN-LAB-005"]
        self.assertEqual(row["collection_status"], "COLLECTED")
        self.assertEqual(row["status"], "NEEDS_REVIEW")
        self.assertEqual(row["feature_collection_status"], "ERROR")
        self.assertEqual(row["feature_error_code"], "permission_denied")

    def test_installed_print_role_prevents_absence_na(self):
        doc = self.absent_spooler()
        doc["sections"]["spooler"]["values"]["print_server_installed"] = True
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_absence_without_verified_integrity_not_na(self):
        self.assertEqual(self.results(self.absent_spooler(), verified=False)["WIN-LAB-005"]["status"], "NEEDS_REVIEW")

    def test_old_query_failed_not_reinterpreted_as_absence(self):
        doc = synthetic_document()
        doc["sections"]["spooler"] = {"state": "ERROR", "error_code": "query_failed"}
        self.assertEqual(self.results(doc)["WIN-LAB-005"]["status"], "ERROR")

    def test_absence_contradictions_rejected(self):
        for key, value in (("running", True), ("disabled", False), ("native_error_code", 5)):
            doc = self.absent_spooler()
            doc["sections"]["spooler"]["values"][key] = value
            with self.assertRaises(windows.WindowsInputError):
                self.bundle(doc)

    def test_missing_time_rejected_without_fabricating_timestamp(self):
        doc = synthetic_document()
        del doc["collected_at"]
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)

    def test_collection_clock_assessment_does_not_overwrite_settings(self):
        doc = synthetic_document()
        doc["collected_at"] = "2999-01-01T00:00:00Z"
        report = windows.audit(self.bundle(doc), asset_id="WIN-LAB-SERVER", synthetic=True)
        self.assertEqual(report["collection_time_validation"]["status"], "UNVERIFIABLE")
        self.assertEqual(report["synthetic_results"][7]["status"], "PASS")
        self.assertEqual(report["synthetic_results"][7]["collected_at"], "2999-01-01T00:00:00Z")
        self.assertEqual(report["synthetic_results"][7]["time_basis"], "reanalysis_time")

    def test_firewall_notconfigured_not_true(self):
        doc = synthetic_document()
        doc["sections"]["firewall"]["values"]["domain"] = None
        self.assertEqual(self.results(doc)["WIN-LAB-006"]["status"], "NEEDS_REVIEW")

    def test_boolean_not_integer_or_string(self):
        for value in (1, "True"):
            doc = synthetic_document()
            doc["sections"]["smb"]["values"]["smb1_enabled"] = value
            with self.assertRaises(windows.WindowsInputError):
                self.bundle(doc)

    def test_unknown_collection_state_rejected(self):
        doc = synthetic_document()
        doc["sections"]["smb"]["state"] = "PASS"
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)

    def test_unexpected_container_types_have_safe_errors(self):
        for field in ("origin", "state", "error_code"):
            for value in ([], {}):
                doc = synthetic_document()
                target = doc if field == "origin" else doc["sections"]["smb"]
                target[field] = value
                with self.assertRaises(windows.WindowsInputError):
                    self.bundle(doc)

    def test_spoofed_not_applicable_section_not_pass(self):
        doc = synthetic_document()
        doc["sections"]["smb"] = {"state": "NOT_APPLICABLE"}
        self.assertEqual(self.results(doc)["WIN-LAB-007"]["status"], "NEEDS_REVIEW")

    def test_audit_parser_flag_cannot_force_pass(self):
        doc = synthetic_document()
        doc["sections"]["audit"]["values"]["parser_verified"] = True
        self.assertEqual(self.results(doc)["WIN-LAB-009"]["status"], "NEEDS_REVIEW")

    def test_missing_expected_hash_remains_not_verified(self):
        bundle = self.bundle(verified=False)
        self.assertEqual(bundle.integrity, "NOT_VERIFIED")
        self.assertTrue(all(row["status"] == "NEEDS_REVIEW" for row in self.results(verified=False).values()))

    def test_tampered_source_rejected_and_unchanged(self):
        bundle = self.bundle()
        self.path.write_bytes(self.path.read_bytes() + b" ")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(windows.WindowsInputError, "sha256_mismatch"):
            windows.load_bundle(self.path, expected_sha256=bundle.sha256)
        self.assertEqual(self.path.read_bytes(), before)

    def test_timestamp_semantics_preserved(self):
        rows = self.results()
        self.assertEqual(rows["WIN-LAB-001"]["collected_at"], "2026-11-06T08:00:00+09:00")
        self.assertNotEqual(rows["WIN-LAB-001"]["checked_at"], rows["WIN-LAB-001"]["collected_at"])

    def test_naive_timestamp_rejected(self):
        doc = synthetic_document()
        doc["collected_at"] = "2026-11-06T08:00:00"
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)

    def test_asset_binding_required(self):
        with self.assertRaisesRegex(windows.WindowsInputError, "asset_binding_mismatch"):
            windows.audit(self.bundle(), asset_id="OTHER", synthetic=True)

    def test_origin_must_match_explicit_mode(self):
        with self.assertRaisesRegex(windows.WindowsInputError, "origin_mode_mismatch"):
            windows.audit(self.bundle(), asset_id="WIN-LAB-SERVER")

    def test_default_cli_only_preparation(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["mode"], "preparation_only")
        self.assertEqual(len(result["results"]), 9)
        self.assertTrue(all(row["status"] == "NOT_TESTED" for row in result["results"]))

    def test_cli_synthetic_channel_only(self):
        bundle = self.bundle()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--input-json", str(self.path), "--expected-sha256", bundle.sha256, "--synthetic"]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["results"], [])
        self.assertEqual(len(result["synthetic_results"]), 9)

    def test_malformed_json_and_missing_file_safe_cli(self):
        for raw in (b"not-json SECRET_CANARY", b'{"a":1,"a":2}', b'{"v":NaN}'):
            self.path.write_bytes(raw)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--input-json", str(self.path)]), 2)
            self.assertNotIn("SECRET_CANARY", output.getvalue())
        self.path.unlink()
        with self.assertRaisesRegex(windows.WindowsInputError, "input_unavailable"):
            windows.load_bundle(self.path)

    def test_secret_fields_rejected_and_not_printed(self):
        for key in ("password", "Authorization", "api_secret", "private_key"):
            doc = synthetic_document()
            doc[key] = "SECRET_CANARY"
            self.path.write_text(json.dumps(doc), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--input-json", str(self.path), "--synthetic"]), 2)
            self.assertNotIn("SECRET_CANARY", output.getvalue())
            self.assertNotIn(key, output.getvalue())

    def test_nested_raw_or_error_text_not_allowed(self):
        doc = synthetic_document()
        doc["sections"]["smb"]["raw"] = "SECRET_CANARY"
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)
        doc = synthetic_document()
        doc["sections"]["smb"]["error_code"] = "SECRET_CANARY"
        with self.assertRaises(windows.WindowsInputError):
            self.bundle(doc)

    def test_bounded_file_read(self):
        self.path.write_bytes(b" " * (windows.MAX_BYTES + 1))
        with self.assertRaisesRegex(windows.WindowsInputError, "input_too_large"):
            windows.load_bundle(self.path)

    def test_common_engine_used_for_all_checks(self):
        with patch.object(windows, "evaluate", wraps=windows.evaluate) as evaluator:
            self.results()
            self.assertEqual(evaluator.call_count, 9)

    def test_common_report_adapter_does_not_promote_simulations(self):
        report = windows.audit(self.bundle(), asset_id="WIN-LAB-SERVER", synthetic=True)
        snapshot = windows.to_report_snapshot(report, snapshot_id="phase2-sim-01")
        self.assertEqual(snapshot.day, 0)
        self.assertTrue(all(row.automatic is None and row.manual is None for row in snapshot.results))
        self.assertTrue(all("synthetic_simulation" in row.analyses for row in snapshot.results))
        self.assertEqual(len(snapshot.to_dict()["results"]), 9)

    def test_actual_format_adapter_and_audit_do_not_mutate_source(self):
        doc = synthetic_document()
        doc["origin"] = "local_server_readonly"  # mocked format, NOT an actual VM result
        original = deepcopy(doc)
        bundle = self.bundle(doc)
        report = windows.audit(bundle, asset_id=doc["asset_id"])
        snapshot = windows.to_report_snapshot(report, snapshot_id="mocked-server-01")
        self.assertTrue(all(row.automatic is not None for row in snapshot.results))
        self.assertEqual(snapshot.results[0].automatic["evidence_references"][0]["reference"], report["results"][0]["evidence_reference"])
        self.assertEqual(bundle.document, original)
        self.assertEqual(self.path.read_bytes(), json.dumps(doc).encode())

    def test_collector_asset_mismatch_is_error_observation(self):
        collector = windows.WindowsServerCollector(self.bundle())
        observation = collector.collect(AuditAsset("OTHER", "windows_server", "2022"), "WIN-LAB-001")
        self.assertTrue(observation.collection_error)


class WindowsChronologyTests(unittest.TestCase):
    """Mocked saved results/index; no real-device verdicts are generated."""
    reference = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)

    def report(self, before="2026-11-06T07:00:00Z", after="2026-11-06T07:30:27Z"):
        snapshots, entries = [], []
        for name, status, capture in (("before", "FAIL", before), ("after", "PASS", after)):
            channel = {"status": status, "scope": "inbound_smb_server_signing_not_sessions",
                       "product": "windows_server", "version": "2022", "os_version": "10.0.20348",
                       "build_number": "20348", "product_type": 3, "domain_role": 2, "part_of_domain": False,
                       "diagnostic_source": "phase2_windows_server", "verification_method": "saved_readonly_settings",
                       "rule_version": "0.1", "collected_at": capture,
                       # Analysis order is increasing even when VM clock is not.
                       "checked_at": "2026-11-06T10:00:00Z" if name == "before" else "2026-11-06T10:01:00Z"}
            row = ReportResult("SYNTHETIC-SERVER", "WIN-LAB-008", "0.1", channel)
            snapshots.append(SourceSnapshot(name, 0, "phase2_windows_server", "windows_server_v1", (row,)))
            digest = hashlib.sha256(name.encode()).hexdigest()
            entries.append({"snapshot_id": name, "asset_id": row.asset_id, "check_id": row.check_id,
                            "rule_version": "0.1", "channel": "automatic", "status": "VERIFIED",
                            "exists": True, "actual_sha256": digest, "expected_sha256": digest, "hash_comparison": "MATCH"})
        return OfflineReport("2026-11-06T11:00:00Z", tuple(snapshots), evidence_index={"entries": entries})

    def result(self, report):
        return compare_windows_snapshots(report, [SnapshotRelation("before", "after")], reference_at=self.reference)["pairs"][0]["results"][0]

    def test_normal_capture_order_uses_capture_not_reanalysis(self):
        row = self.result(self.report())
        self.assertEqual(row["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(row["diagnostic_time"]["before"], "2026-11-06T07:00:00Z")
        self.assertFalse(row["remediation_history_confirmed"])
        self.assertEqual(row["reanalysis_time"]["before"], "2026-11-06T10:00:00Z")

    def test_generic_comparison_cannot_treat_reanalysis_as_capture(self):
        report = self.report()
        for snapshot in report.snapshots:
            snapshot.results[0].automatic["time_basis"] = "reanalysis_time"
        result = compare_snapshots(report, [SnapshotRelation("before", "after")]).to_dict()
        self.assertEqual(result["pairs"][0]["results"][0]["comparison_result"], "UNVERIFIABLE")

    def test_future_ordered_capture_unverifiable_not_improvement(self):
        row = self.result(self.report(before="2026-11-07T07:00:00Z", after="2026-11-07T08:00:00Z"))
        self.assertEqual(row["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(row["observed_change"])
        self.assertIn("before_collection_time_in_future", row["unmet_conditions"])
        self.assertEqual(row["recorded_status_transition"], "FAIL_TO_PASS")
        result = compare_windows_snapshots(self.report(before="2026-11-07T07:00:00Z", after="2026-11-07T08:00:00Z"),
                                          [SnapshotRelation("before", "after")], reference_at=self.reference)
        self.assertEqual(result["recorded_status_transition_summary"]["FAIL_TO_PASS"], 1)
        self.assertEqual(result["summary"]["IMPROVED_OBSERVED"], 0)

    def test_reported_lab_time_reversal_incomparable_and_preserved(self):
        before, after = "2026-11-07T00:12:16.4773242+00:00", "2026-11-06T07:30:27.6763422+00:00"
        report = self.report(before, after)
        original = deepcopy(report.to_dict())
        row = self.result(report)
        self.assertEqual(row["comparison_result"], "INCOMPARABLE")
        self.assertEqual(row["recorded_status_transition"], "FAIL_TO_PASS")
        self.assertFalse(row["collection_chronology"]["strictly_increasing"])
        self.assertEqual(row["diagnostic_time"]["before"], before)
        self.assertEqual(report.to_dict(), original)

    def test_reversed_historical_time_still_incomparable(self):
        row = self.result(self.report(before="2026-11-06T08:00:00Z", after="2026-11-06T07:00:00Z"))
        self.assertEqual(row["comparison_result"], "INCOMPARABLE")
        self.assertIn("collection_time_not_strictly_increasing", row["unmet_conditions"])

    def test_equal_capture_time_not_strict_before_after(self):
        row = self.result(self.report(after="2026-11-06T07:00:00Z"))
        self.assertEqual(row["comparison_result"], "INCOMPARABLE")

    def test_missing_capture_cannot_fall_back_to_analysis_time(self):
        row = self.result(self.report(before=None))
        self.assertEqual(row["comparison_result"], "UNVERIFIABLE")
        self.assertIn("before_collection_time_missing_or_invalid", row["unmet_conditions"])

    def test_naive_and_unknown_offset_times_not_assumed_utc(self):
        for value in ("2026-11-06T07:00:00", "2026-11-06T07:00:00-00:00"):
            self.assertEqual(self.result(self.report(before=value))["comparison_result"], "UNVERIFIABLE")

    def test_offsets_compared_as_instants(self):
        row = self.result(self.report(before="2026-11-06T15:00:00+09:00", after="2026-11-06T07:00:00Z"))
        self.assertEqual(row["comparison_result"], "IMPROVED_OBSERVED")

    def test_invalid_reference_clock_rejected(self):
        with self.assertRaises(ComparisonInputError):
            assess_collection_time("2026-11-06T07:00:00Z", reference_at=datetime(2026, 11, 6))

    def test_no_evidence_index_not_fabricated(self):
        report = self.report()
        report = OfflineReport(report.generated_at, report.snapshots)
        row = self.result(report)
        self.assertEqual(row["comparison_result"], "UNVERIFIABLE")
        self.assertIn("before_evidence_index_not_supplied", row["unmet_conditions"])

    def test_manual_or_day5_inputs_not_silently_reinterpreted(self):
        report = self.report()
        with self.assertRaises(ComparisonInputError):
            compare_windows_snapshots(report, [SnapshotRelation("before", "after", "manual", "automatic")])
        wrong = SourceSnapshot("before", 4, "day4", "results", report.snapshots[0].results)
        with self.assertRaises(ComparisonInputError):
            self.result(OfflineReport(report.generated_at, (wrong, report.snapshots[1])))


if __name__ == "__main__":
    unittest.main()
