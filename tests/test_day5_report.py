"""Offline reporting contract tests; no collectors, subprocesses or network."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config_audit.reporting import (
    ReportInputError, integrate, load_snapshot, normalize,
)
from config_audit.statuses import AuditStatus


CHECKED = "2026-11-04T10:26:11.949010+00:00"
GENERATED = "2026-11-06T09:00:00+09:00"


def row(check="FW-06", state="NOT_TESTED", asset="lab/firewall"):
    return dict(asset_id=asset, check_id=check, rule_version="1", status=state,
                execution_id="saved-execution", checked_at=CHECKED)


def day2():
    return {name: {"checks": [row(f"{name}-01", "PASS", name), row(f"{name}-02", "FAIL", name)],
                   "settings": {"passwordauthentication" if name == "ubuntu" else "version":
                                {"status": "COLLECTED", "value": "DO_NOT_EXPORT"}}}
            for name in ("ubuntu", "mysql")}


def day4():
    fw6 = row()
    fw6.update(automatic_status="NOT_TESTED", manual_verification={
        "status": "PASS", "reported_status": "PASS", "validation_status": "VALID",
        "attached": True, "verified_at": CHECKED, "time_basis": "artifact_review",
        "scope": "windows_to_alpine_icmp_lab_only", "sources": [],
    })
    fw4 = row("FW-04", "ERROR")
    fw4.update(api_results={"rules": {"status": "ERROR", "http_status": 403,
                                     "endpoint": "/api/firewall/filter/search_rule", "stage": "http"}},
               pf_snapshot={"status": "NEEDS_REVIEW", "rule_version": "pf-snapshot-1",
                            "checked_at": CHECKED, "scope": "top_level_only",
                            "integrity": {"rules": {"sha256": "a" * 64, "verified": True}},
                            "complete_effective_ruleset": False,
                            "missing_conditions": ["anchor_coverage_unverified"]})
    fw5 = row("FW-05", "NEEDS_REVIEW")
    fw5["log_rule_evidence"] = {
        "status": "NEEDS_REVIEW", "rule_version": "log-pf-1",
        "automatic_collection": {"status": "COLLECTED", "http_status": 200},
        "api_rule_id_mapping": {"status": "ERROR", "http_status": 403},
        "rule_mapping": {"status": "NEEDS_REVIEW", "identity_match": True,
                         "historical_continuity_verified": False},
        "limitations": ["ruleset_generation_not_proven"],
        "integrity": {},
        "time_comparison": {"timezone_verified": False, "wall_clock_window_match": None},
    }
    return {"results": [fw4, fw5, fw6]}


class OfflineReportingTests(unittest.TestCase):
    def convert(self, document, day=4, **kwargs):
        return normalize(document, day=day, source="saved/input.json", snapshot_id="snapshot", **kwargs)

    def test_day2_existing_shape_and_no_settings_values(self):
        snapshot = self.convert(day2(), day=2)
        self.assertEqual(len(snapshot.results), 4)
        self.assertEqual(snapshot.results[1].automatic["status"], "FAIL")
        self.assertEqual(snapshot.collection["mysql"]["version"]["status"], "COLLECTED")
        self.assertEqual(snapshot.collection["ubuntu"]["passwordauthentication"]["status"], "COLLECTED")
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(snapshot.to_dict()))

    def test_day3_twelve_results_and_opaque_evidence(self):
        rows = [row(f"{product}-{index:02}", "PASS", product)
                for product in ("suricata", "waf") for index in range(1, 7)]
        rows[0]["evidence_reference"] = "container:/tmp/eve.json"
        snapshot = self.convert({"results": rows}, day=3)
        self.assertEqual(len(snapshot.results), 12)
        ref = snapshot.results[0].automatic["evidence_references"][0]
        self.assertEqual(ref["reference"], "container:/tmp/eve.json")
        self.assertEqual(ref["verification"], "NOT_VERIFIED")

    def test_day4_nested_channels_and_independent_api_states(self):
        fw4, fw5, _ = self.convert(day4()).results
        self.assertEqual(fw4.automatic["status"], "ERROR")
        self.assertEqual(fw4.automatic["api_results"]["rules"]["http_status"], 403)
        self.assertEqual(fw4.analyses["pf_snapshot"]["status"], "NEEDS_REVIEW")
        self.assertFalse(fw4.analyses["pf_snapshot"]["complete_effective_ruleset"])
        claim = fw4.analyses["pf_snapshot"]["source_integrity_claims"]["rules"]
        self.assertTrue(claim["source_reported_verified"])
        self.assertEqual(claim["verification"], "NOT_VERIFIED")
        log = fw5.analyses["log_rule_evidence"]
        self.assertEqual(log["automatic_collection"]["status"], "COLLECTED")
        self.assertEqual(log["api_rule_id_mapping"]["http_status"], 403)
        self.assertFalse(log["rule_mapping"]["historical_continuity_verified"])
        self.assertIsNone(log["time_comparison"]["wall_clock_window_match"])

    def test_manual_pass_does_not_override_automatic_not_tested(self):
        fw6 = self.convert(day4()).results[2]
        self.assertEqual(fw6.automatic["status"], "NOT_TESTED")
        self.assertEqual(fw6.manual["status"], "PASS")
        self.assertEqual(fw6.manual["validation_status"], "VALID")

    def test_all_audit_statuses_preserved(self):
        for state in AuditStatus:
            with self.subTest(status=state):
                result = self.convert({"results": [row(state=state.value)]}).results[0]
                self.assertEqual(result.automatic["status"], state.value)

    def test_manual_document_is_a_claim_not_synthetic_automatic_result(self):
        document = {"schema_version": 1, "asset_id": "firewall", "checks": [{
            "check_id": "FW-06", "reported_status": "PASS", "verified_at": CHECKED,
            "time_basis": "artifact_review", "scope": "icmp_lab_only", "sources": [
                {"path": "restore.txt", "sha256": "a" * 64, "kind": "test_output"}]}]}
        snapshot = self.convert(document, input_kind="manual")
        record = snapshot.results[0]
        self.assertIsNone(record.automatic)
        self.assertIsNone(record.rule_version)
        self.assertEqual(record.manual["status"], "PASS")
        self.assertNotIn("attached", record.manual)
        self.assertNotIn("validation_status", record.manual)
        self.assertEqual(record.manual["evidence_references"][0]["verification"], "NOT_VERIFIED")
        self.assertIn("automatic_results_not_supplied", snapshot.diagnostics)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = load_snapshot(Path(directory) / "missing.json", day=4, snapshot_id="absent")
        self.assertEqual(snapshot.import_status, "ERROR")
        self.assertEqual(snapshot.diagnostics, ("input_missing",))
        self.assertFalse(snapshot.results)

    def load_text(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.json"
            path.write_text(value, encoding="utf-8")
            return load_snapshot(path, day=4, snapshot_id="bad")

    def test_invalid_json(self):
        self.assertEqual(self.load_text('{"secret":').diagnostics, ("json_invalid",))

    def test_duplicate_json_keys(self):
        self.assertEqual(self.load_text('{"results": [], "results": []}').diagnostics,
                         ("duplicate_json_key",))

    def test_nonfinite_json_rejected(self):
        self.assertEqual(self.load_text('{"results": [], "raw": NaN}').import_status, "ERROR")

    def test_invalid_status(self):
        for value in ("OK", None, [], 1):
            with self.subTest(value=value), self.assertRaisesRegex(ReportInputError, "status_invalid"):
                self.convert({"results": [row(state=value)]})

    def test_required_fields_missing(self):
        for field in ("asset_id", "check_id", "rule_version", "execution_id", "checked_at", "status"):
            item = row()
            del item[field]
            with self.subTest(field=field), self.assertRaises(ReportInputError):
                self.convert({"results": [item]})

    def test_timestamp_semantics_and_no_reanalysis(self):
        document = day4()
        document["results"][2]["manual_verification"]["verified_at"] = "2026-11-05T17:53:39"
        report = integrate([self.convert(document)], generated_at=GENERATED).to_dict()
        record = report["snapshots"][0]["results"][2]
        self.assertEqual(record["automatic"]["checked_at"], CHECKED)
        self.assertEqual(record["manual"]["verified_at"], "2026-11-05T17:53:39")
        self.assertEqual(record["manual"]["time_basis"], "artifact_review")
        self.assertEqual(report["generated_at"], GENERATED)
        self.assertIsNone(report["reanalysis_at"])

    def test_same_asset_check_different_snapshots_preserved(self):
        before = self.convert(day2(), day=2)
        after = normalize(day2(), day=2, snapshot_id="after", source="day2-after.json")
        report = integrate([before, after])
        self.assertEqual(sum(len(source.results) for source in report.snapshots), 8)
        self.assertEqual(report.snapshots[0].results[0].asset_id, report.snapshots[1].results[0].asset_id)

    def test_duplicate_within_snapshot_rejected_without_merging(self):
        item = row()
        with self.assertRaisesRegex(ReportInputError, "duplicate_result_identity"):
            self.convert({"results": [item, deepcopy(item)]})

    def test_duplicate_snapshot_ids_rejected(self):
        snapshot = self.convert(day4())
        with self.assertRaisesRegex(ReportInputError, "duplicate_snapshot_id"):
            integrate([snapshot, snapshot])

    def test_rule_versions_and_assets_disambiguate(self):
        items = [row(), row(asset="other"), {**row(), "rule_version": "2"}]
        self.assertEqual(len(self.convert({"results": items}).results), 3)

    def test_conflicting_automatic_status_is_not_overwritten(self):
        item = row()
        item["automatic_status"] = "PASS"
        with self.assertRaisesRegex(ReportInputError, "automatic_status_conflict"):
            self.convert({"results": [item]})

    def test_unknown_raw_fields_never_exported(self):
        document = day4()
        document["results"][0].update(observed_value="RAW_SECRET", api_key="KEY_SECRET")
        document["results"][0]["api_results"]["rules"]["Authorization"] = "AUTH_SECRET"
        exported = json.dumps(self.convert(document).to_dict())
        for value in ("RAW_SECRET", "KEY_SECRET", "AUTH_SECRET"):
            self.assertNotIn(value, exported)

    def test_sensitive_text_rejected_with_fixed_safe_error(self):
        item = row()
        item["reason"] = "Authorization: Bearer PRIVATE_VALUE"
        snapshot = self.load_text(json.dumps({"results": [item]}))
        self.assertEqual(snapshot.diagnostics, ("sensitive_metadata_rejected",))
        self.assertNotIn("PRIVATE_VALUE", json.dumps(snapshot.to_dict()))

    def test_no_file_access_during_normalize_and_evidence_not_verified(self):
        item = row()
        item["evidence_reference"] = "never-read.txt"
        with patch.object(Path, "open", side_effect=AssertionError("unexpected file access")):
            record = self.convert({"results": [item]}).results[0]
        self.assertEqual(record.automatic["evidence_references"][0]["verification"], "NOT_VERIFIED")

    def test_bad_optional_analysis_status_rejected(self):
        document = day4()
        document["results"][1]["log_rule_evidence"]["status"] = "SUCCESS"
        with self.assertRaisesRegex(ReportInputError, "status_invalid"):
            self.convert(document)

    def test_no_invented_risk_or_recommendation(self):
        record = self.convert({"results": [row()]}).results[0]
        self.assertIsNone(record.risk)
        self.assertIsNone(record.recommendation)

    def test_explicit_risk_and_recommendation_preserved(self):
        item = {**row(), "risk": "HIGH", "recommendation": "Review the approved policy."}
        result = self.convert({"results": [item]}).results[0]
        self.assertEqual(result.risk, "HIGH")
        self.assertEqual(result.recommendation, item["recommendation"])

    def test_raw_artifacts_are_references_without_verdicts_or_file_reads(self):
        with patch.object(Path, "open", side_effect=AssertionError("artifact must not be read")):
            report = integrate([], evidence_sources=[{"path": "rules.txt", "kind": "pf_snapshot"},
                                                     {"path": "logs.json", "kind": "raw_firewall_log"}]).to_dict()
        self.assertEqual(report["snapshots"], [])
        self.assertEqual(len(report["evidence_sources"]), 2)
        self.assertTrue(all(item["verification"] == "NOT_VERIFIED" for item in report["evidence_sources"]))

    def test_bad_timestamps_are_rejected(self):
        for value in ("yesterday", "2026-11-06", "2026-13-05T17:53:39", None):
            with self.subTest(value=value), self.assertRaises(ReportInputError):
                self.convert({"results": [{**row(), "checked_at": value}]})

    def test_oversized_file_rejected(self):
        with patch("config_audit.reporting.MAX_BYTES", 5):
            self.assertEqual(self.load_text('{"results": []}').diagnostics, ("input_too_large",))

    def test_bad_structure_and_empty_results(self):
        for document in ([], {"results": {}}, {"results": [None]}):
            with self.subTest(document=document), self.assertRaises(ReportInputError):
                self.convert(document)
        self.assertEqual(self.convert({"results": []}).diagnostics, ("no_results_in_input",))


ROOT = Path(__file__).resolve().parents[1]


class LocalStoredResultsTests(unittest.TestCase):
    @unittest.skipUnless(all((ROOT / name).is_file() for name in
                             ("logs/day2-before.json", "logs/day2-after.json", "logs/day3-final.json")),
                         "Local ignored Day2/3 saved results are not included in this checkout")
    def test_actual_saved_day2_and_day3_inputs(self):
        snapshots = [load_snapshot(ROOT / name, day=day, snapshot_id=identifier)
                     for name, day, identifier in (("logs/day2-before.json", 2, "before"),
                                                   ("logs/day2-after.json", 2, "after"),
                                                   ("logs/day3-final.json", 3, "day3-final"))]
        self.assertEqual([s.import_status for s in snapshots], ["LOADED"] * 3)
        self.assertEqual([len(s.results) for s in snapshots], [4, 4, 12])
        self.assertEqual(sum(r.automatic["status"] == "FAIL" for r in snapshots[0].results), 2)
        self.assertTrue(all(r.automatic["status"] == "PASS" for r in snapshots[1].results))
        self.assertTrue(all(r.automatic["evidence_references"] for r in snapshots[2].results))
        self.assertEqual(len(integrate(snapshots).snapshots), 3)

    def test_actual_day4_manual_claims_without_auto_fabrication(self):
        snapshot = load_snapshot(ROOT / "evidence/day4/manual.json", day=4,
                                 snapshot_id="day4-manual", input_kind="manual")
        self.assertEqual(snapshot.import_status, "LOADED")
        claims = {r.check_id: r for r in snapshot.results}
        self.assertEqual(len(claims), 5)
        for check_id in ("FW-02", "FW-03", "FW-06"):
            self.assertEqual(claims[check_id].manual["status"], "PASS")
        for check_id in ("FW-04", "FW-05"):
            self.assertEqual(claims[check_id].manual["status"], "NEEDS_REVIEW")
        self.assertTrue(all(r.automatic is None and not r.analyses for r in snapshot.results))
        restored = next(test for test in claims["FW-06"].manual["tests"] if test["scenario"] == "restored")
        self.assertEqual(restored["packets_received"], 4)
        self.assertTrue(all(ref["verification"] == "NOT_VERIFIED" for r in snapshot.results
                            for ref in r.manual["evidence_references"]))


if __name__ == "__main__":
    unittest.main()
