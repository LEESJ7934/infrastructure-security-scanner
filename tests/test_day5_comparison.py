"""No devices: comparison tests use saved JSON, common models and real temp hashes."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config_audit.comparison import (
    BaselineCoverage, ComparisonInputError, RuleCompatibility, SnapshotRelation, compare_snapshots,
)
from config_audit.evidence_index import EvidenceBinding, attach_evidence_index, build_evidence_index
from config_audit.reporting import integrate, load_snapshot

ROOT = Path(__file__).resolve().parents[1]
BEFORE = "2026-11-04T10:26:11+00:00"
AFTER = "2026-11-04T10:33:02+00:00"


def row(state="FAIL", *, after=False, **kwargs):
    return {"asset_id": "lab/linux", "check_id": "CHECK-1", "rule_version": "1", "status": state,
            "execution_id": "after-run" if after else "before-run", "checked_at": AFTER if after else BEFORE,
            "scope": "ssh_config_only", "diagnostic_source": "lab.config_collector.v1",
            "verification_method": "effective_config_read", **kwargs}


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.files = self.root / "evidence/day4"
        self.files.mkdir(parents=True)

    def report(self, before=None, after=None, *, extras=(), indexed=True):
        snapshots = []
        for name, rows in (("before", [row()] if before is None else before),
                           ("after", [row("PASS", after=True)] if after is None else after)):
            path = self.files / (name + ".json")
            path.write_text(json.dumps({"results": rows}), encoding="utf-8")
            snapshot = load_snapshot(path, day=4, snapshot_id=name)
            self.assertEqual(snapshot.import_status, "LOADED", snapshot.diagnostics)
            snapshots.append(snapshot)
        report = integrate(snapshots, generated_at="2026-11-05T00:00:00+00:00")
        if indexed:
            report = attach_evidence_index(report, build_evidence_index(report, project_root=self.root, extra_bindings=extras))
        return report

    def compare(self, report=None, relation=None):
        report = report or self.report()
        relation = relation or SnapshotRelation("before", "after")
        return compare_snapshots(report, [relation]).to_dict()

    def result(self, report=None, relation=None):
        return self.compare(report, relation)["pairs"][0]["results"][0]

    def test_fail_to_pass_is_observed_not_confirmed_remediation(self):
        result = self.result()
        self.assertEqual(result["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(result["comparability"]["status"], "COMPARABLE")
        self.assertFalse(result["remediation_history_confirmed"])
        self.assertIn("remediation_history_not_provided_or_verified", result["limitations"])

    def test_fail_to_fail(self):
        self.assertEqual(self.result(self.report(after=[row("FAIL", after=True)]))["comparison_result"], "UNRESOLVED")

    def test_pass_to_fail(self):
        self.assertEqual(self.result(self.report(before=[row("PASS")], after=[row("FAIL", after=True)]))["comparison_result"], "REGRESSED")

    def test_pass_to_pass(self):
        self.assertEqual(self.result(self.report(before=[row("PASS")]))["comparison_result"], "UNCHANGED_PASS")

    def test_error_to_pass_not_improvement(self):
        result = self.result(self.report(before=[row("ERROR")]))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(result["observed_change"])

    def test_review_to_pass_not_improvement(self):
        self.assertEqual(self.result(self.report(before=[row("NEEDS_REVIEW")]))["comparison_result"], "UNVERIFIABLE")

    def test_not_tested_and_not_applicable_are_not_improvements(self):
        for state in ("NOT_TESTED", "NOT_APPLICABLE"):
            with self.subTest(state=state):
                self.assertEqual(self.result(self.report(before=[row(state)]))["comparison_result"], "UNVERIFIABLE")

    def test_no_baseline_does_not_automatically_mean_new_finding(self):
        result = self.result(self.report(before=[], after=[row("FAIL", after=True)]))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(result["before_status"])
        self.assertIn("baseline_coverage_not_verified", result["unmet_conditions"])

    def test_retest_item_missing_not_improved(self):
        result = self.result(self.report(after=[]))
        self.assertEqual(result["comparison_result"], "MISSING_IN_RETEST")
        self.assertIsNone(result["after_status"])

    def test_asset_id_mismatch_is_not_ip_based_pairing(self):
        report = self.report(after=[row("PASS", after=True, asset_id="different-asset")])
        results = self.compare(report)["pairs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["comparison_result"] == "INCOMPARABLE" for r in results))
        self.assertTrue(all(r["before_status"] is None or r["after_status"] is None for r in results))

    def test_rule_version_mismatch(self):
        result = self.result(self.report(after=[row("PASS", after=True, rule_version="2")]))
        self.assertEqual(result["comparison_result"], "INCOMPARABLE")

    def test_missing_rule_version_not_inferred(self):
        report = self.report()
        snapshot = report.snapshots[0]
        result = snapshot.results[0]
        changed = replace(result, automatic={**result.automatic, "rule_version": None})
        report = replace(report, snapshots=(replace(snapshot, results=(changed,)), report.snapshots[1]))
        self.assertEqual(self.result(report)["comparability"]["checks"]["rule_version"], "UNKNOWN")

    def test_automatic_and_manual_not_compared(self):
        after = row("NOT_TESTED", after=True)
        after["manual_verification"] = {"status": "PASS", "scope": "ssh_config_only", "rule_version": "1",
                                        "verified_at": AFTER, "time_basis": "test_time",
                                        "diagnostic_source": "lab.config_collector.v1", "verification_method": "effective_config_read"}
        result = self.result(self.report(after=[after]), SnapshotRelation("before", "after", after_channel="manual"))
        self.assertEqual(result["comparison_result"], "INCOMPARABLE")
        self.assertIsNone(result["observed_change"])

    def test_selected_channel_absent_is_not_replaced(self):
        before, after = row(), row("PASS", after=True)
        after["manual_verification"] = {"status": "PASS"}
        report = self.report(before=[before], after=[after])
        snapshot = report.snapshots[1]
        report = replace(report, snapshots=(report.snapshots[0], replace(snapshot, results=(replace(snapshot.results[0], automatic=None),))))
        self.assertEqual(self.result(report)["comparison_result"], "INCOMPARABLE")

    def test_scope_mismatch(self):
        self.assertEqual(self.result(self.report(after=[row("PASS", after=True, scope="other_scope")]))["comparison_result"], "INCOMPARABLE")

    def test_missing_scope_preserves_raw_transition_without_counting_improvement(self):
        before, after = row(), row("PASS", after=True)
        before.pop("scope")
        after.pop("scope")
        comparison = self.compare(self.report(before=[before], after=[after]))
        result = comparison["pairs"][0]["results"][0]
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertEqual(result["observed_change"], "FAIL_TO_PASS")
        self.assertEqual(comparison["summary"]["IMPROVED_OBSERVED"], 0)
        self.assertIn("scope_not_established", result["unmet_conditions"])

    def test_source_and_method_mismatch(self):
        for field in ("diagnostic_source", "verification_method"):
            with self.subTest(field=field):
                self.assertEqual(self.result(self.report(after=[row("PASS", after=True, **{field: "other"})]))["comparison_result"], "INCOMPARABLE")

    def test_evidence_hash_mismatch_separate_from_recorded_transition(self):
        (self.files / "probe.txt").write_bytes(b"changed")
        after = row("PASS", after=True, sources=[{"path": "probe.txt", "sha256": "0" * 64}])
        result = self.result(self.report(after=[after]))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertEqual(result["observed_change"], "FAIL_TO_PASS")
        self.assertEqual(result["after_evidence"]["confidence"], "CONFLICTED")
        self.assertIn("after_evidence_mismatch", result["unmet_conditions"])

    def test_no_expected_hash_stays_not_verified_with_limited_confidence(self):
        result = self.result()
        self.assertEqual(result["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(result["before_evidence"]["counts"]["NOT_VERIFIED"], 1)
        self.assertEqual(result["before_evidence"]["counts"]["VERIFIED"], 0)
        self.assertEqual(result["before_evidence"]["confidence"], "LIMITED")

    def test_duplicate_results_never_choose_one_version(self):
        report = self.report(before=[row(), row("PASS", rule_version="2")])
        result = self.result(report)
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(result["before_status"])
        self.assertEqual(result["candidate_counts"]["before"], 2)

    def test_exact_duplicate_in_constructed_common_model(self):
        report = self.report()
        snapshot = report.snapshots[0]
        report = replace(report, snapshots=(replace(snapshot, results=snapshot.results * 2), report.snapshots[1]))
        self.assertIn("ambiguous_duplicate_results", self.result(report)["unmet_conditions"])

    def test_review_timestamp_is_not_test_timestamp(self):
        before, after = row(), row("PASS", after=True)
        for item, time in ((before, BEFORE), (after, AFTER)):
            item["manual_verification"] = {"status": item["status"], "rule_version": "1", "scope": item["scope"],
                "diagnostic_source": item["diagnostic_source"], "verification_method": item["verification_method"],
                "verified_at": time, "time_basis": "artifact_review"}
        result = self.result(self.report(before=[before], after=[after]), SnapshotRelation("before", "after", "manual", "manual"))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(result["diagnostic_time"]["before"])
        self.assertEqual(result["diagnostic_time"]["before_reviewed_at"], BEFORE)

    def test_naive_and_unknown_offset_times_not_assumed_utc(self):
        for time in ("2026-11-04T10:33:02", "2026-11-04T10:33:02-00:00"):
            with self.subTest(time=time):
                self.assertEqual(self.result(self.report(after=[row("PASS", after=True, checked_at=time)]))["comparison_result"], "UNVERIFIABLE")

    def test_reversed_or_identical_diagnostic_time_incomparable(self):
        for time in (BEFORE, "2026-11-03T10:33:02+00:00"):
            with self.subTest(time=time):
                self.assertEqual(self.result(self.report(after=[row("PASS", after=True, checked_at=time)]))["comparison_result"], "INCOMPARABLE")

    def test_evidence_index_missing(self):
        self.assertEqual(self.result(self.report(indexed=False))["comparison_result"], "UNVERIFIABLE")

    def test_invalid_verified_hash_metadata_not_trusted(self):
        report = self.report()
        index = deepcopy(report.evidence_index)
        for entry in index["entries"]:
            entry.update(status="VERIFIED", actual_sha256="", expected_sha256="", hash_comparison="MATCH")
        result = self.result(replace(report, evidence_index=index))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIn("before_evidence_index_inconsistent", result["unmet_conditions"])

    def test_manual_rule_version_is_not_inherited_from_automatic_result(self):
        before, after = row(), row("PASS", after=True)
        for item, time in ((before, BEFORE), (after, AFTER)):
            item["manual_verification"] = {"status": item["status"], "scope": item["scope"],
                "diagnostic_source": item["diagnostic_source"], "verification_method": item["verification_method"],
                "verified_at": time, "time_basis": "test_time", "validation_status": "VALID", "attached": True}
        result = self.result(self.report(before=[before], after=[after]), SnapshotRelation("before", "after", "manual", "manual"))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertEqual(result["rule_version"], {"before": None, "after": None})

    def test_manual_comparison_requires_saved_validation_and_test_time(self):
        before, after = row(), row("PASS", after=True)
        for item, time in ((before, BEFORE), (after, AFTER)):
            item["manual_verification"] = {"status": item["status"], "scope": item["scope"], "rule_version": "1",
                "diagnostic_source": item["diagnostic_source"], "verification_method": item["verification_method"],
                "verified_at": time, "time_basis": "test_time", "validation_status": "VALID", "attached": True}
        relation = SnapshotRelation("before", "after", "manual", "manual")
        self.assertEqual(self.result(self.report(before=[before], after=[after]), relation)["comparison_result"], "IMPROVED_OBSERVED")
        after["manual_verification"].pop("validation_status")
        self.assertEqual(self.result(self.report(before=[before], after=[after]), relation)["comparison_result"], "UNVERIFIABLE")

    def test_missing_local_evidence_not_hidden_by_source_json(self):
        after = row("PASS", after=True, evidence_reference="missing-probe.txt")
        result = self.result(self.report(after=[after]))
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIn("after_evidence_missing", result["unmet_conditions"])

    def test_no_relations_makes_no_retest_results(self):
        data = compare_snapshots(self.report(), []).to_dict()
        self.assertFalse(data["pairs"])
        self.assertEqual(data["unpaired_snapshot_ids"], ["after", "before"])
        self.assertFalse(any(data["summary"].values()))

    def test_unknown_snapshot_relation_is_reported(self):
        data = self.compare(relation=SnapshotRelation("before", "not-stored"))
        self.assertEqual(data["invalid_relation_count"], 1)
        self.assertEqual(data["pairs"][0]["results"][0]["comparison_result"], "UNVERIFIABLE")

    def test_duplicate_relation_rejected(self):
        relation = SnapshotRelation("before", "after")
        with self.assertRaisesRegex(ComparisonInputError, "duplicate_relation"):
            compare_snapshots(self.report(), [relation, relation])

    def test_duplicate_snapshot_ids_do_not_select_first(self):
        report = self.report()
        report = replace(report, snapshots=(report.snapshots[0], report.snapshots[0], report.snapshots[1]))
        result = self.result(report)
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIsNone(result["before_status"])
        self.assertIn("before_snapshot_missing_or_ambiguous", result["unmet_conditions"])

    def test_failed_import_is_not_item_omission(self):
        report = self.report()
        report = replace(report, snapshots=(report.snapshots[0], replace(report.snapshots[1], results=(), import_status="ERROR")))
        result = self.result(report)
        self.assertEqual(result["comparison_result"], "UNVERIFIABLE")
        self.assertIn("after_snapshot_import_not_loaded", result["unmet_conditions"])

    def test_result_order_is_deterministic(self):
        before = [row(check_id="CHECK-2"), row()]
        after = [row("PASS", after=True), row("FAIL", after=True, check_id="CHECK-2")]
        first = self.compare(self.report(before=before, after=after))["pairs"]
        second = self.compare(self.report(before=list(reversed(before)), after=list(reversed(after))))["pairs"]
        self.assertEqual([r["check_id"] for r in first[0]["results"]], ["CHECK-1", "CHECK-2"])
        self.assertEqual([r["comparison_result"] for r in first[0]["results"]],
                         [r["comparison_result"] for r in second[0]["results"]])

    def test_same_snapshot_relation_rejected(self):
        with self.assertRaisesRegex(ComparisonInputError, "same_snapshot_relation_invalid"):
            self.compare(relation=SnapshotRelation("before", "before"))

    def test_original_models_not_modified(self):
        report = self.report()
        original = deepcopy(report.to_dict())
        compared = self.compare(report)
        self.assertEqual(report.to_dict(), original)
        self.assertEqual(compared["source_report_generated_at"], report.generated_at)
        self.assertEqual(compared["evidence_verified_at"], report.evidence_index["verified_at"])

    def test_comparison_itself_never_opens_files(self):
        report = self.report()
        with patch.object(Path, "open", side_effect=AssertionError("no I/O")):
            self.assertEqual(self.result(report)["comparison_result"], "IMPROVED_OBSERVED")

    def reviewed_evidence(self, role):
        content = b"independent reviewed fixture declaration"
        (self.files / "review.txt").write_bytes(content)
        return EvidenceBinding("evidence/day4/review.txt", asset_id="lab/linux", check_id="CHECK-1", day=4,
                               snapshot_id="before", channel="automatic", rule_version="1", role=role,
                               expected_sha256=hashlib.sha256(content).hexdigest(), expected_hash_source="fixture_declaration")

    def test_explicit_verified_rule_compatibility_review(self):
        report = self.report(after=[row("PASS", after=True, rule_version="2")],
                             extras=[self.reviewed_evidence("rule_compatibility_review")])
        evidence_id = next(e["evidence_id"] for e in report.evidence_index["entries"] if e["role"] == "rule_compatibility_review")
        review = RuleCompatibility("lab/linux", "CHECK-1", "automatic", "1", "2", "ssh_config_only",
                                   "lab.config_collector.v1", "effective_config_read", evidence_id, "fixture_reviewer", AFTER)
        result = self.result(report, SnapshotRelation("before", "after", compatibility_reviews=(review,)))
        self.assertEqual(result["comparison_result"], "IMPROVED_OBSERVED")
        self.assertEqual(result["comparability"]["checks"]["rule_version"], "REVIEWED_COMPATIBLE")

    def test_unverified_compatibility_does_not_override_version_mismatch(self):
        review = RuleCompatibility("lab/linux", "CHECK-1", "automatic", "1", "2", "ssh_config_only",
                                   "lab.config_collector.v1", "effective_config_read", "missing-evidence", "reviewer", AFTER)
        result = self.result(self.report(after=[row("PASS", after=True, rule_version="2")]),
                             SnapshotRelation("before", "after", compatibility_reviews=(review,)))
        self.assertEqual(result["comparison_result"], "INCOMPARABLE")

    def test_new_finding_requires_explicit_verified_baseline_scope(self):
        report = self.report(before=[], after=[row("FAIL", after=True)],
                             extras=[self.reviewed_evidence("baseline_coverage")])
        evidence_id = next(e["evidence_id"] for e in report.evidence_index["entries"] if e["role"] == "baseline_coverage")
        coverage = BaselineCoverage("lab/linux", "CHECK-1", "automatic", "1", "ssh_config_only",
                                    "lab.config_collector.v1", "effective_config_read", BEFORE,
                                    evidence_id, "fixture_reviewer", AFTER)
        result = self.result(report, SnapshotRelation("before", "after", baseline_coverage=(coverage,)))
        self.assertEqual(result["comparison_result"], "NEW_FINDING")
        self.assertIsNone(result["before_status"])
        self.assertEqual(result["before_evidence"]["entries"][0]["evidence_id"], evidence_id)
        self.assertEqual(result["before_evidence"]["confidence"], "VERIFIED_DECLARATION_INTEGRITY")


class StoredLocalComparisonTests(unittest.TestCase):
    @unittest.skipUnless(all((ROOT / p).is_file() for p in ("logs/day2-before.json", "logs/day2-after.json")),
                         "Ignored local Day2 snapshots not available")
    def test_actual_day2_json_preserves_changes_but_missing_metadata_blocks_confirmation(self):
        snapshots = [load_snapshot(ROOT / path, day=2, snapshot_id=name) for path, name in
                     (("logs/day2-before.json", "day2-before"), ("logs/day2-after.json", "day2-after"))]
        report = integrate(snapshots)
        report = attach_evidence_index(report, build_evidence_index(report, project_root=ROOT))
        output = compare_snapshots(report, [SnapshotRelation("day2-before", "day2-after")]).to_dict()
        self.assertEqual(output["summary"]["UNVERIFIABLE"], 4)
        self.assertEqual(output["summary"]["IMPROVED_OBSERVED"], 0)
        self.assertEqual(output["observed_transition_summary"]["FAIL_TO_PASS"], 2)
        self.assertEqual(output["observed_transition_summary"]["PASS_TO_PASS"], 2)
        results = {r["check_id"]: r for r in output["pairs"][0]["results"]}
        self.assertEqual(results["LAB-SSH-002"]["recorded_transition"], {"before": "FAIL", "after": "PASS"})
        self.assertEqual(results["LAB-MYSQL-002"]["recorded_transition"], {"before": "FAIL", "after": "PASS"})
        self.assertTrue(all(r["scope"]["before"] is None for r in results.values()))
        self.assertTrue(all(not r["remediation_history_confirmed"] for r in results.values()))

    def test_day3_day4_have_no_implicit_before_after(self):
        snapshots = [load_snapshot(ROOT / "evidence/day4/manual.json", day=4, snapshot_id="day4-manual", input_kind="manual")]
        path = ROOT / "logs/day3-final.json"
        if path.is_file():
            snapshots.append(load_snapshot(path, day=3, snapshot_id="day3-final"))
        output = compare_snapshots(integrate(snapshots), []).to_dict()
        self.assertFalse(output["pairs"])
        self.assertEqual(set(output["unpaired_snapshot_ids"]), {s.snapshot_id for s in snapshots})
        self.assertFalse(any(output["summary"].values()))


if __name__ == "__main__":
    unittest.main()
