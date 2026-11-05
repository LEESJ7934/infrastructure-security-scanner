"""Offline comparison of explicit snapshot relations; never reevaluate checks.

Diagnostic metadata, recorded status transitions, evidence confidence and
remediation history are separate. Missing scope/provenance is not equality.
This module performs no I/O. Evidence comes from the previously built index.
"""

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import re

from .evidence_index import STATES
from .reporting import OfflineReport, text

RESULTS = ("IMPROVED_OBSERVED", "UNRESOLVED", "REGRESSED", "UNCHANGED_PASS", "NEW_FINDING",
           "UNVERIFIABLE", "INCOMPARABLE", "MISSING_IN_RETEST")
CHANNELS = {"automatic", "manual", "pf", "log_analysis"}
TRANSITIONS = {("FAIL", "PASS"): "IMPROVED_OBSERVED", ("FAIL", "FAIL"): "UNRESOLVED",
               ("PASS", "FAIL"): "REGRESSED", ("PASS", "PASS"): "UNCHANGED_PASS"}
RECORDED_TRANSITIONS = {pair: "_TO_".join(pair) for pair in TRANSITIONS}
LIMITATIONS = ("recorded_transitions_do_not_establish_remediation_causality",
               "remediation_history_not_provided_or_verified",
               "hash_integrity_does_not_prove_authenticity_or_collection_completeness",
               "evidence_index_is_a_prior_verification_snapshot_files_not_reopened")


class ComparisonInputError(ValueError):
    """Fixed codes only."""


def require(condition, code):
    if not condition:
        raise ComparisonInputError(code)


@dataclass(frozen=True)
class RuleCompatibility:
    asset_id: str
    check_id: str
    channel: str
    before_version: str
    after_version: str
    scope: str
    diagnostic_source: str
    verification_method: str
    evidence_id: str
    reviewer: str
    reviewed_at: str


@dataclass(frozen=True)
class BaselineCoverage:
    """Explicit reviewed coverage, not a synthetic baseline PASS result."""
    asset_id: str
    check_id: str
    channel: str
    rule_version: str
    scope: str
    diagnostic_source: str
    verification_method: str
    checked_at: str
    evidence_id: str
    reviewer: str
    reviewed_at: str


@dataclass(frozen=True)
class SnapshotRelation:
    before_snapshot_id: str
    after_snapshot_id: str
    before_channel: str = "automatic"
    after_channel: str = "automatic"
    compatibility_reviews: tuple[RuleCompatibility, ...] = ()
    baseline_coverage: tuple[BaselineCoverage, ...] = ()


@dataclass(frozen=True)
class ComparisonReport:
    source_report_generated_at: str
    generated_at: str
    evidence_verified_at: str | None
    pairs: tuple[dict, ...]
    unpaired_snapshot_ids: tuple[str, ...]

    def to_dict(self):
        results = [row for pair in self.pairs for row in pair["results"]]
        counts = Counter(row["comparison_result"] for row in results)
        observed = Counter(row["observed_change"] for row in results if row["observed_change"])
        return {"schema_version": 1, "source_report_generated_at": self.source_report_generated_at,
                "generated_at": self.generated_at, "evidence_verified_at": self.evidence_verified_at,
                "pairs": deepcopy(list(self.pairs)), "unpaired_snapshot_ids": list(self.unpaired_snapshot_ids),
                "summary": {state: counts[state] for state in RESULTS},
                "observed_transition_summary": {state: observed[state] for state in RECORDED_TRANSITIONS.values()},
                "invalid_relation_count": sum(pair["relation_status"] != "VALID" for pair in self.pairs),
                "limitations": list(LIMITATIONS)}


def _aware(value):
    if not isinstance(value, str) or len(value) > 64 or "T" not in value or value.endswith("-00:00"):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.utcoffset() is not None else None
    except ValueError:
        return None


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None


def _channel(row, channel):
    if row is None:
        return None
    if channel in {"automatic", "manual"}:
        return getattr(row, channel)
    return row.analyses.get({"pf": "pf_snapshot", "log_analysis": "log_rule_evidence"}[channel])


def _datum(row, channel):
    value = _channel(row, channel)
    result = {"status": None, "scope": None, "diagnostic_source": None, "verification_method": None,
              "rule_version": None, "diagnostic_time": None, "time_basis": None,
              "reviewed_at": None, "evidence_references": []}
    if value is None:
        return result
    result.update({key: value.get(key) for key in ("status", "scope", "diagnostic_source", "verification_method")})
    result["rule_version"] = value.get("rule_version", row.rule_version if channel == "automatic" else None)
    result["evidence_references"] = deepcopy(value.get("evidence_references", []))
    if channel == "automatic":
        result.update(diagnostic_time=value.get("checked_at"), time_basis=value.get("time_basis", "diagnostic_time"))
    elif channel == "manual":
        result["time_basis"] = value.get("time_basis")
        if value.get("time_basis") == "test_time":
            result["diagnostic_time"] = value.get("verified_at")
        else:
            result["reviewed_at"] = value.get("verified_at")
    else:
        result["time_basis"] = value.get("time_basis")
        if value.get("time_basis") == "snapshot_capture_time":
            result["diagnostic_time"] = value.get("collected_at")
        result["reviewed_at"] = value.get("checked_at")
    return result


def _evidence(report, snapshot_id, row, channel):
    index = report.evidence_index
    output = {"references": _datum(row, channel)["evidence_references"], "entries": [],
              "counts": {state: 0 for state in STATES}, "confidence": "UNKNOWN",
              "blocking_issues": [], "limitations": []}
    if row is None:
        return output
    if index is None:
        output["blocking_issues"].append("evidence_index_not_supplied")
        return output
    entries = [entry for entry in index.get("entries", [])
               if (entry.get("snapshot_id"), entry.get("asset_id"), entry.get("check_id"), entry.get("rule_version"))
               == (snapshot_id, row.asset_id, row.check_id, row.rule_version)
               and entry.get("channel") in {channel, "snapshot_input"}
               and entry.get("role") not in {"baseline_coverage", "rule_compatibility_review"}]
    keys = ("evidence_id", "original_reference", "local_path", "exists", "status", "actual_sha256",
            "expected_sha256", "hash_comparison", "size_bytes", "verified_at", "error", "role", "channel")
    output["entries"] = [{key: entry.get(key) for key in keys} for entry in entries]
    if not entries:
        output["blocking_issues"].append("evidence_index_entries_missing")
    local_read = False
    for entry in entries:
        state = entry.get("status")
        if state not in STATES:
            output["blocking_issues"].append("evidence_index_status_invalid")
            continue
        output["counts"][state] += 1
        if state in {"MISMATCH", "MISSING", "INVALID_REFERENCE"}:
            output["blocking_issues"].append("evidence_" + state.lower())
        if state == "EXTERNAL_REFERENCE":
            output["limitations"].append("external_evidence_not_locally_verified")
            continue
        read = entry.get("exists") is True and _hash(entry.get("actual_sha256")) and not entry.get("error")
        if state in {"VERIFIED", "NOT_VERIFIED"}:
            if not read:
                output["blocking_issues"].append("evidence_read_not_successful")
            else:
                local_read = True
        if state == "VERIFIED":
            expected, actual = entry.get("expected_sha256"), entry.get("actual_sha256")
            if not _hash(expected) or actual != expected.lower() or entry.get("hash_comparison") != "MATCH":
                output["blocking_issues"].append("evidence_index_inconsistent")
        if state == "NOT_VERIFIED":
            output["limitations"].append("independent_expected_hash_not_verified")
    if not local_read:
        output["blocking_issues"].append("no_readable_local_evidence")
    if not any(entry.get("channel") == channel for entry in entries):
        output["limitations"].append("saved_result_file_only_no_direct_check_evidence")
    output["blocking_issues"] = sorted(set(output["blocking_issues"]))
    output["limitations"] = sorted(set(output["limitations"]))
    output["confidence"] = ("CONFLICTED" if output["counts"]["MISMATCH"] else "UNAVAILABLE") if output["blocking_issues"] else (
        "VERIFIED_INTEGRITY" if all(entry.get("status") == "VERIFIED" for entry in entries)
        and not output["limitations"] else "LIMITED")
    return output


def _equal(before, after):
    return "UNKNOWN" if before is None or after is None else "MATCH" if before == after else "MISMATCH"


def _review_valid(report, declaration, relation, role):
    if not _aware(declaration.reviewed_at) or not declaration.reviewer:
        return False
    matching = [entry for entry in (report.evidence_index or {}).get("entries", [])
                if entry.get("evidence_id") == declaration.evidence_id]
    if len(matching) != 1:
        return False
    entry = matching[0]
    expected, actual = entry.get("expected_sha256"), entry.get("actual_sha256")
    return (entry.get("status") == "VERIFIED" and entry.get("exists") is True and not entry.get("error")
            and _hash(expected) and _hash(actual) and actual == expected.lower() and entry.get("hash_comparison") == "MATCH"
            and entry.get("role") == role and entry.get("channel") == declaration.channel
            and entry.get("asset_id") == declaration.asset_id and entry.get("check_id") == declaration.check_id
            and entry.get("snapshot_id") in ({relation.before_snapshot_id} if role == "baseline_coverage"
                                             else {relation.before_snapshot_id, relation.after_snapshot_id}))


def _compare_item(report, relation, key, before_rows, after_rows, before_snapshot, after_snapshot, pair_issues,
                  before_keys, after_keys):
    asset, check = key
    before_row = before_rows[0] if len(before_rows) == 1 else None
    after_row = after_rows[0] if len(after_rows) == 1 else None
    before, after = _datum(before_row, relation.before_channel), _datum(after_row, relation.after_channel)
    evidence_before = _evidence(report, relation.before_snapshot_id, before_row, relation.before_channel)
    evidence_after = _evidence(report, relation.after_snapshot_id, after_row, relation.after_channel)
    issues, limitations, checks = list(pair_issues), list(LIMITATIONS), {}
    missing_before, missing_after = not before_rows, not after_rows
    duplicate = len(before_rows) > 1 or len(after_rows) > 1
    if duplicate:
        issues.append("ambiguous_duplicate_results")
    checks["channel"] = _equal(relation.before_channel, relation.after_channel)
    checks["source_format"] = _equal((before_snapshot.day, before_snapshot.input_kind) if before_snapshot else None,
                                      (after_snapshot.day, after_snapshot.input_kind) if after_snapshot else None)
    asset_mismatch = (missing_before and any(k[1] == check and k[0] != asset for k in before_keys)
                      or missing_after and any(k[1] == check and k[0] != asset for k in after_keys))
    coverage = None
    if missing_before and not asset_mismatch:
        declarations = [item for item in relation.baseline_coverage
                        if (item.asset_id, item.check_id, item.channel) == (asset, check, relation.before_channel)]
        if len(declarations) == 1 and _review_valid(report, declarations[0], relation, "baseline_coverage"):
            coverage = declarations[0]
            before.update(scope=coverage.scope, diagnostic_source=coverage.diagnostic_source,
                          verification_method=coverage.verification_method, rule_version=coverage.rule_version,
                          diagnostic_time=coverage.checked_at, time_basis="reviewed_baseline_coverage_declaration")
            proof = next(entry for entry in report.evidence_index["entries"] if entry["evidence_id"] == coverage.evidence_id)
            evidence_before.update(confidence="VERIFIED_DECLARATION_INTEGRITY",
                                   entries=[{key: proof.get(key) for key in ("evidence_id", "original_reference", "local_path",
                                            "status", "actual_sha256", "expected_sha256", "verified_at", "role")}],
                                   references=[{"reference": proof["original_reference"], "role": "baseline_coverage"}])
            evidence_before["counts"]["VERIFIED"] = 1
            evidence_before["limitations"].append("baseline_coverage_is_not_an_original_diagnostic_result")
        else:
            issues.append("baseline_coverage_not_verified")
    for name in ("scope", "diagnostic_source", "verification_method", "rule_version"):
        checks[name] = _equal(before[name], after[name])
    review_used = None
    if checks["rule_version"] == "MISMATCH" and all(checks[name] == "MATCH" for name in
            ("scope", "diagnostic_source", "verification_method", "channel")):
        reviews = [review for review in relation.compatibility_reviews
                   if (review.asset_id, review.check_id, review.channel, review.before_version, review.after_version,
                       review.scope, review.diagnostic_source, review.verification_method) == (
                       asset, check, relation.before_channel, before["rule_version"], after["rule_version"],
                       before["scope"], before["diagnostic_source"], before["verification_method"])]
        if len(reviews) == 1 and _review_valid(report, reviews[0], relation, "rule_compatibility_review"):
            checks["rule_version"] = "REVIEWED_COMPATIBLE"
            review_used = reviews[0].evidence_id
            limitations.append("rule_compatibility_is_explicit_caller_review_not_inferred_from_hash")
    initial_time, retest_time = _aware(before["diagnostic_time"]), _aware(after["diagnostic_time"])
    checks["diagnostic_time"] = ("UNKNOWN" if initial_time is None or retest_time is None else
                                  "MATCH" if initial_time < retest_time else "MISMATCH")
    if before["time_basis"] not in {"diagnostic_time", "test_time", "snapshot_capture_time", "reviewed_baseline_coverage_declaration"}:
        checks["diagnostic_time"] = "UNKNOWN"
    if after["time_basis"] not in {"diagnostic_time", "test_time", "snapshot_capture_time"}:
        checks["diagnostic_time"] = "UNKNOWN"
    if asset_mismatch:
        checks["asset_id"] = "MISMATCH"
        issues.append("asset_id_mismatch_no_cross_asset_pairing")
    else:
        checks["asset_id"] = "MATCH"
    for side, rows, value in (("before", before_rows, before), ("after", after_rows, after)):
        if len(rows) == 1 and _channel(rows[0], getattr(relation, side + "_channel")) is None:
            checks["channel"] = "MISMATCH"
            issues.append(side + "_selected_channel_missing")
        if rows and value["status"] not in {"PASS", "FAIL"}:
            issues.append(side + "_diagnostic_status_not_comparable")
        if getattr(relation, side + "_channel") == "manual" and len(rows) == 1:
            manual = _channel(rows[0], "manual") or {}
            checks[side + "_manual_validation"] = "MATCH" if (
                manual.get("validation_status") == "VALID" and manual.get("attached") is True) else "UNKNOWN"
    for name, value in checks.items():
        if value == "UNKNOWN":
            issues.append(name + "_not_established")
        elif value == "MISMATCH":
            issues.append(name + "_mismatch")
    metadata_mismatch = any(value == "MISMATCH" for value in checks.values())
    observed = TRANSITIONS.get((before["status"], after["status"])) if not duplicate and not metadata_mismatch else None
    if pair_issues or duplicate:
        result = "UNVERIFIABLE"
    elif asset_mismatch:
        result = "INCOMPARABLE"
    elif missing_after:
        result = "MISSING_IN_RETEST"
        issues.append("item_missing_in_supplied_retest_snapshot")
    elif metadata_mismatch:
        result = "INCOMPARABLE"
    elif missing_before and (coverage is None or after["status"] != "FAIL"):
        result = "UNVERIFIABLE"
        issues.append("baseline_result_absent_not_a_proven_new_failure")
    elif any(value == "UNKNOWN" for value in checks.values()) or any(
            rows and datum["status"] not in {"PASS", "FAIL"} for rows, datum in ((before_rows, before), (after_rows, after))):
        result = "UNVERIFIABLE"
    else:
        blockers = (evidence_before["blocking_issues"] if not missing_before else []) + evidence_after["blocking_issues"]
        result = "UNVERIFIABLE" if blockers else "NEW_FINDING" if missing_before else observed
    for side, value in (("before", evidence_before), ("after", evidence_after)):
        issues.extend(side + "_" + issue for issue in value["blocking_issues"])
        limitations.extend(side + "_" + limit for limit in value["limitations"])
    if missing_before and coverage:
        limitations.append("new_finding_means_newly_recorded_failure_not_a_proven_previous_pass")
    return {"asset_id": asset, "check_id": check, "before_snapshot_id": relation.before_snapshot_id,
            "after_snapshot_id": relation.after_snapshot_id, "before_status": before["status"], "after_status": after["status"],
            "comparison_result": result,
            "observed_change": RECORDED_TRANSITIONS.get((before["status"], after["status"])) if observed else None,
            "recorded_transition": {"before": before["status"], "after": after["status"]},
            "comparability": {"status": "COMPARABLE" if result in {*TRANSITIONS.values(), "NEW_FINDING"}
                              else "INCOMPARABLE" if result == "INCOMPARABLE" else "UNVERIFIABLE",
                              "metadata_status": "INCOMPARABLE" if metadata_mismatch else "UNVERIFIABLE" if
                              pair_issues or duplicate or any(v == "UNKNOWN" for v in checks.values()) else "COMPARABLE",
                              "checks": checks, "compatibility_review_evidence_id": review_used,
                              "baseline_coverage_evidence_id": coverage.evidence_id if coverage else None},
            "before_evidence": evidence_before, "after_evidence": evidence_after,
            "verification_method": {"before_channel": relation.before_channel, "after_channel": relation.after_channel,
                                    "before": before["verification_method"], "after": after["verification_method"]},
            "rule_version": {"before": before["rule_version"], "after": after["rule_version"]},
            "scope": {"before": before["scope"], "after": after["scope"]},
            "diagnostic_source": {"before": before["diagnostic_source"], "after": after["diagnostic_source"]},
            "diagnostic_time": {"before": before["diagnostic_time"], "after": after["diagnostic_time"],
                                "before_basis": before["time_basis"], "after_basis": after["time_basis"],
                                "before_reviewed_at": before["reviewed_at"], "after_reviewed_at": after["reviewed_at"]},
            "candidate_counts": {"before": len(before_rows), "after": len(after_rows)},
            "unmet_conditions": sorted(set(issues)), "limitations": sorted(set(limitations)),
            "remediation_history_confirmed": False}


def compare_snapshots(report, relations):
    """Compare only explicit pairs. No implicit Day3/4 or IP-based relations."""
    require(isinstance(report, OfflineReport), "report_invalid")
    relations = tuple(relations)
    require(len(relations) <= 1024 and all(isinstance(item, SnapshotRelation) for item in relations), "relations_invalid")
    identities, used, pairs = set(), set(), []
    for relation in relations:
        for value in (relation.before_snapshot_id, relation.after_snapshot_id):
            text(value)
        require(relation.before_snapshot_id != relation.after_snapshot_id, "same_snapshot_relation_invalid")
        require(isinstance(relation.before_channel, str) and isinstance(relation.after_channel, str)
                and relation.before_channel in CHANNELS and relation.after_channel in CHANNELS, "channel_invalid")
        identity = (relation.before_snapshot_id, relation.after_snapshot_id, relation.before_channel, relation.after_channel)
        require(identity not in identities, "duplicate_relation")
        identities.add(identity)
        for declarations, cls in ((relation.compatibility_reviews, RuleCompatibility), (relation.baseline_coverage, BaselineCoverage)):
            require(len(declarations) <= 4096 and all(isinstance(item, cls) for item in declarations), "declarations_invalid")
            for item in declarations:
                for value in vars(item).values():
                    text(value)
        used.update(identity[:2])
        before_matches = [item for item in report.snapshots if item.snapshot_id == relation.before_snapshot_id]
        after_matches = [item for item in report.snapshots if item.snapshot_id == relation.after_snapshot_id]
        issues, snapshots = [], []
        for side, matches in (("before", before_matches), ("after", after_matches)):
            snapshot = matches[0] if len(matches) == 1 else None
            snapshots.append(snapshot)
            if snapshot is None:
                issues.append(side + "_snapshot_missing_or_ambiguous")
            elif snapshot.import_status != "LOADED":
                issues.append(side + "_snapshot_import_not_loaded")
        before_snapshot, after_snapshot = snapshots
        groups = []
        for snapshot in snapshots:
            group = defaultdict(list)
            if snapshot:
                for row in snapshot.results:
                    group[(row.asset_id, row.check_id)].append(row)
            groups.append(group)
        initial, retest = groups
        results = [_compare_item(report, relation, key, initial.get(key, []), retest.get(key, []), before_snapshot, after_snapshot,
                                 issues, set(initial), set(retest)) for key in sorted(set(initial) | set(retest))]
        pairs.append({"before_snapshot_id": relation.before_snapshot_id, "after_snapshot_id": relation.after_snapshot_id,
                      "before_source_file": before_snapshot.source if before_snapshot else None,
                      "after_source_file": after_snapshot.source if after_snapshot else None,
                      "before_channel": relation.before_channel, "after_channel": relation.after_channel,
                      "relation_status": "UNVERIFIABLE" if issues else "VALID", "issues": issues, "results": results})
    pairs.sort(key=lambda pair: (pair["before_snapshot_id"], pair["after_snapshot_id"], pair["before_channel"], pair["after_channel"]))
    return ComparisonReport(report.generated_at, datetime.now(timezone.utc).isoformat(),
                            (report.evidence_index or {}).get("verified_at"), tuple(pairs),
                            tuple(sorted(item.snapshot_id for item in report.snapshots if item.snapshot_id not in used)))
