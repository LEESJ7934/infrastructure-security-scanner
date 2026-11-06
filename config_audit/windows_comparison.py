"""Phase2-only chronology adapter for the existing offline comparison engine.

Saved-setting capture times, not the time Python reanalyzed them, establish
chronology. No source result or timestamp is edited. Clock checks cannot prove
the clock/source is authentic. This module performs no file or device I/O.
"""

from copy import deepcopy
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone

from .comparison import ComparisonInputError, SnapshotRelation, compare_snapshots
from .reporting import OfflineReport


def _aware(value):
    if not isinstance(value, str) or len(value) > 64 or "T" not in value or value.endswith("-00:00"):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.utcoffset() is not None else None
    except ValueError:
        return None


def _reference(value):
    result = datetime.now(timezone.utc) if value is None else value
    if not isinstance(result, datetime) or result.utcoffset() is None:
        raise ComparisonInputError("clock_reference_invalid")
    return result


def assess_collection_time(value, *, reference_at=None):
    """No skew allowance is silently applied. Missing/naive/future => unverified."""
    reference = _reference(reference_at)
    capture = _aware(value)
    issues = (["collection_time_missing_or_invalid"] if capture is None else
              ["collection_time_in_future"] if capture > reference else [])
    return {"status": "UNVERIFIABLE" if issues else "VALID", "issues": issues,
            "reference_at": reference.isoformat(), "original_time_preserved": True,
            "clock_authenticity_verified": False}


def compare_windows_snapshots(report, relations, *, reference_at=None):
    """Return existing comparison categories plus separate recorded transitions.

    Caller supplies explicit relations and the existing evidence index, if any.
    No index or provenance is fabricated from the collector's hash agreement.
    The optional reference is an analysis clock, never a timestamp correction.
    """
    if not isinstance(report, OfflineReport):
        raise ComparisonInputError("report_invalid")
    reference = _reference(reference_at)
    relations = tuple(relations)
    for relation in relations:
        if (not isinstance(relation, SnapshotRelation) or
                not all(isinstance(value, str) for value in (relation.before_snapshot_id, relation.after_snapshot_id))):
            raise ComparisonInputError("relations_invalid")
        if (getattr(relation, "before_channel", None), getattr(relation, "after_channel", None)) != ("automatic", "automatic"):
            raise ComparisonInputError("windows_automatic_relation_required")
    selected = {value for relation in relations for value in (relation.before_snapshot_id, relation.after_snapshot_id)}
    snapshots = []
    reanalysis_times = defaultdict(list)
    originals = defaultdict(list)
    for snapshot in report.snapshots:
        if snapshot.snapshot_id not in selected:
            snapshots.append(snapshot)
            continue
        if snapshot.source != "phase2_windows_server" or snapshot.input_kind != "windows_server_v1":
            raise ComparisonInputError("windows_snapshot_required")
        rows = []
        for row in snapshot.results:
            channel = deepcopy(row.automatic)
            originals[(snapshot.snapshot_id, row.asset_id, row.check_id)].append(channel)
            reanalysis_times[(snapshot.snapshot_id, row.asset_id, row.check_id)].append(channel.get("checked_at") if channel else None)
            if channel is not None:
                channel["reanalysis_at"] = channel.get("checked_at")
                channel["checked_at"] = channel.get("collected_at")
                channel["time_basis"] = "snapshot_capture_time"
            rows.append(replace(row, automatic=channel))
        snapshots.append(replace(snapshot, results=tuple(rows)))
    base = compare_snapshots(replace(report, snapshots=tuple(snapshots)), relations)
    pairs = deepcopy(list(base.pairs))
    for pair in pairs:
        for row in pair["results"]:
            times = row["diagnostic_time"]
            before = assess_collection_time(times["before"], reference_at=reference)
            after = assess_collection_time(times["after"], reference_at=reference)
            initial, retest = _aware(times["before"]), _aware(times["after"])
            ordered = initial < retest if initial is not None and retest is not None else None
            row["collection_chronology"] = {"before": before, "after": after, "strictly_increasing": ordered,
                                            "timestamp_correction_applied": False}
            row["reanalysis_time"] = {}
            selected_channels = {}
            for side in ("before", "after"):
                values = reanalysis_times[(row[side + "_snapshot_id"], row["asset_id"], row["check_id"])]
                row["reanalysis_time"][side] = values[0] if len(values) == 1 else None
                candidates = originals[(row[side + "_snapshot_id"], row["asset_id"], row["check_id"])]
                selected_channels[side] = candidates[0] if len(candidates) == 1 and candidates[0] else {}
            transition = row["recorded_transition"]
            # This is a reported value change, not an improvement verdict.
            row["recorded_status_transition"] = (transition["before"] + "_TO_" + transition["after"]
                if all(isinstance(transition[side], str) for side in ("before", "after")) else None)
            issues = [side + "_" + issue for side, assessment in (("before", before), ("after", after))
                      for issue in assessment["issues"]]
            if ordered is False:
                issues.append("collection_time_not_strictly_increasing")
            for field in ("product", "version", "os_version", "build_number", "product_type", "domain_role", "part_of_domain"):
                a, b = (selected_channels[side].get(field) for side in ("before", "after"))
                check = "UNKNOWN" if a is None or b is None else "MATCH" if a == b else "MISMATCH"
                row["comparability"]["checks"]["windows_" + field] = check
                if check != "MATCH": issues.append("windows_" + field + "_" + check.lower())
            if row["check_id"] in {"WIN-LAB-002", "WIN-LAB-003", "WIN-LAB-004", "WIN-LAB-009"}:
                policies = [selected_channels[side].get("internal_policy", {}) for side in ("before", "after")]
                if not all(policy.get("sha256") for policy in policies): issues.append("policy_identity_missing")
                elif policies[0]["sha256"] != policies[1]["sha256"]: issues.append("policy_identity_mismatch")
            row["unmet_conditions"] = sorted(set(row["unmet_conditions"] + issues))
            # Retain MISSING_IN_RETEST etc. Missing item is not a missing clock.
            if issues and all(row["candidate_counts"][side] == 1 for side in ("before", "after")):
                mismatch = ordered is False or any(issue.endswith("_mismatch") for issue in issues)
                row["comparison_result"] = "INCOMPARABLE" if mismatch else "UNVERIFIABLE"
                row["comparability"]["status"] = row["comparison_result"]
                row["comparability"]["metadata_status"] = row["comparison_result"]
                if ordered is False or before["issues"] or after["issues"]:
                    row["comparability"]["checks"]["collection_clock"] = "MISMATCH" if ordered is False else "UNKNOWN"
                row["observed_change"] = None
            row["limitations"] = sorted(set(row["limitations"] + ["analysis_clock_not_independently_authenticated",
                "recorded_status_transition_not_verified_temporal_improvement"]))
    result = replace(base, pairs=tuple(pairs)).to_dict()
    result["clock_reference_at"] = reference.isoformat()
    result["comparison_mode"] = "windows_saved_collection_time_strict"
    result["recorded_status_transition_summary"] = dict(sorted(Counter(
        row["recorded_status_transition"] for pair in pairs for row in pair["results"]
        if row["recorded_status_transition"] is not None).items()))
    return result
