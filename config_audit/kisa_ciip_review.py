"""Opt-in KISA comparison of *saved* LAB observations, not a live audit.

Only U-18, W-04 and W-08 are mapped to verified guide thresholds.
The original LAB criteria, historical observations and statuses are untouched.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

GUIDE = "KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드"
GUIDE_PUBLICATION_DATE = "2025-12-24"
GUIDE_URL = "https://www.kisa.or.kr/2060204/form?lang_type=KO&postSeq=22"
PROFILE = "KISA-CIIP-2025-12-24-SELECTED-0.1"


class KisaReviewInputError(ValueError):
    """Do not display raw source values in exceptions."""


def _int(value):
    return type(value) is int


def _row(check_id, kisa_id, criterion, observed, verdict, source_status, source_basis, evidence=None, reason=None):
    return {
        "source_lab_id": check_id,
        "kisa_id": kisa_id,
        "criterion": criterion,
        "observation": observed,
        "kisa_recommendation_result": verdict,
        "original_lab_status": source_status,
        "source_basis": source_basis,
        "evidence_reference": evidence,
        "reason": reason,
        "comparison_only_not_a_live_check": True,
    }


def _source_status(source):
    value = source.get("status")
    return value if value in {"PASS", "FAIL", "NEEDS_REVIEW", "ERROR", "NOT_TESTED", "NOT_APPLICABLE"} else "NEEDS_REVIEW"


def _result_status(source, observed):
    source_status = _source_status(source)
    if source_status in {"ERROR", "NOT_TESTED", "NOT_APPLICABLE"}:
        return source_status
    if observed is None:
        return "NOT_TESTED"
    return None


def review_linux(report):
    """Review a saved config_audit.collectors.linux_mysql_lab.audit() report."""
    if not isinstance(report, dict) or not isinstance(report.get("results"), list) or report.get("mode") != "LAB":
        raise KisaReviewInputError("linux_lab_report_invalid")
    rows = [row for row in report["results"] if isinstance(row, dict) and row.get("check_id") == "LINUX-LAB-003"]
    if len(rows) > 1:
        raise KisaReviewInputError("duplicate_linux_check")
    source = rows[0] if rows else {}
    observed = source.get("observed_value")
    deferred = _result_status(source, observed)
    description = "root-owned regular /etc/shadow, no symlink, mode restricted to root read (0400 or more restrictive)"
    shadow = None
    if deferred is not None:
        verdict, reason = deferred, "source_not_sufficient_for_review"
    elif not isinstance(observed, list):
        verdict, reason = "ERROR", "invalid_observation_type"
    else:
        matching = [item for item in observed if isinstance(item, dict) and item.get("path") == "/etc/shadow"]
        if len(matching) != 1:
            verdict, reason = "NEEDS_REVIEW", "shadow_record_missing_or_ambiguous"
        else:
            item = matching[0]
            shadow = {key: item.get(key) for key in ("uid", "mode", "regular", "symlink")}
            if not _int(item.get("mode")) or not _int(item.get("uid")) or type(item.get("regular")) is not bool or type(item.get("symlink")) is not bool:
                verdict, reason = "NEEDS_REVIEW", "shadow_metadata_incomplete"
            else:
                # Bitwise policy, not raw numeric <= 0o400: 0044 must not pass.
                allowed = (item["mode"] & ~0o400) == 0 and 0 <= item["mode"] <= 0o7777
                verdict, reason = ("PASS", "matches_kisa_recommendation") if item["uid"] == 0 and item["regular"] and not item["symlink"] and allowed else ("FAIL", "does_not_match_kisa_recommendation")
    return [_row("LINUX-LAB-003", "U-18", description, shadow, verdict,
                 _source_status(source), "saved_linux_lab_report", source.get("evidence_reference"), reason)]


def review_windows(report):
    """Review a saved config_audit.windows_lab.build_lab_view() report."""
    if not isinstance(report, dict) or not isinstance(report.get("results"), list) or report.get("mode") != "LAB":
        raise KisaReviewInputError("windows_lab_report_invalid")
    rows = [row for row in report["results"] if isinstance(row, dict) and row.get("check_id") == "WIN-LAB-004"]
    if len(rows) > 1:
        raise KisaReviewInputError("duplicate_windows_check")
    source = rows[0] if rows else {}
    values = source.get("after_values")
    preliminary = _result_status(source, values)
    rules = (
        ("W-04", "Lockout threshold enabled and <= 5 failed attempts", ("lockout_threshold",)),
        ("W-08", "Lockout duration and counter reset both >= 60 minutes", ("lockout_duration", "reset_minutes")),
    )
    output = []
    for kisa_id, criterion, keys in rules:
        observed = None
        if preliminary is not None:
            verdict, reason = preliminary, "source_not_sufficient_for_review"
        elif not isinstance(values, dict):
            verdict, reason = "ERROR", "invalid_observation_type"
        else:
            observed = {key: values.get(key) for key in keys}
            if any(not _int(values.get(key)) for key in keys):
                verdict, reason = "NEEDS_REVIEW", "missing_or_invalid_policy_value"
            elif kisa_id == "W-04":
                verdict = "PASS" if 1 <= values["lockout_threshold"] <= 5 else "FAIL"
                reason = "matches_kisa_recommendation" if verdict == "PASS" else "does_not_match_kisa_recommendation"
            else:
                verdict = "PASS" if all(values[key] >= 60 for key in keys) else "FAIL"
                reason = "matches_kisa_recommendation" if verdict == "PASS" else "does_not_match_kisa_recommendation"
        output.append(_row("WIN-LAB-004", kisa_id, criterion, observed, verdict, _source_status(source),
                           source.get("assessment_basis", "saved_windows_lab_report"), None, reason))
    return output


def review(*, linux=None, windows=None):
    """No source I/O, configuration change or past status mutation."""
    if linux is None and windows is None:
        raise KisaReviewInputError("at_least_one_lab_report_required")
    rows = []
    if linux is not None:
        rows.extend(review_linux(linux))
    if windows is not None:
        rows.extend(review_windows(windows))
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "guide": {"title": GUIDE, "published": GUIDE_PUBLICATION_DATE, "url": GUIDE_URL},
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline_reassessment_of_saved_lab_data",
        "results": rows,
        "summary": dict(Counter(row["kisa_recommendation_result"] for row in rows)),
        "limitations": [
            "selected_U18_W04_W08_only_not_complete_KISA_guide_coverage",
            "KISA_recommendations_not_automatic_customer_policy_or_audit_conclusion",
            "original_LAB_results_are_unchanged",
            "saved_evidence_not_independently_verified_or_recollected",
            "manual_confirmation_not_equivalent_to_automated_collection",
            "different_collection_times_and_sources_must_not_be_combined_as_one_live_snapshot",
            "an_observed_PASS_only_means_the_selected_KISA_recommendation_is_met",
        ],
    }
