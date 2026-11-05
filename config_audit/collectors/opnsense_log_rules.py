"""Historical WAN SSH log/PF correlation, separate from live API collection.

The optional context is a hash-pinned trusted-collector evidence contract,
not an OPNsense API response schema. Missing clock/generation provenance must
never be fabricated from timestamps, rule numbers, labels or file mtimes.
"""

from datetime import datetime, timedelta, timezone
import json
import re

from . import opnsense_pf as pf
from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation

SCOPE = "historical_10.77.50.10_to_10.77.50.1_tcp22_block_only"
TUPLE = ("10.77.50.10", "10.77.50.1", "tcp", 22, "hn0")
LABEL = "Default deny / state violation rule"


class EvidenceError(Exception):
    """Fixed safe codes only."""


def require(condition, code="fw05_input_invalid"):
    if not condition:
        raise EvidenceError(code)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=object_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError("fw05_json_invalid") from None


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 64, "fw05_timestamp_invalid")
    try:
        result = datetime.fromisoformat(value)
        # RFC3339 -00:00 denotes an unknown local offset, not established UTC.
        return result.replace(tzinfo=None) if value.endswith("-00:00") else result
    except ValueError:
        raise EvidenceError("fw05_timestamp_invalid") from None


def aware(value):
    result = timestamp(value)
    require(result.utcoffset() is not None, "fw05_context_timezone_missing")
    return result


def integer(value, maximum):
    require(type(value) is int or isinstance(value, str) and value.isascii() and value.isdigit())
    result = int(value)
    require(0 <= result <= maximum)
    return result


def exact_keys(value, names):
    require(isinstance(value, dict) and value.keys() == set(names))


def load_context(path, expected_hash):
    raw = pf.read_bounded(path)
    pinned = pf.check_digest(raw, expected_hash)
    context = decode(raw)
    exact_keys(context, ("schema_version", "test", "log_clock", "capture_session"))
    require(type(context["schema_version"]) is int and context["schema_version"] == 1)
    test, clock, session = (context[key] for key in ("test", "log_clock", "capture_session"))
    exact_keys(test, ("source", "destination", "protocol", "destination_port", "source_port", "interface",
                      "actual_result", "started_at", "finished_at"))
    require((test["source"], test["destination"], test["protocol"], test["destination_port"], test["interface"]) == TUPLE)
    require(type(test["destination_port"]) is int and type(test["source_port"]) is int and 0 < test["source_port"] <= 65535)
    require(test["actual_result"] in ("timeout", "success", "inconclusive"))
    start, finish = aware(test["started_at"]), aware(test["finished_at"])
    require(start <= finish, "fw05_context_interval_invalid")
    exact_keys(clock, ("offset", "basis"))
    require(clock["basis"] == "trusted_collector_device_clock")
    require(isinstance(clock["offset"], str) and re.fullmatch(r"[+-](?:0\d|1[0-4]):[0-5]\d", clock["offset"]))
    require(clock["offset"] != "-00:00", "fw05_context_timezone_missing")
    sign, hour, minute = clock["offset"][0], int(clock["offset"][1:3]), int(clock["offset"][4:6])
    require(hour < 14 or minute == 0)
    offset = timezone((1 if sign == "+" else -1) * timedelta(hours=hour, minutes=minute))
    exact_keys(session, ("session_id", "log_sha256", "rules_sha256", "detail_sha256", "before_at", "after_at",
                         "rules_captured_at", "generation_before", "generation_at_snapshot", "generation_after", "basis"))
    require(session["basis"] == "trusted_collector_ruleset_generation")
    require(isinstance(session["session_id"], str) and re.fullmatch(r"[0-9a-f]{32}", session["session_id"]))
    for key in ("log_sha256", "rules_sha256", "detail_sha256", "generation_before", "generation_at_snapshot", "generation_after"):
        require(isinstance(session[key], str) and re.fullmatch(r"[0-9a-f]{64}", session[key]))
    before, after, captured = aware(session["before_at"]), aware(session["after_at"]), aware(session["rules_captured_at"])
    require(before <= start <= finish <= after and before <= captured <= after, "fw05_context_interval_invalid")
    return context, pinned, offset, pf.digest(raw)


def analyze(log_path, *, rules_path, detail=None, log_sha256=None, rules_sha256=None, detail_sha256=None,
            archive=None, archive_sha256=None, test_start=None, test_end=None, context_path=None, context_sha256=None,
            execution_id, checked_at):
    report = {
        "scope": SCOPE, "current_execution_traffic": False, "whole_firewall_log_policy_verified": False,
        "integrity": {}, "log_file_collection": {"status": "NOT_TESTED"},
        "rule_mapping": {"status": "NEEDS_REVIEW", "identity_match": False, "historical_continuity_verified": False},
        "time_comparison": {"timezone_verified": False, "wall_clock_window_match": None},
        "checks": {}, "missing_conditions": [],
        "limitations": ["trusted_collector_context_is_not_an_opnsense_api_schema",
                        "file_hashes_do_not_prove_collector_authenticity_or_capture_completeness"],
    }
    missing = report["missing_conditions"]
    value, error, reason = "unverified", False, "fw05_correlation_incomplete"
    stage = "log_file"
    try:
        raw_log = pf.read_bounded(log_path)
        log_trusted = pf.check_digest(raw_log, log_sha256)
        payload = decode(raw_log)
        events = payload.get("logs") if isinstance(payload, dict) else payload
        require(isinstance(events, list) and len(events) <= 10000, "fw05_log_schema_invalid")
        report["integrity"]["logs"] = {"sha256": pf.digest(raw_log), "verified": log_trusted, "bytes": len(raw_log)}
        file_capture = aware(payload["captured_at_utc"]) if isinstance(payload, dict) and "captured_at_utc" in payload else None
        report["log_file_collection"] = {"status": "COLLECTED", "event_count": len(events), "origin": "local_file_not_live_api"}
        stage = "pf_snapshot"
        rules_raw = pf.read_bounded(rules_path)
        rules_trusted = pf.check_digest(rules_raw, rules_sha256)
        detailed_raw = pf.read_bounded(detail) if detail else None
        detail_trusted = pf.check_digest(detailed_raw, detail_sha256) if detailed_raw is not None else False
        if archive:
            from pathlib import Path
            files = [(Path(rules_path).name, rules_raw)] + ([(Path(detail).name, detailed_raw)] if detail else [])
            pinned, archive_hash = pf.archive_matches(archive, archive_sha256, files)
            rules_trusted, detail_trusted = rules_trusted or pinned, detail_trusted or pinned
            report["integrity"]["archive"] = {"sha256": archive_hash, "verified": pinned, "members_match": True}
        report["integrity"]["rules"] = {"sha256": pf.digest(rules_raw), "verified": rules_trusted}
        if detailed_raw is not None:
            report["integrity"]["detail"] = {"sha256": pf.digest(detailed_raw), "verified": detail_trusted}
        rules, fingerprints, coverage = pf.parse_snapshot(rules_raw)
        label_index = {}
        for rule in rules:
            if rule is not None and rule.label is not None:
                label_index.setdefault(rule.label, []).append(rule)
        detail_matches = False
        if detailed_raw is not None:
            _, other, _ = pf.parse_snapshot(detailed_raw, detailed=True)
            require(fingerprints == other, "fw05_pf_detail_mismatch")
            detail_matches = True
        else:
            missing.append("detailed_pf_snapshot_missing")
        if not log_trusted or not rules_trusted or not detail_trusted:
            missing.append("input_integrity_not_independently_pinned")
        if coverage["anchor_statements"] or coverage["unsupported_statements"]:
            missing.append("pf_mapping_scope_incomplete")
        context, context_pinned, log_offset = None, False, None
        stage = "test_context"
        if context_path is not None:
            context, context_pinned, log_offset, context_digest = load_context(context_path, context_sha256)
            report["integrity"]["test_context"] = {"sha256": context_digest, "verified": context_pinned}
            if not context_pinned:
                missing.append("test_context_not_independently_pinned")
            session = context["capture_session"]
            require(aware(session["after_at"]) <= checked_at, "fw05_context_future_time")
            binding = (session["log_sha256"] == pf.digest(raw_log) and session["rules_sha256"] == pf.digest(rules_raw)
                       and detailed_raw is not None and session["detail_sha256"] == pf.digest(detailed_raw))
            report["checks"]["context_file_binding"] = binding
            if not binding:
                missing.append("test_context_file_binding_mismatch")
            continuity = len({session[key] for key in ("generation_before", "generation_at_snapshot", "generation_after")}) == 1
            if not continuity:
                missing.append("ruleset_generation_mismatch")
            report["rule_mapping"]["historical_continuity_verified"] = bool(context_pinned and binding and continuity)
            report["time_comparison"]["timezone_verified"] = context_pinned
        else:
            missing.extend(("test_execution_context_missing", "log_timezone_unverified", "snapshot_test_continuity_unverified"))
        start = timestamp(test_start) if test_start is not None else aware(context["test"]["started_at"]) if context else None
        end = timestamp(test_end) if test_end is not None else aware(context["test"]["finished_at"]) if context else None
        require((start is None) == (end is None), "fw05_test_window_invalid")
        if start is not None:
            require((start.utcoffset() is None) == (end.utcoffset() is None) and start <= end, "fw05_test_window_invalid")
        else:
            missing.append("test_window_not_supplied")
        if context:
            session = context["capture_session"]
            if file_capture is not None and not (aware(session["before_at"]) <= file_capture <= aware(session["after_at"])):
                missing.append("log_capture_outside_collection_session")
        observed = []
        stage = "log_events"
        all_event_times_explicit = bool(events)
        identity_matches, tuple_matches, action_matches, label_matches, windows, context_windows = [], [], [], [], [], []
        for event in events:
            require(isinstance(event, dict), "fw05_log_schema_invalid")
            require({"__timestamp__", "src", "dst", "srcport", "dstport", "protoname", "interface", "action", "rid", "rulenr", "label"} <= event.keys(), "fw05_log_schema_invalid")
            event_time = timestamp(event["__timestamp__"])
            all_event_times_explicit = all_event_times_explicit and event_time.utcoffset() is not None
            port, source_port, number = integer(event["dstport"], 65535), integer(event["srcport"], 65535), integer(event["rulenr"], pf.MAX_RULES)
            require(isinstance(event["rid"], str) and len(event["rid"]) <= 128 and isinstance(event["label"], str) and len(event["label"]) <= 256)
            require(event["action"] in ("pass", "block", "reject"), "fw05_log_schema_invalid")
            packet = (event["src"], event["dst"], event["protoname"], port, event["interface"])
            tuple_ok = packet == TUPLE and (context is None or source_port == context["test"]["source_port"])
            tuple_matches.append(tuple_ok)
            action_matches.append(event["action"] == "block")
            case = ("hn0", "10.77.50.10", "10.77.50.1", "tcp", source_port, 22, "block")
            candidates = []
            for rule in label_index.get(event["rid"], ()):
                if pf.matches(rule, case) is True and rule.action == event["action"]:
                    candidates.append(rule)
                    if len(candidates) > 1:
                        break  # two possible matches already disprove unique identity
            default_deny_shape = len(candidates) == 1 and (
                candidates[0].action == "block" and candidates[0].direction in {"in", "any"}
                and candidates[0].interface == "any" and candidates[0].family in {"inet", "any"}
                and candidates[0].protocol == "any" and candidates[0].source == candidates[0].destination == "any"
                and candidates[0].source_port is None and candidates[0].destination_port is None)
            label_matches.append(event["label"] == LABEL and default_deny_shape)
            # The rid-to-PF-label match is primary; numeric position only checks
            # consistency AFTER semantic/family disambiguation (IPv4 vs IPv6).
            identity_ok = tuple_ok and bool(event["rid"]) and len(candidates) == 1 and candidates[0].order == number and detail_matches
            identity_matches.append(identity_ok)
            normalized = event_time.replace(tzinfo=log_offset) if event_time.utcoffset() is None and log_offset else event_time
            if start is None:
                window_ok = False
            elif event_time.utcoffset() is None and start.utcoffset() is None:
                window_ok = start <= event_time <= end  # wall-clock comparison ONLY
            elif normalized.utcoffset() is not None and start.utcoffset() is not None:
                window_ok = start <= normalized <= end
            else:
                window_ok = False
            windows.append(window_ok)
            if context:
                context_ok = (normalized.utcoffset() is not None
                              and aware(context["test"]["started_at"]) <= normalized <= aware(context["test"]["finished_at"]))
                context_windows.append(context_ok)
            if tuple_ok:
                observed.append({"timestamp_as_recorded": event["__timestamp__"], "timezone_explicit_in_event": event_time.utcoffset() is not None,
                                 "source_port": source_port, "rulenr": number,
                                 "pf_reference": candidates[0].reference if identity_ok else None})
        if all_event_times_explicit:
            report["time_comparison"]["timezone_verified"] = True
            if "log_timezone_unverified" in missing:
                missing.remove("log_timezone_unverified")
        report["checks"].update(tuple_match=bool(events) and all(tuple_matches), action_block=bool(events) and all(action_matches),
                                 label_consistent_with_default_deny=bool(events) and all(label_matches))
        identity = bool(events) and all(identity_matches)
        report["rule_mapping"].update(identity_match=identity, comparison_basis="rid_equals_pf_label_then_semantics_and_detailed_position",
                                      numeric_position_alone_sufficient=False, gui_description_authoritatively_mapped=False)
        report["time_comparison"].update(wall_clock_window_match=bool(events) and all(windows),
                                          event_timestamps_assumed_utc=False, file_capture_time_used_as_event_timezone=False)
        report["observed_events"] = observed
        conditions = (
            (bool(events), "log_events_missing"), (all(tuple_matches), "test_tuple_or_source_port_mismatch"),
            (all(action_matches), "log_action_mismatch"), (all(label_matches), "log_label_inconsistent_or_unverified"),
            (identity, "rid_semantics_or_detailed_rule_position_mismatch"),
            (bool(events) and all(windows), "test_window_mismatch"),
        )
        for valid, code in conditions:
            if not valid:
                missing.append(code)
        if context and (not all(context_windows) or context["test"]["actual_result"] != "timeout"):
            missing.append("test_context_outcome_or_time_mismatch")
        report["rule_mapping"]["status"] = "PASS" if identity and report["rule_mapping"]["historical_continuity_verified"] and context_pinned and detail_trusted and rules_trusted else "NEEDS_REVIEW"
        missing[:] = list(dict.fromkeys(missing))
        if not missing:
            value, reason = True, "fw05_scoped_historical_test_and_rule_match"
        else:
            value, reason = "unverified", "fw05_correlation_incomplete"
    except (pf.PFError, EvidenceError) as exc:
        value, error, reason = None, True, str(exc)
    except (TypeError, KeyError, ValueError):
        value, error, reason = None, True, "fw05_input_invalid"
    if error:
        report["failure_stage"] = stage
        if stage in {"log_file", "log_events"}:
            report["log_file_collection"] = {"status": "ERROR", "reason": reason}
        elif stage == "pf_snapshot":
            report["rule_mapping"]["status"] = "ERROR"
    result = evaluate(AuditAsset("SJ-D4-OPNsense", "opnsense", "26.7"),
                      AuditRule("FW-05", "log-pf-1", SCOPE, "Review missing clock, probe and ruleset-generation evidence.",
                                condition=lambda observed: observed if type(observed) is bool else None, product="opnsense"),
                      Observation(value, f"day4:{execution_id}:FW-05:log-pf", error), execution_id=execution_id, checked_at=checked_at)
    report.update(result.to_safe_dict(), reason=reason, evidence_reference=result.evidence_reference)
    return report
