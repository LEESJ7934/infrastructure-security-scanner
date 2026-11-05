"""Offline adapters for saved Day 2/3/4 results, without executing collectors.

No verdict is calculated here. Missing automatic results remain None. Manual
claims, saved validations and supplemental analyses are independent channels.
Evidence identifiers/hashes are declarations, never verification by this module.
Only explicit input paths are read; referenced evidence is not opened.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from .statuses import AuditStatus

MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 4096
STATUSES = {status.value for status in AuditStatus}
COLLECTION_STATUSES = STATUSES | {"COLLECTED", "LOADED", "MATCH", "MISSING", "UNAVAILABLE"}
SETTING_NAMES = {
    "ubuntu": {"maxauthtries", "permitrootlogin", "passwordauthentication", "x11forwarding", "permitemptypasswords"},
    "mysql": {"version", "local_infile", "require_secure_transport", "skip_name_resolve", "general_log"},
}
# Reject credential-bearing text even in otherwise permitted metadata fields.
# Unknown keys (including settings, observed values, raw logs and headers) are
# never copied. Callers must still review free-text metadata before publication.
SENSITIVE = re.compile(
    r"authorization|api[ _-]?(?:key|secret)|password|private[ _-]?key|"
    r"-----BEGIN|\b(?:bearer|basic)\s+\S+|https?://[^/\s]+@|[?&](?:token|secret|key)=",
    re.IGNORECASE,
)


class ReportInputError(ValueError):
    """Only fixed codes; never echo input values or OS exception messages."""


def require(condition, code="schema_invalid"):
    if not condition:
        raise ReportInputError(code)


def text(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096, "text_invalid")
    require(not SENSITIVE.search(value), "sensitive_metadata_rejected")
    return value


def timestamp(value):
    text(value)
    try:
        require(len(value) <= 64 and "T" in value, "timestamp_invalid")
        datetime.fromisoformat(value)
    except ValueError:
        raise ReportInputError("timestamp_invalid") from None
    # Preserve original spelling/offset. In particular, naive time is not UTC.
    return value


def status(value, *, collection=False):
    require(isinstance(value, str) and value in (COLLECTION_STATUSES if collection else STATUSES),
            "status_invalid")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


# Explicit safe fields shared by the saved manual/PF/log/API schemas. Nested
# dictionaries are filtered too: allowing a parent never copies its raw body.
TEXT_FIELDS = {
    "reason", "scope", "rule_version", "check_id", "execution_id", "endpoint",
    "stage", "error_code", "origin", "comparison_basis", "time_basis",
    "validation_status", "scenario", "source", "destination", "protocol",
    "expected_result", "actual_result", "firewall_action", "rule_name", "kind",
    "reference", "timezone_basis", "failure_stage", "diagnostic_source", "verification_method",
}
BOOL_FIELDS = {
    "attached", "content_verified_by_agent", "current_execution_evidence",
    "current_execution_traffic", "identity_match", "historical_continuity_verified",
    "default_deny_seen", "anti_lockout_seen", "lan_default_allow_seen",
    "lab_block_before_default_allow", "lab_block_enabled",
    "complete_effective_ruleset", "gui_rule_identity_verified",
    "snapshot_is_current_execution_traffic", "whole_firewall_log_policy_verified",
    "numeric_position_alone_sufficient", "gui_description_authoritatively_mapped",
    "timezone_verified", "event_timestamps_assumed_utc", "file_capture_time_used_as_event_timezone",
}
INT_FIELDS = {"http_status", "event_count", "rule_count", "port", "source_port", "destination_port",
              "packets_sent", "packets_received"}
LIST_FIELDS = {"limitations", "missing_conditions", "findings"}
CHILD_FIELDS = {"automatic_collection", "api_rule_id_mapping", "log_file_collection", "rule_mapping",
                "inspection", "time_comparison"}


def metadata(value, depth=0):
    require(isinstance(value, dict) and depth <= 20)
    result = {}
    for key, item in value.items():
        if key in {"status", "reported_status"}:
            result[key] = status(item, collection=key == "status")
        elif key in {"checked_at", "verified_at", "collected_at", "reanalysis_at"}:
            result[key] = timestamp(item) if item is not None else None
        elif key in TEXT_FIELDS:
            result[key] = text(item) if item is not None else None
        elif key in BOOL_FIELDS:
            require(type(item) is bool)
            result[key] = item
        elif key == "wall_clock_window_match":
            require(item is None or type(item) is bool)
            result[key] = item
        elif key in INT_FIELDS:
            require(item is None or type(item) is int and item >= 0)
            result[key] = item
        elif key in LIST_FIELDS:
            require(isinstance(item, list) and len(item) <= MAX_ROWS)
            result[key] = [text(entry) for entry in item]
        elif key in CHILD_FIELDS:
            result[key] = metadata(item, depth + 1)
        elif key == "source_indices":
            require(isinstance(item, list) and len(item) <= MAX_ROWS
                    and all(type(index) is int and index >= 0 for index in item))
            result[key] = list(item)
    return result


def references(value, *, base):
    require(isinstance(value, list) and len(value) <= MAX_ROWS)
    output = []
    for item in value:
        if isinstance(item, str):
            item = {"reference": item}
        require(isinstance(item, dict))
        reference = item.get("path", item.get("reference"))
        require(reference is not None, "evidence_reference_missing")
        entry = {"reference": text(reference), "relative_to": base,
                 "verification": "NOT_VERIFIED"}
        if "sha256" in item:
            require(isinstance(item["sha256"], str) and re.fullmatch(r"[a-fA-F0-9]{64}", item["sha256"]),
                    "sha256_invalid")
            entry["declared_sha256"] = item["sha256"]
        if "kind" in item:
            entry["kind"] = text(item["kind"])
        output.append(entry)
    return output


def channel(value, *, base, audit=False):
    result = metadata(value)
    if audit:
        result["status"] = status(value.get("status"))
    evidence = value.get("sources", [])
    if value.get("evidence_reference") is not None:
        evidence = [*evidence, value["evidence_reference"]] if isinstance(evidence, list) else evidence
    result["evidence_references"] = references(evidence, base=base)
    if "tests" in value:
        require(isinstance(value["tests"], list) and len(value["tests"]) <= MAX_ROWS)
        result["tests"] = [metadata(test) for test in value["tests"]]
    if "integrity" in value:
        require(isinstance(value["integrity"], dict))
        claims = {}
        for role in ("logs", "rules", "detail", "archive", "test_context"):
            if role not in value["integrity"]:
                continue
            claim = value["integrity"][role]
            require(isinstance(claim, dict))
            # Explicitly label the historical claim instead of adopting it as
            # verification performed by this importer.
            safe = {"verification": "NOT_VERIFIED"}
            if "sha256" in claim:
                require(isinstance(claim["sha256"], str) and re.fullmatch(r"[a-fA-F0-9]{64}", claim["sha256"]),
                        "sha256_invalid")
                safe["declared_sha256"] = claim["sha256"]
            if "verified" in claim:
                require(type(claim["verified"]) is bool)
                safe["source_reported_verified"] = claim["verified"]
            claims[role] = safe
        result["source_integrity_claims"] = claims
    result["import_validation"] = "STRUCTURE_ONLY"
    return result


@dataclass(frozen=True)
class ReportResult:
    asset_id: str
    check_id: str
    rule_version: str | None
    automatic: dict | None
    manual: dict | None = None
    analyses: dict = field(default_factory=dict)
    risk: str | None = None
    recommendation: str | None = None
    evidence_index_ids: dict = field(default_factory=dict)

    def to_dict(self):
        return deepcopy(vars(self))


@dataclass(frozen=True)
class SourceSnapshot:
    snapshot_id: str
    day: int
    source: str
    input_kind: str
    results: tuple[ReportResult, ...] = ()
    diagnostics: tuple[str, ...] = ()
    collection: dict = field(default_factory=dict)
    # Input-level errors are import errors, not synthetic diagnostic ERRORs.
    import_status: str = "LOADED"

    def to_dict(self):
        return {**deepcopy(vars(self)), "results": [row.to_dict() for row in self.results],
                "diagnostics": list(self.diagnostics)}


@dataclass(frozen=True)
class OfflineReport:
    generated_at: str
    snapshots: tuple[SourceSnapshot, ...]
    evidence_sources: tuple[dict, ...] = ()
    evidence_index: dict | None = None

    def to_dict(self):
        return {"schema_version": 1, "generated_at": self.generated_at,
                "reanalysis_at": None, "mode": "offline_import_only",
                "limitations": ["no_checks_reevaluated",
                                 "evidence_files_not_verified" if self.evidence_index is None else "only_indexed_paths_checked_integrity_not_authenticity",
                                 "manual_claims_do_not_override_automatic_results"],
                "evidence_index": deepcopy(self.evidence_index),
                "evidence_sources": deepcopy(list(self.evidence_sources)),
                "snapshots": [snapshot.to_dict() for snapshot in self.snapshots]}


def normalize(document, *, day, snapshot_id, source, input_kind="results"):
    """Normalize a decoded source atomically; raises safe ReportInputError codes."""
    require(type(day) is int and day in (2, 3, 4), "day_invalid")
    text(snapshot_id)
    text(source)
    require(isinstance(document, dict))
    require(input_kind in {"results", "manual"} and (input_kind != "manual" or day == 4), "input_kind_invalid")
    base = str(Path(source).parent)
    diagnostics = []
    collection = {}
    if input_kind == "manual":
        require(type(document.get("schema_version")) is int and document["schema_version"] == 1,
                "manual_schema_version_invalid")
        asset_id = text(document.get("asset_id"))
        rows = document.get("checks")
        diagnostics += ["automatic_results_not_supplied", "manual_claims_not_revalidated",
                        "pf_and_log_analysis_results_not_supplied"]
    elif day == 2:
        rows = []
        for name in ("ubuntu", "mysql"):
            require(isinstance(document.get(name), dict) and isinstance(document[name].get("checks"), list))
            rows.extend(document[name]["checks"])
            settings = document[name].get("settings", {})
            require(isinstance(settings, dict) and len(settings) <= MAX_ROWS)
            require(all(isinstance(value, dict) for value in settings.values()))
            # Fixed setting identifiers may contain 'password'; their values are
            # never exported. Arbitrary input keys are not metadata identifiers.
            collection[name] = {key: {"status": status(value.get("status"), collection=True)}
                                for key, value in settings.items() if key in SETTING_NAMES[name]}
        diagnostics.append("raw_settings_excluded_collection_separate_from_verdict")
    else:
        rows = document.get("results")
        if day == 4:
            apis = document.get("api_results", {})
            require(isinstance(apis, dict))
            collection["api_results"] = {name: metadata(apis[name]) for name in
                                         ("interfaces", "export", "rules", "logs", "rule_ids") if name in apis}
            if "rule_id_mapping" in document:
                collection["rule_id_mapping"] = metadata(document["rule_id_mapping"])
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS)
    if not rows:
        diagnostics.append("no_results_in_input")
    results, identities = [], set()
    for row in rows:
        require(isinstance(row, dict))
        check_id = text(row.get("check_id"))
        if input_kind == "manual":
            manual = channel(row, base=base)
            manual["status"] = status(row.get("reported_status"))
            manual["status_origin"] = "operator_reported_not_revalidated"
            require("verified_at" in row and "scope" in row and isinstance(row.get("sources"), list))
            automatic, version, analyses = None, None, {}
        else:
            asset_id = text(row.get("asset_id"))
            version = text(row.get("rule_version"))
            text(row.get("execution_id"))
            timestamp(row.get("checked_at"))
            automatic = channel(row, base=base, audit=True)
            if "automatic_status" in row:
                require(status(row["automatic_status"]) == automatic["status"], "automatic_status_conflict")
            # Child channels are never used to replace this stored automatic status.
            automatic.pop("tests", None)
            manual = channel(row["manual_verification"], base=base, audit=True) if "manual_verification" in row else None
            analyses = {key: channel(row[key], base=base, audit=True) for key in
                        ("pf_snapshot", "log_rule_evidence") if key in row}
            if "api_results" in row:
                require(isinstance(row["api_results"], dict))
                automatic["api_results"] = {name: metadata(row["api_results"][name]) for name in
                                            ("interfaces", "export", "rules", "logs", "rule_ids") if name in row["api_results"]}
            if "rule_id_mapping" in row:
                automatic["rule_id_mapping"] = metadata(row["rule_id_mapping"])
        identity = (asset_id, check_id, version)
        require(identity not in identities, "duplicate_result_identity")
        identities.add(identity)
        results.append(ReportResult(asset_id, check_id, version, automatic, manual, analyses,
                                    text(row["risk"]) if row.get("risk") is not None else None,
                                    text(row["recommendation"]) if row.get("recommendation") is not None else None))
    return SourceSnapshot(snapshot_id, day, source, input_kind, tuple(results), tuple(diagnostics), collection)


def load_snapshot(path, *, day, snapshot_id, input_kind="results"):
    """Read exactly one bounded UTF-8 JSON file. Errors do not leak its contents."""
    source = text(str(path))
    text(snapshot_id)
    require(type(day) is int and day in (2, 3, 4), "day_invalid")
    try:
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        except FileNotFoundError:
            raise ReportInputError("input_missing") from None
        except (OSError, ValueError):
            raise ReportInputError("input_unreadable") from None
        require(len(data) <= MAX_BYTES, "input_too_large")
        try:
            document = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object,
                                  parse_constant=lambda _: require(False, "json_constant_invalid"))
        except ReportInputError:
            raise
        except (UnicodeError, ValueError, RecursionError):
            raise ReportInputError("json_invalid") from None
        return normalize(document, day=day, snapshot_id=snapshot_id, source=source, input_kind=input_kind)
    except ReportInputError as exc:
        return SourceSnapshot(snapshot_id, day, source, input_kind, diagnostics=(str(exc),), import_status="ERROR")


def integrate(snapshots, *, generated_at=None, evidence_sources=()):
    """Combine snapshots and optional unverified artifact identifiers.

    Raw PF/log files may be referenced here, but are not parsed or converted
    into verdicts. This is not an evidence index or an integrity check.
    """
    snapshots = tuple(snapshots)
    require(all(isinstance(item, SourceSnapshot) for item in snapshots))
    require(len({item.snapshot_id for item in snapshots}) == len(snapshots), "duplicate_snapshot_id")
    generated_at = timestamp(generated_at or datetime.now(timezone.utc).isoformat())
    artifacts = references(list(evidence_sources), base=None)
    return OfflineReport(generated_at, snapshots, tuple(artifacts))
