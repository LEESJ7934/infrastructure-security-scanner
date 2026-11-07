"""Linux FRR / Docker bridge LAB observations, evaluated by the common engine.

No vendor CLI is guessed. Raw configurations and Docker environment variables
are never published. Docker collection is explicitly local and project-scoped.
"""
from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation
from ..reporting import ReportResult, SourceSnapshot
from ..statuses import AuditStatus

PROJECT = "scanner-p2net"
CHECKS = {
    "NET-LAB-R01": ("router", "ssh", "SSH root/password login disabled and listen address restricted to management", "Review effective sshd settings when SSH management is introduced."),
    "NET-LAB-R02": ("router", "listeners", "No non-loopback Telnet or FRR TCP VTY listener", "Keep FRR TCP VTY on loopback; use local Docker exec/vtysh."),
    "NET-LAB-R03": ("router", "guard", "Owned container input policy drop; only recognized non-TCP exceptions", "Apply the isolated LAB input guard; separately verify packet behavior."),
    "NET-LAB-R04": ("router", "listeners", "No unneeded HTTP/HTTPS/demo listener beyond loopback in this LAB", "Stop the explicitly started demo HTTP process inside this LAB router."),
    "NET-LAB-R05": ("router", "logging", "Active FRR running config has log stdout informational or more verbose", "Configure FRR log stdout; verify delivery separately."),
    "NET-LAB-S01": ("switch", "bridge", "Managed-switch control plane access restriction", "Docker bridge has no switch management CLI; assess Docker daemon access separately."),
    "NET-LAB-S02": ("switch", "bridge", "802.1Q VLAN filtering and port membership", "Separate Docker bridges are not proof of 802.1Q VLAN enforcement."),
    "NET-LAB-S03": ("switch", "bridge", "Exactly the expected LAB endpoints attached to each data bridge", "Remove unexpected LAB bridge attachments; physical port shutdown is outside scope."),
}


class NetworkInputError(ValueError):
    """Fixed codes only. Never include raw command stderr or configurations."""


def require(ok, code="network_schema_invalid"):
    if not ok: raise NetworkInputError(code)


def object_keys(value, keys):
    require(isinstance(value, dict) and set(value) <= set(keys))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def validate(bundle):
    object_keys(bundle, {"schema_version", "origin", "collected_at", "router", "switch"})
    require(type(bundle.get("schema_version")) is int and bundle["schema_version"] == 1)
    require(isinstance(bundle.get("origin"), str) and bundle["origin"] in {"local_container_readonly", "synthetic"})
    stamp = bundle.get("collected_at")
    require(isinstance(stamp, str) and len(stamp) <= 64 and "T" in stamp)
    try: require(datetime.fromisoformat(stamp).utcoffset() is not None)
    except ValueError: raise NetworkInputError("capture_time_invalid") from None
    for target, product, sections in (("router", "linux_frr", {"ssh", "listeners", "guard", "logging"}),
                                      ("switch", "docker_linux_bridge", {"bridge"})):
        node = bundle.get(target)
        object_keys(node, {"asset_id", "product", "version", "sections"})
        require(isinstance(node.get("asset_id"), str) and re.fullmatch(r"NET-LAB-[A-Z0-9-]{1,48}", node["asset_id"]))
        require(node.get("product") in ("linux_frr", "linux_router") if target == "router" else node.get("product") == product, "platform_not_supported")
        version = node.get("version")
        require(version is None or isinstance(version, str) and re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,63}", version))
        object_keys(node.get("sections"), sections)
        for section, observation in node["sections"].items():
            object_keys(observation, {"state", "error_code", "values", "source_kind", "collected_at", "reanalysis_at", "evidence_reference"})
            require(isinstance(observation.get("state"), str) and observation["state"] in {"COLLECTED", "NOT_TESTED", "ERROR"})
            if "source_kind" in observation: require(observation["source_kind"] in ("live_nft_chain", "user_exported_nft_chain"))
            if "evidence_reference" in observation: require(isinstance(observation["evidence_reference"], str) and re.fullmatch(r"sha256:[a-f0-9]{64}#inet/phase2_guard/input", observation["evidence_reference"]))
            for stamp_key in ("collected_at", "reanalysis_at"):
                if observation.get(stamp_key) is not None:
                    try: require(isinstance(observation[stamp_key], str) and len(observation[stamp_key]) <= 64 and datetime.fromisoformat(observation[stamp_key]).utcoffset() is not None)
                    except (ValueError, TypeError): raise NetworkInputError("capture_time_invalid") from None
            if observation["state"] == "ERROR": require(observation.get("error_code") in ("query_failed", "parse_failed", "command_unavailable", "permission_denied"))
            values = observation.get("values", {})
            require(observation["state"] == "COLLECTED" or not values)
            fields = {
                "ssh": {"installed": bool, "root_login_disabled": bool, "password_login_disabled": bool, "management_bind_only": bool},
                "listeners": {"tcp": list},
                "guard": {"input_policy": str, "recognized_scope_only": bool, "parser_version": str, "query_scope": str,
                          "recognized_exceptions": list, "unrecognized_reason_codes": list, "disallowed_accept": bool},
                "logging": {"stdout_enabled": bool},
                "bridge": {"driver_bridge": bool, "internal": bool, "expected_endpoints_only": bool, "two_distinct_segments": bool},
            }[section]
            object_keys(values, fields)
            for key, value in values.items():
                require(value is None or type(value) is fields[key])
                if value is None: continue
                if key == "input_policy": require(value in (None, "accept", "drop"))
                if key == "parser_version": require(value == "NET-GUARD-0.2")
                if key == "query_scope": require(value == "inet/phase2_guard/input")
                if key == "recognized_exceptions": require(len(value) <= 3 and all(item in ("loopback", "established_related", "icmp") for item in value))
                if key == "unrecognized_reason_codes": require(len(value) <= 16 and all(item in ("chain_missing_or_ambiguous", "chain_metadata_mismatch", "malformed_rule", "unapproved_accept", "unsupported_statement", "dormant_table") for item in value))
                if key == "tcp" and value is not None:
                    require(len(value) <= 256)
                    for endpoint in value:
                        object_keys(endpoint, {"address", "port"})
                        require(type(endpoint.get("port")) is int and 0 < endpoint["port"] < 65536)
                        require(isinstance(endpoint.get("address"), str), "listener_address_invalid")
                        try: ipaddress.ip_address(endpoint.get("address"))
                        except (ValueError, TypeError): raise NetworkInputError("listener_address_invalid") from None


def _load_document(path):
    try:
        with Path(path).open("rb") as stream: raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "input_size_limit")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False, "json_invalid"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise NetworkInputError("input_invalid") from None
    return data, hashlib.sha256(raw).hexdigest()


def load_bundle(path):
    data, digest = _load_document(path)
    if isinstance(data, dict) and "bundle" in data: data = data["bundle"]
    validate(data)
    return data, digest


def normalize_guard(document):
    """One canonical parser, shared with the container, loaded without running it."""
    source = Path(__file__).resolve().parents[2] / "lab/phase2-network/collect.py"
    spec = importlib.util.spec_from_file_location("network_guard_normalizer", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.guard(document)


def apply_guard_export(bundle, path):
    """Reanalyze the new user-exported chain; never recast old JSON as live data."""
    require(bundle["origin"] == "local_container_readonly", "actual_guard_export_requires_actual_saved_bundle")
    document, digest = _load_document(path)
    try: values = normalize_guard(document)
    except (ValueError, TypeError, KeyError): raise NetworkInputError("guard_json_invalid") from None
    updated = deepcopy(bundle)
    now = datetime.now(timezone.utc).isoformat()
    previous = deepcopy(updated["router"]["sections"].get("guard"))
    updated["router"]["sections"]["guard"] = {"state": "COLLECTED", "values": values,
        "source_kind": "user_exported_nft_chain", "collected_at": None, "reanalysis_at": now,
        "evidence_reference": "sha256:" + digest + "#inet/phase2_guard/input"}
    validate(updated)
    return updated, {"source": "user_exported_nft_chain", "sha256": digest, "integrity": "NOT_VERIFIED",
        "collected_at": None, "reanalysis_at": now, "original_guard": previous,
        "other_sections": "reused_from_saved_after_json_not_recollected", "file_mtime_not_used_as_capture_time": True}


def satisfied(check, value):
    if check == "NET-LAB-R01":
        fields = ("root_login_disabled", "password_login_disabled", "management_bind_only")
        return all(value[key] for key in fields) if all(type(value.get(key)) is bool for key in fields) else None
    if check in {"NET-LAB-R02", "NET-LAB-R04"}:
        endpoints = value.get("tcp")
        if endpoints is None: return None
        ports = {23, *range(2600, 2620)} if check.endswith("R02") else {80, 443, 8080, 8443}
        return not any(row["port"] in ports and not ipaddress.ip_address(row["address"]).is_loopback for row in endpoints)
    if check == "NET-LAB-R03":
        if value.get("disallowed_accept") is True: return False
        if value.get("input_policy") == "accept": return False
        return True if value.get("input_policy") == "drop" and value.get("recognized_scope_only") is True else None
    if check == "NET-LAB-R05": return value.get("stdout_enabled")
    if check == "NET-LAB-S03":
        return value.get("expected_endpoints_only") if value.get("driver_bridge") is True and value.get("internal") is True else None
    return None


class NetworkDeviceCollector:
    def __init__(self, bundle=None):
        if bundle: validate(bundle)
        self.bundle = bundle

    def rule(self, check):
        target, section, criterion, recommendation = CHECKS[check]
        node = self.bundle[target] if self.bundle else None
        values = node["sections"].get(section, {}).get("values", {}) if node else {}
        def applicable(version):
            if check == "NET-LAB-R01" and values.get("installed") is False: return False
            if check in {"NET-LAB-S01", "NET-LAB-S02"} and values.get("driver_bridge") is True: return False
            return True
        return AuditRule(check, "NET-LAB-0.2" if check == "NET-LAB-R03" else "NET-LAB-0.1", criterion, recommendation,
            condition=lambda value: satisfied(check, value), product=node["product"] if node else "linux_router" if target == "router" else "docker_linux_bridge",
            version_matches=applicable if node else None, standard_reference="Internal LAB only; KISA official mapping unverified")

    def collect(self, asset, check):
        target, section, _, _ = CHECKS[check]
        if self.bundle is None: return Observation()
        node = self.bundle[target]
        if node["asset_id"] != asset.asset_id: return Observation(collection_error=True)
        observation = node["sections"].get(section, {})
        reference = observation.get("evidence_reference") or "network-lab:" + self.bundle["collected_at"] + "#" + section
        if observation.get("state") == "ERROR": return Observation(evidence_reference=reference, collection_error=True)
        value = observation.get("values", {}) if observation.get("state") == "COLLECTED" else None
        return Observation(value, reference)


def audit(bundle=None, *, synthetic=False, error_code=None):
    if bundle: require((bundle["origin"] == "synthetic") == synthetic, "origin_mode_mismatch")
    collector = NetworkDeviceCollector(bundle)
    now, execution = datetime.now(timezone.utc), str(uuid4())
    rows = []
    for check, (target, section, criterion, _) in CHECKS.items():
        node = bundle[target] if bundle else {"asset_id": "NET-LAB-" + target.upper(), "product": "linux_router" if target == "router" else "docker_linux_bridge", "version": None}
        asset = AuditAsset(node["asset_id"], node["product"], node["version"])
        observation = Observation(collection_error=True) if error_code else collector.collect(asset, check)
        result = evaluate(asset, collector.rule(check), observation, execution_id=execution, checked_at=now)
        reason = ("no_switch_management_plane" if check == "NET-LAB-S01" else "8021q_vlan_not_implemented") if result.status.value == "NOT_APPLICABLE" and target == "switch" else (
            "ssh_server_not_installed_local_docker_exec_management_only" if result.status.value == "NOT_APPLICABLE" else error_code or "configuration_scope_only_no_packet_test")
        rows.append({**result.to_safe_dict(), "product": asset.product, "version": asset.version,
            "status": result.status.value, "reason": reason, "criterion": criterion, "recommendation": result.recommendation,
            "scope": "virtual_bridge_endpoint_inventory_only" if check == "NET-LAB-S03" else "linux_container_configuration_only",
            "verification_method": "readonly_project_scoped_docker" if bundle and not synthetic else "synthetic_fixture" if synthetic else "not_executed",
            "collected_at": bundle["collected_at"] if bundle else None, "evidence_reference": result.evidence_reference})
        if check == "NET-LAB-R03" and bundle:
            captured = bundle["router"]["sections"].get("guard", {})
            rows[-1]["scope"] = "inet/phase2_guard/input_configuration_only"
            if "collected_at" in captured: rows[-1]["collected_at"] = captured["collected_at"]
            if captured.get("source_kind") == "user_exported_nft_chain": rows[-1]["verification_method"] = "offline_user_exported_nft_chain"
            rows[-1]["recognition"] = deepcopy(captured.get("values", {}))
        rows[-1]["evidence_references"] = [{"reference": result.evidence_reference}] if result.evidence_reference else []
    return {"schema_version": 1, "mode": "synthetic_test_only" if synthetic else "LAB", "generated_at": now.isoformat(),
        "bundle": bundle, "results": [] if synthetic else rows, "synthetic_results": rows if synthetic else [],
        "packet_verification": {"status": "NOT_TESTED", "source": None},
        "limitations": ["not_physical_router_switch_validation", "no_Cisco_features_claimed", "8021q_not_verified",
                         "configuration_not_packet_proof", "no_KISA_certification", "LAB_no_organization_approval_or_independent_hash_gate"]}


def to_report_snapshot(report, *, snapshot_id):
    require(isinstance(snapshot_id, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", snapshot_id))
    simulated = report["mode"] == "synthetic_test_only"
    rows = report["synthetic_results"] if simulated else report["results"]
    return SourceSnapshot(snapshot_id, 0, "phase2_network_devices", "network_devices_v1",
        tuple(ReportResult(row["asset_id"], row["check_id"], row["rule_version"], None if simulated else dict(row),
            analyses={"synthetic_simulation": dict(row)} if simulated else {}, recommendation=row["recommendation"]) for row in rows),
        diagnostics=tuple(report["limitations"]))


def attach_baseline(report, path):
    """Link recorded before verdicts, without modifying or silently reevaluating them."""
    before, digest = _load_document(path)
    require(isinstance(before, dict) and isinstance(before.get("results"), list) and before.get("bundle") is not None, "baseline_report_invalid")
    validate(before["bundle"])
    require(before["bundle"]["origin"] == "local_container_readonly" and report["bundle"] is not None
            and report["bundle"]["origin"] == "local_container_readonly", "actual_baseline_required")
    require(len(before["results"]) <= 32, "baseline_report_invalid")
    initial = {}
    for row in before["results"]:
        require(isinstance(row, dict) and isinstance(row.get("check_id"), str) and row["check_id"] in CHECKS, "baseline_report_invalid")
        check = row["check_id"]
        require(check not in initial, "baseline_duplicate_result")
        require(isinstance(row.get("status"), str) and row["status"] in {status.value for status in AuditStatus}, "baseline_status_invalid")
        initial[check] = row
    transitions = {("FAIL", "PASS"): "IMPROVED_OBSERVED", ("PASS", "PASS"): "UNCHANGED_PASS",
                   ("FAIL", "FAIL"): "UNRESOLVED", ("PASS", "FAIL"): "REGRESSED"}
    comparisons = []
    for last in report["results"]:
        check = last["check_id"]
        first = initial.get(check)
        target = CHECKS[check][0]
        a, b = before["bundle"][target], report["bundle"][target]
        issues = []
        if first is None: issues.append("baseline_item_missing")
        if first and (first.get("asset_id") != a["asset_id"] or a["asset_id"] != b["asset_id"]): issues.append("asset_mismatch")
        expected_scope = {"linux_container_configuration_only"}
        if check == "NET-LAB-R03": expected_scope.add("inet/phase2_guard/input_configuration_only")
        if check == "NET-LAB-S03": expected_scope = {"virtual_bridge_endpoint_inventory_only"}
        if first and first.get("scope") not in expected_scope: issues.append("baseline_scope_not_supported")
        if (a["product"], a["version"]) != (b["product"], b["version"]): issues.append("platform_or_version_mismatch")
        version = first.get("rule_version") if first else None
        reviewed_fix = check == "NET-LAB-R03" and (version, last["rule_version"]) == ("NET-LAB-0.1", "NET-LAB-0.2")
        if first and version != last["rule_version"] and not reviewed_fix: issues.append("rule_version_not_compatible")
        old_status = first["status"] if first else None
        comparisons.append({"asset_id": last["asset_id"], "check_id": check, "before_status": old_status,
            "after_status": last["status"], "comparison_result": "INCOMPARABLE" if issues else transitions.get((old_status, last["status"]), "UNVERIFIABLE"),
            "before_evidence_sha256": digest, "after_evidence_reference": last["evidence_reference"],
            "rule_compatibility": "reviewed_R03_same_LAB_criterion_parser_fix" if reviewed_fix else "same_version" if not issues else "not_established",
            "after_verification_method": last["verification_method"], "before_collected_at": before["bundle"]["collected_at"],
            "after_collected_at": last["collected_at"], "issues": issues, "remediation_performed_by_this_run": False,
            "limitations": ["LAB_recorded_transition_not_whole_policy_or_packet_proof", "unknown_supplemental_capture_time_not_invented"]})
    from collections import Counter
    report["baseline_comparison"] = {"mode": "LAB", "baseline_sha256": digest,
        "results": comparisons, "summary": dict(Counter(row["comparison_result"] for row in comparisons)),
        "baseline_original_results_preserved": True}
    return report


def _run(arguments):
    try:
        done = subprocess.run(arguments, capture_output=True, timeout=20, encoding="utf-8", errors="strict", shell=False)
        require(done.returncode == 0 and len(done.stdout) <= 1024 * 1024, "docker_query_failed")
        return done.stdout
    except (OSError, UnicodeError, subprocess.SubprocessError): raise NetworkInputError("docker_unavailable") from None


def collect_docker():
    """Only current local Docker context and three fixed project-owned nodes."""
    context = _run(["docker", "context", "show"]).strip()
    require(context in {"desktop-linux", "default"}, "docker_context_not_allowed")
    try:
        settings = json.loads(_run(["docker", "context", "inspect", context]))
        endpoint = settings[0]["Endpoints"]["docker"]["Host"]
        require(endpoint in {"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine", "npipe:////./pipe/dockerDesktopLinuxEngine"}, "remote_docker_not_allowed")
        prefix = ["docker", "--context", context]
        require(_run(prefix + ["info", "--format", "{{.OSType}}"] ).strip() == "linux", "linux_engine_required")
        containers = {}
        for service in ("router", "client-a", "client-b"):
            name = PROJECT + "-" + service + "-1"
            info = json.loads(_run(prefix + ["inspect", name]))[0]
            labels = info.get("Config", {}).get("Labels", {})
            require(labels.get("com.docker.compose.project") == PROJECT and labels.get("com.docker.compose.service") == service, "foreign_container_rejected")
            require(info.get("State", {}).get("Running") is True and not info.get("HostConfig", {}).get("Privileged")
                    and info.get("HostConfig", {}).get("NetworkMode") != "host", "unsafe_or_stopped_container")
            require(not {cap.removeprefix("CAP_") for cap in info.get("HostConfig", {}).get("CapAdd") or []}
                    & {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE"}, "unsafe_capabilities")
            require(info.get("HostConfig", {}).get("PidMode") != "host" and info.get("HostConfig", {}).get("IpcMode") != "host", "host_namespace_rejected")
            require(not info.get("Mounts"), "unexpected_container_mounts")
            require(not any(info.get("HostConfig", {}).get("PortBindings", {}).values()), "published_ports_rejected")
            expected_networks = {PROJECT + "_" + name for name in (("management", "data_a", "data_b") if service == "router" else ("data_a",) if service == "client-a" else ("data_b",))}
            require(set(info.get("NetworkSettings", {}).get("Networks", {})) == expected_networks, "unexpected_network_membership")
            containers[service] = info["Id"]
        networks = []
        for side, client in (("a", "client-a"), ("b", "client-b")):
            info = json.loads(_run(prefix + ["network", "inspect", PROJECT + "_data_" + side]))[0]
            require(info.get("Labels", {}).get("com.docker.compose.project") == PROJECT, "foreign_network_rejected")
            require(info.get("Internal") is True and info.get("Driver") == "bridge", "nonisolated_network_rejected")
            networks.append((info, {containers["router"], containers[client]}))
        management = json.loads(_run(prefix + ["network", "inspect", PROJECT + "_management"]))[0]
        require(management.get("Labels", {}).get("com.docker.compose.project") == PROJECT and management.get("Internal") is True
                and management.get("Driver") == "bridge" and set(management.get("Containers", {})) == {containers["router"]}, "management_network_scope_invalid")
        router = json.loads(_run(prefix + ["exec", PROJECT + "-router-1", "python3", "/opt/network-lab/collect.py"]))
        # The running image may contain the old normalizer. Requery only the
        # named chain and use the current HOST parser; never rebuild/restart/cp.
        try:
            raw_guard = _run(prefix + ["exec", PROJECT + "-router-1", "nft", "-j", "list", "chain", "inet", "phase2_guard", "input"])
            normalized = normalize_guard(json.loads(raw_guard))
            router["sections"]["guard"] = {"state": "COLLECTED", "values": normalized, "source_kind": "live_nft_chain",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "evidence_reference": "sha256:" + hashlib.sha256(raw_guard.encode("utf-8")).hexdigest() + "#inet/phase2_guard/input"}
        except NetworkInputError:
            router["sections"]["guard"] = {"state": "ERROR", "error_code": "query_failed", "values": {}}
        except (ValueError, OSError, KeyError, TypeError):
            router["sections"]["guard"] = {"state": "ERROR", "error_code": "parse_failed", "values": {}}
        bridge = {"driver_bridge": all(info.get("Driver") == "bridge" for info, _ in networks),
                  "internal": all(info.get("Internal") is True for info, _ in networks),
                  "expected_endpoints_only": all(set(info.get("Containers", {})) == expected for info, expected in networks),
                  "two_distinct_segments": networks[0][0]["Id"] != networks[1][0]["Id"]}
        bundle = {"schema_version": 1, "origin": "local_container_readonly", "collected_at": datetime.now(timezone.utc).isoformat(),
            "router": router, "switch": {"asset_id": "NET-LAB-SWITCH", "product": "docker_linux_bridge",
                "version": _run(prefix + ["version", "--format", "{{.Server.Version}}"] ).strip(),
                "sections": {"bridge": {"state": "COLLECTED", "values": bridge}}}}
        validate(bundle)
        return bundle
    except NetworkInputError: raise
    except (ValueError, KeyError, IndexError, TypeError): raise NetworkInputError("docker_response_invalid") from None
