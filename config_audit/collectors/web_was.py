"""Fixed local WEB/WAS LAB, conservative configuration parsing, common engine.

No Docker lifecycle/configuration mutations. Raw configs, logs and HTTP payloads
are reduced to allowlisted observations in memory, never exported.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4
import xml.etree.ElementTree as ET

from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation
from ..reporting import ReportResult, SourceSnapshot

PROJECT = "scanner-p2web"
RULE_VERSION = "WEB-WAS-LAB-0.1"
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {"nginx": "1.30.6", "tomcat": "10.1.61"}
SCOPE = "fixed_readonly_container_configuration_and_named_http_endpoints"
CHECKS = {
    "WEB-LAB-N01": ("nginx", "autoindex_disabled", "Directory listing off and /files/ denied", "Set autoindex off for /files/."),
    "WEB-LAB-N02": ("nginx", "tokens_hidden", "Version tokens off and tested responses hide the version", "Set server_tokens off; check response headers and error body."),
    "WEB-LAB-N03": ("nginx", "private_blocked", "/private/ denied", "Return 404 for the unused /private/ path."),
    "WEB-LAB-N04": ("nginx", "access_logging", "Access log enabled and this run's marker recorded", "Enable the LAB access log and verify a current request marker."),
    "WAS-LAB-T01": ("tomcat", "autodeploy_disabled", "Explicit autoDeploy=false for the LAB Host", "Disable automatic deployment; deploy the LAB app at startup."),
    "WAS-LAB-T02": ("tomcat", "default_apps_absent", "docs/examples/manager/host-manager absent from active appBase", "Remove unneeded default applications from active webapps."),
    "WAS-LAB-T03": ("tomcat", "server_info_hidden", "ErrorReportValve hides report/server info; tested error hides product", "Disable showReport/showServerInfo and use a neutral connector Server value."),
    "WAS-LAB-T04": ("tomcat", "access_logging", "AccessLogValve enabled and this run's marker recorded", "Enable the Host AccessLogValve and verify a current request marker."),
}
RUNTIME_KEYS = {"proxy_ok", "directory_listing_blocked", "nginx_version_hidden", "private_path_blocked", "tomcat_version_hidden"}


class WebInputError(ValueError):
    """Fixed codes only; no subprocess stderr, payload or credentials."""


def require(ok, code="web_schema_invalid"):
    if not ok:
        raise WebInputError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def stamp(value):
    try:
        require(isinstance(value, str) and len(value) <= 64)
        parsed = datetime.fromisoformat(value)
        require(parsed.utcoffset() is not None, "timezone_required")
        return parsed
    except (TypeError, ValueError):
        raise WebInputError("collection_time_invalid") from None


def nginx_values(raw):
    """Recognize only the two shipped, include-free LAB configurations.

    Unknown contexts, includes, directives or overrides are NOT guessed. This
    is intentionally not a general nginx grammar/inheritance implementation.
    """
    def normalized(text):
        return re.sub(r"\s+", " ", re.sub(r"#[^\n]*", "", text)).strip()
    for stage in ("before", "after"):
        template = (ROOT / "lab/web-was-lab" / stage / "nginx.conf").read_text(encoding="utf-8")
        if normalized(raw) == normalized(template):
            good = stage == "after"
            return {"autoindex_disabled": good, "tokens_hidden": good,
                    "private_blocked": good, "access_logging": good}
    return {key: None for product, key, *_ in CHECKS.values() if product == "nginx"}


def tomcat_values(raw, apps):
    require(len(raw) <= 65536 and "<!" not in raw, "tomcat_xml_rejected")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise WebInputError("tomcat_xml_invalid") from None
    hosts = root.findall("./Service/Engine/Host")
    connectors = root.findall("./Service/Connector")
    values = {"autodeploy_disabled": None, "default_apps_absent": None,
              "server_info_hidden": None, "access_logging": None}
    allowed = {"Server": {"port"}, "Service": {"name"}, "Connector": {"port", "protocol", "server", "xpoweredBy"},
               "Engine": {"name", "defaultHost"}, "Host": {"name", "appBase", "unpackWARs", "autoDeploy", "deployOnStartup"},
               "Valve": {"className", "showReport", "showServerInfo", "directory", "prefix", "suffix", "rotatable", "pattern", "enabled", "buffered"}}
    if any(e.tag not in allowed or not set(e.attrib) <= allowed[e.tag] for e in root.iter()):
        return values
    if root.tag != "Server" or len(hosts) != 1 or len(connectors) != 1:
        return values
    if len(list(root.iter("Host"))) != 1 or len(list(root.iter("Connector"))) != 1:
        return values
    host, connector = hosts[0], connectors[0]
    if host.get("appBase") != "webapps" or host.get("name") != "localhost" or connector.get("port") != "8080":
        return values
    auto = host.get("autoDeploy")
    values["autodeploy_disabled"] = auto == "false" if auto in {"true", "false"} else None
    if isinstance(apps, dict) and set(apps) == {"docs", "examples", "manager", "host-manager"} and all(type(v) is bool for v in apps.values()):
        values["default_apps_absent"] = not any(apps.values())
    errors = [v for v in host.findall("Valve") if v.get("className") == "org.apache.catalina.valves.ErrorReportValve"]
    logs = [v for v in host.findall("Valve") if v.get("className") == "org.apache.catalina.valves.AccessLogValve"]
    if len(host.findall("Valve")) != len(errors) + len(logs):
        return {key: None for key in values}
    if len(errors) == 1:
        e = errors[0]
        if e.get("showReport") in {"true", "false"} and e.get("showServerInfo") in {"true", "false"}:
            values["server_info_hidden"] = (e.get("showReport") == e.get("showServerInfo") == "false" and connector.get("server") == "lab")
    # A missing Valve is genuinely disabled for this isolated single Host.
    if not logs:
        values["access_logging"] = False
    elif len(logs) == 1:
        log = logs[0]
        values["access_logging"] = (log.get("enabled") == "true" and log.get("directory") == "logs"
            and log.get("prefix") == "lab_access" and log.get("suffix") == ".log"
            and log.get("rotatable") == "false" and log.get("pattern") == "%r %s" and log.get("buffered") == "false")
    return values


def validate(bundle):
    require(isinstance(bundle, dict) and set(bundle) == {"schema_version", "origin", "collected_at", "nodes", "http"})
    require(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1)
    require(bundle["origin"] in {"synthetic", "local_container_readonly"})
    stamp(bundle["collected_at"])
    require(isinstance(bundle["http"], dict) and set(bundle["http"]) <= RUNTIME_KEYS)
    require(all(type(v) is bool for v in bundle["http"].values()))
    require(isinstance(bundle["nodes"], dict) and set(bundle["nodes"]) == set(VERSIONS))
    for name, node in bundle["nodes"].items():
        require(isinstance(node, dict) and set(node) <= {"version", "values", "configuration_sha256", "image_id", "started_at", "error_code", "explicit_settings_only"})
        require(node.get("version") is None or isinstance(node["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", node["version"]))
        require(isinstance(node.get("values"), dict))
        require(set(node["values"]) <= {key for product, key, *_ in CHECKS.values() if product == name})
        require(all(v is None or type(v) is bool for v in node["values"].values()))
        if node.get("error_code") is not None:
            require(node["error_code"] in {"query_failed", "parse_failed", "startup_config_mismatch"})
        if node.get("configuration_sha256") is not None:
            require(isinstance(node["configuration_sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", node["configuration_sha256"]))
        if node.get("image_id") is not None:
            require(isinstance(node["image_id"], str) and re.fullmatch(r"sha256:[a-f0-9]{64}", node["image_id"]))
        if "started_at" in node:
            require(stamp(node["started_at"]) <= stamp(bundle["collected_at"]), "startup_time_after_collection")
        if "explicit_settings_only" in node:
            require(node["explicit_settings_only"] is True)


def load_bundle(path):
    try:
        with Path(path).open("rb") as f:
            raw = f.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "input_too_large")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
        bundle = data.get("bundle") if isinstance(data, dict) and "bundle" in data else data
        validate(bundle)
        return bundle, sha(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise WebInputError("input_unreadable_or_invalid_json") from None


def audit(bundle=None, *, synthetic=False):
    if bundle is not None:
        validate(bundle)
        require(synthetic == (bundle["origin"] == "synthetic"), "origin_flag_mismatch")
    now = datetime.now(timezone.utc)
    execution = str(uuid4())
    results = []
    for check, (product, key, criterion, recommendation) in CHECKS.items():
        node = bundle["nodes"][product] if bundle else {}
        config_value = node.get("values", {}).get(key)
        runtime_key = {"WEB-LAB-N01": "directory_listing_blocked", "WEB-LAB-N02": "nginx_version_hidden",
                       "WEB-LAB-N03": "private_path_blocked", "WAS-LAB-T03": "tomcat_version_hidden"}.get(check)
        runtime_value = bundle["http"].get(runtime_key) if bundle and runtime_key else None
        observed = None if bundle is None else {"configured": config_value, "http_confirmed": runtime_value}
        def condition(v, needs_http=runtime_key is not None):
            if v["configured"] is False or (needs_http and v["http_confirmed"] is False):
                return False
            if v["configured"] is None or (needs_http and v["http_confirmed"] is None):
                return None
            return True
        asset = AuditAsset(PROJECT + "-" + product, product, node.get("version"))
        rule = AuditRule(check, RULE_VERSION, criterion, recommendation, condition=condition,
                         product=product, version_matches=(lambda version, p=product: True if version == VERSIONS[p] else None) if bundle else None)
        evidence = "sha256:" + node["configuration_sha256"] + "#" + key if node.get("configuration_sha256") else None
        verdict = evaluate(asset, rule, Observation(observed, evidence, bool(node.get("error_code"))),
                           execution_id=execution, checked_at=now)
        row = {**verdict.to_safe_dict(), "product": product, "version": asset.version, "observed_value": observed,
               "expected_condition": criterion, "recommendation": recommendation, "evidence_reference": evidence,
               "collected_at": bundle["collected_at"] if bundle else None, "scope": SCOPE,
               "verification_method": "synthetic_fixture" if synthetic else "readonly_fixed_docker_config_and_http" if bundle else "not_executed",
               "reason": node.get("error_code") or ("supported_version_not_verified" if asset.version and asset.version != VERSIONS[product] else "internal_LAB_criterion"),
               "settings_basis": "explicit_LAB_config_and_observed_runtime_only_no_default_inference"}
        results.append(row)
    return {"schema_version": 1, "mode": "LAB", "origin": bundle["origin"] if bundle else "not_executed",
            "generated_at": now.isoformat(), "rule_version": RULE_VERSION, "bundle": bundle,
            "results": results, "summary": dict(Counter(r["status"] for r in results)),
            "http_verification": {"status": "PASS" if bundle and bundle["http"].get("proxy_ok") is True else "FAIL" if bundle and bundle["http"].get("proxy_ok") is False else "NOT_TESTED",
                                  "scope": "nginx_to_tomcat_lab_health_endpoint"},
            "limitations": ["internal_LAB_not_KISA_certification", "not_a_general_configuration_parser",
                            "tested_named_HTTP_paths_only", "no_TLS_or_internet_exposure_assessment",
                            "hash_identifies_bytes_not_source_authenticity", "no_container_lifecycle_or_policy_changes_by_collector"]}


def as_snapshot(report, snapshot_id):
    """Reuse the Day5 common model, independently of its historical day catalog."""
    return SourceSnapshot(snapshot_id=snapshot_id, day=0, source="phase2_web_was", input_kind="LAB",
        collection={"origin": report["origin"], "collected_at": report["bundle"]["collected_at"] if report["bundle"] else None},
        results=tuple(ReportResult(asset_id=r["asset_id"], check_id=r["check_id"], rule_version=r["rule_version"],
            automatic={k: r[k] for k in ("status", "collected_at", "checked_at", "scope", "verification_method", "evidence_reference")},
            recommendation=r["recommendation"]) for r in report["results"]))


def compare(report, baseline_path):
    before, digest = load_bundle(baseline_path)
    after = report["bundle"]
    require(after is not None and before["origin"] == after["origin"], "comparison_origin_mismatch")
    # Re-evaluate both recorded observations under the same LAB rule version.
    # This is not a claim that a saved historical verdict used this version.
    previous = audit(before, synthetic=before["origin"] == "synthetic")
    issues = []
    if stamp(before["collected_at"]) >= stamp(after["collected_at"]): issues.append("collection_time_not_increasing")
    if any(before["nodes"][p]["version"] != after["nodes"][p]["version"] for p in VERSIONS): issues.append("product_version_mismatch")
    if before["http"].get("proxy_ok") is not True or after["http"].get("proxy_ok") is not True:
        issues.append("proxy_path_not_verified_before_and_after")
    transitions = {("FAIL", "PASS"): "IMPROVED_OBSERVED", ("FAIL", "FAIL"): "UNRESOLVED", ("PASS", "FAIL"): "REGRESSED", ("PASS", "PASS"): "UNCHANGED_PASS"}
    rows = [{"asset_id": b["asset_id"], "check_id": b["check_id"], "before_status": a["status"], "after_status": b["status"],
             "before_values": a["observed_value"], "after_values": b["observed_value"],
             "comparison_result": "INCOMPARABLE" if issues else transitions.get((a["status"], b["status"]), "UNVERIFIABLE"),
             "remediation_complete_in_LAB": not issues and a["status"] == "FAIL" and b["status"] == "PASS" and report["origin"] == "local_container_readonly"}
            for a, b in zip(previous["results"], report["results"])]
    report["comparison"] = {"baseline_sha256": digest, "issues": issues, "basis": "saved_observations_reevaluated_same_internal_LAB_rule",
        "results": rows, "summary": dict(Counter(r["comparison_result"] for r in rows)),
        "remediation_performed_by_collector": False, "independent_expected_hash_provided": False}
    return report


def run(args):
    try:
        completed = subprocess.run(args, capture_output=True, timeout=45, encoding="utf-8", errors="strict", shell=False)
        require(completed.returncode == 0 and len(completed.stdout) <= 1024 * 1024, "docker_query_failed")
        return completed.stdout
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise WebInputError("docker_query_failed") from None


def docker_scope():
    context = run(["docker", "context", "show"]).strip()
    require(context in {"default", "desktop-linux"}, "local_docker_context_required")
    try:
        endpoint = json.loads(run(["docker", "context", "inspect", context]))[0]["Endpoints"]["docker"]["Host"]
        require(endpoint in {"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine", "npipe:////./pipe/dockerDesktopLinuxEngine"}, "remote_docker_rejected")
        args = ["docker", "--context", context]
        require(run(args + ["info", "--format", "{{.OSType}}"] ).strip() == "linux", "linux_engine_required")
        nodes = {}
        for name in VERSIONS:
            obj = json.loads(run(args + ["inspect", PROJECT + "-" + name + "-1"]))[0]
            cfg, host = obj["Config"], obj["HostConfig"]
            labels = cfg.get("Labels", {})
            require(labels.get("com.docker.compose.project") == PROJECT and labels.get("com.docker.compose.service") == name, "foreign_container_rejected")
            require(obj["State"]["Running"] is True and not host.get("Privileged") and host.get("ReadonlyRootfs") is True
                    and cfg.get("User") == "10001:10001" and host.get("NetworkMode") != "host"
                    and host.get("PidMode") != "host" and host.get("IpcMode") != "host"
                    and not host.get("CapAdd") and not any((host.get("PortBindings") or {}).values()), "unsafe_container_rejected")
            require(cfg.get("Entrypoint") == ["/bin/sh", "/opt/lab/start.sh"] and cfg.get("Cmd") == (["nginx", "-g", "daemon off;"] if name == "nginx" else ["catalina.sh", "run"]), "unknown_startup_command")
            require(set(obj["NetworkSettings"]["Networks"]) == {PROJECT + "_backend"}, "unexpected_network_membership")
            require(all(m.get("Type") == "tmpfs" and m.get("Destination") in {"/tmp", "/usr/local/tomcat/logs", "/usr/local/tomcat/work", "/usr/local/tomcat/temp"} for m in obj.get("Mounts", [])), "unexpected_mount")
            nodes[name] = obj
        net = json.loads(run(args + ["network", "inspect", PROJECT + "_backend"]))[0]
        require(net.get("Internal") is True and net.get("Driver") == "bridge" and net.get("Labels", {}).get("com.docker.compose.project") == PROJECT
                and set(net.get("Containers", {})) == {n["Id"] for n in nodes.values()}, "isolated_network_scope_invalid")
        return args, nodes
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise WebInputError("docker_response_invalid") from None


def collect_docker():
    args, nodes = docker_scope()
    def execute(name, command): return run(args + ["exec", nodes[name]["Id"]] + command)
    captured = {}
    for product in VERSIONS:
        node = {"version": None, "values": {}, "image_id": nodes[product]["Image"],
                "started_at": nodes[product]["State"]["StartedAt"], "explicit_settings_only": True}
        try:
            version_text = execute(product, ["sh", "-c", "nginx -v 2>&1"] if product == "nginx" else ["catalina.sh", "version"])
            match = re.search(r"nginx/(\d+\.\d+\.\d+)" if product == "nginx" else r"Apache Tomcat/(\d+\.\d+\.\d+)", version_text)
            require(match is not None, "version_parse_failed")
            node["version"] = match[1]
            config_path = "/etc/nginx/nginx.conf" if product == "nginx" else "/usr/local/tomcat/conf/server.xml"
            config = execute(product, ["cat", config_path])
            digest = sha(config.encode("utf-8"))
            startup = execute(product, ["cat", "/tmp/startup-config.sha256"]).split()
            require(startup == [digest, config_path], "startup_config_mismatch")
            node["configuration_sha256"] = digest
            if product == "nginx":
                execute(product, ["nginx", "-t"])
                node["values"] = nginx_values(config)
            else:
                apps = {app: execute(product, ["sh", "-c", 'if [ -e "' + "/usr/local/tomcat/webapps/" + app + '" ] || [ -e "' + "/usr/local/tomcat/webapps/" + app + '.war" ]; then printf yes; else printf no; fi']) == "yes"
                        for app in ("docs", "examples", "manager", "host-manager")}
                node["values"] = tomcat_values(config, apps)
        except WebInputError as e:
            node["error_code"] = "startup_config_mismatch" if str(e) == "startup_config_mismatch" else "query_failed"
        captured[product] = node
    marker = uuid4().hex
    http = {}
    try:
        http = json.loads(execute("tomcat", ["java", "-cp", "/opt/lab", "Probe", marker]))
        require(set(http) == RUNTIME_KEYS and all(type(v) is bool for v in http.values()), "http_response_invalid")
    except (WebInputError, ValueError, TypeError):
        http = {}
    # Only marker presence is retained. No original access log is exported.
    for product in VERSIONS:
        if captured[product]["values"].get("access_logging") is True:
            path = "/tmp/lab-access.log" if product == "nginx" else "/usr/local/tomcat/logs/lab_access.log"
            try:
                text = execute(product, ["cat", path])
                captured[product]["values"]["access_logging"] = marker in text
            except WebInputError:
                captured[product]["values"]["access_logging"] = None
    bundle = {"schema_version": 1, "origin": "local_container_readonly", "collected_at": datetime.now(timezone.utc).isoformat(), "nodes": captured, "http": http}
    validate(bundle)
    return bundle


def synthetic_bundle(stage):
    """Explicit test data derived from templates, never a live VM verdict."""
    require(stage in {"before", "after"}, "synthetic_stage_invalid")
    base = ROOT / "lab/web-was-lab" / stage
    nginx = (base / "nginx.conf").read_text(encoding="utf-8")
    tomcat = (base / "server.xml").read_text(encoding="utf-8")
    values = {"nginx": nginx_values(nginx), "tomcat": tomcat_values(tomcat,
        {app: stage == "before" and app in {"docs", "examples"} for app in ("docs", "examples", "manager", "host-manager")})}
    return {"schema_version": 1, "origin": "synthetic", "collected_at": "2026-01-01T00:00:00+00:00" if stage == "before" else "2026-01-01T00:01:00+00:00",
        "nodes": {p: {"version": VERSIONS[p], "configuration_sha256": sha(text.encode()), "values": values[p], "explicit_settings_only": True}
                  for p, text in (("nginx", nginx), ("tomcat", tomcat))},
        "http": {key: True if key == "proxy_ok" else stage == "after" for key in RUNTIME_KEYS}}
