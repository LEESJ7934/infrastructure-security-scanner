"""Run the approved Windows Docker Desktop IDS and WAF lab audit."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from config_audit.collectors import modsecurity as waf
from config_audit.collectors import suricata as ids
from config_audit.engine import evaluate
from config_audit.models import AuditAsset, AuditRule, Observation

PROJECT = "infra-day3-lab"
NETWORK = PROJECT + "_day3"
LAB = Path(__file__).resolve().parents[1] / "lab/ids-waf-lab"
DOCKER = ("docker", "--host", "npipe:////./pipe/dockerDesktopLinuxEngine")
IMAGES = {
    "suricata": "jasonish/suricata:8.0.6",
    "waf": "owasp/modsecurity-crs:4.25.2-nginx-202610180210-lts",
    "backend": "python:3.12.12-slim-bookworm",
}
# Deterministic output of lab/ids-waf-lab/suricata/make_pcap.py. Only this fixture is replayed.
PCAP_SHA256 = "5a4221411956330f9e67754304f7c63005e193e7fc4d1bc7e8a54578c0474b1c"
INSPECT = (
    '{{.Id}}|{{.Name}}|{{index .Config.Labels "com.docker.compose.project"}}|'
    '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|'
    '{{.Config.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|'
    '{{json .HostConfig.PortBindings}}|'
    '{{range $name, $network := .NetworkSettings.Networks}}{{$name}}={{$network.NetworkID}} {{end}}'
)
NETWORK_INSPECT = (
    '{{.Name}}|{{.Internal}}|{{index .Labels "com.docker.compose.project"}}|'
    '{{index .Labels "com.docker.compose.network"}}|{{range $id, $_ := .Containers}}{{$id}} {{end}}'
)
IDS_SCRIPT = """run_suricata() {
    /usr/bin/suricata -c /etc/suricata/suricata.yaml -S /lab/ids-marker.rules -l /tmp \
        --set 'vars.address-groups.HOME_NET=[198.51.100.0/24]' \
        --set outputs.1.eve-log.enabled=yes --set unix-command.enabled=no "$@" 2>&1
}
run_suricata --dump-config
printf '\\n@@config:%s@@\\n' "$?"
run_suricata -T -v --init-errors-fatal
checked=$?
printf '\\n@@validate:%s@@\\n' "$checked"
if [ "$checked" -eq 0 ]; then
    run_suricata -r /lab/ids-waf-lab.pcap
    replay=$?
    printf '\\n@@replay:%s@@\\n' "$replay"
    if [ "$replay" -eq 0 ] && [ -r /tmp/eve.json ]; then
        cat /tmp/eve.json
    fi
fi
"""
IDS_RULES = (
    "EVE JSON regular file enabled", "EVE alert output enabled", "HOME_NET limited to fixture subnet",
    "Approved local signature loaded", "Suricata -T succeeds", "Synthetic marker alerts; control does not",
)
WAF_RULES = (
    "SecRuleEngine On", "SecAuditEngine RelevantOnly", "SecAuditLogFormat JSON", "SecRequestBodyAccess On",
    "CRS loaded with blocking level 1 and inbound threshold 5", "GET 200, PUT 403 and correlated CRS audit",
)


class CollectionError(Exception):
    """A fixed error code safe to report without subprocess diagnostics."""


def docker(*args, timeout=20):
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    try:
        return subprocess.run(
            [*DOCKER, *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", check=False, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise CollectionError("timeout") from None
    except OSError:
        raise CollectionError("docker_unavailable") from None


def require(result, reason="command_failed"):
    if result.returncode:
        raise CollectionError(reason)
    return result.stdout


def inspect(service, name, state, user, mode):
    raw = require(docker("container", "inspect", "--format", INSPECT, name), "target_unavailable")
    fields = raw.strip().split("|")
    expected = ["/" + name, PROJECT, service, state, IMAGES[service], user, mode]
    if (len(fields) != 10 or not re.fullmatch(r"[a-f0-9]{64}", fields[0])
            or fields[1:8] != expected or fields[8] not in {"null", "{}"}):
        raise CollectionError("target_rejected")
    return fields[0], fields[9].strip()


def artifact(name):
    path = LAB / name
    if path.resolve() != path or not path.is_file():
        raise CollectionError("fixture_unavailable")
    return path


def reading(value=None, source=None, reason=None, *, error=False):
    return Observation(value, source, error), reason


def read_ids(run_id):
    pcap = artifact("artifacts/day3.pcap")
    rule = artifact("suricata/ids-marker.rules")
    if hashlib.sha256(pcap.read_bytes()).hexdigest() != PCAP_SHA256:
        raise CollectionError("fixture_mismatch")
    active = [line for line in rule.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    if len(active) != 1 or re.findall(r"\bsid:\s*(\d+)\s*;", active[0]) != [str(ids.TEST_SID)]:
        raise CollectionError("fixture_rule_mismatch")

    name = f"{PROJECT}-ids-audit-{run_id}"
    created = require(docker(
        "container", "create", "--pull", "never", "--name", name,
        "--label", f"com.docker.compose.project={PROJECT}", "--label", "com.docker.compose.service=suricata",
        "--label", "com.docker.compose.oneoff=True", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "suricata",
        "--mount", f"type=bind,source={rule},target=/lab/ids-marker.rules,readonly",
        "--mount", f"type=bind,source={pcap},target=/lab/ids-waf-lab.pcap,readonly",
        "--entrypoint", "/bin/sh", IMAGES["suricata"], "-c", IDS_SCRIPT,
    ), "ids_create_failed").strip()
    container_id, _ = inspect("suricata", name, "created", "suricata", "none")
    if container_id != created:
        raise CollectionError("target_rejected")
    output = require(docker("container", "start", "--attach", container_id, timeout=90), "ids_execution_failed")
    return ids_readings(output, name)


def ids_readings(output, name):
    stages = re.split(r"(?m)^@@(config|validate|replay):(\d+)@@\s*$", output)
    if len(stages) < 7 or stages[1] != "config" or stages[4] != "validate":
        raise CollectionError("ids_output_invalid")
    values = [reading(value, f"{name}#dump-config") if value is not None else reading(reason="config_value_missing")
              for value in ids.parse_config(stages[0])]
    if stages[2] != "0":
        values = [reading(reason="config_dump_failed", error=True)] * 3

    validation_ok = stages[5] == "0"
    loaded = ids.parse_rule_load(stages[3])
    values.append(reading(loaded, f"{name}#rule-load", "rule_load_unverified" if loaded is None else None))
    values.append(reading(validation_ok, f"{name}#suricata-T",
                          None if validation_ok else "configuration_validation_failed"))
    if not validation_ok:
        values.append(reading(reason="validation_failed_before_replay"))
        return values
    if len(stages) != 10 or stages[7] != "replay":
        values.append(reading(reason="replay_output_invalid", error=True))
    elif stages[8] != "0":
        values.append(reading(reason="replay_failed", error=True))
    else:
        source = f"{name}:/tmp/eve.json"
        try:
            found = ids.parse_eve(stages[9])
        except ValueError:
            values.append(reading(source=source, reason="eve_parse_error", error=True))
        else:
            reason = {None: "eve_missing", False: "fixture_alert_mismatch",
                      "uncorrelated_packet": "fixture_packet_unverified"}.get(found)
            values.append(reading(found, source, reason))
    return values


def waf_targets():
    waf_id, network = inspect("waf", f"{PROJECT}-waf-1", "running", "nginx", NETWORK)
    backend_id, backend_network = inspect("backend", f"{PROJECT}-backend-1", "running", "65534:65534", NETWORK)
    match = re.fullmatch(rf"{re.escape(NETWORK)}=([a-f0-9]{{64}})", network)
    if not match or network != backend_network:
        raise CollectionError("network_rejected")
    raw = require(docker("network", "inspect", "--format", NETWORK_INSPECT, match[1]), "network_unavailable")
    fields = raw.strip().split("|")
    if fields[:4] != [NETWORK, "true", PROJECT, "day3"] or len(fields) != 5:
        raise CollectionError("network_rejected")
    if set(fields[4].split()) != {waf_id, backend_id}:
        raise CollectionError("network_rejected")
    return waf_id, backend_id


def read_waf():
    waf_id, backend_id = waf_targets()
    source = f"{PROJECT}/waf"
    nginx = docker("container", "exec", "--user", "nginx", waf_id, "nginx", "-T")
    rendered = require(nginx, "nginx_validation_failed")
    if waf.nginx_values(rendered, "proxy_pass") != {"http://backend:8081"}:
        raise CollectionError("backend_target_rejected")

    rules_files = waf.nginx_values(rendered, "modsecurity_rules_file")
    module = waf.nginx_values(rendered, "modsecurity")
    if rules_files != {waf.SETUP} or module != {"on"}:
        values = [reading(False, source + "#nginx-T", "module_disabled") if module == {"off"}
                  else reading("unverified", source + "#nginx-T", "modsecurity_include_unverified")]
        return values + [reading(reason="modsecurity_include_unverified")] * 5

    def read_file(path):
        return require(docker("container", "exec", "--user", "nginx", waf_id, "cat", path),
                       "rendered_config_read_failed")

    setup = read_file(waf.SETUP)
    if not waf.valid_setup_includes(setup):
        return [reading("unverified", source + "#setup", "include_chain_unverified")] * 6
    main, override = read_file(waf.MAIN), read_file(waf.OVERRIDE)
    if waf.includes(main) or waf.includes(override):
        return [reading("unverified", source + "#setup", "include_chain_unverified")] * 6
    values = [reading(value, source + "#rendered-modsecurity", "config_value_missing" if value is None else None)
              for value in waf.parse_directives(main, override)]
    crs_setup = read_file(waf.CRS_SETUP)
    if waf.includes(crs_setup):
        return [reading("unverified", source + "#crs", "include_chain_unverified")] * 6
    # Reuse the existing fixed client inside the validated, non-root backend.
    try:
        probe = docker("container", "exec", "--user", "65534:65534", backend_id, "python", "-B", "-c",
                       artifact("waf/check_waf.py").read_text(encoding="utf-8"), timeout=45)
        logs = docker("container", "logs", "--tail", "300", waf_id)
        log_text = require(logs, "audit_log_unavailable") + "\n" + logs.stderr
    except CollectionError as exc:
        values.append(reading(waf.parse_crs_setup(crs_setup, nginx.stderr), source + "#crs"))
        return values + [reading(reason=str(exc), error=True)]

    crs = waf.parse_crs_setup(crs_setup, log_text + "\n" + nginx.stderr)
    values.append(reading(crs, source + "#crs", crs if isinstance(crs, str) else None))
    try:
        run, control, policy = waf.parse_probe(probe.stdout)
    except ValueError:
        failed_control = re.fullmatch(r"Backend control failed \(HTTP \d{3}\)", probe.stdout.strip())
        values.append(reading(False, source + "#http-probe", "control_request_failed") if failed_control
                      else reading(reason="http_probe_failed", error=True))
        return values

    ref = f"{source}#audit-run-{run}"
    if (control, policy) != (200, 403):
        values.append(reading(False, ref, "http_status_mismatch"))
    elif probe.returncode:
        values.append(reading(source=ref, reason="http_probe_failed", error=True))
    else:
        matched = waf.correlate_audit(log_text, run)
        values.append(reading(matched, ref, matched if isinstance(matched, str) else None))
    return values


def rows(prefix, descriptions, service, product, collector, execution_id, checked_at):
    try:
        values = collector()
    except CollectionError as exc:
        values = [reading(reason=str(exc), error=True)] * len(descriptions)
    except (OSError, UnicodeError):
        values = [reading(reason="lab_file_read_failed", error=True)] * len(descriptions)
    asset = AuditAsset(f"{PROJECT}/{service}", product)
    output = []
    for index, (description, (observation, reason)) in enumerate(zip(descriptions, values, strict=True), start=1):
        rule = AuditRule(
            f"{prefix}-{index:02}", "1", description, "Review the Day 3 lab policy and its evidence.",
            condition=lambda value: value if type(value) is bool else None,
            product=product,
        )
        result = evaluate(asset, rule, observation, execution_id=execution_id, checked_at=checked_at)
        row = result.to_safe_dict()
        if result.evidence_reference:
            row["evidence_reference"] = result.evidence_reference
        if reason or result.status == "FAIL":
            row["reason"] = reason or "lab_policy_mismatch"
        output.append(row)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect from the approved local Day 3 Docker lab.")
    parser.add_argument("--execute", action="store_true", help="Approve the isolated offline and internal HTTP tests.")
    if not parser.parse_args(argv).execute:
        parser.error("--execute is required to authorize collection")
    run_id = uuid4().hex
    checked_at = datetime.now(timezone.utc)
    results = rows("IDS", IDS_RULES, "suricata", "suricata", lambda: read_ids(run_id), run_id, checked_at)
    results += rows("WAF", WAF_RULES, "waf", "modsecurity", read_waf, run_id, checked_at)
    print(json.dumps({"project": PROJECT, "results": results}, indent=2))
    return int(any(row["status"] == "ERROR" for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
