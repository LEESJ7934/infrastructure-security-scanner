"""Explicit, read-only collection from the Windows Docker Desktop Day 2 lab."""

import argparse
from datetime import datetime, timezone
import json
import os
import re
import subprocess
from uuid import uuid4

from config_audit.collectors.linux_ssh import SSH_COMMAND, SSH_VALUES, parse_ssh_settings
from config_audit.collectors.mysql_config import MYSQL_COMMAND, MYSQL_KEYS, parse_mysql_settings
from config_audit.engine import evaluate
from config_audit.models import AuditAsset, AuditRule, Observation

PROJECT = "infra-day2-lab"
DOCKER = ("docker", "--host", "npipe:////./pipe/dockerDesktopLinuxEngine")
LABEL_FORMAT = (
    '{{index .Config.Labels "com.docker.compose.project"}}|'
    '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Running}}|{{.Name}}'
)
SERVICES = {
    "ubuntu": (SSH_COMMAND, parse_ssh_settings, SSH_VALUES),
    "mysql": (MYSQL_COMMAND, parse_mysql_settings, MYSQL_KEYS),
}
RULES = {
    "ubuntu": {
        "permitemptypasswords": AuditRule(
            "LAB-SSH-001", "1", "PermitEmptyPasswords = no", "Disable empty SSH passwords.",
            condition=lambda value: None if value == "unrecognized" else value == "no",
            product="linux",
        ),
        "permitrootlogin": AuditRule(
            "LAB-SSH-002", "1", "PermitRootLogin = no", "Disable direct SSH root login.",
            condition=lambda value: None if value == "unrecognized" else value == "no",
            product="linux",
        ),
    },
    "mysql": {
        "local_infile": AuditRule(
            "LAB-MYSQL-001", "1", "local_infile = 0", "Disable LOCAL INFILE when not required.",
            condition=lambda value: value == 0,
            product="mysql",
        ),
        "require_secure_transport": AuditRule(
            "LAB-MYSQL-002", "1", "require_secure_transport = 1", "Require secure MySQL transport.",
            condition=lambda value: value == 1,
            product="mysql",
        ),
    },
}


class CollectionError(Exception):
    """Contains a fixed diagnostic code, never process output."""


def _docker(args):
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in {"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    try:
        return subprocess.run(
            [*DOCKER, *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20, check=False, env=env,
        )
    except subprocess.TimeoutExpired:
        raise CollectionError("timeout") from None
    except OSError:
        raise CollectionError("docker_unavailable") from None


def _container_id(service):
    if service not in SERVICES:
        raise CollectionError("target_rejected")
    found = _docker((
        "container", "ls", "--no-trunc",
        "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--filter", f"label=com.docker.compose.service={service}",
        "--format", "{{.ID}}",
    ))
    if found.returncode:
        raise CollectionError("docker_connection_failed")
    ids = found.stdout.split()
    if not ids:
        raise CollectionError("target_unavailable")
    if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{64}", ids[0]):
        raise CollectionError("target_rejected")

    identity = _docker(("container", "inspect", "--format", LABEL_FORMAT, ids[0]))
    if identity.returncode:
        raise CollectionError("target_unavailable")
    if identity.stdout.strip() != f"{PROJECT}|{service}|true|/{PROJECT}-{service}-1":
        raise CollectionError("target_rejected")
    return ids[0]


def _collect(service):
    container = _container_id(service)
    command, parse, _ = SERVICES[service]
    process = _docker(("container", "exec", container, *command))
    if process.returncode:
        if service == "ubuntu" and "no hostkeys available" in process.stderr.lower():
            raise CollectionError("ssh_host_keys_missing")
        if service == "mysql":
            if process.returncode == 42:
                raise CollectionError("mysql_credentials_missing")
            if re.search(r"\bERROR (?:1045|2002|2003|2006|2013)\b", process.stderr):
                raise CollectionError("mysql_connection_failed")
        raise CollectionError("command_failed")
    return parse(process.stdout)


def _report(service, execution_id, checked_at):
    error = None
    try:
        settings = _collect(service)
    except CollectionError as exc:
        error = str(exc)
        settings = dict.fromkeys(SERVICES[service][2], Observation(collection_error=True))

    # The parsers only retain validated numbers, a constrained version, or fixed SSH tokens.
    observations = {}
    for key, observation in settings.items():
        if observation.collection_error:
            observations[key] = {"status": "ERROR", "error_code": error or "parse_error"}
        elif observation.observed_value is None:
            observations[key] = {"status": "NOT_TESTED"}
        else:
            observations[key] = {"status": "COLLECTED", "value": observation.observed_value}

    asset = AuditAsset(
        f"{PROJECT}/{service}", "linux" if service == "ubuntu" else "mysql",
        settings["version"].observed_value if service == "mysql" else None,
    )
    results = [
        evaluate(asset, rule, settings[key], execution_id=execution_id, checked_at=checked_at).to_safe_dict()
        for key, rule in RULES[service].items()
    ]
    return {"settings": observations, "checks": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read settings from the local infra-day2-lab only.")
    parser.add_argument("--execute", action="store_true", help="Explicitly approve local read-only lab collection.")
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("--execute is required to authorize collection")

    execution_id, checked_at = str(uuid4()), datetime.now(timezone.utc)
    reports = {service: _report(service, execution_id, checked_at) for service in SERVICES}
    print(json.dumps(reports, indent=2))
    return int(any(setting["status"] == "ERROR"
                   for report in reports.values() for setting in report["settings"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
