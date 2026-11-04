"""Read rendered ModSecurity directives and correlate the lab audit event."""

import json
import re

SETUP = "/etc/modsecurity.d/setup.conf"
MAIN = "/etc/modsecurity.d/modsecurity.conf"
OVERRIDE = "/etc/modsecurity.d/modsecurity-override.conf"
CRS_SETUP = "/etc/modsecurity.d/owasp-crs/crs-setup.conf"
CRS_RULES = "/etc/modsecurity.d/owasp-crs/rules/*.conf"
REQUIRED_INCLUDES = (MAIN, OVERRIDE, CRS_SETUP, CRS_RULES)
PLUGIN_DIR = "/etc/modsecurity.d/owasp-crs/plugins"
ALLOWED_INCLUDES = (
    MAIN, OVERRIDE, CRS_SETUP,
    f"{PLUGIN_DIR}/*-config.conf",
    f"{PLUGIN_DIR}/*-before.conf",
    CRS_RULES,
    f"{PLUGIN_DIR}/*-after.conf",
)


def includes(output: str) -> tuple[str, ...]:
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"(?i)^Include\b", line):
            match = re.fullmatch(r'(?i)Include\s+(?:"([^"]+)"|([^\s#"]+))\s*(?:#.*)?', line)
            paths.append((match[1] or match[2]) if match else "")
    return tuple(paths)


def valid_setup_includes(output: str) -> bool:
    """Accept only the stock include order with optional CRS plugin globs."""
    active = includes(output)
    return (
        all(path in active for path in REQUIRED_INCLUDES)
        and active == tuple(path for path in ALLOWED_INCLUDES if path in active)
    )


def nginx_values(output: str, directive: str) -> set[str]:
    return {value.strip() for value in re.findall(rf"(?m)^\s*{directive}\s+([^;\r\n]+);", output)}


def parse_directives(main: str, override: str) -> tuple[bool | None, ...]:
    settings = dict(
        (name.lower(), value.strip('"\'').lower())
        for name, value in re.findall(r"(?mi)^\s*(Sec\w+)\s+([^\s#]+)", main + "\n" + override)
    )
    keys = ("secruleengine", "secauditengine", "secauditlogformat", "secrequestbodyaccess")
    return tuple(settings[key] == expected if key in settings else None
                 for key, expected in zip(keys, ("on", "relevantonly", "json", "on"), strict=True))


def parse_crs_setup(setup: str, load_log: str) -> bool | str:
    active = "\n".join(line for line in setup.splitlines() if not line.lstrip().startswith("#"))
    paranoia = set(re.findall(r"\btx\.blocking_paranoia_level=(\d+)\b", active, re.IGNORECASE))
    inbound = set(re.findall(r"\btx\.inbound_anomaly_score_threshold=(\d+)\b", active, re.IGNORECASE))
    if len(paranoia) != 1 or len(inbound) != 1:
        return "crs_threshold_unverified"
    if paranoia != {"1"} or inbound != {"5"}:
        return False
    matches = re.findall(r"rules loaded inline/local/remote:\s*\d+/(\d+)/\d+", load_log, re.IGNORECASE)
    if not matches:
        return "crs_load_unverified"
    return int(matches[-1]) > 0


def parse_probe(output: str) -> tuple[str, int, int]:
    payload = json.loads(output)
    if not isinstance(payload, dict):
        raise ValueError("invalid probe")
    run, control, policy = (payload.get(key) for key in ("run", "control_status", "policy_status"))
    if (not isinstance(run, str) or not re.fullmatch(r"[0-9a-f]{32}", run)
            or type(control) is not int or type(policy) is not int):
        raise ValueError("invalid probe")
    return run, control, policy


def correlate_audit(output: str, run: str) -> bool | str:
    uri = f"/day3-policy?run={run}"
    for line in output.splitlines():
        if not line.lstrip().startswith("{") or run not in line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        transaction = event.get("transaction") if isinstance(event, dict) else None
        if not isinstance(transaction, dict):
            continue
        request, response = transaction.get("request"), transaction.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        if request.get("uri") != uri or request.get("method") != "PUT" or response.get("http_code") != 403:
            continue
        messages = transaction.get("messages")
        if not isinstance(messages, list):
            continue
        rules = set()
        for message in messages:
            details = message.get("details") if isinstance(message, dict) else None
            if isinstance(details, dict):
                rule = details.get("ruleId")
                if isinstance(rule, (str, int)):
                    rules.add(str(rule))
        if {"911100", "949110"} <= rules:
            return True
    return "audit_event_unverified"
