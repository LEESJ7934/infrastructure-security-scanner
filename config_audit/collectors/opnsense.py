"""Read-only Day 4 collection and conservative, offline-testable evidence checks.

Rule/Probe/Log are our evidence contract, NOT alleged OPNsense JSON schemas.
Only the interface overview has a source-reviewed API adapter. Never feed raw
API dictionaries directly into the normalized evidence checks.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import IncompleteRead
import ipaddress
import json
import os
import re
import subprocess

import requests

from ..models import AuditAsset, Observation

TARGET = "https://10.77.40.1"
EXPECTED = {"lan": ("hn1", "10.77.40.1/24"), "wan": ("hn0", "10.77.50.1/24")}
ENDPOINTS = {
    "interfaces": "/api/interfaces/overview/interfaces_info",
    "export": "/api/interfaces/overview/export",
    "config": "/api/diagnostics/interface/get_interface_config",
    "rules": "/api/firewall/filter/search_rule",
    "logs": "/api/diagnostics/firewall/log",
    "rule_ids": "/api/diagnostics/firewall/list_rule_ids",
}


class CollectionError(Exception):
    """Only fixed, non-secret error codes may cross the reporting boundary."""

    def __init__(self, code, *, http_status=None, stage="collection", error_code=None):
        super().__init__(code)
        self.http_status = http_status
        self.stage = stage
        self.error_code = error_code or code


def incomplete_response(error):
    """Recognize requests/urllib3 wrapping without reading exception text/body.

    IncompleteRead.partial may contain sensitive firewall records. Never format
    this exception or its arguments into diagnostic output.
    """
    pending, visited = [error], set()
    while pending:
        current_error = pending.pop()
        if id(current_error) in visited:
            continue
        visited.add(id(current_error))
        if isinstance(current_error, (IncompleteRead, requests.exceptions.ChunkedEncodingError)):
            return True
        pending.extend(item for item in (
            current_error.__cause__, current_error.__context__, *current_error.args,
        ) if isinstance(item, BaseException))
    return False


class ReadOnlyClient:
    def __init__(self, *, account, key, secret, ca_bundle, target=TARGET):
        if target != TARGET:
            raise CollectionError("target_rejected")
        if not account or account.strip().casefold() == "root":
            raise CollectionError("non_root_account_required")
        if not key or not secret:
            raise CollectionError("credentials_missing")
        if not isinstance(ca_bundle, str) or not os.path.isfile(ca_bundle):
            raise CollectionError("trusted_ca_required")
        self._auth = (key, secret)
        self._ca = ca_bundle
        self._session = requests.Session()
        # No environment proxies, netrc credentials or implicit redirects.
        self._session.trust_env = False

    def close(self):
        self._session.close()

    def get(self, name, uuid=None):
        if name == "rule" and isinstance(uuid, str) and re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid
        ):
            path = "/api/firewall/filter/get_rule/" + uuid
        elif name in ENDPOINTS and uuid is None:
            path = ENDPOINTS[name]
        else:
            raise CollectionError("endpoint_rejected")
        http_status = None
        try:
            # The appliance's unbounded log response can terminate prematurely.
            # Preserve the request parameters of every other API unchanged.
            options = {"params": {"limit": 20}} if name == "logs" else {}
            response = self._session.get(
                TARGET + path, auth=self._auth, verify=self._ca,
                timeout=(3, 10), allow_redirects=False, **options,
            )
            http_status = response.status_code
            if response.status_code in {401, 403}:
                raise CollectionError("api_authentication_or_acl_failed", http_status=response.status_code,
                                      stage="http", error_code={401: "api_unauthorized", 403: "api_forbidden"}[response.status_code])
            if response.status_code != 200:
                raise CollectionError("api_http_failed", http_status=response.status_code, stage="http",
                                      error_code="api_not_found" if response.status_code == 404 else "api_http_failed")
            try:
                value = response.json()
            except ValueError:
                raise CollectionError("api_json_invalid", http_status=200, stage="json_parse") from None
            if not isinstance(value, (dict, list)):
                raise CollectionError("api_response_invalid", http_status=200, stage="response_schema")
            if isinstance(value, dict) and (
                "error" in value or value.get("status") in ("error", "failed")
            ):
                raise CollectionError("api_response_failed", http_status=200, stage="api_response")
            return value
        except IncompleteRead:
            raise CollectionError("api_incomplete_response", http_status=http_status,
                                  stage="response_read") from None
        except requests.exceptions.SSLError:
            raise CollectionError("api_transport_or_tls_failed", stage="tls", error_code="api_tls_failed") from None
        except requests.Timeout:
            raise CollectionError("api_transport_or_tls_failed", stage="transport", error_code="api_timeout") from None
        except requests.RequestException as exc:
            if incomplete_response(exc):
                raise CollectionError("api_incomplete_response", http_status=http_status,
                                      stage="response_read") from None
            raise CollectionError("api_transport_or_tls_failed", stage="transport", error_code="api_connection_failed") from None


@dataclass(frozen=True)
class Rule:
    """Flattened, globally ordered IPv4 inbound rules for this small lab only.

    A verified adapter must expand aliases, groups, floating and generated rules
    and attest coverage. Unsupported PF features must leave coverage false.
    """
    rule_id: str
    order: int
    interface: str
    action: str
    enabled: bool
    quick: bool
    source: str = "any"
    destination: str = "any"
    protocol: str = "any"
    port: int | None = None


@dataclass(frozen=True)
class Probe:
    probe_id: str
    execution_id: str
    started_at: datetime
    finished_at: datetime
    interface: str
    source: str
    destination: str
    protocol: str
    outcome: str  # allowed, blocked, or inconclusive
    port: int | None = None
    scenario: str = "pass"
    control_ok: bool = False
    rule_id: str | None = None


@dataclass(frozen=True)
class Log:
    probe_id: str
    execution_id: str
    timestamp: datetime
    interface: str
    source: str
    destination: str
    protocol: str
    action: str
    port: int | None = None
    rule_id: str | None = None


@dataclass
class Evidence:
    execution_id: str
    started_at: datetime
    checked_at: datetime
    interfaces: object = field(default=None, repr=False)
    rules: list[Rule] | None = field(default=None, repr=False)
    complete_rules: bool = False
    probes: list[Probe] = field(default_factory=list, repr=False)
    logs: list[Log] = field(default_factory=list, repr=False)
    api_log_state: str | None = None
    errors: dict[str, str] = field(default_factory=dict)
    interface_export: object = field(default=None, repr=False)
    api_results: dict[str, dict] = field(default_factory=dict)
    rule_id_mapping: dict = field(default_factory=lambda: {
        "status": "NOT_TESTED", "reason": "rule_id_mapping_not_attempted",
    })


def interface_rows(payload, *, exported=False):
    """Confirmed outer containers only; nested config/flags have no guessed semantics."""
    if exported:
        rows = payload
    else:
        rows = payload.get("rows") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise CollectionError("interface_response_invalid", stage="response_schema")
    if any(not isinstance(row, dict) for row in rows):
        raise CollectionError("interface_response_invalid", stage="response_schema")
    return rows


def interfaces_match(payload, exported=None):
    """Use either confirmed outer shape, and only explicit understood fields.

    User-confirmed 26.7 rows do not establish enabled/IP field layouts. config,
    flags, capabilities, description and status alone cannot establish PASS.
    A complete explicit row in export may fill gaps in interfaces_info. Never
    join rows by position/device alone, or silently discard conflicting facts.
    """
    sources = []
    if payload is not None:
        sources.append(interface_rows(payload))
    if exported is not None:
        sources.append(interface_rows(exported, exported=True))
    if not sources:
        return None
    unknown = None
    for name, (device, address) in EXPECTED.items():
        candidates = []
        for rows in sources:
            matches = [row for row in rows if row.get("identifier") == name]
            if len(matches) > 1:
                return "interface_assignment_missing_or_ambiguous"
            candidates.extend(matches)
        if not candidates:
            unknown = "interface_assignment_missing_or_ambiguous"
            continue
        complete = False
        for row in candidates:
            if "device" not in row:
                unknown = "interface_fields_missing"
                continue
            if not isinstance(row["device"], str):
                unknown = "interface_fields_unverified"
                continue
            if row["device"] != device:
                return False
            if type(row.get("enabled")) is bool and row["enabled"] is False:
                return False
            if isinstance(row.get("status"), str) and row["status"] in {"down", "no carrier"}:
                return False
            ips = row.get("ipv4")
            if not isinstance(ips, list) or not ips:
                unknown = "interface_fields_missing" if "ipv4" not in row else "interface_address_missing"
                continue
            try:
                if any(not isinstance(item, dict) or not isinstance(item.get("ipaddr"), str)
                       or "/" not in item["ipaddr"] for item in ips):
                    raise ValueError("address_schema")
                addresses = [ipaddress.ip_interface(item["ipaddr"]) for item in ips]
            except (ValueError, KeyError, TypeError):
                unknown = "interface_address_unverified"
                continue
            if ipaddress.ip_interface(address) not in addresses:
                return False
            if not all(key in row for key in ("enabled", "status")):
                unknown = "interface_fields_missing"
                continue
            if type(row["enabled"]) is not bool or row["status"] != "up":
                unknown = "interface_fields_unverified"
                continue
            complete = True
        if not complete:
            return unknown or "interface_fields_missing"
    # Unknown metadata in a secondary source need not invalidate a complete row.
    if any(not any(row.get("identifier") == name for rows in sources for row in rows)
           for name in EXPECTED):
        return "interface_assignment_missing_or_ambiguous"
    return True


def current(evidence, probe):
    return (
        probe.execution_id == evidence.execution_id
        and evidence.started_at <= probe.started_at <= probe.finished_at <= evidence.checked_at
    )


def log_snapshot_state(payload):
    """Inspect source-reviewed read_log.py fields without inventing run identity.

    The official backend returns a list. Its timestamps may omit timezone/year;
    neither __digest__ nor rid is an execution id. Even recognized records must
    be correlated by a verified adapter before they can satisfy FW-05/06.
    """
    if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
        raise CollectionError("log_response_invalid")
    if not payload:
        return "firewall_log_snapshot_empty"
    fields = {"src", "dst", "protoname", "interface", "action", "rid", "__timestamp__"}
    for row in payload:
        if not fields <= row.keys() or any(not isinstance(row[key], str) for key in fields):
            return "log_schema_unverified"
        if row["action"] not in {"pass", "block", "reject"}:
            return "log_action_unverified"
    return "current_log_correlation_unverified"


def correlated(evidence, probe):
    """Timestamps alone are insufficient: a verified probe association is required.

    The adapter must establish probe_id from packet/rule evidence, not copy the
    current run id onto historical log lines. All tuple fields must agree.
    """
    if not current(evidence, probe):
        return []
    return [event for event in evidence.logs if (
        event.execution_id == evidence.execution_id and event.probe_id == probe.probe_id
        and probe.started_at <= event.timestamp <= probe.finished_at
        and (event.interface, event.source, event.destination, event.protocol, event.port)
        == (probe.interface, probe.source, probe.destination, probe.protocol, probe.port)
        and (probe.rule_id is None or event.rule_id == probe.rule_id)
    )]


def traffic_matches(rule, probe):
    def contains(network, address):
        return network == "any" or ipaddress.ip_address(address) in ipaddress.ip_network(network)
    return (
        rule.interface in {"any", probe.interface}
        and rule.protocol in {"any", probe.protocol}
        and (rule.port is None or rule.port == probe.port)
        and contains(rule.source, probe.source) and contains(rule.destination, probe.destination)
    )


def effective_rule(rules, probe):
    """Analyze a normalized packet case, not a replacement audit status engine.

    PF quick stops at first match; otherwise the last matching rule wins.
    No implicit default is invented: the normalized rules must include it.
    """
    if any(type(rule.order) is not int or type(rule.enabled) is not bool
           or type(rule.quick) is not bool or rule.action not in {"pass", "block", "reject"}
           or rule.protocol not in {"any", "icmp", "tcp", "udp"}
           or rule.interface not in {"any", "lan", "wan"} for rule in rules):
        raise ValueError("unsupported_rule")
    if len({r.order for r in rules}) != len(rules) or len({r.rule_id for r in rules}) != len(rules):
        raise ValueError("ambiguous_rule_order")
    winner = None
    for rule in sorted(rules, key=lambda item: item.order):
        if rule.enabled and traffic_matches(rule, probe):
            winner = rule
            if rule.quick:
                break
    return winner


def logged_outcome(evidence, probe):
    if probe.outcome not in {"allowed", "blocked"}:
        return "probe_inconclusive"
    events = correlated(evidence, probe)
    if not events:
        return "correlated_log_missing"
    expected = {"pass"} if probe.outcome == "allowed" else {"block", "reject"}
    if any(event.action not in expected for event in events):
        return False
    if probe.outcome == "blocked" and not probe.control_ok:
        return "block_control_unverified"
    return True


def packet_case(evidence, interface, source, destination, protocol, port=None, scenario="pass"):
    return Probe("case", evidence.execution_id, evidence.started_at, evidence.checked_at,
                 interface, source, destination, protocol, "inconclusive", port, scenario)


def rules_match(evidence):
    if evidence.rules is None:
        return None
    if not evidence.complete_rules:
        return "effective_ruleset_coverage_unverified"
    cases = [
        (packet_case(evidence, "wan", "10.77.50.10", "10.77.50.1", "icmp"), "pass"),
        (packet_case(evidence, "wan", "10.77.50.10", "10.77.50.1", "tcp", 443), "block"),
        (packet_case(evidence, "wan", "10.77.50.10", "10.77.50.1", "tcp", 22), "block"),
        (packet_case(evidence, "wan", "10.77.50.11", "10.77.50.1", "icmp"), "block"),
        (packet_case(evidence, "lan", "10.77.40.10", "10.77.50.10", "icmp"), "pass"),
    ]
    # An explicitly requested block scenario overrides the LAN baseline case.
    if any(p.scenario == "block" and current(evidence, p)
           and (p.interface, p.source, p.destination, p.protocol)
           == ("lan", "10.77.40.10", "10.77.50.10", "icmp")
           for p in evidence.probes):
        cases[-1] = (cases[-1][0], "block")
    for probe, expected in cases:
        winner = effective_rule(evidence.rules, probe)
        if winner is None:
            return "default_policy_unverified"
        if ("block" if winner.action == "reject" else winner.action) != expected:
            return False
    return True


class OPNsenseCollector:
    def __init__(self, evidence):
        self.evidence = evidence
        self.reasons = {}

    def collect(self, asset: AuditAsset, check_id: str) -> Observation:
        e = self.evidence
        reference = f"day4:{e.execution_id}:{check_id}"
        if check_id in e.errors:
            self.reasons[check_id] = e.errors[check_id]
            return Observation(None, reference, True)
        try:
            value = self._value(check_id)
        except (ValueError, TypeError, KeyError, AttributeError, CollectionError):
            self.reasons[check_id] = "evidence_schema_invalid"
            return Observation(None, reference, True)
        self.reasons[check_id] = (
            value if isinstance(value, str) else "test_not_performed" if value is None
            else "policy_or_evidence_mismatch" if value is False else "evidence_matches_defined_scope"
        )
        return Observation(value, reference)

    def _value(self, check_id):
        e = self.evidence
        if check_id == "FW-01":
            return interfaces_match(e.interfaces, e.interface_export)
        if check_id == "FW-04":
            return rules_match(e)
        probes = [p for p in e.probes if current(e, p)]
        if check_id == "FW-02":
            probes = [p for p in probes if (p.interface, p.source, p.destination, p.protocol, p.port)
                      == ("wan", "10.77.50.10", "10.77.50.1", "tcp", 443)]
            if not probes:
                return None
            if any(p.outcome == "allowed" for p in probes):
                return False
            outcomes = [logged_outcome(e, p) for p in probes]
        elif check_id == "FW-03":
            approved = [p for p in probes if (p.interface, p.source, p.destination, p.protocol)
                        == ("wan", "10.77.50.10", "10.77.50.1", "icmp")]
            denied = [p for p in probes if (p.interface, p.source, p.destination, p.protocol, p.port)
                      == ("wan", "10.77.50.10", "10.77.50.1", "tcp", 22)]
            if not approved or not denied:
                return None
            if any(p.outcome == "allowed" for p in denied):
                return False
            if any(p.outcome == "blocked" for p in approved):
                return False
            outcomes = [logged_outcome(e, p) for p in approved + denied]
        elif check_id == "FW-05":
            if not probes:
                return e.api_log_state
            outcomes = [logged_outcome(e, p) for p in probes]
            if not {"allowed", "blocked"} <= {p.outcome for p in probes}:
                outcomes.append("allow_and_block_evidence_required")
        elif check_id == "FW-06":
            probes = [p for p in probes if (p.interface, p.source, p.destination, p.protocol)
                      == ("lan", "10.77.40.10", "10.77.50.10", "icmp")]
            if not probes:
                return None
            if any(p.scenario not in {"pass", "block"} for p in probes):
                return "scenario_unverified"
            if any(p.outcome in {"allowed", "blocked"}
                   and (p.outcome == "allowed") != (p.scenario == "pass") for p in probes):
                return False
            outcomes = [logged_outcome(e, p) for p in probes]
        else:
            raise ValueError("unknown_check")
        if False in outcomes:
            return False
        return next((value for value in outcomes if value is not True), True)


SAFE_ERROR_CODES = frozenset({
    "api_unauthorized", "api_forbidden", "api_not_found", "api_http_failed", "api_tls_failed",
    "api_timeout", "api_connection_failed", "api_json_invalid", "api_response_invalid",
    "api_response_failed", "api_authentication_or_acl_failed", "api_transport_or_tls_failed",
    "interface_response_invalid", "rule_response_invalid", "log_response_invalid",
    "rule_id_response_invalid",
    "api_incomplete_response",
})


def collect_api_endpoint(client, evidence, name):
    """Record only a fixed endpoint, HTTP code, stage and allowlisted error code.

    Collection success is not audit PASS or proof of complete rules/ID mapping.
    Rule ID lookup never changes the independently collected log result.
    """
    http_status = None
    try:
        payload = client.get(name)
        http_status = 200  # ReadOnlyClient.get returns only after HTTP 200.
        if name in {"interfaces", "export"}:
            interface_rows(payload, exported=name == "export")
            if name == "interfaces":
                evidence.interfaces = payload
            else:
                evidence.interface_export = payload
        elif name == "rules":
            if (not isinstance(payload, dict) or not isinstance(payload.get("rows"), list)
                    or any(not isinstance(row, dict) for row in payload["rows"])):
                raise CollectionError("rule_response_invalid", stage="response_schema")
            evidence.rules = []
            evidence.complete_rules = False
            evidence.errors.pop("FW-04", None)
        elif name == "logs":
            evidence.api_log_state = log_snapshot_state(payload)
            evidence.errors.pop("FW-05", None)
        elif name == "rule_ids":
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), (dict, list)):
                raise CollectionError("rule_id_response_invalid", stage="response_schema")
            evidence.rule_id_mapping = {"status": "NEEDS_REVIEW", "reason": "rule_id_mapping_unverified"}
        evidence.api_results[name] = {
            "endpoint": ENDPOINTS[name], "http_status": 200, "stage": "response_schema",
            "status": "COLLECTED", "error_code": None,
        }
        return True
    except CollectionError as exc:
        code = exc.error_code if exc.error_code in SAFE_ERROR_CODES else "api_collection_failed"
        stage = exc.stage if exc.stage in {
            "http", "tls", "transport", "response_read", "json_parse", "api_response", "response_schema", "collection",
        } else "collection"
        if http_status == 200 and stage == "collection":
            stage = "response_schema"
        status = exc.http_status if type(exc.http_status) is int and 100 <= exc.http_status <= 599 else http_status
        evidence.api_results[name] = {
            "endpoint": ENDPOINTS[name], "http_status": status, "stage": stage,
            "status": "ERROR", "error_code": code,
        }
        if name == "rules":
            evidence.rules, evidence.complete_rules = None, False
            evidence.errors["FW-04"] = code
        elif name == "logs":
            evidence.api_log_state = None
            evidence.errors["FW-05"] = code
        elif name == "rule_ids":
            evidence.rule_id_mapping = {"status": "ERROR", "reason": code}
        elif name == "interfaces":
            evidence.interfaces = None
        elif name == "export":
            evidence.interface_export = None
        return False


def collect_api(client, evidence):
    """Try independent GETs; get_interface_config is deliberately not required."""
    for check in ("FW-01", "FW-04", "FW-05"):
        evidence.errors.pop(check, None)
    for name in ("interfaces", "export", "rules", "logs", "rule_ids"):
        collect_api_endpoint(client, evidence, name)
    if evidence.interfaces is None and evidence.interface_export is None:
        evidence.errors["FW-01"] = "interface_sources_unavailable"


# Fixed command, no shell interpolation. Determine the route-selected source
# before probing. Destination unreachable is inconclusive, never proof of block.
PING_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$route = Find-NetRoute -RemoteIPAddress '10.77.50.10'
if (@($route | Where-Object { $_.IPAddress -eq '10.77.40.10' }).Count -ne 1) { exit 2 }
$p = [System.Net.NetworkInformation.Ping]::new()
try { $r = $p.Send('10.77.50.10', 2000); @{status=$r.Status.ToString()} | ConvertTo-Json -Compress }
finally { $p.Dispose() }
"""


def ping_lan(execution_id, scenario):
    if scenario not in {"pass", "block"}:
        raise CollectionError("scenario_rejected")
    if os.name != "nt":
        raise CollectionError("windows_probe_required")
    started = datetime.now(timezone.utc)
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PING_SCRIPT],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode:
            raise CollectionError("ping_source_or_execution_failed")
        status = json.loads(result.stdout)["status"]
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        raise CollectionError("ping_execution_failed") from None
    outcome = {"Success": "allowed", "TimedOut": "blocked"}.get(status, "inconclusive")
    return Probe("lan-icmp", execution_id, started, datetime.now(timezone.utc),
                 "lan", "10.77.40.10", "10.77.50.10", "icmp", outcome, scenario=scenario)
