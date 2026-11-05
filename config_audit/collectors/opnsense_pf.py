"""Bounded, read-only PF snapshot analysis. This is not a complete PF compiler.

Unexpanded addresses/tables and unsupported features remain indeterminate.
Only fixed lab packet cases and supplied top-level rules are in scope. Audit
statuses come from the existing evaluate(), not a second verdict engine.
"""

from dataclasses import dataclass, field
import hashlib
import ipaddress
from pathlib import Path, PurePosixPath
import re
import shlex
import tarfile

from ..engine import evaluate
from ..models import AuditAsset, AuditRule, Observation

LIMIT = 4 * 1024 * 1024
ARCHIVE_LIMIT = 16 * 1024 * 1024
MAX_RULES = 4096
PORTS = {"http": 80, "https": 443, "ssh": 22}
SCOPE = "supplied_top_level_ipv4_inbound_new_flow_lab_cases_only"


class PFError(Exception):
    """Fixed safe error code only; never include paths or input lines."""


class Unsupported(PFError):
    pass


def read_bounded(path, limit=LIMIT):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(limit + 1)
    except (OSError, ValueError):
        raise PFError("pf_file_unreadable") from None
    if len(data) > limit:
        raise PFError("pf_file_too_large")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data, expected):
    if expected is None:
        return False
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise PFError("pf_hash_invalid")
    if digest(data) != expected.lower():
        raise PFError("pf_hash_mismatch")
    return True


def archive_matches(path, expected, files):
    """Verify a pinned tar and exact member bytes, without extracting anything."""
    data = read_bounded(path, ARCHIVE_LIMIT)
    verified = check_digest(data, expected)
    try:
        import io
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > 100:
                raise PFError("pf_archive_invalid")
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                    raise PFError("pf_archive_invalid")
            for filename, content in files:
                matches = [m for m in members if m.isfile() and PurePosixPath(m.name).name == filename]
                if len(matches) != 1 or matches[0].size > LIMIT:
                    raise PFError("pf_archive_member_invalid")
                with archive.extractfile(matches[0]) as stream:
                    if stream.read(LIMIT + 1) != content:
                        raise PFError("pf_archive_member_mismatch")
    except (tarfile.TarError, OSError, EOFError):
        raise PFError("pf_archive_invalid") from None
    return verified, digest(data)


@dataclass(frozen=True)
class PFRule:
    order: int
    action: str
    direction: str = "any"
    interface: str = "any"
    interface_not: bool = False
    family: str = "any"
    protocol: str = "any"
    source: str = field(default="any", repr=False)
    destination: str = field(default="any", repr=False)
    source_port: int | None = None
    destination_port: int | None = None
    quick: bool = False
    icmp_type: str | None = None
    label: str | None = field(default=None, repr=False)

    @property
    def reference(self):
        return f"pf-rule-{self.order:04}"


def address(value):
    if value == "any" or re.fullmatch(r"\((?:self|[a-zA-Z][\w]*(?::network)?)\)", value) or re.fullmatch(r"<[\w.-]+>", value):
        return value
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise Unsupported("pf_address_unsupported") from None


def parse_rule(line, order):
    try:
        tokens = shlex.split(line)
    except ValueError:
        raise PFError("pf_syntax_invalid") from None
    if not tokens or tokens[0] not in {"pass", "block"}:
        raise Unsupported("pf_statement_unsupported")
    values = {"order": order, "action": tokens[0]}
    i = 1
    if i < len(tokens) and tokens[i] == "drop":
        if tokens[0] != "block":
            raise PFError("pf_syntax_invalid")
        i += 1
    seen = set()
    while i < len(tokens) and tokens[i] not in {"from", "all"}:
        key = tokens[i]
        if key in seen:
            raise PFError("pf_syntax_invalid")
        seen.add(key)
        if key in {"in", "out"}:
            if "direction" in values:
                raise PFError("pf_syntax_invalid")
            values["direction"] = key
        elif key == "quick":
            values["quick"] = True
        elif key == "log":
            pass
        elif key in {"inet", "inet6"}:
            if "family" in values:
                raise PFError("pf_syntax_invalid")
            values["family"] = key
        elif key in {"on", "proto"}:
            i += 1
            if i >= len(tokens):
                raise PFError("pf_syntax_invalid")
            if key == "on":
                if tokens[i] == "!":
                    values["interface_not"] = True
                    i += 1
                if i >= len(tokens) or not re.fullmatch(r"[a-zA-Z][\w]*", tokens[i]):
                    raise Unsupported("pf_interface_unsupported")
                values["interface"] = tokens[i]
            else:
                if tokens[i] not in {"tcp", "udp", "icmp", "ipv6-icmp"}:
                    raise Unsupported("pf_protocol_unsupported")
                values["protocol"] = tokens[i]
        else:
            raise Unsupported("pf_feature_unsupported")
        i += 1
    if i >= len(tokens):
        raise PFError("pf_syntax_invalid")
    if tokens[i] == "all":
        i += 1
    else:
        for keyword, target in (("from", "source"), ("to", "destination")):
            if i + 1 >= len(tokens) or tokens[i] != keyword:
                raise PFError("pf_syntax_invalid")
            values[target] = address(tokens[i + 1])
            i += 2
            if i < len(tokens) and tokens[i] == "port":
                if i + 2 >= len(tokens) or tokens[i + 1] != "=":
                    raise Unsupported("pf_port_operator_unsupported")
                raw_port = tokens[i + 2]
                number = PORTS.get(raw_port)
                if number is None and raw_port.isascii() and raw_port.isdigit():
                    number = int(raw_port)
                if number is None or not 0 <= number <= 65535:
                    raise Unsupported("pf_port_unsupported")
                values[target + "_port"] = number
                i += 3
    while i < len(tokens):
        key = tokens[i]
        if key == "flags" and i + 1 < len(tokens) and tokens[i + 1] == "S/SA":
            i += 2  # fixed cases are new TCP SYN flows; not evidence of existing states
        elif key == "keep" and tokens[i:i + 2] == ["keep", "state"]:
            i += 2
        elif key == "allow-opts":
            i += 1
        elif key in {"icmp-type", "icmp6-type", "label"} and i + 1 < len(tokens):
            attribute = "label" if key == "label" else "icmp_type"
            if attribute in values:
                raise PFError("pf_syntax_invalid")
            if key in {"icmp-type", "icmp6-type"} and values.get("protocol") != (
                "icmp" if key == "icmp-type" else "ipv6-icmp"
            ):
                raise Unsupported("pf_icmp_type_unsupported")
            if key != "label" and tokens[i + 1] not in {
                "echoreq", "echorep", "8", "0", "unreach", "toobig", "timex", "paramprob",
                "neighbrsol", "neighbradv", "routersol", "routeradv",
            }:
                raise Unsupported("pf_icmp_type_unsupported")
            values[attribute] = tokens[i + 1]
            i += 2
        else:
            raise Unsupported("pf_feature_unsupported")
    return PFRule(**values)


def canonical(line):
    # pfctl -vv decorates symbolic references with expansion counters. A counter
    # is NOT a captured table value, address list, or GUI-rule identifier.
    line = re.sub(r"<([\w.-]+):(?:\d+|\*)>", r"<\1>", line)
    line = re.sub(r"\((self|[a-zA-Z][\w]*(?::network)?):(?:\d+|\*)\)", r"(\1)", line)
    return line


def parse_snapshot(data, *, detailed=False):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise PFError("pf_encoding_invalid") from None
    if not text.strip():
        raise PFError("pf_snapshot_empty")
    rules, fingerprints, numbered, anchors, unknown = [], [], [], 0, 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if detailed and line.startswith(("[ Evaluations:", "[ Source Nodes:", "[ Inserted:", "[ Last Active Time:")):
            if not line.endswith("]") or not fingerprints:
                raise PFError("pf_detail_invalid")
            continue
        match = re.fullmatch(r"@(\d+)\s+(.+)", line) if detailed else None
        if detailed:
            if match is None:
                raise PFError("pf_detail_invalid")
            index, line = int(match[1]), match[2]
        line = canonical(line)
        try:
            fingerprints.append(tuple(shlex.split(line)))
        except ValueError:
            raise PFError("pf_syntax_invalid") from None
        if line == "scrub in all fragment reassemble":
            continue
        if detailed:
            numbered.append(index)
        order = len(rules)
        if order >= MAX_RULES:
            raise PFError("pf_too_many_rules")
        if line.startswith(("anchor ", "anchor\t")):
            anchors += 1
            rules.append(None)
        else:
            try:
                rules.append(parse_rule(line, order))
            except Unsupported:
                unknown += 1
                rules.append(None)
    if not rules:
        raise PFError("pf_no_filter_rules")
    if detailed and numbered != list(range(len(numbered))):
        raise PFError("pf_detail_order_invalid")
    return rules, fingerprints, {"anchor_statements": anchors, "unsupported_statements": unknown}


CASES = {
    "lan_ipv4_forward": ("hn1", "10.77.40.10", "10.77.50.10", "tcp", 50000, 8080, "pass"),
    "lan_http_management": ("hn1", "10.77.40.10", "10.77.40.1", "tcp", 50000, 80, "pass"),
    "lan_https_management": ("hn1", "10.77.40.10", "10.77.40.1", "tcp", 50000, 443, "pass"),
    "wan_approved_icmp": ("hn0", "10.77.50.10", "10.77.50.1", "icmp", None, None, "pass"),
    "wan_other_host_icmp": ("hn0", "10.77.50.11", "10.77.50.1", "icmp", None, None, "block"),
    "wan_https": ("hn0", "10.77.50.10", "10.77.50.1", "tcp", 50000, 443, "block"),
    "wan_ssh": ("hn0", "10.77.50.10", "10.77.50.1", "tcp", 50000, 22, "block"),
    "restored_lan_icmp": ("hn1", "10.77.40.10", "10.77.50.10", "icmp", None, None, "pass"),
}


def address_matches(value, ip):
    if value == "any":
        return True
    if value.startswith(("<", "(")):
        return None
    return ipaddress.ip_address(ip) in ipaddress.ip_network(value)


def matches(rule, case):
    if rule is None:
        return None
    interface, source, destination, protocol, source_port, destination_port, _ = case
    criteria = [rule.family != "inet6", rule.direction != "out", rule.protocol in {"any", protocol}]
    if rule.interface not in {"any", "hn0", "hn1"}:
        criteria.append(None)  # an uncollected interface group may include the target
    elif rule.interface != "any":
        criteria.append((rule.interface == interface) != rule.interface_not)
    elif rule.interface_not:
        criteria.append(False)
    criteria.extend((rule.source_port is None or rule.source_port == source_port,
                     rule.destination_port is None or rule.destination_port == destination_port,
                     address_matches(rule.source, source), address_matches(rule.destination, destination)))
    if protocol == "icmp" and rule.icmp_type is not None:
        if rule.icmp_type not in {"echoreq", "8"}:
            return False
    if False in criteria:
        return False
    return None if None in criteria else True


def packet_result(rules, case):
    """Propagate unknown matches instead of silently skipping quick blockers."""
    pending, finished = {(None, None)}, set()
    uncertain = False
    for rule in rules:
        if not pending:
            break
        match = matches(rule, case)
        if match is False:
            continue
        if rule is None:
            uncertain = True
            # Unsupported/anchor content can decide either action and stop.
            finished.update({("pass", "unresolved"), ("block", "unresolved")})
            continue
        choice = (rule.action, rule.reference)
        if match is None:
            uncertain = True
            if rule.quick:
                finished.add(choice)
            else:
                pending.add(choice)
        elif rule.quick:
            finished.add(choice)
            pending.clear()
        else:
            pending = {choice}
    candidates = finished | pending
    actions = {action for action, _ in candidates}
    expected = case[-1]
    outcome = "MATCH" if actions == {expected} else "CONFLICT" if len(actions) == 1 and None not in actions else "UNRESOLVED"
    return {"outcome": outcome, "expected_action": expected, "possible_actions": sorted(action or "unproven_default" for action in actions),
            "rule_references": sorted(ref for _, ref in candidates if ref), "unresolved_match_encountered": uncertain}


def structural_checks(rules):
    known = [rule for rule in rules if rule is not None]
    predicates = {
        "default_ipv4_deny": lambda r: r.action == "block" and r.direction in {"in", "any"} and r.family in {"inet", "any"}
            and r.interface == "any" and r.protocol == "any" and r.source == r.destination == "any"
            and r.source_port is None and r.destination_port is None,
        "lan_ipv4_default_allow": lambda r: r.action == "pass" and r.direction == "in" and r.interface == "hn1"
            and not r.interface_not and r.family == "inet" and r.protocol == "any" and r.destination == "any"
            and r.source in {"(hn1:network)", "10.77.40.0/24"} and r.quick and r.source_port is None and r.destination_port is None,
        "lan_http_management": lambda r: r.action == "pass" and r.direction == "in" and r.interface == "hn1"
            and not r.interface_not and r.family != "inet6" and r.protocol == "tcp" and r.quick
            and r.destination in {"(self)", "10.77.40.1/32"} and r.destination_port == 80
            and r.source in {"any", "10.77.40.0/24", "(hn1:network)"} and r.source_port is None,
        "lan_https_management": lambda r: r.action == "pass" and r.direction == "in" and r.interface == "hn1"
            and not r.interface_not and r.family != "inet6" and r.protocol == "tcp" and r.quick
            and r.destination in {"(self)", "10.77.40.1/32"} and r.destination_port == 443
            and r.source in {"any", "10.77.40.0/24", "(hn1:network)"} and r.source_port is None,
        "wan_host_icmp_exception": lambda r: r.action == "pass" and r.direction == "in" and r.interface == "hn0"
            and not r.interface_not and r.family == "inet" and r.protocol == "icmp" and r.quick
            and r.source == "10.77.50.10/32" and r.destination in {"(hn0)", "10.77.50.1/32"}
            and r.icmp_type in {"echoreq", "8"} and r.source_port is None and r.destination_port is None,
    }
    return {key: {"observation": "PRESENT" if any(predicate(r) for r in known) else "NOT_ESTABLISHED",
                  "rule_references": [r.reference for r in known if predicate(r)]} for key, predicate in predicates.items()}


def priority_checks(rules):
    findings = []
    for name, case in CASES.items():
        earlier = None
        for rule in rules:
            if rule is None or matches(rule, case) is not True:
                continue
            if rule.action == "block" and earlier is not None:
                findings.append({"case": name, "earlier": earlier.reference, "later": rule.reference,
                                 "observation": "EARLIER_QUICK_PASS_CAN_SHADOW_LATER_BLOCK"})
                if len(findings) == 20:
                    return findings
            if earlier is None and rule.action == "pass" and rule.quick:
                earlier = rule
    return findings


def safe_rule(rule):
    def safe_address(value):
        if value.startswith("<"):
            return "unresolved_table"
        if value.startswith("("):
            return "unresolved_dynamic_address"
        if value == "any" or value in {"10.77.40.0/24", "10.77.50.0/24", "10.77.40.1/32", "10.77.50.1/32", "10.77.40.10/32", "10.77.50.10/32"}:
            return value
        return "other_literal_redacted"
    if rule is None:
        return {"observation": "UNSUPPORTED_OR_ANCHOR"}
    return {"reference": rule.reference, "order": rule.order, "action": rule.action, "direction": rule.direction,
            "interface": rule.interface if rule.interface in {"hn0", "hn1", "any"} else "other_interface",
            "interface_not": rule.interface_not, "family": rule.family, "protocol": rule.protocol,
            "source": safe_address(rule.source), "destination": safe_address(rule.destination),
            "source_port": rule.source_port, "destination_port": rule.destination_port, "quick": rule.quick,
            "icmp_type": rule.icmp_type,
            "label_present": rule.label is not None}


def analyze(path, *, detail=None, sha256=None, detail_sha256=None, archive=None, archive_sha256=None,
            execution_id, checked_at):
    report = {"scope": SCOPE, "complete_effective_ruleset": False, "gui_rule_identity_verified": False,
              "snapshot_is_current_execution_traffic": False,
              "limitations": ["anchors_and_dynamic_policies_not_fully_collected", "states_nat_and_ipv6_out_of_scope",
                              "gui_label_to_pf_identifier_mapping_unproven", "snapshot_capture_time_unverified"],
              "integrity": {}, "structural_checks": {}, "packet_cases": {}, "rules": []}
    value, error, reason = None, False, "pf_not_supplied"
    try:
        main = read_bounded(path)
        trusted = check_digest(main, sha256)
        report["integrity"]["rules"] = {"sha256": digest(main), "verified": trusted, "bytes": len(main)}
        verbose = read_bounded(detail) if detail else None
        detail_trusted = check_digest(verbose, detail_sha256) if verbose is not None else False
        if verbose is not None:
            report["integrity"]["detail"] = {"sha256": digest(verbose), "verified": detail_trusted, "bytes": len(verbose)}
        if archive is not None:
            files = [(Path(path).name, main)] + ([(Path(detail).name, verbose)] if detail else [])
            pinned, archive_digest = archive_matches(archive, archive_sha256, files)
            trusted = trusted or pinned
            detail_trusted = detail_trusted or pinned
            report["integrity"]["archive"] = {"sha256": archive_digest, "verified": pinned, "members_match": True}
            report["integrity"]["rules"]["verified"] = trusted
            if verbose is not None:
                report["integrity"]["detail"]["verified"] = detail_trusted
        rules, fingerprints, coverage = parse_snapshot(main)
        report["coverage"] = coverage | {"filter_rule_count": len(rules), "verbose_comparison": "NOT_SUPPLIED"}
        if verbose is not None:
            _, other, _ = parse_snapshot(verbose, detailed=True)
            if fingerprints != other:
                raise PFError("pf_detail_rules_mismatch")
            report["coverage"]["verbose_comparison"] = "MATCH"
        structural = structural_checks(rules)
        cases = {key: packet_result(rules, case) for key, case in CASES.items()}
        report.update(structural_checks=structural, packet_cases=cases, rules=[safe_rule(r) for r in rules])
        report["priority_checks"] = priority_checks(rules)
        report["unresolved_references"] = {
            "table_rules": [r.reference for r in rules if r and any(v.startswith("<") for v in (r.source, r.destination))],
            "dynamic_address_rules": [r.reference for r in rules if r and any(v.startswith("(") for v in (r.source, r.destination))],
            "possible_interface_group_rules": [r.reference for r in rules if r and r.interface not in {"any", "hn0", "hn1"}],
        }
        report["lab_block_policy"] = {
            "observation": "NO_EFFECTIVE_BLOCK_FOR_SAMPLE_IN_SUPPLIED_ROOT" if cases["restored_lan_icmp"]["outcome"] == "MATCH"
            else "NOT_ESTABLISHED", "gui_rule_disabled_confirmed": False,
        }
        report["findings"] = []
        if structural["lan_ipv4_default_allow"]["observation"] == "PRESENT":
            report["findings"].append("lan_default_all_protocols_any_destination_is_lab_baseline")
        if structural["lan_http_management"]["observation"] == "PRESENT":
            report["findings"].append("lan_plain_http_management_permitted_review_exposure")
        if any(r and r.action == "pass" and r.direction != "out" and r.interface in {"any", "hn0"}
               and not r.interface_not and r.family != "inet6" and r.source == r.destination == "any" for r in rules):
            report["findings"].append("possible_broad_wan_allow")
        if not trusted or (verbose is not None and not detail_trusted):
            value, reason = "unverified", "pf_integrity_not_pinned"
        elif any(item["observation"] != "PRESENT" for item in structural.values()) or any(coverage.values()):
            value, reason = "unverified", "pf_required_scope_not_established"
        elif any(case["outcome"] == "CONFLICT" for case in cases.values()):
            value, reason = False, "pf_supplied_root_packet_policy_conflict"
        elif all(case["outcome"] == "MATCH" for case in cases.values()):
            value, reason = True, "pf_supplied_root_lab_cases_match"
        else:
            value, reason = "unverified", "pf_scope_or_dynamic_conditions_unresolved"
    except PFError as exc:
        value, error, reason = None, True, str(exc)
    rule = AuditRule("FW-04", "pf-snapshot-1", SCOPE, "Review unresolved snapshot coverage and packet cases.",
                     condition=lambda observed: observed if type(observed) is bool else None, product="opnsense")
    result = evaluate(AuditAsset("SJ-D4-OPNsense", "opnsense", "26.7"), rule,
                      Observation(value, f"day4:{execution_id}:FW-04:pf", error),
                      execution_id=execution_id, checked_at=checked_at)
    report.update(result.to_safe_dict(), reason=reason, evidence_reference=result.evidence_reference)
    return report
