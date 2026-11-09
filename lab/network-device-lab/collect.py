"""Read-only normalizer inside the LAB router. Never outputs raw configs."""
import ipaddress
import json
import os
import re
import shutil
import subprocess


def query(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if result.returncode or len(result.stdout) > 1024 * 1024: raise ValueError("query_failed")
    return result.stdout


def listeners(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 5: raise ValueError("parse_failed")
        address, port = fields[3].rsplit(":", 1)
        address = address.strip("[]").split("%", 1)[0]
        if address == "*": address = "0.0.0.0"
        ipaddress.ip_address(address)
        if not port.isdigit() or not 0 < int(port) < 65536: raise ValueError("parse_failed")
        rows.append({"address": address, "port": int(port)})
    return {"tcp": rows}


def guard(document):
    if not isinstance(document, dict): raise ValueError("parse_failed")
    rows = document.get("nftables")
    if not isinstance(rows, list) or len(rows) > 4096 or any(not isinstance(row, dict) for row in rows): raise ValueError("parse_failed")
    target = ("inet", "phase2_guard", "input")
    # Analyze only the named LAB chain. Docker NAT/forwarding objects do not
    # belong to this verdict. This is not whole-host effective-policy analysis.
    inputs = [row["chain"] for row in rows if isinstance(row.get("chain"), dict)
              and (row["chain"].get("family"), row["chain"].get("table"), row["chain"].get("name")) == target]
    result = {"input_policy": None, "recognized_scope_only": False, "parser_version": "NET-GUARD-0.2",
              "query_scope": "inet/phase2_guard/input", "recognized_exceptions": [],
              "unrecognized_reason_codes": [], "disallowed_accept": False}
    if len(inputs) != 1:
        result["unrecognized_reason_codes"] = ["chain_missing_or_ambiguous"]
        return result
    chain = inputs[0]
    priority = chain.get("prio")
    if chain.get("type") != "filter" or chain.get("hook") != "input" or chain.get("policy") not in ("accept", "drop") or not (type(priority) is int and priority == 0 or priority == "filter"):
        result["unrecognized_reason_codes"] = ["chain_metadata_mismatch"]
        return result
    result["input_policy"] = chain["policy"]
    def members(value):
        if isinstance(value, dict) and set(value) == {"set"}: value = value["set"]
        return value if isinstance(value, list) else [value] if type(value) in (str, int) else None
    recognized, unknown = set(), set()
    for row in rows:
        rule = row.get("rule", {})
        if not isinstance(rule, dict): raise ValueError("parse_failed")
        if (rule.get("family"), rule.get("table"), rule.get("chain")) != ("inet", "phase2_guard", "input"): continue
        expression = rule.get("expr")
        if not isinstance(expression, list) or not expression or any(not isinstance(item, dict) for item in expression):
            unknown.add("malformed_rule"); continue
        # Counters do not alter packet matching or verdicts. Other statements
        # (including jumps, limits and extra matches) are deliberately not erased.
        semantic = [item for item in expression if set(item) != {"counter"}]
        kind = None
        if len(semantic) == 2 and semantic[-1] == {"accept": None}:
            match = semantic[0].get("match")
            if isinstance(match, dict) and set(match) == {"op", "left", "right"} and match["op"] in ("==", "in"):
                right = members(match["right"])
                if match["left"] == {"meta": {"key": "iifname"}} and right == ["lo"]: kind = "loopback"
                elif match["left"] == {"meta": {"key": "l4proto"}} and (right == ["icmp"] or isinstance(right, list) and len(right) == 1 and type(right[0]) is int and right[0] == 1): kind = "icmp"
                elif match["left"] == {"ct": {"key": "state"}} and isinstance(right, list) and len(right) == 2 and all(isinstance(state, str) for state in right) and set(right) == {"established", "related"}: kind = "established_related"
        if kind:
            recognized.add(kind)
        else:
            unknown.add("unapproved_accept" if any("accept" in item for item in semantic) else "unsupported_statement")
            if any("accept" in item for item in semantic): result["disallowed_accept"] = True
    for row in rows:
        table = row.get("table", {})
        if isinstance(table, dict) and (table.get("family"), table.get("name")) == ("inet", "phase2_guard") and "dormant" in (table.get("flags") or []): unknown.add("dormant_table")
    result.update(recognized_scope_only=not unknown, recognized_exceptions=sorted(recognized), unrecognized_reason_codes=sorted(unknown))
    return result


def collect():
    sections = {}
    def collect_section(name, action):
        try: sections[name] = {"state": "COLLECTED", "values": action()}
        except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
            sections[name] = {"state": "ERROR", "error_code": "query_failed", "values": {}}
    def ssh():
        installed = shutil.which("sshd") is not None
        if not installed: return {"installed": False}
        lines = query(["sshd", "-T"]).splitlines()
        fields = {}
        for line in lines:
            key, _, value = line.partition(" ")
            if key in ("permitrootlogin", "passwordauthentication", "listenaddress"): fields.setdefault(key, []).append(value)
        addresses = fields.get("listenaddress", [])
        return {"installed": True, "root_login_disabled": fields["permitrootlogin"] == ["no"] if "permitrootlogin" in fields else None,
            "password_login_disabled": fields["passwordauthentication"] == ["no"] if "passwordauthentication" in fields else None,
            "management_bind_only": all(value == "10.203.0.254:22" for value in addresses) if addresses else None}
    collect_section("ssh", ssh)
    collect_section("listeners", lambda: listeners(query(["ss", "-H", "-lnt"])))
    collect_section("guard", lambda: guard(json.loads(query(["nft", "-j", "list", "chain", "inet", "phase2_guard", "input"]))))
    frr_requested = os.environ.get("NETWORK_LAB_START_FRR", "0") == "1"
    version = None
    if frr_requested:
        collect_section("logging", lambda: {"stdout_enabled": any(re.fullmatch(r"log stdout (?:informational|debugging)", line.strip()) for line in query(["vtysh", "-c", "show running-config"]).splitlines())})
        try:
            match = re.search(r"FRRouting\s+([0-9]+(?:\.[0-9]+){1,3})", query(["vtysh", "-c", "show version"]))
            version = match.group(1) if match else None
        except (ValueError, OSError, subprocess.SubprocessError): pass
    else:
        sections["logging"] = {"state": "NOT_TESTED", "values": {}}
        version = os.uname().release
    return {"asset_id": "NET-LAB-ROUTER", "product": "linux_frr" if frr_requested else "linux_router", "version": version, "sections": sections}


if __name__ == "__main__": print(json.dumps(collect()))
