"""Evidence parsers for the Day 3 offline Suricata fixture."""

import ipaddress
import json
import re

HOME_NET = ipaddress.ip_network("198.51.100.0/24")
TEST_SID = 1000003
CONTROL_PACKET = 1
MARKER_PACKET = 2

RULE_COUNTS = re.compile(
    r"(\d+) rule files processed\. (\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped"
)


def parse_config(output: str) -> tuple[bool | None, bool | None, bool | None]:
    settings = dict(re.findall(r"(?m)^([\w.-]+) = ([^\r\n]*)$", output))
    prefixes = {key.rsplit(".", 1)[0] for key in settings if re.fullmatch(r"outputs\.\d+\.eve-log\.enabled", key)}
    eve, alert = None, None
    if len(prefixes) == 1:
        prefix = prefixes.pop()
        enabled = settings[f"{prefix}.enabled"].lower() in {"yes", "true", "1", "on"}
        filename = settings.get(f"{prefix}.filename")
        filetype = settings.get(f"{prefix}.filetype")
        if not enabled:
            eve = False
        elif filename is not None and filetype is not None:
            eve = filename == "eve.json" and filetype == "regular"
        types = {key: value for key, value in settings.items() if key.startswith(f"{prefix}.types.")}
        if types:
            alert = enabled and any(
                value == "alert" or re.search(r"\.types\.\d+\.alert(?:\.|$)", key)
                for key, value in types.items()
            )
            if any(re.fullmatch(rf"{re.escape(prefix)}\.types\.\d+\.alert\.enabled", key)
                   and value.lower() in {"no", "false", "0", "off"} for key, value in types.items()):
                alert = False

    raw_home = settings.get("vars.address-groups.HOME_NET")
    home = None
    if raw_home:
        try:
            networks = [ipaddress.ip_network(value.strip()) for value in raw_home.strip("[]").split(",")]
        except ValueError:
            home = False
        else:
            home = networks == [HOME_NET]
    return eve, alert, home


def parse_rule_load(output: str) -> bool | None:
    match = RULE_COUNTS.search(output)
    if match:
        return tuple(map(int, match.groups())) == (1, 1, 0, 0)
    if re.search(r"no rules were loaded|no signatures supplied", output, re.IGNORECASE):
        return False
    return None


def parse_eve(output: str) -> bool | str | None:
    """Return fixture match, mismatch, missing log, or uncorrelated packet evidence."""
    events = [json.loads(line) for line in output.splitlines() if line.strip()]
    if not events:
        return None
    if any(not isinstance(event, dict) or "event_type" not in event for event in events):
        raise ValueError("invalid EVE event")
    alerts = [event for event in events if event["event_type"] == "alert"]
    for event in alerts:
        if not isinstance(event.get("alert"), dict) or type(event["alert"].get("signature_id")) is not int:
            raise ValueError("invalid EVE alert")
    if any(event.get("pcap_cnt") == CONTROL_PACKET for event in alerts):
        return False
    matches = [event for event in alerts if event["alert"]["signature_id"] == TEST_SID]
    if not matches:
        return False
    if any(type(event.get("pcap_cnt")) is not int for event in alerts):
        return "uncorrelated_packet"
    return len(matches) == 1 and matches[0]["pcap_cnt"] == MARKER_PACKET
