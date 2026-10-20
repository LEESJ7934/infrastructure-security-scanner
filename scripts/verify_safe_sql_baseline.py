"""Read-only normal/injection-shaped input comparison on a separate safe lab app.

This is not remediation of DVWA and never proves DVWA became safe.
"""
import hashlib
import requests


def verify_safe_lookup(origin):
    observations = []
    with requests.Session() as session:
        session.trust_env = False
        for label, value in (("normal", "1"), ("injection_shaped", "1' OR '1'='1")):
            response = session.get(origin + "/lookup", params={"id": value},
                                   timeout=5, allow_redirects=False)
            observations.append({"label": label, "http_status": response.status_code,
                                 "result_rows": response.text.count("First name:"),
                                 "response_sha256": hashlib.sha256(response.content).hexdigest()})
    if [(x["http_status"], x["result_rows"]) for x in observations] != [(200, 1), (200, 0)]:
        raise ValueError("Expected safe parameterized lookup behavior not established")
    return {"application": "separate_parameterized_sqlite_lab", "comparison_type": "INDEPENDENT_APPLICATION",
            "dvwa_remediated": False, "finding_status": "NOT_DETECTED", "steps": observations}


def validate_evidence(data, local_scan_id):
    if (not isinstance(data, dict) or data.get("scan_id") != local_scan_id
            or data.get("environment") != "LOCAL_BASELINE"
            or data.get("application") != "separate_parameterized_sqlite_lab"
            or data.get("dvwa_remediated") is not False
            or data.get("finding_status") != "NOT_DETECTED"
            or data.get("comparison_type") != "INDEPENDENT_APPLICATION"):
        raise ValueError("Safe SQL evidence must belong to the selected independent baseline")
    allowed = {"scan_id", "port_id", "asset_uid", "environment", "tested_at", "scope",
               "application", "comparison_type", "dvwa_remediated", "finding_status", "steps"}
    if set(data) - allowed:
        raise ValueError("Unexpected safe SQL evidence fields")
    steps = data.get("steps")
    if not isinstance(steps, list) or len(steps) != 2:
        raise ValueError("Two safe SQL observations required")
    for step, label, count in zip(steps, ("normal", "injection_shaped"), (1, 0)):
        import re
        if (set(step) != {"label", "http_status", "result_rows", "response_sha256"}
                or step["label"] != label or type(step["http_status"]) is not int or step["http_status"] != 200
                or type(step["result_rows"]) is not int or step["result_rows"] != count
                or not re.fullmatch(r"[0-9a-f]{64}", step["response_sha256"])):
            raise ValueError("Invalid safe SQL observation")
    return data


def main(argv=None):
    import argparse
    from datetime import datetime, timezone
    import json
    from pathlib import Path
    from db.query_helpers import get_all_ports
    from scanner.scope import ScopePolicy
    from scanner.targets import ResolvedTarget
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scan-id", type=int, required=True)
    p.add_argument("--port-id", type=int, required=True)
    p.add_argument("--scope-file", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        ports = [r for r in get_all_ports(scan_id=a.scan_id) if r["port_id"] == a.port_id
                 and r["host_ip"] == "127.0.0.1" and r["port"] == 8081 and r["service"] == "http"]
        if len(ports) != 1:
            raise ValueError("Existing loopback baseline HTTP 8081 required")
        scope = ScopePolicy.load(a.scope_file)
        scope.authorize([ResolvedTarget("127.0.0.1", "127.0.0.1", "IP")], worker_count=1, port_count=1)
        evidence = verify_safe_lookup("http://127.0.0.1:8081")
        evidence.update(scan_id=a.scan_id, port_id=a.port_id, asset_uid=ports[0]["asset_uid"],
                        environment="LOCAL_BASELINE", tested_at=datetime.now(timezone.utc).isoformat(),
                        scope=scope.to_snapshot())
        a.output.parent.mkdir(parents=True, exist_ok=True)
        with a.output.open("x", encoding="utf-8") as output:
            json.dump(evidence, output, indent=2)
        print(json.dumps({"status": "OBSERVED", "source_sha256": hashlib.sha256(a.output.read_bytes()).hexdigest(),
                          "dvwa_remediated": False}))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "NOT_TESTED", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
