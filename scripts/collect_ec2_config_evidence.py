"""User-run EC2 loopback checks; no service/configuration changes or response bodies.

Copy this stdlib-only file to the approved EC2. Each invocation performs ONE
check, emits bounded JSON, and never infers that an exception means secure.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ftplib
import hashlib
import http.client
import json
from pathlib import Path
import subprocess

HEADER_NAMES = ("x-content-type-options", "referrer-policy", "content-security-policy", "x-frame-options")


def collect(check):
    port = {"FTP_ANONYMOUS": 21, "HTTP_SECURITY_HEADERS": 80, "SSH_AUTH_POLICY": 22}[check]
    result = {"schema_version": 1, "environment": "EC2_LAB", "check": check,
              "tested_at": datetime.now(timezone.utc).isoformat(),
              "target": {"host": "127.0.0.1", "port": port},
              "execution_status": "SUCCESS", "details": {}}
    try:
        if check == "FTP_ANONYMOUS":
            with ftplib.FTP() as ftp:
                ftp.connect("127.0.0.1", port, timeout=5)
                try:
                    reply = ftp.login("anonymous", "lab@example.invalid")
                    code = int(reply[:3])
                except ftplib.error_perm as exc:
                    code = int(str(exc)[:3])
                    if code != 530:
                        raise ValueError("Unexpected FTP response") from exc
            result["details"] = {"reply_code": code}
        elif check == "HTTP_SECURITY_HEADERS":
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                # Header values, cookies, credentials and HTML are never emitted.
                headers = {k: response.getheader(k) for k in HEADER_NAMES}
                result["details"] = {
                    "http_status": response.status,
                    "nosniff": (headers["x-content-type-options"] or "").lower() == "nosniff",
                    "referrer_policy_present": bool(headers["referrer-policy"]),
                    "csp_present": bool(headers["content-security-policy"]),
                    "frame_protection_present": bool(headers["x-frame-options"] or
                        "frame-ancestors" in (headers["content-security-policy"] or "").lower()),
                }
            finally:
                connection.close()
        else:
            # Default daemon config only: Match blocks / custom daemon arguments
            # must be reviewed by the operator; no remote banner inference.
            run = subprocess.run(["sudo", "-n", "/usr/sbin/sshd", "-T"],
                                 capture_output=True, text=True, timeout=10, check=True)
            flags = dict(line.split(None, 1) for line in run.stdout.splitlines() if " " in line)
            selected = {k: flags[k] for k in ("pubkeyauthentication", "passwordauthentication")}
            if any(v not in {"yes", "no"} for v in selected.values()):
                raise ValueError("Unrecognized SSH flags")
            result["details"] = {**{k: v == "yes" for k, v in selected.items()},
                                 "policy_source": "sshd_T_default_config"}
    except Exception as exc:
        result.update(execution_status="ERROR", details={"error_type": type(exc).__name__})
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", choices=("FTP_ANONYMOUS", "HTTP_SECURITY_HEADERS", "SSH_AUTH_POLICY"), required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    data = collect(a.check)
    raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    # Exclusive creation protects prior evidence from accidental overwrite.
    with a.output.open("xb") as output:
        output.write(raw)
    print(json.dumps({"check": a.check, "execution_status": data["execution_status"],
                      "source_file_sha256": hashlib.sha256(raw).hexdigest()}))
    return 0 if data["execution_status"] == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
