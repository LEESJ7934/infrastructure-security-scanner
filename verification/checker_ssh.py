"""SSH observation and separately attested configuration; no login guessing."""
from __future__ import annotations

import socket
import time
from .base_checker import BaseChecker, check_result


class SSHChecker(BaseChecker):
    def __init__(self, timeout=5, *, approved_auth_policy=None):
        self.timeout = timeout
        self.approved_auth_policy = approved_auth_policy

    def run_check(self, port_record, vuln_candidate):
        started = time.monotonic()
        details = {"safe_checks": ["ssh_greeting_only"],
                   "authentication_probe_attempted": False}
        try:
            with socket.create_connection(
                (port_record["host_ip"], int(port_record["port"])), timeout=self.timeout
            ) as connection:
                connection.settimeout(self.timeout)
                banner = connection.recv(256).decode("ascii", errors="replace").splitlines()[0]
                if not banner.startswith("SSH-"):
                    return check_result(
                        "ERROR", "Unexpected SSH greeting; authentication policy unknown.",
                        checker=type(self).__name__, evidence_type="ERROR_LOG",
                        error_code="INVALID_SSH_BANNER", details=details,
                    )
                details["banner"] = banner[:255]
                if self.approved_auth_policy is not None:
                    # The caller MUST supply this from approved admin configuration
                    # (e.g. sshd -T), never infer it from an SSH banner.
                    approved = self.approved_auth_policy
                    if type(approved) is not dict or not all(
                        type(approved.get(key)) is bool for key in
                        ("pubkeyauthentication", "passwordauthentication")
                    ):
                        raise ValueError("Attested policy must contain two boolean authentication flags")
                    details["attested_auth_policy"] = dict(approved)
                    details["policy_source"] = "operator_attested"
                    details["finding_status"] = (
                        "POTENTIAL" if approved["passwordauthentication"] else "NOT_DETECTED"
                    )
                else:
                    details["finding_status"] = "INCONCLUSIVE"
                details["duration_ms"] = round((time.monotonic() - started) * 1000)
                return check_result(
                    "POTENTIAL", "SSH greeting observed; remote banner cannot establish auth policy.",
                    checker=type(self).__name__, evidence_type="BANNER", details=details,
                    additional_checks=["Obtain sshd -T results or an approved read-only administrative attestation."],
                )
        except (OSError, TimeoutError, ValueError) as exc:
            return check_result(
                "ERROR", "SSH inspection failed; no security verdict.",
                checker=type(self).__name__, evidence_type="ERROR_LOG",
                error_code="SSH_INSPECTION_ERROR",
                details={**details, "error_type": type(exc).__name__},
            )
