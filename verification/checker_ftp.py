"""Opt-in, non-destructive FTP configuration inspection for approved labs.

A successful anonymous login proves the *configuration*, never a CVE.
The legacy CVE dispatcher never calls this checker automatically.
"""
from ftplib import FTP, all_errors
import time

from .base_checker import BaseChecker, check_result


class FTPChecker(BaseChecker):
    def __init__(self, timeout=5, *, allow_anonymous_login=False, approved_endpoints=()):
        self.timeout = timeout
        self.allow_anonymous_login = allow_anonymous_login
        self.approved_endpoints = frozenset(approved_endpoints)

    def run_check(self, port_record, vuln_candidate):
        if self.allow_anonymous_login and (port_record["host_ip"], int(port_record["port"])) not in self.approved_endpoints:
            return check_result(
                "ERROR", "Anonymous authentication was not authorized for this exact endpoint.",
                checker=type(self).__name__, evidence_type="ERROR_LOG",
                error_code="SCOPE_DENIED", details={"safe_checks": []},
            )
        ftp = FTP()
        started = time.monotonic()
        details = {"safe_checks": ["ftp_greeting"], "anonymous_login_attempted": False}
        try:
            welcome = ftp.connect(port_record["host_ip"], int(port_record["port"]), timeout=self.timeout)
            details["banner"] = (welcome or "")[:256]
            if not self.allow_anonymous_login:
                return check_result(
                    "POTENTIAL", "FTP greeting observed; authentication policy not tested.",
                    checker=type(self).__name__, evidence_type="BANNER", details=details,
                    additional_checks=["Use explicit opt-in on an approved lab to test anonymous login."],
                )
            details["anonymous_login_attempted"] = True
            details["safe_checks"].append("anonymous_login_no_file_operations")
            try:
                response = ftp.login(user="anonymous", passwd="lab-check@example.invalid")
            except all_errors as exc:
                # Only a clear FTP 530 authentication denial proves anonymous login failed.
                code = str(exc)[:3]
                if code == "530":
                    details.update(anonymous_login_allowed=False, server_response_code="530",
                                   finding_status="NOT_DETECTED")
                else:
                    return check_result(
                        "ERROR", "FTP authentication response was not a conclusive denial.",
                        checker=type(self).__name__, evidence_type="ERROR_LOG",
                        error_code="FTP_LOGIN_ERROR", details={**details, "server_response_code": code},
                    )
            else:
                details.update(anonymous_login_allowed=True,
                               server_response_code=str(response)[:3], finding_status="CONFIRMED")
            details["duration_ms"] = round((time.monotonic() - started) * 1000)
            return check_result(
                "POTENTIAL", "FTP anonymous-authentication configuration was inspected; no CVE was confirmed.",
                checker=type(self).__name__, evidence_type="BANNER", details=details,
                additional_checks=["Review whether anonymous read access is authorized by policy."],
            )
        except (OSError, TimeoutError, *all_errors) as exc:
            return check_result(
                "ERROR", "FTP connection failed; security posture remains unknown.",
                checker=type(self).__name__, evidence_type="ERROR_LOG",
                error_code="FTP_CONNECTION_ERROR",
                details={**details, "error_type": type(exc).__name__},
            )
        finally:
            try:
                ftp.close()
            except OSError:
                pass
