"""Header-only, redirect-safe HTTP configuration check. Never confirms a CVE."""
from __future__ import annotations

import time
import requests
from .base_checker import BaseChecker, check_result


class HTTPChecker(BaseChecker):
    def __init__(self, timeout=4):
        self.timeout = timeout

    def run_check(self, port_record, vuln_candidate):
        ip, port = port_record["host_ip"], int(port_record["port"])
        scheme = "https" if port_record.get("service") == "https" else "http"
        if ":" in ip and not ip.startswith("["):
            ip = f"[{ip}]"
        url = f"{scheme}://{ip}:{port}/"
        session = requests.Session()
        session.trust_env = False
        started = time.monotonic()
        try:
            with session.get(url, timeout=self.timeout, allow_redirects=False, stream=True) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                required = {
                    "x-content-type-options": "nosniff",
                    "referrer-policy": None,
                    "content-security-policy": None,
                }
                missing = [key for key, value in required.items()
                           if not headers.get(key) or (value and headers[key].lower() != value)]
                if not (headers.get("x-frame-options") or
                        "frame-ancestors" in headers.get("content-security-policy", "").lower()):
                    missing.append("x-frame-options_or_csp_frame-ancestors")
                if scheme == "https" and not headers.get("strict-transport-security"):
                    missing.append("strict-transport-security")
                details = {
                    "safe_checks": ["http_get_headers_no_redirect_no_body"],
                    "url": url, "http_status": response.status_code,
                    "present_header_names": sorted(k for k in headers if k in required or
                                                   k in {"x-frame-options", "strict-transport-security"}),
                    "missing_headers": missing,
                    "finding_status": "POTENTIAL" if missing else "NOT_DETECTED",
                    "duration_ms": round((time.monotonic() - started) * 1000),
                }
                return check_result(
                    "POTENTIAL", "HTTP security-header configuration inspected; applicability needs review.",
                    checker=type(self).__name__, evidence_type="HTTP_RESPONSE", details=details,
                    additional_checks=["Review header applicability and CSP directives in application context."],
                )
        except requests.RequestException as exc:
            return check_result(
                "ERROR", "HTTP headers could not be inspected; no security verdict.",
                checker=type(self).__name__, evidence_type="ERROR_LOG",
                error_code="HTTP_REQUEST_ERROR",
                details={"safe_checks": ["http_get_headers_no_redirect_no_body"],
                         "error_type": type(exc).__name__},
            )
        finally:
            session.close()
