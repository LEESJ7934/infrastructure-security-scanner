"""Compare live, authenticated DVWA Low responses on the two local lab ports."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

from bs4 import BeautifulSoup
import requests


ORIGINS = {"before": "http://127.0.0.1:4280", "after": "http://127.0.0.1:4281"}
ENDPOINT = "/vulnerabilities/sqli/"
CASES = {
    "id_1": {"id": "1", "Submit": "Submit"},
    "id_2": {"id": "2", "Submit": "Submit"},
    "unknown_id": {"id": "999999", "Submit": "Submit"},
    "sqli": {"id": "1' OR '1'='1", "Submit": "Submit"},
    "array_id": {"id[]": "1", "Submit": "Submit"},
    "missing_id": {"Submit": "Submit"},
    "out_of_range_id": {"id": "2147483648", "Submit": "Submit"},
}
EXPECTED = {
    "before": {"id_1": (200, 1), "id_2": (200, 1), "unknown_id": (200, 0), "sqli": (200, 5)},
    "after": {"id_1": (200, 1), "id_2": (200, 1), "unknown_id": (200, 0), "sqli": (400, 0),
              "array_id": (400, 0), "missing_id": (400, 0), "out_of_range_id": (400, 0)},
}
TIMEOUT = 10


def login(session, origin, username, password):
    url = origin + "/login.php"
    page = session.get(url, timeout=TIMEOUT, allow_redirects=False)
    token = BeautifulSoup(page.content, "html.parser").select_one('input[name="user_token"]')
    if page.status_code != 200 or not token or not token.get("value"):
        raise RuntimeError("DVWA login form or CSRF token unavailable")
    response = session.post(url, timeout=TIMEOUT, allow_redirects=False, data={
        "username": username, "password": password, "Login": "Login", "user_token": token["value"],
    })
    if response.status_code not in (200, 302, 303) or "PHPSESSID" not in session.cookies:
        raise RuntimeError("DVWA did not establish a login session")
    for cookie in list(session.cookies):
        if cookie.name == "security":
            session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    session.cookies.set("security", "low", domain="127.0.0.1", path="/")


def collect(response):
    soup = BeautifulSoup(response.content, "html.parser")
    blocks = soup.select(".vulnerable_code_area pre")
    rows = []
    for block in blocks:
        match = re.fullmatch(r"ID: (.*)\nFirst name: (.*)\nSurname: (.*)", block.get_text("\n", strip=True))
        if match:
            rows.append(match.groups())

    text = soup.get_text(" ", strip=True)
    low_page = bool(re.search(r"\bSecurity Level:\s*low\b", text, flags=re.IGNORECASE))
    request_cookies = response.request.headers.get("Cookie", "")
    sent_low = re.findall(r"(?:^|;\s*)security=([^;]*)", request_cookies) == ["low"]
    record = {
        "request": {"method": response.request.method, "target": response.request.path_url,
                    "security_level_sent": "low" if sent_low else None},
        "response": {"http_status": response.status_code, "content_type": response.headers.get("Content-Type"),
                     "body_bytes": len(response.content), "body_sha256": hashlib.sha256(response.content).hexdigest(),
                     "result_rows": len(rows), "result_blocks": len(blocks),
                     "distinct_user_names": len({row[1:] for row in rows}), "low_page": low_page,
                     "invalid_id_message": "Invalid user ID." in text},
    }
    return record, rows


def compare():
    evidence = {"finding": "CWE-89", "captured_at_utc": datetime.now(timezone.utc).isoformat(), "targets": {}}
    responses = {}
    errors = []
    for stage, origin in ORIGINS.items():
        target = {"origin": origin, "cases": {}}
        evidence["targets"][stage] = target
        with requests.Session() as session:
            session.trust_env = False
            username = os.environ.get("DVWA_BEFORE_USERNAME", "admin") if stage == "before" else "admin"
            password = os.environ.get("DVWA_BEFORE_PASSWORD", "password") if stage == "before" else "password"
            try:
                login(session, origin, username, password)
                for case, (expected_status, expected_count) in EXPECTED[stage].items():
                    response = session.get(origin + ENDPOINT, params=CASES[case], timeout=TIMEOUT, allow_redirects=False)
                    record, rows = collect(response)
                    target["cases"][case] = record
                    responses[stage, case] = (record["request"], rows)
                    observed = record["response"]
                    valid = (observed["http_status"] == expected_status and observed["low_page"]
                             and record["request"]["security_level_sent"] == "low"
                             and observed["result_rows"] == observed["result_blocks"] == expected_count
                             and observed["distinct_user_names"] == expected_count
                             and observed["invalid_id_message"] == (expected_status == 400))
                    record["verdict"] = "PASS" if valid else "FAIL"
                    if not valid:
                        errors.append(f"{stage}/{case}: expected HTTP {expected_status}, {expected_count} rows on Low")
            except (requests.RequestException, RuntimeError) as error:
                # Login bodies, credentials, cookies and redirect URLs stay in memory.
                reason = type(error).__name__ if isinstance(error, requests.RequestException) else str(error)
                errors.append(f"{stage}: {reason}")

    shared_cases = EXPECTED["before"].keys()
    matched_requests = {}
    for case in shared_cases:
        if ("before", case) in responses and ("after", case) in responses:
            matched_requests[case] = responses["before", case][0] == responses["after", case][0]
    matched_rows = {}
    for case in ("id_1", "id_2"):
        if ("before", case) in responses and ("after", case) in responses:
            before, after = responses["before", case][1], responses["after", case][1]
            matched_rows[case] = before == after and len(before) == 1 and before[0][0] == CASES[case]["id"]
    if matched_requests.keys() != shared_cases or not all(matched_requests.values()):
        errors.append("Could not confirm identical HTTP methods and request targets for all shared cases")
    if len(matched_rows) != 2 or not all(matched_rows.values()):
        errors.append("Could not confirm both original user records were preserved")
    evidence.update(matched_requests=matched_requests, matched_normal_rows=matched_rows,
                    verdict="FAIL" if errors else "PASS", errors=errors)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new file for sanitized evidence JSON")
    args = parser.parse_args()
    with args.output.open("x", encoding="utf-8") as output:
        evidence = compare()
        json.dump(evidence, output, indent=2)
        output.write("\n")
    for stage, target in evidence["targets"].items():
        for case, record in target["cases"].items():
            observed = record["response"]
            print(f"{stage}/{case}: HTTP {observed['http_status']}, {observed['result_rows']} rows ({record['verdict']})")
    for error in evidence["errors"]:
        print(error)
    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
