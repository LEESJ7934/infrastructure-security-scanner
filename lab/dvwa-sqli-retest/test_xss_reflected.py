"""Check real HTTP responses and Chromium execution for DVWA Low Reflected XSS."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode, urlsplit

from playwright.sync_api import Error as BrowserError, sync_playwright
import requests

from test_http_comparison import ORIGINS, TIMEOUT, login


ENDPOINT = "/vulnerabilities/xss_r/"
SCRIPT = "<script>alert(1)</script>"
PUNCTUATION = "Tom & \"O'Reilly\""
CASES = {
    "normal": ("name", "test123"),
    "script": ("name", SCRIPT),
    "html_characters": ("name", PUNCTUATION),
    "entity_text": ("name", "&lt;script&gt;"),
    "array_name": ("name[]", "test123"),
    "invalid_utf8": ("name", b"\xff"),
}
# Each expectation checks both the response bytes and what Chromium renders.
# (Raw greeting, visible greeting text, nested element tags, alert messages.)
NORMAL = ("<pre>Hello test123</pre>", "Hello test123", [], [])
EXPECTED = {
    "before": {
        "normal": NORMAL,
        "script": (f"<pre>Hello {SCRIPT}</pre>", "Hello ", ["SCRIPT"], ["1"]),
        "html_characters": (f"<pre>Hello {PUNCTUATION}</pre>", f"Hello {PUNCTUATION}", [], []),
    },
    "after": {
        "normal": NORMAL,
        "script": ("<pre>Hello &lt;script&gt;alert(1)&lt;/script&gt;</pre>", f"Hello {SCRIPT}", [], []),
        "html_characters": (
            "<pre>Hello Tom &amp; &quot;O&#039;Reilly&quot;</pre>", f"Hello {PUNCTUATION}", [], [],
        ),
        "entity_text": ("<pre>Hello &amp;lt;script&amp;gt;</pre>", "Hello &lt;script&gt;", [], []),
        "array_name": (None, None, [], []),
        "invalid_utf8": ("<pre>Hello \ufffd</pre>", "Hello \ufffd", [], []),
    },
}


def session_cookies(stage, origin):
    username = os.environ.get("DVWA_BEFORE_USERNAME", "admin") if stage == "before" else "admin"
    password = os.environ.get("DVWA_BEFORE_PASSWORD", "password") if stage == "before" else "password"
    with requests.Session() as session:
        session.trust_env = False
        login(session, origin, username, password)
        return [{"name": name, "value": session.cookies[name], "url": origin}
                for name in ("PHPSESSID", "security")]


def run_case(page, origin, case, expected):
    dialogs = []

    def dismiss(dialog):
        message = dialog.message
        dialogs.append({"type": dialog.type, "message": message if message == "1" else "[redacted]"})
        dialog.dismiss()

    page.on("dialog", dismiss)
    try:
        target = ENDPOINT + "?" + urlencode([CASES[case]])
        response = page.goto(origin + target, wait_until="load", timeout=TIMEOUT * 1000)
    finally:
        page.remove_listener("dialog", dismiss)

    if response is None:
        raise RuntimeError("Navigation yielded no HTTP response")
    body = response.body()
    raw = re.findall(rb"<pre>Hello [\s\S]*?</pre>", body)
    content_type = response.header_value("content-type") or ""
    request_url = urlsplit(response.request.url)
    actual_target = request_url.path + "?" + request_url.query
    cookie_header = response.request.header_value("cookie") or ""
    sent_low = re.findall(r"(?:^|;\s*)security=([^;]*)", cookie_header) == ["low"]
    low_page = bool(re.search(r"\bSecurity Level:\s*low\b", page.locator("body").inner_text(), re.IGNORECASE))

    greeting = page.locator(".vulnerable_code_area pre")
    count = greeting.count()
    visible = count == 1 and greeting.is_visible()
    visible_text = greeting.inner_text() if visible else None
    child_tags = greeting.locator("*").evaluate_all("nodes => nodes.map(node => node.tagName)")
    expected_html, expected_text, expected_tags, expected_alerts = expected
    expected_raw = [expected_html.encode("utf-8")] if expected_html is not None else []
    # Chromium can trim trailing whitespace in the original non-visible script case.
    text_matches = visible_text == expected_text or (case == "script" and expected_tags == ["SCRIPT"]
                                                     and visible_text == "Hello")
    valid = (response.status == 200 and page.url == origin + target and response.request.method == "GET"
             and response.request.redirected_from is None and "text/html" in content_type.lower()
             and sent_low and low_page and raw == expected_raw and count == len(expected_raw)
             and text_matches and child_tags == expected_tags
             and dialogs == [{"type": "alert", "message": value} for value in expected_alerts])
    return {
        "request": {"method": response.request.method, "target": actual_target if actual_target == target else None,
                    "security_level_sent": "low" if sent_low else None},
        "response": {"status": response.status, "content_type": content_type, "low_page": low_page,
                     "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                     "greeting_html": expected_html if raw == expected_raw else None,
                     "greeting_html_matches": raw == expected_raw},
        "browser": {"greeting_count": count, "greeting_visible": visible,
                    "visible_text": visible_text if text_matches else None,
                    "greeting_descendant_tags": child_tags, "dialogs_during_load": dialogs},
        "verdict": "PASS" if valid else "FAIL",
    }


def compare(evidence):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        evidence["browser"] = {"engine": "Chromium", "version": browser.version, "headless": True}
        for stage, origin in ORIGINS.items():
            target = {"origin": origin, "cases": {}}
            evidence["targets"][stage] = target
            try:
                with browser.new_context() as context:
                    context.add_cookies(session_cookies(stage, origin))
                    for case, expected in EXPECTED[stage].items():
                        page = context.new_page()
                        try:
                            result = run_case(page, origin, case, expected)
                        finally:
                            page.close()
                        target["cases"][case] = result
                        if result["verdict"] != "PASS":
                            evidence["errors"].append(f"{stage}/{case}: response or Chromium did not match expectation")
            except (requests.RequestException, RuntimeError, BrowserError) as error:
                # Avoid persisting browser diagnostics that might include login URLs or session data.
                evidence["errors"].append(f"{stage}: {type(error).__name__}")
        browser.close()

    for case in EXPECTED["before"]:
        before = evidence["targets"]["before"]["cases"].get(case)
        after = evidence["targets"]["after"]["cases"].get(case)
        evidence["matched_requests"][case] = bool(before and after and before["request"] == after["request"]
                                                   and before["request"]["target"] is not None)
    if not all(evidence["matched_requests"].values()):
        evidence["errors"].append("Could not confirm identical shared HTTP request targets")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new path for sanitized JSON evidence")
    args = parser.parse_args()
    evidence = {"finding": "CWE-79", "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "targets": {}, "matched_requests": {}, "errors": []}
    with args.output.open("x", encoding="utf-8") as output:
        try:
            compare(evidence)
        except BrowserError as error:
            evidence["errors"].append(f"Chromium unavailable or interrupted: {type(error).__name__}")
        evidence["verdict"] = "FAIL" if evidence["errors"] else "PASS"
        output.write(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    for stage, target in evidence["targets"].items():
        for case, result in target["cases"].items():
            print(f"{stage}/{case}: HTTP {result['response']['status']}, "
                  f"{len(result['browser']['dialogs_during_load'])} dialogs ({result['verdict']})")
    for error in evidence["errors"]:
        print(error)
    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
