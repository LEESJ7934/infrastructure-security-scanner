"""Structured NVD CVSS results and bounded HTTP reads for 위험도 평가 외부 정보원."""
from __future__ import annotations

import math
import os
import re
import time
from datetime import date

import requests
from analysis.intel_freshness import stamp_acquisition

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
INTEL_URLS = frozenset({NVD_BASE_URL, EPSS_URL, KEV_URL, KEV_MIRROR_URL})
RETRYABLE = frozenset({429, 500, 502, 503, 504})


def valid_cve(value):
    return isinstance(value, str) and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", value) is not None


def validate_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be finite, greater than 0 and at most 30 seconds")


def bounded_number(value, maximum):
    if isinstance(value, bool) or value is None:
        raise ValueError("Missing or invalid number")
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= maximum:
        raise ValueError("Number is outside the supported range")
    return number


def iso_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError("Expected an ISO calendar date")
    return date.fromisoformat(value).isoformat()


def request_json(url, *, params=None, headers=None, timeout=10, session=None):
    """GET only fixed public intel URLs; never follow a redirect to a target.

    At most three attempts, and only 429 / transient 5xx are retried. Exceptions
    and headers are never serialized: they may contain an NVD API key.
    """
    validate_timeout(timeout)
    if url not in INTEL_URLS:
        raise ValueError("URL is not a 위험도 평가 intel source")
    client = session if session is not None else requests
    for attempt in range(3):
        response = None
        try:
            response = client.get(url, params=params, headers=headers or {},
                                  timeout=timeout, allow_redirects=False)
            status = response.status_code
            if status in RETRYABLE and attempt < 2:
                delay = 0.5 * (2 ** attempt)
                try:
                    requested = float(response.headers.get("Retry-After", delay))
                    if math.isfinite(requested):
                        delay = min(2.0, max(delay, requested))
                except (TypeError, ValueError):
                    pass
                response.close()
                response = None
                time.sleep(delay)
                continue
            if status != 200:
                return None, f"HTTP_{status}"
            try:
                data = response.json()
            except ValueError:
                return None, "JSON_PARSE_ERROR"
            if not isinstance(data, dict):
                return None, "SCHEMA_ERROR"
            return data, None
        except requests.Timeout:
            return None, "TIMEOUT"
        except requests.ConnectionError:
            return None, "CONNECTION_ERROR"
        except requests.RequestException:
            return None, "REQUEST_ERROR"
        finally:
            if response is not None:
                response.close()
    raise AssertionError("Bounded request loop must return")


def cvss_result(state, *, error_code=None, **values):
    return {"state": state, "score": None, "version": None, "vector": None,
            "severity": None, "source": None, "metric_type": None,
            "endpoint": NVD_BASE_URL, "error_code": error_code, **values}


def parse_cvss(data, cve_id):
    try:
        items = data["vulnerabilities"]
        if not isinstance(items, list):
            raise ValueError("Invalid CVE list")
        if not items:
            if data.get("totalResults", 0) != 0:
                raise ValueError("Incomplete CVE response")
            return cvss_result("NOT_FOUND")
        cves = [item["cve"] for item in items]
        selected = next(cve for cve in cves if cve["id"] == cve_id)
        metrics = selected.get("metrics", {})
        if not isinstance(metrics, dict):
            raise ValueError("Invalid metrics")
        malformed = False
        for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                             ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key, [])
            if not isinstance(entries, list):
                malformed = True
                continue
            valid = []
            for entry in entries:
                try:
                    cvss = entry["cvssData"]
                    score = bounded_number(cvss["baseScore"], 10)
                    source, metric_type = entry["source"], entry["type"]
                    vector = cvss["vectorString"]
                    if (cvss.get("version") != version or not isinstance(vector, str) or not vector
                            or len(vector) > 255 or not isinstance(source, str) or not source or len(source) > 255
                            or metric_type not in {"Primary", "Secondary"}):
                        raise ValueError("Invalid CVSS metric")
                    severity = cvss.get("baseSeverity", entry.get("baseSeverity"))
                    if severity is not None and severity not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                        raise ValueError("Invalid severity")
                    preference = (0 if source.lower() == "nvd@nist.gov" and metric_type == "Primary"
                                  else 1 if metric_type == "Primary" else 2)
                    valid.append((preference, cvss_result("OK", score=score, version=version,
                                  vector=vector, severity=severity, source=source, metric_type=metric_type)))
                except (KeyError, TypeError, ValueError, OverflowError):
                    malformed = True
            if valid:
                return min(valid, key=lambda item: item[0])[1]
        return cvss_result("ERROR", error_code="SCHEMA_ERROR") if malformed else cvss_result("NO_SCORE")
    except (KeyError, TypeError, ValueError, StopIteration):
        return cvss_result("ERROR", error_code="SCHEMA_ERROR")


def fetch_cvss(cve_id, *, timeout=10, session=None):
    validate_timeout(timeout)
    if not valid_cve(cve_id):
        return stamp_acquisition(cvss_result("ERROR", error_code="INVALID_CVE"), "cvss")
    api_key = os.getenv("NVD_API_KEY")
    data, error = request_json(NVD_BASE_URL, params={"cveId": cve_id},
                               headers={"apiKey": api_key} if api_key else {},
                               timeout=timeout, session=session)
    result = cvss_result("ERROR", error_code=error) if error else parse_cvss(data, cve_id)
    return stamp_acquisition(result, "cvss")


def fetch_cvss_scores(cve_ids, *, timeout=10, session=None):
    """Run-scoped deduplication; no stale global cache."""
    validate_timeout(timeout)
    return {cve: fetch_cvss(cve, timeout=timeout, session=session) for cve in sorted(set(cve_ids))}


def fetch_cvss_score(cve_id: str) -> float | None:
    """Compatibility scalar API: unavailable/error is None, never a fabricated 0."""
    return fetch_cvss(cve_id)["score"]
