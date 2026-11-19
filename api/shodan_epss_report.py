"""FIRST EPSS batch client. The historical ``epss`` key remains an alias of score."""
from __future__ import annotations
from analysis.intel_freshness import stamp_acquisition

from analysis.nvd_cvss import (EPSS_URL, bounded_number, iso_date, request_json,
                               valid_cve, validate_timeout)

EPSS_BASE_URL = EPSS_URL
MAX_CVE_PARAMETER = 1800  # FIRST permits 2000 characters including commas.
MAX_BATCH_CVES = 100


def epss_result(state, *, error_code=None, score=None, percentile=None, date=None):
    return {"state": state, "score": score, "epss": score, "percentile": percentile,
            "date": date, "source": EPSS_BASE_URL, "error_code": error_code}


def _chunks(cves):
    chunk, length = [], 0
    for cve in cves:
        extra = len(cve) + bool(chunk)
        if chunk and (length + extra > MAX_CVE_PARAMETER or len(chunk) >= MAX_BATCH_CVES):
            yield chunk
            chunk, length = [], 0
        chunk.append(cve)
        length += len(cve) + (len(chunk) > 1)
    if chunk:
        yield chunk


def _parse_batch(data, cves):
    try:
        rows = data["data"]
        if data.get("status") != "OK" or not isinstance(rows, list):
            raise ValueError("Invalid EPSS response")
        # Do not interpret omitted pagination as official absence.
        total, offset = data["total"], data["offset"]
        if isinstance(total, bool) or not isinstance(total, int) or total != len(rows) or offset != 0:
            raise ValueError("Incomplete EPSS page")
        result = {cve: epss_result("NOT_FOUND") for cve in cves}
        seen = set()
        for row in rows:
            cve = row["cve"]
            if cve not in result or cve in seen:
                raise ValueError("Unexpected or duplicate CVE")
            seen.add(cve)
            try:
                result[cve] = epss_result("OK", score=bounded_number(row["epss"], 1),
                                          percentile=bounded_number(row["percentile"], 1),
                                          date=iso_date(row["date"]))
            except (KeyError, TypeError, ValueError, OverflowError):
                result[cve] = epss_result("ERROR", error_code="SCHEMA_ERROR")
        return result
    except (KeyError, TypeError, ValueError):
        return {cve: epss_result("ERROR", error_code="SCHEMA_ERROR") for cve in cves}


def fetch_epss_scores(cve_list: list[str], *, timeout=15, session=None) -> dict[str, dict]:
    """Return every requested CVE with OK / NOT_FOUND / ERROR and no invented zeros."""
    validate_timeout(timeout)
    cves = sorted(set(cve_list))
    result = {cve: epss_result("ERROR", error_code="INVALID_CVE") for cve in cves if not valid_cve(cve)}
    for chunk in _chunks([cve for cve in cves if valid_cve(cve)]):
        data, error = request_json(EPSS_BASE_URL, params={"cve": ",".join(chunk), "limit": len(chunk)},
                                   timeout=timeout, session=session)
        result.update({cve: epss_result("ERROR", error_code=error) for cve in chunk}
                      if error else _parse_batch(data, chunk))
    return {cve: stamp_acquisition(value, "epss") for cve, value in result.items()}
