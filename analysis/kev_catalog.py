"""CISA KEV membership, with an official mirror and explicit unknown results."""
from __future__ import annotations

from datetime import datetime
from analysis.intel_freshness import stamp_acquisition

from analysis.nvd_cvss import KEV_URL, KEV_MIRROR_URL, iso_date, request_json, valid_cve, validate_timeout

FIELDS = {"date_added": "dateAdded", "due_date": "dueDate",
          "known_ransomware_campaign_use": "knownRansomwareCampaignUse", "required_action": "requiredAction",
          "vendor_project": "vendorProject", "product": "product"}


def _parse_catalog(data):
    version, released, rows = data["catalogVersion"], data["dateReleased"], data["vulnerabilities"]
    if not isinstance(version, str) or not version or len(version) > 100:
        raise ValueError("Invalid catalog version")
    if not isinstance(released, str) or len(released) > 40:
        raise ValueError("Invalid release date")
    datetime.fromisoformat(released.replace("Z", "+00:00"))
    count = data["count"]
    if not isinstance(rows, list) or isinstance(count, bool) or not isinstance(count, int) or count != len(rows):
        raise ValueError("Incomplete catalog")
    entries = {}
    for row in rows:
        cve = row["cveID"]
        if not valid_cve(cve) or cve in entries:
            raise ValueError("Malformed or duplicate catalog CVE")
        entry = {key: row.get(raw) for key, raw in FIELDS.items()}
        entry["date_added"] = iso_date(entry["date_added"])
        entry["due_date"] = iso_date(entry["due_date"])
        for key in ("vendor_project", "product", "required_action"):
            if not isinstance(entry[key], str) or not entry[key] or len(entry[key]) > 5000:
                raise ValueError("Malformed catalog metadata")
        if entry["known_ransomware_campaign_use"] not in (None, "Known", "Unknown"):
            raise ValueError("Malformed ransomware metadata")
        entries[cve] = entry
    return version, released, entries


def fetch_kev_catalog(*, timeout=10, session=None):
    """One catalog per run; fallback only to the fixed cisagov mirror."""
    validate_timeout(timeout)
    errors = []
    for source in (KEV_URL, KEV_MIRROR_URL):
        data, error = request_json(source, timeout=timeout, session=session)
        if error is None:
            try:
                version, released, entries = _parse_catalog(data)
                return stamp_acquisition({"state": "OK", "source": source, "catalog_version": version,
                        "date_released": released, "entries": entries, "errors": errors, "error_code": None}, "kev")
            except (KeyError, TypeError, ValueError):
                error = "SCHEMA_ERROR"
        errors.append({"source": source, "error_code": error})
    return stamp_acquisition({"state": "ERROR", "source": None, "catalog_version": None, "date_released": None,
            "entries": {}, "errors": errors, "error_code": "KEV_UNAVAILABLE"}, "kev")


def lookup_kev(catalog, cve_id):
    base = {"source": catalog["source"], "catalog_version": catalog["catalog_version"],
            "date_released": catalog["date_released"], "error_code": catalog["error_code"],
            "errors": list(catalog["errors"]), **dict.fromkeys(FIELDS)}
    base.update({key: catalog[key] for key in ("fetched_at", "ttl_seconds", "freshness_policy") if key in catalog})
    if not valid_cve(cve_id):
        return {**base, "state": "ERROR", "status": "UNKNOWN", "error_code": "INVALID_CVE"}
    if catalog["state"] != "OK":
        return {**base, "state": "ERROR", "status": "UNKNOWN"}
    entry = catalog["entries"].get(cve_id)
    return {**base, **(entry or {}), "state": "OK",
            "status": "KNOWN_EXPLOITED" if entry is not None else "NOT_LISTED"}
