"""Explicit source acquisition time and bounded triage freshness, without I/O.

These TTLs are project policy, not provider guarantees. A recent fetch does not
make an old EPSS observation recent. Legacy records with no timestamp stay unknown.
"""
from datetime import datetime, timedelta, timezone
from copy import deepcopy

TTL_SECONDS = {"cvss": 7 * 86400, "epss": 2 * 86400, "kev": 86400}
POLICY_ID = "intel-freshness-v1"


def aware_utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if not isinstance(value, datetime) or value.utcoffset() is None:
        return None
    return value.astimezone(timezone.utc)


def stamp_acquisition(result, provider, *, now=None):
    """Add metadata after actual fetch; parser-only/legacy inputs are not stamped."""
    if provider not in TTL_SECONDS:
        raise ValueError("unsupported_intel_provider")
    moment = aware_utc(now) if now is not None else datetime.now(timezone.utc)
    if moment is None:
        raise ValueError("timezone_aware_acquisition_time_required")
    return {**result, "fetched_at": moment.isoformat(),
            "freshness_policy": POLICY_ID, "ttl_seconds": TTL_SECONDS[provider]}


def source_freshness(provider, source, *, now=None):
    if provider not in TTL_SECONDS:
        raise ValueError("unsupported_intel_provider")
    current = aware_utc(now) if now is not None else datetime.now(timezone.utc)
    if current is None:
        raise ValueError("timezone_aware_evaluation_time_required")
    source = source if isinstance(source, dict) else {}
    fetched = aware_utc(source.get("fetched_at"))
    base = {"policy": POLICY_ID, "fetched_at": fetched.isoformat() if fetched else None,
            "ttl_seconds": TTL_SECONDS[provider], "valid_until": None,
            "data_date": source.get("date") if provider == "epss" else source.get("date_released"),
            "status": "UNKNOWN", "reason": "acquisition_time_missing_or_invalid"}
    if source.get("state") != "OK":
        return {**base, "status": "UNAVAILABLE", "reason": "source_not_available"}
    if fetched is None:
        return base
    if fetched > current + timedelta(minutes=5):
        return {**base, "status": "UNKNOWN", "reason": "acquisition_time_in_future"}
    expiry = fetched + timedelta(seconds=TTL_SECONDS[provider])
    if provider == "epss":
        try:
            day = datetime.strptime(source["date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError, KeyError):
            return {**base, "reason": "epss_data_date_missing_or_invalid"}
        if day.date() > current.date():
            return {**base, "reason": "epss_data_date_in_future"}
        expiry = min(expiry, day + timedelta(days=3))
    return {**base, "valid_until": expiry.isoformat(),
            "status": "FRESH" if current < expiry else "STALE",
            "reason": "within_project_ttl" if current < expiry else "project_ttl_expired"}


def evaluate_intel_freshness(sources, *, now=None):
    current = aware_utc(now) if now is not None else datetime.now(timezone.utc)
    return {name: source_freshness(name, sources.get(name), now=current) for name in TTL_SECONDS}


def usable_intel(sources, *, now=None):
    """Prevent explicitly stale/future data from entering a fresh priority decision.

    Missing metadata keeps legacy numeric behavior for compatibility, while its
    UNKNOWN freshness remains visible. Reports must not call that source fresh.
    """
    freshness = evaluate_intel_freshness(sources, now=now)
    output = deepcopy(sources)
    for name, info in freshness.items():
        timed_invalid = info["status"] == "STALE" or (info["status"] == "UNKNOWN" and "fetched_at" in sources.get(name, {}))
        if timed_invalid:
            output[name] = {**output.get(name, {}), "state": "ERROR", "error_code": "STALE_OR_INVALID_INTEL"}
            if name == "kev":
                output[name]["status"] = "UNKNOWN"
    return output, freshness
