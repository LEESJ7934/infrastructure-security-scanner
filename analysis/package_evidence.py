"""Package/advisory review attachment. No version guessing or automatic closure.

Operator-supplied review is separate from banner matching and exploitability.
Only a bound exact package, advisory, CVE and supported release can establish a
reported patch decision. Evidence authenticity is independently disclosed.
"""
import re
from urllib.parse import urlsplit
from analysis.intel_freshness import aware_utc

VENDORS = {"ubuntu": "ubuntu.com", "debian": "debian.org", "rhel": "redhat.com"}


def assess_package_evidence(cve_id, product, evidence=None):
    base = {"patch_status": "UNKNOWN", "manual_review_required": True,
            "backport_possible": True, "evidence_origin": "NOT_INDEPENDENTLY_VERIFIED",
            "reason": "installed_package_and_vendor_advisory_required"}
    if evidence is None:
        return base
    if not isinstance(evidence, dict):
        return {**base, "reason": "package_evidence_invalid"}
    distro = evidence.get("distribution")
    try:
        url = urlsplit(evidence.get("advisory_url", ""))
        hostname = url.hostname or ""
        domain = VENDORS.get(distro)
        valid = (evidence.get("cve_id") == cve_id and evidence.get("product") == product
                 and domain is not None and url.scheme == "https" and not url.username and not url.password
                 and not url.query and not url.fragment and len(evidence.get("advisory_url", "")) <= 2048
                 and (hostname == domain or hostname.endswith("." + domain))
                 and isinstance(evidence.get("distribution_release"), str) and bool(evidence["distribution_release"].strip())
                 and isinstance(evidence.get("package_name"), str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}", evidence["package_name"])
                 and isinstance(evidence.get("installed_version"), str) and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z:.+~_-]{0,254}", evidence["installed_version"])
                 and isinstance(evidence.get("reviewer"), str) and bool(evidence["reviewer"].strip())
                 and aware_utc(evidence.get("reviewed_at")) is not None
                 and isinstance(evidence.get("evidence_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", evidence["evidence_sha256"])
                 and evidence.get("package_inventory_complete") is True
                 and evidence.get("advisory_applies_to_release") is True
                 and evidence.get("vendor_patch_status") in {"FIXED", "AFFECTED", "NOT_AFFECTED", "UNKNOWN"})
    except (TypeError, ValueError):
        valid = False
    if not valid:
        return {**base, "reason": "package_advisory_binding_incomplete_or_unsupported"}
    return {**base, "patch_status": "REPORTED_" + evidence["vendor_patch_status"],
            "reason": "operator_vendor_advisory_review_not_automatic_cve_verification",
            "package": {key: evidence[key] for key in ("distribution", "distribution_release", "package_name", "installed_version")},
            "review": {key: evidence[key] for key in ("advisory_url", "reviewer", "reviewed_at", "evidence_sha256")}}
