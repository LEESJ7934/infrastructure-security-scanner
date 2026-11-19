"""Deterministic, offline product/version matching against a reviewed subset."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from scanner.fingerprints import identify_service
from analysis.package_evidence import assess_package_evidence

DEFAULT_RULES = Path(__file__).with_name("vuln_rules.json")
RETIRED_RULE_IDS = frozenset({
    "rule_ftp_vsftpd_3_0_5", "rule_ssh_openssh_8_9", "rule_telnet_default",
    "rule_dvwa_sqli", "rule_dvwa_fileupload",
})
SUPPORTED_PRODUCTS = {"apache_http_server", "nginx", "openssh"}
LIMITATION = ("This is a reviewed CVE subset, not a complete vulnerability database. "
              "No match does not mean secure. Banners can be hidden, forged or backported; "
              "configuration and installed-package checks are still required.")


def normalized_version(product: str, version: str | None) -> tuple[int, ...] | None:
    if not isinstance(version, str) or len(version) > 255:
        return None
    # Unknown/pre-release syntax is not silently truncated to a vulnerable release.
    if re.search(r"(?:rc|alpha|beta|preview|dev|snapshot)", version, re.I):
        return None
    if product == "openssh":
        match = re.fullmatch(r"(\d+)\.(\d+)(?:p\d+)?(?:[-+][0-9A-Za-z.+_~:-]+)?", version)
    elif product in {"apache_http_server", "nginx"}:
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+_~:-]+)?", version)
    else:
        return None
    return tuple(map(int, match.groups())) if match else None


def load_catalog(rule_path: str | Path = DEFAULT_RULES) -> tuple[dict, str]:
    raw = Path(rule_path).read_bytes()
    catalog = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise ValueError("Use the 제품·버전 범위 카탈로그; legacy regex rules are rejected.")
    if not isinstance(catalog.get("rules"), list) or not catalog.get("reviewed_on"):
        raise ValueError("Catalog requires rules and reviewed_on.")
    seen = set()
    for rule in catalog["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Each rule must be an object.")
        required = {"id", "product", "services", "cve", "title", "severity",
                    "severity_basis", "affected", "references", "conditions"}
        if not required <= rule.keys():
            raise ValueError("Incomplete CVE rule.")
        product = rule["product"]
        if product not in SUPPORTED_PRODUCTS or not re.fullmatch(r"CVE-\d{4}-\d{4,}", rule["cve"]):
            raise ValueError("Unsupported product or malformed CVE identifier.")
        if not re.fullmatch(r"catalog:[a-z0-9_:-]{1,85}", rule["id"]) or rule["id"] in seen:
            raise ValueError("Rule IDs must be unique and start with catalog:.")
        seen.add(rule["id"])
        if rule["severity"] not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Unsupported severity.")
        if not rule["services"] or not set(rule["services"]) <= {"http", "https", "ssh"}:
            raise ValueError("Unsupported service.")
        bounds = rule["affected"]
        if not isinstance(bounds, dict) or set(bounds) != {"introduced", "fixed"}:
            raise ValueError("Affected range requires inclusive introduced and exclusive fixed.")
        lower = normalized_version(product, bounds["introduced"])
        upper = normalized_version(product, bounds["fixed"])
        if lower is None or upper is None or lower >= upper:
            raise ValueError("Invalid affected version interval.")
        if not isinstance(rule["references"], list) or not rule["references"] or any(
            not isinstance(url, str) or not url.startswith("https://") for url in rule["references"]
        ):
            raise ValueError("Every rule requires HTTPS source references.")
        if not isinstance(rule["conditions"], list) or not rule["conditions"]:
            raise ValueError("Every rule must document unverified conditions.")
    return catalog, hashlib.sha256(raw).hexdigest()


def load_rules(rule_path: str | Path = DEFAULT_RULES) -> list[dict]:
    return load_catalog(rule_path)[0]["rules"]


def fingerprint_for(record: dict) -> dict:
    # Re-parse the preserved response so arbitrary stored version fields are not trusted.
    fingerprint = identify_service(record.get("banner"), record.get("service") or "unknown")
    return fingerprint


def match_rule(port_record: dict, rule: dict) -> bool:
    if port_record.get("state") != "open" or port_record.get("protocol") != "tcp":
        return False
    fingerprint = fingerprint_for(port_record)
    product = fingerprint["product"]
    if product != rule["product"] or fingerprint["service"] not in rule["services"]:
        return False
    version = normalized_version(product, fingerprint["version"])
    if version is None:
        return False
    return (normalized_version(product, rule["affected"]["introduced"]) <= version
            < normalized_version(product, rule["affected"]["fixed"]))


def analyze_ports(port_records: list[dict], rule_path: str | Path = DEFAULT_RULES) -> dict:
    catalog, digest = load_catalog(rule_path)
    candidates, observations = [], []
    for record in port_records:
        if not isinstance(record, dict):
            raise ValueError("Each port observation must be an object.")
        fingerprint = fingerprint_for(record)
        product, version = fingerprint["product"], fingerprint["version"]
        matched = []
        for rule in catalog["rules"]:
            if not match_rule(record, rule):
                continue
            matched.append(rule["cve"])
            bounds = rule["affected"]
            candidates.append({
                "port_id": record.get("port_id", record.get("id")),
                "observation_id": record.get("observation_id"),
                "scan_id": record.get("scan_id"), "host_ip": record.get("host_ip"),
                "port": record.get("port"), "protocol": record.get("protocol"),
                "cve_id": rule["cve"], "title": rule["title"],
                "severity": rule["severity"], "severity_basis": rule["severity_basis"],
                "status": "CANDIDATE", "source": rule["id"], "rule_id": rule["id"],
                "product": product, "version": version, "fingerprint": fingerprint,
                "package_assessment": assess_package_evidence(
                    rule['cve'], product, record.get('package_evidence')),
                "affected": bounds,
                "match_reason": f"{product} {version}: >= {bounds['introduced']} and < {bounds['fixed']}",
                "conditions_to_verify": rule["conditions"], "references": rule["references"],
                "catalog_sha256": digest, "catalog_reviewed_on": catalog["reviewed_on"],
                "cvss": None, "epss": None, "risk": None,
            })
        if record.get("state") != "open" or record.get("protocol") != "tcp":
            reason = "not_open_tcp"
        elif not product:
            reason = "product_not_identified"
        elif product not in {rule["product"] for rule in catalog["rules"]}:
            reason = "product_not_in_catalog"
        elif not version:
            reason = "version_not_identified"
        elif normalized_version(product, version) is None:
            reason = "unsupported_version_format"
        else:
            reason = "candidate_found" if matched else "outside_reviewed_ranges"
        observations.append({"port_id": record.get("port_id", record.get("id")),
                             "host_ip": record.get("host_ip"), "port": record.get("port"),
                             "product": product, "version": version,
                             "reason": reason, "matched_cves": matched})
    return {"catalog_reviewed_on": catalog["reviewed_on"], "catalog_sha256": digest,
            "rule_count": len(catalog["rules"]), "limitation": LIMITATION,
            "observations": observations, "candidates": candidates}


def map_vulns(port_records, rule_path: str | Path = DEFAULT_RULES) -> list[dict]:
    return analyze_ports(port_records, rule_path)["candidates"]
