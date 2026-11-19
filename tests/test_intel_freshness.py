"""Acquisition provenance and TTL regression; no actual provider or target I/O."""
import copy
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch, MagicMock

from analysis.intel_freshness import stamp_acquisition, source_freshness, usable_intel
from analysis.package_evidence import assess_package_evidence
from analysis.nvd_cvss import fetch_cvss
from analysis.kev_catalog import fetch_kev_catalog, lookup_kev
from api.shodan_epss_report import fetch_epss_scores

NOW = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
CVE = "CVE-2021-42013"


class IntelFreshnessTests(unittest.TestCase):
    def test_naive_time_is_rejected_and_offsets_normalized(self):
        with self.assertRaises(ValueError):
            stamp_acquisition({}, "cvss", now=datetime(2026, 11, 19, 15))
        kst = datetime(2026, 11, 19, 15, tzinfo=timezone(timedelta(hours=9)))
        self.assertEqual(stamp_acquisition({}, "cvss", now=kst)["fetched_at"], NOW.isoformat())

    def test_exact_ttl_boundary_is_expired(self):
        source = stamp_acquisition({"state": "OK", "score": 8.0}, "cvss", now=NOW)
        self.assertEqual(source_freshness("cvss", source, now=NOW + timedelta(days=7) - timedelta(microseconds=1))["status"], "FRESH")
        self.assertEqual(source_freshness("cvss", source, now=NOW + timedelta(days=7))["status"], "STALE")

    def test_recent_fetch_cannot_refresh_old_epss_date(self):
        source = stamp_acquisition({"state": "OK", "score": .9, "date": "2026-11-01"}, "epss", now=NOW)
        self.assertEqual(source_freshness("epss", source, now=NOW)["status"], "STALE")

    def test_missing_future_invalid_and_unavailable_are_not_fresh(self):
        for source, expected in (({"state": "OK"}, "UNKNOWN"),
                                 ({"state": "OK", "fetched_at": "not-a-time"}, "UNKNOWN"),
                                 ({"state": "OK", "fetched_at": (NOW + timedelta(hours=1)).isoformat()}, "UNKNOWN"),
                                 ({"state": "ERROR", "score": None}, "UNAVAILABLE")):
            with self.subTest(source=source):
                self.assertEqual(source_freshness("cvss", source, now=NOW)["status"], expected)

    def test_stale_kev_is_unknown_and_original_snapshot_is_immutable(self):
        kev = stamp_acquisition({"state": "OK", "status": "NOT_LISTED"}, "kev", now=NOW - timedelta(days=2))
        sources = {"cvss": {"state": "NO_SCORE"}, "epss": {"state": "NOT_FOUND"}, "kev": kev}
        saved = copy.deepcopy(sources)
        effective, freshness = usable_intel(sources, now=NOW)
        self.assertEqual(effective["kev"]["status"], "UNKNOWN")
        self.assertEqual(effective["kev"]["state"], "ERROR")
        self.assertEqual(sources, saved)
        self.assertEqual(freshness["kev"]["status"], "STALE")

    def test_legacy_records_remain_unknown_without_fabricating_fetch_time(self):
        source = {"state": "OK", "score": 8.1}
        effective, freshness = usable_intel({"cvss": source}, now=NOW)
        self.assertEqual(effective["cvss"], source)
        self.assertEqual(freshness["cvss"]["status"], "UNKNOWN")
        self.assertIsNone(freshness["cvss"]["fetched_at"])

    @patch("requests.get")
    def test_real_fetch_wrappers_stamp_success_or_failure_and_kev_lookup_propagates(self, get):
        response = MagicMock(status_code=200)
        response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        get.return_value = response
        self.assertIn("fetched_at", fetch_cvss(CVE))
        response.json.return_value = {"status": "OK", "total": 0, "offset": 0, "data": []}
        self.assertIn("fetched_at", fetch_epss_scores([CVE])[CVE])
        response.json.return_value = {"catalogVersion": "2026.11.19", "dateReleased": "2026-11-19T00:00:00Z", "count": 0, "vulnerabilities": []}
        catalog = fetch_kev_catalog()
        self.assertEqual(lookup_kev(catalog, CVE)["fetched_at"], catalog["fetched_at"])
        get.side_effect = __import__('requests').Timeout()
        result = fetch_cvss(CVE)
        self.assertEqual(result["state"], "ERROR")
        self.assertIsNone(result["score"])
        self.assertIn("fetched_at", result)


class PackageEvidenceTests(unittest.TestCase):
    def evidence(self):
        return {"cve_id": CVE, "product": "apache_http_server", "distribution": "ubuntu",
                "distribution_release": "24.04", "package_name": "apache2", "installed_version": "2.4.49-1ubuntu0.1",
                "advisory_url": "https://ubuntu.com/security/CVE-2021-42013", "reviewer": "approved-reviewer",
                "reviewed_at": NOW.isoformat(), "evidence_sha256": "a" * 64,
                "package_inventory_complete": True, "advisory_applies_to_release": True, "vendor_patch_status": "FIXED"}

    def test_backport_never_guessed_from_banner_or_suffix(self):
        result = assess_package_evidence(CVE, "apache_http_server")
        self.assertEqual(result["patch_status"], "UNKNOWN")
        self.assertTrue(result["manual_review_required"])

    def test_complete_bound_review_remains_reported_not_automatically_confirmed(self):
        result = assess_package_evidence(CVE, "apache_http_server", self.evidence())
        self.assertEqual(result["patch_status"], "REPORTED_FIXED")
        self.assertEqual(result["evidence_origin"], "NOT_INDEPENDENTLY_VERIFIED")
        self.assertTrue(result["manual_review_required"])
        self.assertNotIn("status", result)

    def test_wrong_cve_product_vendor_partial_or_missing_origin_prevents_decision(self):
        for key, value in (("cve_id", "CVE-2021-41773"), ("product", "nginx"),
                           ("advisory_url", "https://ubuntu.com.attacker.example/advisory"),
                           ("advisory_url", "https://token@ubuntu.com/advisory"),
                           ("advisory_url", "https://ubuntu.com/advisory?token=do-not-store"),
                           ("reviewed_at", "2026-11-19"), ("evidence_sha256", None),
                           ("package_inventory_complete", False), ("advisory_applies_to_release", False),
                           ("distribution", "unsupported")):
            evidence = {**self.evidence(), key: value}
            with self.subTest(key=key):
                self.assertEqual(assess_package_evidence(CVE, "apache_http_server", evidence)["patch_status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
