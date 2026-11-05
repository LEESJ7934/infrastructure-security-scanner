"""Synthetic local artifacts only; no real firewall or evidence is accessed."""

from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config_audit import manual_evidence as manual
from config_audit.collectors import opnsense as fw
from scripts import run_day4_audit as audit


class ManualEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.artifact = self.base / "artifact.txt"
        self.artifact.write_bytes(b"SYNTHETIC_CONTENT_DO_NOT_EXPORT")
        self.source = {"kind": "firewall_log", "path": "artifact.txt",
                       "sha256": hashlib.sha256(self.artifact.read_bytes()).hexdigest()}
        self.path = self.base / "manual.json"

    def packet_case(self, check="FW-02", scenario="block"):
        source, destination, protocol, port = {
            "FW-02": ("10.77.50.10", "10.77.50.1", "tcp", 443),
            "FW-03": ("10.77.50.10", "10.77.50.1", "tcp", 22),
            "FW-06": ("10.77.40.10", "10.77.50.10", "icmp", None),
        }[check]
        result = {"scenario": scenario, "source": source, "destination": destination,
                  "protocol": protocol, "port": port,
                  "expected_result": "blocked" if scenario == "block" else "allowed",
                  "actual_result": "timeout" if scenario == "block" else "success",
                  "firewall_action": "block" if scenario == "block" else "not_observed",
                  "rule_name": ("LAB-D4-Block-Windows-Alpine" if check == "FW-06"
                                else "Default deny / state violation rule") if scenario == "block" else None,
                  "source_indices": [0]}
        if protocol == "icmp":
            result.update(packets_sent=4, packets_received=0 if scenario == "block" else 4)
        return result

    def record(self, check="FW-02", reported="PASS"):
        result = {"check_id": check, "reported_status": reported, "verified_at": "2026-11-05T10:00:00+09:00",
                  "scope": manual.SCOPES[check], "sources": [deepcopy(self.source)],
                  "tests": [self.packet_case(check)] if check in {"FW-02", "FW-03"} else []}
        if check == "FW-06":
            result["tests"] = [self.packet_case(check, scenario) for scenario in ("pass", "block", "restored")]
        if check == "FW-04":
            result["inspection"] = {"rule_count": 18, "default_deny_seen": True, "anti_lockout_seen": True,
                                    "lan_default_allow_seen": True, "lab_block_before_default_allow": True,
                                    "lab_block_enabled": False}
        return result

    def load(self, records):
        self.path.write_text(json.dumps({"schema_version": 1, "asset_id": "SJ-D4-OPNsense", "checks": records}), encoding="utf-8")
        return manual.load_manual_evidence(self.path)

    def automatic_rows(self):
        now = datetime.now(timezone.utc)
        return audit.rows(fw.Evidence("a" * 32, now, now))

    def invoke(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = audit.main(list(args))
        return code, json.loads(out.getvalue())

    def test_absent_evidence_is_not_attached(self):
        bundle = manual.load_manual_evidence(None)
        rows = self.automatic_rows()
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(bundle["status"], "NOT_SUPPLIED")
        self.assertTrue(all(not row["manual_verification"]["attached"] for row in rows))
        self.assertTrue(all(row["status"] == "NOT_TESTED" for row in rows))

    def test_missing_json_has_safe_error(self):
        bundle = manual.load_manual_evidence(self.base / "PRIVATE_SECRET.json")
        self.assertEqual(bundle["reason"], "manual_file_unreadable")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(bundle))

    def test_valid_manual_pass_preserves_automatic_not_tested(self):
        bundle = self.load([self.record()])
        rows = self.automatic_rows()
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[1]["status"], "NOT_TESTED")
        self.assertEqual(rows[1]["automatic_status"], "NOT_TESTED")
        self.assertEqual(rows[1]["manual_verification"]["status"], "PASS")
        self.assertFalse(rows[1]["manual_verification"]["content_verified_by_agent"])
        self.assertFalse(rows[1]["manual_verification"]["current_execution_evidence"])

    def test_manual_ssh_scope_is_not_wan_forwarding_or_full_fw03(self):
        bundle = self.load([self.record("FW-03")])
        self.assertEqual(bundle["checks"]["FW-03"]["scope"], "wan_to_firewall_tcp22_only")
        record = self.record("FW-03")
        record["tests"][0]["destination"] = "10.77.40.10"
        self.assertEqual(self.load([record])["status"], "ERROR")

    def test_pass_block_restore_scenario_preserves_auto_fw06_not_tested(self):
        bundle = self.load([self.record("FW-06")])
        rows = self.automatic_rows()
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[5]["manual_verification"]["status"], "PASS")
        self.assertEqual(rows[5]["status"], "NOT_TESTED")

    def test_missing_restore_cannot_support_manual_pass(self):
        record = self.record("FW-06")
        record["tests"].pop()
        result = self.load([record])["checks"]["FW-06"]
        self.assertEqual(result["status"], "NEEDS_REVIEW")
        self.assertEqual(result["reported_status"], "PASS")
        self.assertEqual(result["reason"], "manual_restore_test_missing")

    def test_missing_source_file_does_not_claim_attachment(self):
        self.artifact.unlink()
        result = self.load([self.record()])["checks"]["FW-02"]
        self.assertFalse(result["attached"])
        self.assertEqual(result["status"], "NEEDS_REVIEW")
        self.assertEqual(result["reason"], "source_missing_or_unreadable")

    def test_hash_mismatch_does_not_validate_artifact(self):
        record = self.record()
        record["sources"][0]["sha256"] = "0" * 64
        result = self.load([record])["checks"]["FW-02"]
        self.assertEqual(result["reason"], "source_hash_mismatch")
        self.assertFalse(result["attached"])

    def test_no_sources_and_no_tests_is_incomplete_not_pass(self):
        record = self.record()
        record["sources"], record["tests"] = [], []
        result = self.load([record])["checks"]["FW-02"]
        self.assertEqual(result["status"], "NEEDS_REVIEW")
        self.assertFalse(result["attached"])

    def test_unknown_fields_or_secrets_are_rejected_without_echo(self):
        for field in ("api_key", "secret", "Authorization", "private_key", "notes"):
            record = self.record()
            record[field] = "PRIVATE_SECRET"
            bundle = self.load([record])
            self.assertEqual(bundle["status"], "ERROR")
            self.assertNotIn("PRIVATE_SECRET", json.dumps(bundle))
        record = self.record()
        record["tests"][0]["rule_name"] = "Authorization: PRIVATE_SECRET"
        self.assertEqual(self.load([record])["status"], "ERROR")

    def test_input_structures_types_timestamps_and_duplicates(self):
        record = self.record()
        for changes in (dict(scope="all_networks"), dict(check_id="FW-99"), dict(reported_status="SUCCESS"),
                        dict(verified_at="2026-11-05T10:00:00"), dict(verified_at="2099-01-01T00:00:00+00:00"),
                        dict(tests=[None]), dict(sources=[None])):
            self.assertEqual(self.load([record | changes])["status"], "ERROR", changes)
        self.assertEqual(self.load([record, record])["status"], "ERROR")

    def test_artifact_review_time_is_distinguished_from_original_test_time(self):
        record = self.record()
        record["time_basis"] = "artifact_review"
        result = self.load([record])["checks"]["FW-02"]
        self.assertEqual(result["time_basis"], "artifact_review")
        self.assertEqual(result["status"], "PASS")
        record.pop("time_basis")
        self.assertEqual(self.load([record])["checks"]["FW-02"]["time_basis"], "test_time")

    def test_unknown_time_basis_is_rejected(self):
        record = self.record()
        record["time_basis"] = "PRIVATE_SECRET"
        bundle = self.load([record])
        self.assertEqual(bundle["status"], "ERROR")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(bundle))

    def test_invalid_json_and_duplicate_keys_are_safe(self):
        for raw in ('{"secret": "PRIVATE_SECRET"', '{"schema_version":1,"schema_version":1}', '[]', 'null'):
            self.path.write_text(raw, encoding="utf-8")
            bundle = manual.load_manual_evidence(self.path)
            self.assertEqual(bundle["status"], "ERROR")
            self.assertNotIn("PRIVATE_SECRET", json.dumps(bundle))

    def test_source_path_escape_is_rejected(self):
        for path in ("../secret.txt", str(self.artifact.resolve()), "C:\\secret.txt"):
            record = self.record()
            record["sources"][0]["path"] = path
            self.assertEqual(self.load([record])["status"], "ERROR")

    def test_bounded_file_sizes(self):
        self.path.write_bytes(b" " * (manual.MAX_JSON_BYTES + 1))
        self.assertEqual(manual.load_manual_evidence(self.path)["status"], "ERROR")
        with patch.object(manual, "MAX_SOURCE_BYTES", 1):
            result = self.load([self.record()])["checks"]["FW-02"]
        self.assertEqual(result["reason"], "source_too_large")

    def test_contradictory_manual_pass_is_downgraded(self):
        record = self.record()
        record["tests"][0]["actual_result"] = "success"
        result = self.load([record])["checks"]["FW-02"]
        self.assertEqual(result["status"], "NEEDS_REVIEW")
        self.assertEqual(result["reason"], "manual_pass_claim_inconsistent")

    def test_impossible_packet_counts_and_bad_references_are_rejected(self):
        record = self.record("FW-06")
        record["tests"][1]["packets_received"] = 5
        self.assertEqual(self.load([record])["status"], "ERROR")
        record = self.record()
        record["tests"][0]["source_indices"] = [99]
        self.assertEqual(self.load([record])["status"], "ERROR")

    def test_conflicting_auto_fail_and_manual_pass_are_both_preserved(self):
        bundle = self.load([self.record()])
        rows = self.automatic_rows()
        rows[1]["status"] = "FAIL"
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[1]["comparison"], "STATUS_CONFLICT_REQUIRES_REVIEW")
        self.assertEqual(rows[1]["status"], "FAIL")
        self.assertEqual(rows[1]["manual_verification"]["status"], "PASS")
        self.assertTrue(manual.manual_failure(rows, bundle))

    def test_auto_pass_and_manual_fail_are_flagged_without_overwrite(self):
        bundle = self.load([self.record(reported="FAIL")])
        rows = self.automatic_rows()
        rows[1]["status"] = "PASS"
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[1]["status"], "PASS")
        self.assertEqual(rows[1]["comparison"], "STATUS_CONFLICT_REQUIRES_REVIEW")

    def test_fw04_inspect_does_not_override_api403(self):
        bundle = self.load([self.record("FW-04")])
        now = datetime.now(timezone.utc)
        e = fw.Evidence("a" * 32, now, now)
        e.errors["FW-04"] = "api_forbidden"
        e.api_results["rules"] = {"http_status": 403, "status": "ERROR"}
        rows = audit.rows(e)
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[3]["status"], "ERROR")
        self.assertEqual(rows[3]["api_results"]["rules"]["http_status"], 403)
        self.assertEqual(rows[3]["manual_verification"]["scope"], "rules_inspect_screen_only")

    def test_fw01_pass_and_fw05_collection_are_preserved(self):
        bundle = self.load([self.record("FW-05")])
        now = datetime.now(timezone.utc)
        e = fw.Evidence("a" * 32, now, now, interfaces={"rows": [
            {"identifier": name, "device": device, "enabled": True, "status": "up", "ipv4": [{"ipaddr": address}]}
            for name, (device, address) in fw.EXPECTED.items()]})
        e.api_log_state = "current_log_correlation_unverified"
        e.api_results["logs"] = {"http_status": 200, "status": "COLLECTED"}
        rows = audit.rows(e)
        manual.attach_manual_results(rows, bundle)
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(rows[4]["status"], "NEEDS_REVIEW")
        self.assertEqual(rows[4]["api_results"]["logs"]["status"], "COLLECTED")

    def test_no_raw_artifact_contents_paths_or_credentials_exported(self):
        bundle = self.load([self.record()])
        rows = self.automatic_rows()
        manual.attach_manual_results(rows, bundle)
        exported = json.dumps(rows)
        self.assertNotIn("SYNTHETIC_CONTENT_DO_NOT_EXPORT", exported)
        self.assertNotIn("artifact.txt", exported)
        self.assertNotIn(str(self.base), exported)

    def test_cli_attachment_does_not_access_network_in_prepare_mode(self):
        self.load([self.record()])
        with patch.object(fw, "ReadOnlyClient") as client, patch.object(fw, "ping_lan") as ping:
            code, report = self.invoke("--manual-evidence", str(self.path))
        client.assert_not_called()
        ping.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual(report["results"][1]["status"], "NOT_TESTED")
        self.assertEqual(report["results"][1]["manual_verification"]["status"], "PASS")

    def test_bad_manual_file_prevents_execute_and_has_no_path_echo(self):
        with patch.object(fw, "ReadOnlyClient") as client:
            code, report = self.invoke("--execute", "--manual-evidence", str(self.base / "PRIVATE_SECRET.json"))
        client.assert_not_called()
        self.assertEqual(code, 1)
        self.assertTrue(report["execution_skipped"])
        self.assertNotIn("PRIVATE_SECRET", json.dumps(report))

    def test_unfilled_repository_template_has_no_claimed_evidence(self):
        template = Path(__file__).resolve().parents[1] / "examples/day4-manual-evidence.template.json"
        bundle = manual.load_manual_evidence(template)
        self.assertEqual(bundle["status"], "LOADED")
        self.assertTrue(all(value["validation_status"] == "DRAFT" and not value["attached"]
                            for value in bundle["checks"].values()))
        code, report = self.invoke("--manual-evidence", str(template))
        self.assertEqual(code, 0)
        self.assertTrue(all(row["status"] == "NOT_TESTED" for row in report["results"]))


if __name__ == "__main__":
    unittest.main()
