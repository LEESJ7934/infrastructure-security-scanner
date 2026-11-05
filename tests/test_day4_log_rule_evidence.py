"""Synthetic historical collector context and log/PF data; never real artifacts."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from config_audit.collectors import opnsense as fw
from config_audit.collectors import opnsense_log_rules as correlation
from config_audit.collectors import opnsense_pf as pf
from scripts import run_day4_audit as audit

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)
RID = "b" * 32


class LogRuleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.log, self.rules, self.detail, self.context = (self.base / name for name in ("logs.json", "rules.txt", "detail.txt", "context.json"))
        self.lines = [f'block in inet6 from 2001:db8::{i + 1} to any label "other-{i}"' for i in range(6)] + [
            f'block drop in log inet all label "{RID}"', f'block drop in log inet6 all label "{RID}"']
        self.write_rules()
        self.event = {"__timestamp__": "2026-11-05T17:53:39", "src": "10.77.50.10", "dst": "10.77.50.1",
                      "srcport": "41993", "dstport": "22", "protoname": "tcp", "interface": "hn0", "action": "block",
                      "rid": RID, "rulenr": "6", "label": correlation.LABEL}
        self.payload = {"captured_at_utc": "2026-11-05T08:53:42+00:00", "timestamp_timezone": "not_explicit_in_log_response",
                        "logs": [deepcopy(self.event)]}
        self.write_log()

    def write_rules(self):
        self.rules.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        self.detail.write_text("\n".join(f"@{index} {line}" for index, line in enumerate(self.lines)) + "\n", encoding="utf-8")

    def write_log(self):
        self.log.write_text(json.dumps(self.payload), encoding="utf-8")

    def context_value(self):
        return {
            "schema_version": 1,
            "test": {"source": "10.77.50.10", "destination": "10.77.50.1", "protocol": "tcp", "destination_port": 22,
                     "source_port": 41993, "interface": "hn0", "actual_result": "timeout",
                     "started_at": "2026-11-05T17:53:39+09:00", "finished_at": "2026-11-05T17:53:41+09:00"},
            "log_clock": {"offset": "+09:00", "basis": "trusted_collector_device_clock"},
            "capture_session": {"session_id": "a" * 32, "log_sha256": pf.digest(self.log.read_bytes()),
                "rules_sha256": pf.digest(self.rules.read_bytes()), "detail_sha256": pf.digest(self.detail.read_bytes()),
                "before_at": "2026-11-05T17:53:38+09:00", "after_at": "2026-11-05T17:53:45+09:00",
                "rules_captured_at": "2026-11-05T17:53:43+09:00", "generation_before": "c" * 64,
                "generation_at_snapshot": "c" * 64, "generation_after": "c" * 64,
                "basis": "trusted_collector_ruleset_generation"},
        }

    def analyze(self, context=True, **options):
        params = dict(rules_path=self.rules, detail=self.detail, log_sha256=pf.digest(self.log.read_bytes()),
                      rules_sha256=pf.digest(self.rules.read_bytes()), detail_sha256=pf.digest(self.detail.read_bytes()),
                      test_start="2026-11-05T17:53:39", test_end="2026-11-05T17:53:41", execution_id="a" * 32, checked_at=NOW)
        if context is not False:
            value = self.context_value() if context is True else context
            self.context.write_text(json.dumps(value), encoding="utf-8")
            params.update(context_path=self.context, context_sha256=pf.digest(self.context.read_bytes()))
        params.update(options)
        return correlation.analyze(self.log, **params)

    def test_normal_matching_requires_all_pinned_collection_context(self):
        report = self.analyze()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["rule_mapping"]["status"], "PASS")
        self.assertEqual(report["observed_events"][0]["pf_reference"], "pf-rule-0006")
        self.assertFalse(report["whole_firewall_log_policy_verified"])
        self.assertFalse(report["current_execution_traffic"])

    def test_existing_engine_is_used(self):
        with patch.object(correlation, "evaluate", wraps=correlation.evaluate) as engine:
            self.analyze()
        engine.assert_called_once()
        self.assertEqual(engine.call_args.args[1].check_id, "FW-05")

    def test_rid_and_position_match_alone_do_not_prove_historical_mapping(self):
        report = self.analyze(context=False)
        self.assertTrue(report["rule_mapping"]["identity_match"])
        self.assertEqual(report["rule_mapping"]["status"], "NEEDS_REVIEW")
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertIn("snapshot_test_continuity_unverified", report["missing_conditions"])

    def test_naive_timestamp_is_never_assumed_utc_from_capture_metadata(self):
        report = self.analyze(context=False)
        self.assertTrue(report["time_comparison"]["wall_clock_window_match"])
        self.assertFalse(report["time_comparison"]["timezone_verified"])
        self.assertFalse(report["time_comparison"]["event_timestamps_assumed_utc"])

    def test_wrong_action_is_not_pass(self):
        self.payload["logs"][0]["action"] = "pass"
        self.write_log()
        report = self.analyze()
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertIn("log_action_mismatch", report["missing_conditions"])

    def test_time_window_mismatch(self):
        report = self.analyze(test_start="2026-11-05T18:00:00", test_end="2026-11-05T18:00:02")
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertIn("test_window_mismatch", report["missing_conditions"])

    def test_rule_number_alone_and_wrong_rid_cannot_map(self):
        self.payload["logs"][0]["rid"] = "d" * 32
        self.write_log()
        report = self.analyze()
        self.assertFalse(report["rule_mapping"]["identity_match"])
        self.assertEqual(report["status"], "NEEDS_REVIEW")

    def test_correct_rid_wrong_position_cannot_map(self):
        self.payload["logs"][0]["rulenr"] = "5"
        self.write_log()
        self.assertFalse(self.analyze()["rule_mapping"]["identity_match"])

    def test_changed_ruleset_generation_keeps_identity_candidate_but_not_pass(self):
        context = self.context_value()
        context["capture_session"]["generation_after"] = "e" * 64
        report = self.analyze(context=context)
        self.assertTrue(report["rule_mapping"]["identity_match"])
        self.assertFalse(report["rule_mapping"]["historical_continuity_verified"])
        self.assertIn("ruleset_generation_mismatch", report["missing_conditions"])
        self.assertEqual(report["status"], "NEEDS_REVIEW")

    def test_negative_zero_offset_means_unknown_not_utc(self):
        self.payload["logs"][0]["__timestamp__"] = "2026-11-05T17:53:39-00:00"
        self.write_log()
        report = self.analyze(context=False)
        self.assertFalse(report["time_comparison"]["timezone_verified"])
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        context = self.context_value()
        context["log_clock"]["offset"] = "-00:00"
        self.assertEqual(self.analyze(context=context)["reason"], "fw05_context_timezone_missing")

    def test_no_context_hash_cannot_pass(self):
        report = self.analyze(context_sha256=None)
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertIn("test_context_not_independently_pinned", report["missing_conditions"])

    def test_context_is_bound_to_all_three_exact_file_hashes(self):
        context = self.context_value()
        context["capture_session"]["rules_sha256"] = "0" * 64
        report = self.analyze(context=context)
        self.assertIn("test_context_file_binding_mismatch", report["missing_conditions"])

    def test_wrong_clock_offset_or_wrong_source_port_is_not_ignored(self):
        context = self.context_value()
        context["log_clock"]["offset"] = "+00:00"
        self.assertIn("test_context_outcome_or_time_mismatch", self.analyze(context=context)["missing_conditions"])
        context = self.context_value()
        context["test"]["source_port"] = 12345
        self.assertIn("test_tuple_or_source_port_mismatch", self.analyze(context=context)["missing_conditions"])

    def test_each_tuple_component_is_checked_without_echoing_wrong_values(self):
        for field, value in (("src", "PRIVATE_SECRET"), ("dst", "10.77.40.10"), ("protoname", "udp"),
                             ("interface", "hn1"), ("dstport", "443")):
            self.payload["logs"] = [deepcopy(self.event) | {field: value}]
            self.write_log()
            report = self.analyze()
            self.assertIn("test_tuple_or_source_port_mismatch", report["missing_conditions"])
            self.assertNotIn("PRIVATE_SECRET", json.dumps(report))

    def test_log_and_pf_file_tampering_are_errors(self):
        report = self.analyze(log_sha256="0" * 64)
        self.assertEqual(report["status"], "ERROR")
        self.assertEqual(report["failure_stage"], "log_file")
        report = self.analyze(rules_sha256="0" * 64)
        self.assertEqual(report["status"], "ERROR")
        self.assertEqual(report["log_file_collection"]["status"], "COLLECTED")
        self.assertEqual(report["rule_mapping"]["status"], "ERROR")

    def test_missing_or_mismatched_detail_is_not_pass(self):
        report = self.analyze(detail=None)
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertIn("detailed_pf_snapshot_missing", report["missing_conditions"])
        self.detail.write_text(self.detail.read_text().replace(RID, "f" * 32), encoding="utf-8")
        self.assertEqual(self.analyze()["reason"], "fw05_pf_detail_mismatch")

    def test_duplicate_semantically_matching_rid_is_ambiguous(self):
        self.lines.append(self.lines[6])
        self.write_rules()
        self.assertFalse(self.analyze()["rule_mapping"]["identity_match"])

    def test_log_label_must_also_fit_pf_default_deny_shape(self):
        self.lines[6] = f'block in inet proto tcp from 10.77.50.10 to any label "{RID}"'
        self.write_rules()
        report = self.analyze()
        self.assertTrue(report["rule_mapping"]["identity_match"])
        self.assertIn("log_label_inconsistent_or_unverified", report["missing_conditions"])

    def test_empty_missing_fields_and_invalid_json(self):
        self.payload["logs"] = []
        self.write_log()
        self.assertEqual(self.analyze()["status"], "NEEDS_REVIEW")
        self.payload["logs"] = [{"action": "block"}]
        self.write_log()
        self.assertEqual(self.analyze()["status"], "ERROR")
        self.log.write_text('{"Authorization":"PRIVATE_SECRET"', encoding="utf-8")
        report = self.analyze()
        self.assertEqual(report["reason"], "fw05_json_invalid")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(report))

    def test_raw_rid_labels_unknown_fields_and_paths_are_not_exported(self):
        self.payload["logs"][0]["label"] = "PRIVATE_SECRET Authorization"
        self.payload["Authorization"] = "PRIVATE_KEY"
        self.write_log()
        serialized = json.dumps(self.analyze())
        for text in ("PRIVATE_SECRET", "Authorization", "PRIVATE_KEY", str(self.base), RID):
            self.assertNotIn(text, serialized)

    def cli(self, *extra):
        output = io.StringIO()
        args = ["--fw05-log-evidence", str(self.log), "--fw05-log-sha256", pf.digest(self.log.read_bytes()),
                "--pf-rules-evidence", str(self.rules), "--pf-rules-sha256", pf.digest(self.rules.read_bytes()),
                "--pf-rules-detail", str(self.detail), "--pf-rules-detail-sha256", pf.digest(self.detail.read_bytes()),
                "--fw05-test-start", "2026-11-05T17:53:39", "--fw05-test-end", "2026-11-05T17:53:41", *extra]
        with redirect_stdout(output):
            code = audit.main(args)
        return code, json.loads(output.getvalue())

    def test_cli_local_analysis_does_not_access_api_or_overwrite_auto_status(self):
        with patch.object(fw, "ReadOnlyClient") as client, patch.object(fw, "ping_lan") as ping:
            _, report = self.cli()
        client.assert_not_called()
        ping.assert_not_called()
        row = report["results"][4]
        self.assertEqual(row["status"], "NOT_TESTED")
        self.assertEqual(row["log_rule_evidence"]["automatic_collection"]["status"], "NOT_TESTED")
        self.assertEqual(row["log_rule_evidence"]["log_file_collection"]["status"], "COLLECTED")

    def test_api_log_collection_and_rule_id_403_are_independent_of_local_mapping(self):
        client = Mock()
        def get(name):
            if name in {"rule_ids", "rules"}:
                raise fw.CollectionError("api_authentication_or_acl_failed", http_status=403, stage="http", error_code="api_forbidden")
            return [] if name in {"logs", "export"} else {"rows": []}
        client.get.side_effect = get
        with patch.object(fw, "ReadOnlyClient", return_value=client):
            _, report = self.cli("--execute")
        row = report["results"][4]
        self.assertEqual(row["api_results"]["logs"]["status"], "COLLECTED")
        self.assertEqual(row["api_results"]["rule_ids"]["http_status"], 403)
        self.assertEqual(row["log_rule_evidence"]["api_rule_id_mapping"]["status"], "ERROR")
        self.assertTrue(row["log_rule_evidence"]["rule_mapping"]["identity_match"])

    def test_invalid_auxiliary_options_are_rejected(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            audit.main(["--fw05-log-evidence", str(self.log)])


if __name__ == "__main__":
    unittest.main()
