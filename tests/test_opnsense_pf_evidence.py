"""Synthetic PF text only: no real appliance, archive or subprocess is used."""

from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from config_audit.collectors import opnsense as fw
from config_audit.collectors import opnsense_pf as pf
from scripts import run_opnsense_lab_audit as audit

NORMAL = '''block drop in log inet all label "opaque-default"
pass in log quick on hn1 inet proto tcp from any to 10.77.40.1 port = http flags S/SA keep state label "opaque-http"
pass in log quick on hn1 inet proto tcp from any to 10.77.40.1 port = https flags S/SA keep state label "opaque-https"
pass in quick on hn1 inet from 10.77.40.0/24 to any flags S/SA keep state label "opaque-lan"
pass in log quick on hn0 inet proto icmp from 10.77.50.10 to 10.77.50.1 icmp-type echoreq keep state label "opaque-icmp"
'''
RUN = "a" * 32
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


class PFSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.path = self.base / "rules.txt"
        self.path.write_text(NORMAL, encoding="utf-8")

    def analyze(self, text=NORMAL, **kwargs):
        self.path.write_text(text, encoding="utf-8")
        options = {"sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}
        options.update(kwargs)
        return pf.analyze(self.path, execution_id=RUN, checked_at=NOW, **options)

    def detail(self, text=NORMAL):
        path = self.base / "detail.txt"
        path.write_text("\n".join(f"@{i} {line}\n  [ Evaluations: 999 Packets: 999 ]" for i, line in enumerate(text.splitlines())), encoding="utf-8")
        return path

    def archive(self, members):
        path = self.base / "rules.tar"
        with tarfile.open(path, "w") as archive:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def test_normal_literal_profile_can_pass_only_scoped_cases(self):
        report = self.analyze()
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["complete_effective_ruleset"])
        self.assertFalse(report["gui_rule_identity_verified"])
        self.assertTrue(all(item["observation"] == "PRESENT" for item in report["structural_checks"].values()))
        self.assertTrue(all(item["outcome"] == "MATCH" for item in report["packet_cases"].values()))

    def test_existing_engine_evaluates_the_snapshot(self):
        with patch.object(pf, "evaluate", wraps=pf.evaluate) as evaluate:
            self.analyze()
        evaluate.assert_called_once()
        self.assertEqual(evaluate.call_args.args[1].check_id, "FW-04")

    def test_partial_or_missing_required_rule_is_not_pass(self):
        lines = NORMAL.splitlines()
        for text in ("\n".join(lines[:3]), "\n".join(lines[1:]), "\n".join(lines[:-1])):
            self.assertEqual(self.analyze(text)["status"], "NEEDS_REVIEW")

    def test_no_hash_pin_is_needs_review_not_file_existence_pass(self):
        report = self.analyze(sha256=None)
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertEqual(report["reason"], "pf_integrity_not_pinned")

    def test_hash_mismatch_is_error(self):
        report = self.analyze(sha256="0" * 64)
        self.assertEqual(report["status"], "ERROR")
        self.assertEqual(report["reason"], "pf_hash_mismatch")

    def test_empty_and_malformed_input(self):
        for text, reason in (("", "pf_snapshot_empty"), ("pass in quick on hn1", "pf_syntax_invalid"),
                             ('pass in all label "unclosed', "pf_syntax_invalid")):
            report = self.analyze(text)
            self.assertEqual(report["status"], "ERROR")
            self.assertEqual(report["reason"], reason)

    def test_unsupported_feature_is_not_silently_ignored(self):
        report = self.analyze('pass in quick on hn0 route-to (hn1 10.77.40.1) all\n' + NORMAL)
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertEqual(report["coverage"]["unsupported_statements"], 1)

    def test_anchor_cannot_be_treated_as_collected_children(self):
        report = self.analyze('anchor "dynamic/*" all\n' + NORMAL)
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertEqual(report["coverage"]["anchor_statements"], 1)

    def test_unknown_table_quick_block_is_not_skipped(self):
        report = self.analyze(NORMAL.replace('pass in log quick on hn1 inet proto tcp from any to 10.77.40.1 port = http',
                                             'block in quick from <dynamic_set> to any\npass in log quick on hn1 inet proto tcp from any to 10.77.40.1 port = http'))
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertEqual(report["packet_cases"]["restored_lan_icmp"]["possible_actions"], ["block", "pass"])

    def test_dynamic_addresses_are_not_resolved_from_assumed_lab_config(self):
        report = self.analyze(NORMAL.replace("to 10.77.50.1 icmp-type", "to (hn0) icmp-type"))
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertEqual(report["packet_cases"]["wan_approved_icmp"]["outcome"], "UNRESOLVED")

    def test_interface_group_membership_is_unknown(self):
        report = self.analyze('block in quick on private_group all\n' + NORMAL)
        self.assertEqual(report["status"], "NEEDS_REVIEW")

    def test_earlier_quick_allow_shadows_later_block(self):
        text = 'pass in quick on hn0 inet all\n' + NORMAL
        report = self.analyze(text)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(report["priority_checks"])
        self.assertIn("possible_broad_wan_allow", report["findings"])

    def test_nonquick_last_match_and_quick_stop_are_distinct(self):
        case = pf.CASES["wan_ssh"]
        first = pf.parse_rule("pass in on hn0 inet all", 0)
        block = pf.parse_rule("block in on hn0 inet all", 1)
        self.assertEqual(pf.packet_result([first, block], case)["outcome"], "MATCH")
        first = pf.parse_rule("pass in quick on hn0 inet all", 0)
        self.assertEqual(pf.packet_result([first, block], case)["outcome"], "CONFLICT")

    def test_ports_direction_negated_interface_and_ipv6(self):
        case = pf.CASES["wan_https"]
        for text in ("block out quick on hn0 inet all", "block in quick on ! hn0 inet all",
                     "block in quick inet6 all", "block in quick proto tcp from any port = 0 to any"):
            self.assertIs(pf.matches(pf.parse_rule(text, 0), case), False)
        self.assertIs(pf.matches(pf.parse_rule("block in quick on ! hn1 inet all", 0), case), True)

    def test_detail_comparison_and_counter_suffix_normalization(self):
        text = NORMAL.replace("10.77.40.0/24", "(hn1:network)")
        detail = self.detail(text.replace("(hn1:network)", "(hn1:network:1)"))
        report = self.analyze(text, detail=detail, detail_sha256=pf.digest(detail.read_bytes()))
        self.assertEqual(report["coverage"]["verbose_comparison"], "MATCH")
        self.assertFalse(report["snapshot_is_current_execution_traffic"])

    def test_mismatched_or_noncontiguous_detail_is_error(self):
        detail = self.detail(NORMAL.replace('opaque-lan', 'other-label'))
        report = self.analyze(detail=detail)
        self.assertEqual(report["reason"], "pf_detail_rules_mismatch")
        detail = self.detail()
        detail.write_text(detail.read_text().replace("@2 ", "@9 "), encoding="utf-8")
        self.assertEqual(self.analyze(detail=detail)["reason"], "pf_detail_order_invalid")

    def test_archive_pin_verifies_both_exact_files_without_extraction(self):
        detail = self.detail()
        archive = self.archive([("rules.txt", self.path.read_bytes()), ("detail.txt", detail.read_bytes())])
        report = self.analyze(sha256=None, detail=detail, archive=archive, archive_sha256=pf.digest(archive.read_bytes()))
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["integrity"]["rules"]["verified"])
        self.assertTrue(report["integrity"]["detail"]["verified"])
        self.assertTrue(report["integrity"]["archive"]["members_match"])

    def test_archive_hash_or_member_mismatch_cannot_pass(self):
        archive = self.archive([("rules.txt", b"different")])
        self.assertEqual(self.analyze(archive=archive, archive_sha256="0" * 64)["reason"], "pf_hash_mismatch")
        self.assertEqual(self.analyze(archive=archive, archive_sha256=pf.digest(archive.read_bytes()))["reason"], "pf_archive_member_mismatch")

    def test_archive_path_traversal_is_rejected_without_extract(self):
        archive = self.archive([("../rules.txt", self.path.read_bytes())])
        self.assertEqual(self.analyze(archive=archive, archive_sha256=pf.digest(archive.read_bytes()))["reason"], "pf_archive_invalid")

    def test_raw_labels_source_paths_and_lines_are_not_reported(self):
        report = self.analyze(NORMAL.replace('opaque-default', 'PRIVATE_KEY Authorization SECRET'))
        serialized = json.dumps(report)
        for secret in ("PRIVATE_KEY", "Authorization", "SECRET", str(self.base)):
            self.assertNotIn(secret, serialized)

    def test_label_absence_alone_is_not_gui_disable_proof(self):
        report = self.analyze()
        self.assertEqual(report["lab_block_policy"]["observation"], "NO_EFFECTIVE_BLOCK_FOR_SAMPLE_IN_SUPPLIED_ROOT")
        self.assertFalse(report["lab_block_policy"]["gui_rule_disabled_confirmed"])

    def test_cli_offline_does_not_run_commands_or_connect_to_api(self):
        output = io.StringIO()
        with patch.object(fw, "ReadOnlyClient") as client, patch.object(fw, "ping_lan") as ping, redirect_stdout(output):
            code = audit.main(["--pf-rules-evidence", str(self.path), "--pf-rules-sha256", pf.digest(self.path.read_bytes())])
        client.assert_not_called()
        ping.assert_not_called()
        row = json.loads(output.getvalue())["results"][3]
        self.assertEqual(row["status"], "NOT_TESTED")
        self.assertEqual(row["pf_snapshot"]["status"], "PASS")
        self.assertEqual(code, 0)

    def test_api403_is_preserved_separately_from_snapshot_pass(self):
        client = Mock()
        client.get.side_effect = fw.CollectionError("api_authentication_or_acl_failed", http_status=403,
                                                   stage="http", error_code="api_forbidden")
        output = io.StringIO()
        with patch.object(fw, "ReadOnlyClient", return_value=client), redirect_stdout(output):
            code = audit.main(["--execute", "--pf-rules-evidence", str(self.path),
                               "--pf-rules-sha256", pf.digest(self.path.read_bytes())])
        row = json.loads(output.getvalue())["results"][3]
        self.assertEqual(code, 1)
        self.assertEqual(row["status"], "ERROR")
        self.assertEqual(row["api_results"]["rules"]["http_status"], 403)
        self.assertEqual(row["pf_snapshot"]["status"], "PASS")

    def test_invalid_pf_file_prevents_execute(self):
        output = io.StringIO()
        with patch.object(fw, "ReadOnlyClient") as client, redirect_stdout(output):
            code = audit.main(["--execute", "--pf-rules-evidence", str(self.path), "--pf-rules-sha256", "0" * 64])
        client.assert_not_called()
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(output.getvalue())["execution_skipped"])

    def test_auxiliary_options_require_corresponding_input(self):
        for args in (["--pf-rules-sha256", "0" * 64],
                     ["--pf-rules-evidence", str(self.path), "--pf-rules-detail-sha256", "0" * 64]):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                audit.main(args)


if __name__ == "__main__":
    unittest.main()
