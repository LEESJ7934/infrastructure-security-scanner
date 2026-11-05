"""Read-only evidence indexing contracts, with temporary files and local inputs."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from config_audit.evidence_index import (
    EvidenceAccessError, EvidenceBinding, EvidencePolicy, STATES,
    _fingerprint, attach_evidence_index, build_evidence_index,
)
from config_audit.reporting import integrate, load_snapshot, normalize


ROOT = Path(__file__).resolve().parents[1]


def stored_row(check="FW-06", state="NOT_TESTED"):
    return {"asset_id": "firewall", "check_id": check, "rule_version": "1",
            "status": state, "execution_id": "historical", "checked_at": "2026-11-05T17:00:00+00:00"}


class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.evidence = self.root / "evidence/day4"
        self.evidence.mkdir(parents=True)
        self.file = self.evidence / "sample.txt"
        self.file.write_bytes(b"historical safe fixture\r\n")
        # Independent declaration from a fixture literal, not the target file.
        self.expected = hashlib.sha256(b"historical safe fixture\r\n").hexdigest()
        self.report = integrate([], generated_at="2026-11-01T00:00:00+00:00")

    def binding(self, reference="evidence/day4/sample.txt", **kwargs):
        return EvidenceBinding(reference, **{"asset_id": "asset", "check_id": "FW-06", "day": 4,
                                            "snapshot_id": "stored-manual", "channel": "manual", **kwargs})

    def index(self, *bindings):
        return build_evidence_index(self.report, project_root=self.root, extra_bindings=bindings)

    def entry(self, reference="evidence/day4/sample.txt", **kwargs):
        return self.index(self.binding(reference, **kwargs))["entries"][0]

    def test_file_matches_independent_expected_hash(self):
        entry = self.entry(expected_sha256=self.expected, expected_hash_source="fixture_declaration")
        self.assertEqual(entry["status"], "VERIFIED")
        self.assertTrue(entry["exists"])
        self.assertEqual(entry["actual_sha256"], self.expected)
        self.assertEqual(entry["hash_comparison"], "MATCH")
        self.assertEqual(entry["size_bytes"], 25)
        self.assertEqual(entry["local_path"], str(self.file))
        self.assertEqual(entry["original_reference"], "evidence/day4/sample.txt")

    def test_tampering_is_mismatch_and_does_not_replace_expectation(self):
        binding = self.binding(expected_sha256=self.expected)
        first = self.index(binding)["entries"][0]
        self.file.write_bytes(b"modified fixture")
        second = self.index(binding)["entries"][0]
        self.assertEqual(second["status"], "MISMATCH")
        self.assertEqual(second["expected_sha256"], self.expected)
        self.assertEqual(second["evidence_id"], first["evidence_id"])

    def test_no_expected_hash_is_not_verified(self):
        entry = self.entry()
        self.assertEqual(entry["status"], "NOT_VERIFIED")
        self.assertEqual(entry["actual_sha256"], self.expected)
        self.assertIsNone(entry["expected_sha256"])

    def test_missing_file_has_no_local_attachment(self):
        entry = self.entry("evidence/day4/absent.txt")
        self.assertEqual(entry["status"], "MISSING")
        self.assertIs(entry["exists"], False)
        self.assertIsNone(entry["actual_sha256"])
        self.assertFalse((self.evidence / "absent.txt").exists())

    def test_external_container_refs_are_not_opened(self):
        for reference in ("container:/tmp/eve.json", "infra-day3-lab/waf#rendered-modsecurity",
                          "https://example.invalid/proof", "day4:execution:FW-05:log-pf", "manual:FW-06:source-1"):
            with self.subTest(reference=reference), patch("config_audit.evidence_index._open_file", side_effect=AssertionError):
                entry = self.entry(reference)
                self.assertEqual(entry["status"], "EXTERNAL_REFERENCE")
                self.assertIsNone(entry["local_path"])
                self.assertIsNone(entry["exists"])

    def test_day3_tmp_absolute_is_external_not_local_substitution(self):
        entry = self.entry("/tmp/eve.json", day=3)
        self.assertEqual(entry["status"], "EXTERNAL_REFERENCE")

    def test_traversal_denied_before_open(self):
        for reference in ("../sample.txt", "evidence/day4/../day4/sample.txt", "evidence\\day4\\..\\sample.txt"):
            with self.subTest(reference=reference), patch("config_audit.evidence_index._open_file", side_effect=AssertionError):
                self.assertEqual(self.entry(reference)["status"], "INVALID_REFERENCE")

    def test_absolute_outside_project_denied_before_stat(self):
        outside = self.root.parent / "not-in-project.txt"
        with patch.object(EvidencePolicy, "inspect", side_effect=AssertionError):
            entry = self.entry(str(outside))
        self.assertEqual(entry["status"], "INVALID_REFERENCE")
        self.assertIsNone(entry["exists"])

    def test_absolute_inside_allowlist(self):
        self.assertEqual(self.entry(str(self.file))["status"], "NOT_VERIFIED")

    def test_other_drive_unc_device_and_drive_relative_denied(self):
        for reference in ("Z:\\outside\\proof.txt", "C:relative.txt", "\\\\server\\share\\proof.txt",
                          "\\\\?\\C:\\evidence\\proof.txt", "\\\\.\\NUL", "evidence/day4/NUL.txt"):
            with self.subTest(reference=reference):
                self.assertEqual(self.entry(reference)["status"], "INVALID_REFERENCE")

    def test_alternate_stream_and_ambiguous_names_denied(self):
        for reference in ("evidence/day4/sample.txt:secret", "evidence/day4/sample.txt.", "evidence/day4/sample.txt "):
            with self.subTest(reference=reference):
                self.assertEqual(self.entry(reference)["status"], "INVALID_REFERENCE")

    def test_not_every_project_file_is_allowed(self):
        for reference in ("config_audit/models.py", "logs/other.json", "evidence/day40/file.txt"):
            with self.subTest(reference=reference):
                self.assertEqual(self.entry(reference)["status"], "INVALID_REFERENCE")

    def test_sensitive_files_never_opened(self):
        for reference in ("evidence/day4/.env", "evidence/day4/.env.backup", "evidence/day4/.git/config",
                          "evidence/day4/client.key", "evidence/day4/client.pem", "evidence/day4/id_rsa",
                          "evidence/day4/API_SECRET.txt", "evidence/day4/cert.pfx", "evidence/day4/secret.txt",
                          "evidence/day4/access-token.json"):
            with self.subTest(reference=reference), patch("config_audit.evidence_index._open_file", side_effect=AssertionError):
                self.assertEqual(self.entry(reference)["status"], "INVALID_REFERENCE")

    def test_sensitive_reference_is_redacted(self):
        entry = self.entry("https://user:secret@example.invalid/file")
        self.assertEqual(entry["status"], "INVALID_REFERENCE")
        self.assertNotIn("user:secret", json.dumps(entry))
        self.assertEqual(entry["original_reference"], "[REDACTED]")

    def test_relative_base_from_manual_json(self):
        entry = self.entry("sample.txt", relative_to=str(self.evidence), expected_sha256=self.expected)
        self.assertEqual(entry["status"], "VERIFIED")
        self.assertEqual(entry["original_reference"], "sample.txt")

    def test_unsafe_relative_base_denied(self):
        for base in ("../evidence/day4", str(self.root.parent), "Z:relative", "evidence/day4/folder:stream"):
            with self.subTest(base=base):
                self.assertEqual(self.entry("sample.txt", relative_to=base)["status"], "INVALID_REFERENCE")

    def test_symlink_component_escape_blocked_without_following(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "outside.txt").write_text("must not read", encoding="utf-8")
        link = self.evidence / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            # Unprivileged Windows may prohibit symlink creation. Exercise the
            # same lstat boundary with a deterministic link fixture in that case.
            original = os.lstat
            def lstat(path, *args, **kwargs):
                if Path(path) == link:
                    return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
                return original(path, *args, **kwargs)
            with patch("config_audit.evidence_index.os.lstat", side_effect=lstat):
                entry = self.entry("evidence/day4/link/outside.txt")
        else:
            entry = self.entry("evidence/day4/link/outside.txt")
        self.assertEqual(entry["status"], "INVALID_REFERENCE")
        self.assertEqual(entry["error"], "symlink_or_reparse_point_denied")

    def test_windows_junction_reparse_flag_denied(self):
        original = os.lstat
        def lstat(path, *args, **kwargs):
            if Path(path) == self.file:
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        with patch("config_audit.evidence_index.os.lstat", side_effect=lstat):
            self.assertEqual(self.entry()["error"], "symlink_or_reparse_point_denied")

    def test_directory_is_not_an_evidence_file(self):
        self.assertEqual(self.entry("evidence/day4")["status"], "INVALID_REFERENCE")

    def test_hash_format_error_is_safe_and_not_read(self):
        with patch("config_audit.evidence_index._open_file", side_effect=AssertionError):
            entry = self.entry(expected_sha256="Authorization: Bearer DO_NOT_LEAK")
        self.assertEqual(entry["status"], "INVALID_REFERENCE")
        self.assertIsNone(entry["expected_sha256"])
        self.assertNotIn("DO_NOT_LEAK", json.dumps(entry))

    def test_uppercase_expected_hash(self):
        self.assertEqual(self.entry(expected_sha256=self.expected.upper())["status"], "VERIFIED")

    def test_multiple_checks_keep_their_relationships(self):
        index = self.index(self.binding(check_id="FW-02"), self.binding(check_id="FW-03"))
        self.assertEqual(len(index["entries"]), 2)
        self.assertEqual(index["unique_local_files"], 1)
        self.assertEqual({entry["check_id"] for entry in index["entries"]}, {"FW-02", "FW-03"})

    def test_channels_do_not_merge(self):
        index = self.index(self.binding(channel="automatic"), self.binding(channel="manual"),
                           self.binding(channel="pf"), self.binding(channel="log_analysis"))
        self.assertEqual(len(index["entries"]), 4)

    def test_duplicate_handling_and_stable_order(self):
        a, b = self.binding(check_id="FW-02"), self.binding(check_id="FW-06")
        first, second = self.index(b, a, a), self.index(a, b)
        self.assertEqual(first["duplicate_bindings_removed"], 1)
        self.assertEqual([e["evidence_id"] for e in first["entries"]], [e["evidence_id"] for e in second["entries"]])
        self.assertEqual(first["counts"], second["counts"])

    def test_conflicting_expected_hashes_not_deduplicated(self):
        index = self.index(self.binding(expected_sha256=self.expected), self.binding(expected_sha256="0" * 64))
        self.assertEqual(index["counts"]["VERIFIED"], 1)
        self.assertEqual(index["counts"]["MISMATCH"], 1)

    def test_read_failure_is_not_verified_and_does_not_echo_exception(self):
        with patch("config_audit.evidence_index._open_file", side_effect=OSError("PRIVATE_VALUE")):
            entry = self.entry(expected_sha256=self.expected)
        self.assertEqual(entry["status"], "NOT_VERIFIED")
        self.assertIsNone(entry["actual_sha256"])
        self.assertNotIn("PRIVATE_VALUE", json.dumps(entry))

    def test_file_change_during_read_is_not_verified(self):
        with patch("config_audit.evidence_index._hash_file", side_effect=EvidenceAccessError("file_changed_during_verification")):
            self.assertEqual(self.entry(expected_sha256=self.expected)["status"], "NOT_VERIFIED")

    def test_swapped_file_descriptor_rejected_before_content_read(self):
        other = self.evidence / "other.txt"
        other.write_bytes(b"do not read this unrelated file")
        descriptor = os.open(other, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        with patch("config_audit.evidence_index._open_file", return_value=descriptor), \
                patch("config_audit.evidence_index.os.read", side_effect=AssertionError("must validate handle first")):
            entry = self.entry(expected_sha256=self.expected)
        self.assertEqual(entry["status"], "NOT_VERIFIED")
        self.assertEqual(entry["error"], "file_changed_during_verification")
        self.assertIsNone(entry["actual_sha256"])
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_windows_ctime_api_difference_is_not_content_change(self):
        a = SimpleNamespace(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        b = SimpleNamespace(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_ctime_ns=6)
        with patch("config_audit.evidence_index.os.name", "nt"):
            self.assertEqual(_fingerprint(a), _fingerprint(b))

    def test_no_file_contents_in_index(self):
        self.assertNotIn("historical safe fixture", json.dumps(self.index(self.binding())))

    def test_index_failure_does_not_change_review_verdict(self):
        item = {**stored_row("FW-05", "NEEDS_REVIEW"), "evidence_reference": "absent.json"}
        snapshot = normalize({"results": [item]}, day=4, snapshot_id="saved", source="evidence/day4/input.json")
        report = integrate([snapshot])
        index = build_evidence_index(report, project_root=self.root, include_snapshot_sources=False)
        attached = attach_evidence_index(report, index)
        self.assertEqual(index["counts"]["MISSING"], 1)
        self.assertEqual(attached.snapshots[0].results[0].automatic["status"], "NEEDS_REVIEW")

    def test_file_size_limit_does_not_report_hash(self):
        with patch("config_audit.evidence_index.MAX_FILE_BYTES", 2):
            entry = self.entry(expected_sha256=self.expected)
        self.assertEqual(entry["status"], "NOT_VERIFIED")
        self.assertEqual(entry["error"], "file_size_limit")

    def test_total_io_limit(self):
        with patch("config_audit.evidence_index.MAX_TOTAL_BYTES", 1):
            self.assertEqual(self.entry()["error"], "total_read_limit")

    def test_index_contains_all_states_even_zero(self):
        index = self.index()
        self.assertEqual(set(index["counts"]), set(STATES))
        self.assertEqual(sum(index["counts"].values()), 0)

    def test_report_attachment_preserves_verdicts_and_times(self):
        item = stored_row()
        item.update(evidence_reference="evidence/day4/sample.txt", manual_verification={
            "status": "PASS", "scope": "icmp_lab_only", "attached": True,
            "sources": [{"reference": "sample.txt"}]})
        snapshot = normalize({"results": [item]}, day=4, snapshot_id="before", source="evidence/day4/input.json")
        # Use correct relative base for the separately saved automatic reference.
        snapshot.results[0].automatic["evidence_references"][0]["relative_to"] = None
        self.report = integrate([snapshot], generated_at="2026-11-01T00:00:00+00:00")
        original = deepcopy(self.report.to_dict())
        index = build_evidence_index(self.report, project_root=self.root, include_snapshot_sources=False)
        attached = attach_evidence_index(self.report, index)
        result = attached.snapshots[0].results[0]
        self.assertEqual(result.automatic["status"], "NOT_TESTED")
        self.assertEqual(result.manual["status"], "PASS")
        self.assertEqual(set(result.evidence_index_ids), {"automatic", "manual"})
        self.assertEqual(self.report.to_dict(), original)
        self.assertEqual(attached.generated_at, self.report.generated_at)
        self.assertNotEqual(index["verified_at"], attached.generated_at)
        self.assertIsNotNone(datetime.fromisoformat(index["verified_at"]).utcoffset())
        json.dumps(attached.to_dict())

    def test_snapshot_input_file_links_to_each_result(self):
        source = self.evidence / "input.json"
        source.write_text(json.dumps({"results": [stored_row("FW-02"), stored_row("FW-03")]}), encoding="utf-8")
        self.report = integrate([load_snapshot(source, day=4, snapshot_id="stored")])
        index = build_evidence_index(self.report, project_root=self.root)
        self.assertEqual(index["unique_local_files"], 1)
        self.assertEqual(index["counts"]["NOT_VERIFIED"], 2)
        self.assertEqual({e["channel"] for e in index["entries"]}, {"snapshot_input"})

    def test_pf_log_channels_keep_status_and_do_not_promote_calculated_hash_claims(self):
        item = stored_row("FW-05", "NEEDS_REVIEW")
        analysis = {"status": "NEEDS_REVIEW", "evidence_reference": "sample.txt",
                    "integrity": {"rules": {"sha256": self.expected, "verified": True}}}
        item.update(pf_snapshot=analysis, log_rule_evidence=deepcopy(analysis))
        report = integrate([normalize({"results": [item]}, day=4, snapshot_id="analysis",
                                      source="evidence/day4/input.json")])
        index = build_evidence_index(report, project_root=self.root, include_snapshot_sources=False)
        self.assertEqual(index["counts"]["VERIFIED"], 0)
        self.assertEqual(index["counts"]["NOT_VERIFIED"], 2)
        self.assertTrue(all(e["expected_sha256"] is None for e in index["entries"]))
        row = attach_evidence_index(report, index).snapshots[0].results[0]
        self.assertEqual(set(row.evidence_index_ids), {"pf", "log_analysis"})
        self.assertTrue(all(a["status"] == "NEEDS_REVIEW" for a in row.analyses.values()))

    def test_missing_snapshot_input_is_indexed_without_creating_result(self):
        source = self.root / "logs/day2-before.json"
        report = integrate([load_snapshot(source, day=2, snapshot_id="missing-before")])
        index = build_evidence_index(report, project_root=self.root)
        self.assertEqual(index["counts"]["MISSING"], 1)
        self.assertFalse(report.snapshots[0].results)
        self.assertEqual(index["entries"][0]["channel"], "snapshot_input")


class RealLocalEvidenceTests(unittest.TestCase):
    def test_day4_all_declared_source_hashes_and_claims_preserved(self):
        report = integrate([load_snapshot(ROOT / "evidence/day4/manual.json", day=4,
                                          snapshot_id="day4-manual", input_kind="manual")])
        index = build_evidence_index(report, project_root=ROOT, include_snapshot_sources=False)
        self.assertEqual(index["counts"]["VERIFIED"], 15)
        self.assertEqual(index["unique_local_files"], 11)
        self.assertFalse(any(e["error"] for e in index["entries"]))
        attached = attach_evidence_index(report, index)
        claims = {r.check_id: r for r in attached.snapshots[0].results}
        for check_id in ("FW-04", "FW-05"):
            self.assertEqual(claims[check_id].manual["status"], "NEEDS_REVIEW")
        self.assertEqual(claims["FW-06"].manual["status"], "PASS")
        self.assertTrue(all(r.automatic is None for r in claims.values()))
        self.assertEqual(len(claims["FW-06"].evidence_index_ids["manual"]), 6)

    @unittest.skipUnless((ROOT / "logs/day3-final.json").is_file(), "Ignored local Day3 saved results not available")
    def test_day3_opaque_references_have_no_automatic_local_mapping(self):
        report = integrate([load_snapshot(ROOT / "logs/day3-final.json", day=3, snapshot_id="day3")])
        index = build_evidence_index(report, project_root=ROOT, include_snapshot_sources=False)
        self.assertEqual(index["counts"]["EXTERNAL_REFERENCE"], 12)
        self.assertEqual(index["unique_local_files"], 0)
        self.assertTrue(all(e["local_path"] is None for e in index["entries"]))


if __name__ == "__main__":
    unittest.main()
