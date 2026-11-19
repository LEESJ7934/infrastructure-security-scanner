"""Transaction behavior tests with a stateful DB double; no MySQL server or endpoint I/O."""
import contextlib
import copy
import io
import json
import re
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from db.query_helpers import get_ports_with_vuln_candidates
from scanner.banner_grabber import BannerObservation
from scanner.scope import ScopePolicy, ScopeValidationError
from scanner.targets import ResolvedTarget
from scripts.run_verification import main
from verification.base_checker import check_result
from verification.run_verification import (VerificationConflictError, VerificationDatabaseError,
                                           resulting_status, run_checker, run_verifications)

ROOT = Path(__file__).resolve().parents[1]
SCOPE_FILE = ROOT / "config" / "scope.example.json"
POLICY = ScopePolicy.load(SCOPE_FILE)


def stored_row(vuln_id=1, status="CANDIDATE", **updates):
    return {"port_id": vuln_id, "host_ip": "127.0.0.1", "port": 8081, "protocol": "tcp",
            "service": "http", "product": "apache_http_server", "version": "2.4.50",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.50\r\n\r\n", "fingerprint": "{}",
            "port_state": "open", "scan_id": 4, "scan_uid": "scan-catalog-demo", "scope_id": 1,
            "input_target": "127.0.0.1", "resolution_type": "IP", "vuln_id": vuln_id,
            "cve_id": "CVE-2021-42013", "title": "Candidate", "source": "catalog:apache:cve-2021-42013",
            "status": status, **updates}


class MemoryDB:
    """A small DB-API test double that models row state, commit and rollback."""
    def __init__(self, rows=None):
        self.state = {"rows": rows or [stored_row()], "evidence": [], "history": []}
        self.connections = []
        self.fail_on = None

    def connect(self):
        connection = MemoryConnection(self)
        self.connections.append(connection)
        return connection


class MemoryConnection:
    def __init__(self, database):
        self.database = database
        self.state = copy.deepcopy(database.state)
        self.log = []
        self.commits = self.rollbacks = 0
        self.closed = self.locked = False

    def cursor(self, **kwargs):
        return MemoryCursor(self)

    def commit(self):
        self.database.state = copy.deepcopy(self.state)
        self.commits += 1

    def rollback(self):
        self.state = copy.deepcopy(self.database.state)
        self.rollbacks += 1

    def close(self):
        self.closed = True


class MemoryCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []
        self.lastrowid = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        text = " ".join(sql.split()).rstrip(";")
        conn, state = self.connection, self.connection.state
        conn.log.append((text, params))
        if conn.database.fail_on and conn.database.fail_on in text:
            raise RuntimeError("injected DB write failure")
        if text.startswith(("INSERT", "UPDATE")):
            assert conn.locked, "Parent must be locked before evidence/status/history writes"
        if text.startswith("SELECT p.id AS port_id"):
            statuses = set(re.findall(r"'([A-Z_]+)'", re.search(r"v.status IN \(([^)]+)\)", text)[1]))
            rows = [row for row in state["rows"] if row["status"] in statuses]
            parameter = iter(params)
            if "AND v.id = %s" in text:
                selected = next(parameter)
                rows = [row for row in rows if row["vuln_id"] == selected]
            if "AND p.last_scan_id = %s" in text:
                selected = next(parameter)
                rows = [row for row in rows if row["scan_id"] == selected]
            self.rows = copy.deepcopy(rows)
            conn.locked = conn.locked or text.endswith("FOR UPDATE")
        elif text.startswith("SELECT id, details FROM vuln_evidence"):
            self.rows = [copy.deepcopy(row) for row in state["evidence"]
                         if (row["vuln_id"], row["checker"], row["sha256"]) == tuple(params)]
        elif text.startswith("INSERT INTO vuln_evidence"):
            self.lastrowid = len(state["evidence"]) + 1
            state["evidence"].append(dict(zip(
                ("vuln_id", "checker", "evidence_type", "details", "evidence_path", "sha256"), params),
                id=self.lastrowid))
        elif text.startswith("UPDATE vuln_evidence SET details"):
            next(row for row in state["evidence"] if row["id"] == params[1])["details"] = params[0]
        elif text.startswith("SELECT status FROM vulns"):
            self.rows = [{"status": row["status"]} for row in state["rows"] if row["vuln_id"] == params[0]]
        elif text.startswith("UPDATE vulns SET"):
            next(row for row in state["rows"] if row["vuln_id"] == params[-1])["status"] = params[0]
        elif text.startswith("INSERT INTO remediation_history"):
            state["history"].append(tuple(params))
        else:
            raise AssertionError("Unexpected SQL in test double: " + text)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class VerificationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDB()
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch("db.query_helpers.get_connection", side_effect=self.db.connect))
        self.patches.enter_context(patch("verification.run_verification.get_connection", side_effect=self.db.connect))
        self.probe = self.patches.enter_context(patch(
            "verification.cve_verifiers.collect_banner",
            return_value=BannerObservation(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.50\r\n\r\n")))
        self.dns = self.patches.enter_context(patch("verification.run_verification.resolve_target_specs"))

    def run_one(self, **options):
        return run_verifications(policy=POLICY, vuln_id=1, **options)

    def test_positive_verification_links_current_observation_in_same_transaction(self):
        with patch('verification.run_verification.run_checker', return_value={
                'status': 'CONFIRMED', 'checker': 'PositiveFixture', 'reason': 'fixture positive proof',
                'evidence_type': 'MANUAL', 'details': {},
                'positive_evidence': {'kind': 'fixture_exact_condition', 'summary': 'synthetic positive fixture'}}), \
             patch('verification.run_verification.link_finding') as link:
            self.run_one()
            link.assert_called_once()
            self.assertEqual(link.call_args.kwargs['relation'], 'VERIFIED')
            self.assertEqual(link.call_args.kwargs['port_id'], 1)
            self.assertEqual(self.db.connections[-1].commits, 1)

    def test_candidate_query_includes_candidate_potential_retest_and_error(self):
        self.db.state["rows"] = [stored_row(i, status) for i, status in enumerate(
            ("CANDIDATE", "POTENTIAL", "RETEST_REQUIRED", "ERROR", "CONFIRMED", "CLOSED"), 1)]
        rows = get_ports_with_vuln_candidates(scan_id=4)
        self.assertEqual([vuln["status"] for _, vuln in rows],
                         ["CANDIDATE", "POTENTIAL", "RETEST_REQUIRED", "ERROR"])
        port, vuln = rows[0]
        for key in ("product", "version", "banner", "fingerprint", "scan_id", "scan_uid"):
            self.assertIn(key, port)
        self.assertEqual(vuln["id"], vuln["vuln_id"])
        self.assertEqual(vuln["cve"], vuln["cve_id"])
        self.assertTrue(self.db.connections[-1].closed)

    def test_explicit_id_and_scan_filters_select_only_the_requested_records(self):
        self.db.state["rows"] = [stored_row(), stored_row(2, scan_id=9)]
        self.assertEqual(get_ports_with_vuln_candidates(vuln_id=2)[0][1]["id"], 2)
        self.assertEqual(len(get_ports_with_vuln_candidates(scan_id=4)), 1)
        self.assertEqual(get_ports_with_vuln_candidates(scan_id=10), [])

    def test_retired_rule_is_skipped_without_network_or_writes(self):
        self.db.state["rows"][0]["source"] = "rule_dvwa_sqli"
        result = self.run_one()[0]
        self.assertEqual(result["action"], "SKIP")
        self.probe.assert_not_called()
        self.assertEqual(self.db.state["evidence"], [])
        self.assertEqual(self.db.state["history"], [])

    def test_service_does_not_override_cve_dispatch(self):
        self.db.state["rows"][0]["service"] = "ftp"
        result = self.run_one()[0]
        self.assertEqual(result["result"]["checker"], "Apache42013Verifier")
        self.assertEqual(self.probe.call_args.args[2], "http")

    def test_unsupported_cve_is_error_evidence_and_no_probe(self):
        self.db.state["rows"][0]["cve_id"] = "CVE-2099-99999"
        result = self.run_one()[0]
        self.assertEqual((result["status"], result["result"]["error_code"]), ("ERROR", "UNSUPPORTED_CVE"))
        self.probe.assert_not_called()
        self.assertEqual(len(self.db.state["evidence"]), 1)

    def test_entire_selection_is_scoped_before_first_probe(self):
        self.db.state["rows"].append(stored_row(2, host_ip="192.0.2.10", input_target="192.0.2.10"))
        with self.assertRaises(ScopeValidationError):
            run_verifications(policy=POLICY, scan_id=4)
        self.probe.assert_not_called()
        self.dns.assert_not_called()
        self.assertEqual(self.db.state["history"], [])

    def test_expired_scope_is_rejected_before_db_selection(self):
        snapshot = POLICY.to_snapshot()
        snapshot["valid_until"] = "2021-01-01T00:00:00+00:00"
        with self.assertRaises(ScopeValidationError):
            run_verifications(policy=ScopePolicy.from_dict(snapshot), vuln_id=1)
        self.assertEqual(self.db.connections, [])
        self.probe.assert_not_called()

    def test_scope_target_and_port_limits_are_enforced(self):
        self.db.state["rows"].append(stored_row(2, port=8082))
        snapshot = POLICY.to_snapshot()
        snapshot["max_ports_per_target"] = 1
        with self.assertRaises(ScopeValidationError):
            run_verifications(policy=ScopePolicy.from_dict(snapshot), scan_id=4)
        self.probe.assert_not_called()

    def test_dry_run_reads_targets_but_has_no_dns_probe_or_db_write(self):
        self.db.state["rows"][0].update(input_target="localhost", resolution_type="HOSTNAME")
        before = copy.deepcopy(self.db.state)
        result = self.run_one(dry_run=True)[0]
        self.assertEqual((result["action"], result["vuln_id"], result["port"]), ("DRY_RUN", 1, 8081))
        self.assertEqual(self.db.state, before)
        self.assertTrue(all(sql.startswith("SELECT") for connection in self.db.connections for sql, _ in connection.log))
        self.assertEqual(sum(connection.commits for connection in self.db.connections), 0)
        self.probe.assert_not_called()
        self.dns.assert_not_called()

    def test_hostname_is_revalidated_and_connection_remains_pinned(self):
        self.db.state["rows"][0].update(input_target="localhost", resolution_type="HOSTNAME")
        self.dns.return_value = [ResolvedTarget("127.0.0.1", "localhost", "HOSTNAME")]
        self.run_one()
        self.dns.assert_called_once()
        self.assertEqual(self.probe.call_args.args[0], "127.0.0.1")
        self.assertEqual(self.probe.call_args.kwargs["server_name"], "localhost")

    def test_changed_dns_is_blocked_before_endpoint_probe(self):
        self.db.state["rows"][0].update(input_target="localhost", resolution_type="HOSTNAME")
        self.dns.return_value = [ResolvedTarget("192.0.2.20", "localhost", "HOSTNAME")]
        with self.assertRaises(ScopeValidationError):
            self.run_one()
        self.probe.assert_not_called()
        self.assertEqual(self.db.state["evidence"], [])

    def test_dns_failure_is_error_evidence_without_endpoint_probe(self):
        self.db.state["rows"][0].update(input_target="localhost", resolution_type="HOSTNAME")
        self.dns.side_effect = ValueError("name resolution failed")
        result = self.run_one()[0]
        self.assertEqual((result["status"], result["result"]["error_code"]), ("ERROR", "DNS_RESOLUTION_ERROR"))
        self.probe.assert_not_called()
        self.assertEqual(len(self.db.state["evidence"]), 1)

    def test_candidate_becomes_potential_with_evidence_and_history(self):
        result = self.run_one()[0]
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertEqual(self.db.state["rows"][0]["status"], "POTENTIAL")
        self.assertEqual(len(self.db.state["evidence"]), 1)
        self.assertEqual(self.db.state["history"][0][1:3], ("CANDIDATE", "POTENTIAL"))
        document = json.loads(self.db.state["evidence"][0]["details"])
        content = document["content"]
        self.assertTrue(document["first_checked_at"])
        self.assertTrue(document["last_checked_at"])
        self.assertEqual(content["cve_id"], "CVE-2021-42013")
        self.assertEqual(content["target"]["scan_id"], 4)
        self.assertEqual(content["target"]["host_ip"], "127.0.0.1")
        self.assertTrue(content["reason"])
        self.assertTrue(content["details"]["safe_checks"])
        self.assertTrue(content["additional_checks"])
        self.assertEqual(self.db.connections[-1].commits, 1)
        self.assertTrue(all(connection.closed for connection in self.db.connections))

    def test_same_result_different_date_header_reuses_evidence_and_history(self):
        first = self.run_one()[0]
        original = json.loads(self.db.state["evidence"][0]["details"])
        self.probe.return_value = BannerObservation(
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.50\r\nDate: another time\r\n\r\n")
        second = self.run_one()[0]
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        self.assertTrue(second["evidence_reused"])
        self.assertEqual(len(self.db.state["evidence"]), 1)
        self.assertEqual(len(self.db.state["history"]), 1)
        document = json.loads(self.db.state["evidence"][0]["details"])
        self.assertEqual(document["observations"], 2)
        self.assertEqual(document["first_checked_at"], original["first_checked_at"])
        self.assertGreaterEqual(document["last_checked_at"], original["last_checked_at"])

    def test_network_error_is_saved_as_error_and_retry_can_recover(self):
        self.probe.return_value = BannerObservation(error="TimeoutError")
        error = self.run_one()[0]
        self.assertEqual(error["status"], "ERROR")
        self.assertEqual(self.db.state["evidence"][0]["evidence_type"], "ERROR_LOG")
        self.probe.return_value = BannerObservation(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.50\r\n\r\n")
        self.assertEqual(self.run_one()[0]["status"], "POTENTIAL")
        self.assertEqual(self.db.state["history"][-1][1:3], ("ERROR", "POTENTIAL"))
        self.assertEqual(len(self.db.state["evidence"]), 2)

    def test_clear_udp_inapplicability_is_saved_as_not_applicable(self):
        self.db.state["rows"][0]["protocol"] = "udp"
        self.assertEqual(self.run_one()[0]["status"], "NOT_APPLICABLE")
        self.assertEqual(self.db.state["history"][0][1:3], ("CANDIDATE", "NOT_APPLICABLE"))
        self.probe.assert_not_called()

    def test_inconclusive_retest_preserves_retest_required(self):
        self.db.state["rows"][0]["status"] = "RETEST_REQUIRED"
        self.assertEqual(self.run_one()[0]["status"], "RETEST_REQUIRED")
        self.assertEqual(self.db.state["history"], [])
        self.assertEqual(len(self.db.state["evidence"]), 1)

    def test_reviewed_states_are_never_rescanned_or_regressed(self):
        for status in ("CONFIRMED", "NOT_APPLICABLE", "FALSE_POSITIVE", "CLOSED"):
            self.db.state["rows"][0]["status"] = status
            self.assertEqual(self.run_one(), [])
            self.assertEqual(self.db.state["rows"][0]["status"], status)
        self.probe.assert_not_called()

    def test_review_state_change_during_probe_rolls_back_without_regression(self):
        observation = self.probe.return_value
        def concurrently_review(*args, **kwargs):
            self.db.state["rows"][0]["status"] = "CONFIRMED"
            return observation
        self.probe.side_effect = concurrently_review
        with self.assertRaises(VerificationConflictError):
            self.run_one()
        self.assertEqual(self.db.state["rows"][0]["status"], "CONFIRMED")
        self.assertEqual(self.db.state["evidence"], [])
        self.assertEqual(self.db.connections[-1].rollbacks, 1)

    def test_endpoint_change_during_probe_is_rejected(self):
        observation = self.probe.return_value
        def replace_target(*args, **kwargs):
            self.db.state["rows"][0]["host_ip"] = "192.0.2.100"
            return observation
        self.probe.side_effect = replace_target
        with self.assertRaises(VerificationConflictError):
            self.run_one()
        self.assertEqual(self.db.state["evidence"], [])

    def test_evidence_status_or_history_failure_rolls_back_all_writes(self):
        before = copy.deepcopy(self.db.state)
        for failure in ("INSERT INTO vuln_evidence", "UPDATE vulns SET", "INSERT INTO remediation_history"):
            with self.subTest(failure=failure):
                self.db.fail_on = failure
                with self.assertRaises(VerificationDatabaseError):
                    self.run_one()
                self.assertEqual(self.db.state, before)
                self.assertEqual(self.db.connections[-1].rollbacks, 1)
                self.assertEqual(self.db.connections[-1].commits, 0)
                self.assertTrue(self.db.connections[-1].closed)

    def test_cli_dry_run_and_error_exit_codes(self):
        args = ["--vuln-id", "1", "--scope-file", str(SCOPE_FILE)]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args + ["--dry-run"]), 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "DRY_RUN")
        self.probe.assert_not_called()
        self.probe.return_value = BannerObservation(error="ConnectionRefusedError")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 1)
        self.assertEqual(json.loads(output.getvalue())["results"][0]["status"], "ERROR")

    def test_cli_scope_and_db_errors_are_distinct(self):
        args = ["--vuln-id", "1", "--scope-file", str(SCOPE_FILE)]
        self.db.state["rows"][0]["host_ip"] = "192.0.2.100"
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(args), 1)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "SCOPE_DENIED")
        self.db.state["rows"][0]["host_ip"] = "127.0.0.1"
        self.db.fail_on = "INSERT INTO vuln_evidence"
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(args), 1)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "DB_SAVE_FAILED")

    def test_cli_requires_selection_scope_and_finite_timeout(self):
        for args in ([], ["--vuln-id", "1"], ["--scope-file", str(SCOPE_FILE)],
                     ["--vuln-id", "1", "--scope-file", str(SCOPE_FILE), "--timeout", "nan"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(args)
            self.assertEqual(raised.exception.code, 2)
        self.probe.assert_not_called()


class ResultContractTests(unittest.TestCase):
    def test_ambiguous_legacy_results_do_not_become_negative_verdicts(self):
        for result in ({"status": "INVALID"}, {"status": "SKIP"}, None):
            checker = MagicMock()
            checker.run_check.return_value = result
            self.assertEqual(run_checker(checker, {}, {})["status"], "ERROR")

    def test_unsubstantiated_confirmed_result_is_rejected(self):
        checker = MagicMock()
        checker.run_check.return_value = check_result("CONFIRMED", "HTTP 200", checker="BadChecker")
        self.assertEqual(run_checker(checker, {}, {})["status"], "ERROR")
        checker.run_check.return_value["positive_evidence"] = {"kind": "banner", "summary": "Apache/2.4.50"}
        self.assertEqual(run_checker(checker, {}, {})["status"], "ERROR")

    def test_status_model_is_preserved_for_confirmation_and_retest(self):
        self.assertEqual(resulting_status("CANDIDATE", "CONFIRMED"), "POTENTIAL")
        self.assertEqual(resulting_status("POTENTIAL", "CONFIRMED"), "CONFIRMED")
        self.assertEqual(resulting_status("RETEST_REQUIRED", "CONFIRMED"), "CONFIRMED")
        self.assertEqual(resulting_status("ERROR", "POTENTIAL"), "POTENTIAL")
        with self.assertRaises(VerificationConflictError):
            resulting_status("CONFIRMED", "POTENTIAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
