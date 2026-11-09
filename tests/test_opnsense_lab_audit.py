"""All fixtures below are synthetic; no appliance, Docker or Hyper-V is used."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
import io
import json
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from config_audit.collectors import opnsense as fw
from config_audit.models import AuditAsset
from scripts import run_opnsense_lab_audit as audit

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
RUN = "a" * 32


def interfaces():
    return {"rows": [
        {"identifier": name, "device": device, "enabled": True, "status": "up",
         "ipv4": [{"ipaddr": address}]} for name, (device, address) in fw.EXPECTED.items()
    ], "total": 2, "rowCount": 2, "current": 1}


def evidence():
    return fw.Evidence(RUN, NOW, NOW + timedelta(seconds=10), interfaces=interfaces())


def probe(interface="lan", protocol="icmp", outcome="allowed", scenario="pass", port=None):
    source, destination = (("10.77.40.10", "10.77.50.10") if interface == "lan"
                           else ("10.77.50.10", "10.77.50.1"))
    return fw.Probe(f"{interface}-{protocol}-{port}", RUN, NOW + timedelta(seconds=1),
                    NOW + timedelta(seconds=3), interface, source, destination, protocol,
                    outcome, port, scenario, True, "rule-1")


def log(p, action=None):
    return fw.Log(p.probe_id, p.execution_id, NOW + timedelta(seconds=2), p.interface,
                  p.source, p.destination, p.protocol,
                  action or ("pass" if p.outcome == "allowed" else "block"), p.port, p.rule_id)


def add(e, p):
    e.probes.append(p)
    e.logs.append(log(p))
    return e


def rules():
    return [
        fw.Rule("wan-icmp", 10, "wan", "pass", True, True, "10.77.50.10/32", "10.77.50.1/32", "icmp"),
        fw.Rule("wan-default", 20, "wan", "block", True, True),
        fw.Rule("lab-disabled", 30, "lan", "block", False, True, "10.77.40.10/32", "10.77.50.10/32", "icmp"),
        fw.Rule("lan-default", 40, "lan", "pass", True, True),
    ]


def status(e, check):
    return next(row["status"] for row in audit.rows(e) if row["check_id"] == check)


class InterfaceTests(unittest.TestCase):
    def test_expected_lan_and_wan(self):
        self.assertEqual(status(evidence(), "FW-01"), "PASS")

    def test_both_ip_and_mask_are_compared(self):
        for address in ("10.77.40.2/24", "10.77.40.1/16"):
            e = evidence()
            e.interfaces["rows"][0]["ipv4"][0]["ipaddr"] = address
            self.assertEqual(status(e, "FW-01"), "FAIL")

    def test_interface_assignment_mismatch(self):
        e = evidence()
        e.interfaces["rows"][0]["device"] = "hn0"
        self.assertEqual(status(e, "FW-01"), "FAIL")

    def test_disabled_or_down(self):
        for field, value in (("enabled", False), ("status", "down")):
            e = evidence()
            e.interfaces["rows"][0][field] = value
            self.assertEqual(status(e, "FW-01"), "FAIL")

    def test_missing_fields_never_pass(self):
        for field in ("device", "enabled", "status", "ipv4", "identifier"):
            e = evidence()
            del e.interfaces["rows"][0][field]
            self.assertEqual(status(e, "FW-01"), "NEEDS_REVIEW")

    def test_duplicate_assignment_never_passes(self):
        e = evidence()
        e.interfaces["rows"].append(deepcopy(e.interfaces["rows"][0]))
        self.assertEqual(status(e, "FW-01"), "NEEDS_REVIEW")

    def test_unknown_boolean_and_empty_ip(self):
        e = evidence()
        e.interfaces["rows"][0]["enabled"] = "1"
        self.assertEqual(status(e, "FW-01"), "NEEDS_REVIEW")
        e = evidence()
        e.interfaces["rows"][0]["ipv4"] = []
        self.assertEqual(status(e, "FW-01"), "NEEDS_REVIEW")

    def test_invalid_response_is_error(self):
        e = evidence()
        e.interfaces = {"rows": [None]}
        self.assertEqual(status(e, "FW-01"), "ERROR")


class TrafficEvidenceTests(unittest.TestCase):
    def test_real_api_field_names_do_not_imply_current_execution(self):
        payload = [{"src": "10.77.40.10", "dst": "10.77.50.10", "protoname": "icmp",
                    "action": "pass", "interface": "hn1", "rid": "legacy-hash",
                    "__timestamp__": "Nov 5 09:00:00", "__digest__": "not-a-run-id"}]
        e = evidence()
        e.api_log_state = fw.log_snapshot_state(payload)
        self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")
        self.assertEqual(status(e, "FW-06"), "NOT_TESTED")

    def test_empty_and_changed_log_schema_never_pass(self):
        self.assertEqual(fw.log_snapshot_state([]), "firewall_log_snapshot_empty")
        self.assertEqual(fw.log_snapshot_state([{"source": "mock"}]), "log_schema_unverified")
        with self.assertRaises(fw.CollectionError):
            fw.log_snapshot_state({"rows": []})

    def test_no_actual_probes(self):
        for check in ("FW-02", "FW-03", "FW-05", "FW-06"):
            self.assertEqual(status(evidence(), check), "NOT_TESTED")

    def test_lan_management_does_not_prove_wan(self):
        p = replace(probe(protocol="tcp", port=443), destination="10.77.40.1")
        self.assertEqual(status(add(evidence(), p), "FW-02"), "NOT_TESTED")

    def test_wan_management_allowed_is_fail(self):
        e = add(evidence(), probe("wan", "tcp", port=443))
        self.assertEqual(status(e, "FW-02"), "FAIL")

    def test_wan_management_block_requires_current_log(self):
        e = add(evidence(), probe("wan", "tcp", "blocked", port=443))
        self.assertEqual(status(e, "FW-02"), "PASS")
        e.logs.clear()
        self.assertEqual(status(e, "FW-02"), "NEEDS_REVIEW")

    def test_timeout_without_control_is_not_pass(self):
        e = add(evidence(), replace(probe("wan", "tcp", "blocked", port=443), control_ok=False))
        self.assertEqual(status(e, "FW-02"), "NEEDS_REVIEW")

    def test_wan_exception_and_unauthorized_sample(self):
        e = add(evidence(), probe("wan"))
        self.assertEqual(status(e, "FW-03"), "NOT_TESTED")
        add(e, probe("wan", "tcp", "blocked", port=22))
        self.assertEqual(status(e, "FW-03"), "PASS")
        e.probes[-1] = replace(e.probes[-1], outcome="allowed")
        self.assertEqual(status(e, "FW-03"), "FAIL")

    def test_wan_denied_icmp_exception_fails(self):
        e = add(evidence(), probe("wan", outcome="blocked"))
        add(e, probe("wan", "tcp", "blocked", port=22))
        self.assertEqual(status(e, "FW-03"), "FAIL")

    def test_policy_pass_and_block_scenarios(self):
        for scenario, outcome in (("pass", "allowed"), ("block", "blocked")):
            e = add(evidence(), probe(outcome=outcome, scenario=scenario))
            self.assertEqual(status(e, "FW-06"), "PASS")

    def test_ping_and_scenario_mismatch(self):
        for scenario, outcome in (("pass", "blocked"), ("block", "allowed")):
            self.assertEqual(status(add(evidence(), probe(outcome=outcome, scenario=scenario)), "FW-06"), "FAIL")

    def test_ping_success_without_log_not_pass(self):
        e = evidence()
        e.probes.append(probe())
        self.assertEqual(status(e, "FW-06"), "NEEDS_REVIEW")

    def test_ping_error_is_not_firewall_block(self):
        self.assertEqual(status(add(evidence(), probe(outcome="inconclusive", scenario="block")), "FW-06"), "NEEDS_REVIEW")

    def test_log_action_mismatch(self):
        e = add(evidence(), probe())
        e.logs[0] = replace(e.logs[0], action="block")
        self.assertEqual(status(e, "FW-06"), "FAIL")
        self.assertEqual(status(e, "FW-05"), "FAIL")

    def test_old_execution_is_not_current(self):
        e = add(evidence(), replace(probe(), execution_id="old"))
        self.assertEqual(status(e, "FW-06"), "NOT_TESTED")

    def test_logs_require_all_correlation_fields(self):
        p = probe()
        changes = [dict(execution_id="old"), dict(probe_id="other"), dict(source="10.77.40.11"),
                   dict(destination="10.77.50.11"), dict(protocol="tcp"), dict(port=443),
                   dict(interface="wan"), dict(rule_id="other"), dict(timestamp=NOW - timedelta(seconds=1))]
        for change in changes:
            e = add(evidence(), p)
            e.logs[0] = replace(e.logs[0], **change)
            self.assertEqual(status(e, "FW-06"), "NEEDS_REVIEW", change)

    def test_probe_outside_run_window_is_ignored(self):
        for change in (dict(started_at=NOW - timedelta(seconds=1)),
                       dict(finished_at=NOW + timedelta(seconds=20))):
            e = add(evidence(), replace(probe(), **change))
            self.assertEqual(status(e, "FW-06"), "NOT_TESTED")

    def test_firewall_logging_needs_both_actions(self):
        e = add(evidence(), probe())
        self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")
        add(e, probe("wan", "tcp", "blocked", port=22))
        self.assertEqual(status(e, "FW-05"), "PASS")

    def test_rule_id_optional_if_unavailable(self):
        e = add(evidence(), replace(probe(), rule_id=None))
        self.assertEqual(status(e, "FW-06"), "PASS")


class RuleTests(unittest.TestCase):
    def test_disabled_lab_rule_is_not_vulnerability(self):
        e = evidence()
        e.rules, e.complete_rules = rules(), True
        self.assertEqual(status(e, "FW-04"), "PASS")

    def test_unknown_coverage_never_passes(self):
        e = evidence()
        e.rules = rules()
        self.assertEqual(status(e, "FW-04"), "NEEDS_REVIEW")

    def test_earlier_quick_allow_shadows_block(self):
        e = evidence()
        e.rules, e.complete_rules = rules(), True
        e.rules.insert(0, fw.Rule("bad-allow", 1, "wan", "pass", True, True))
        self.assertEqual(status(e, "FW-04"), "FAIL")

    def test_nonquick_allow_can_be_overridden(self):
        e = evidence()
        e.rules, e.complete_rules = rules(), True
        e.rules.insert(0, fw.Rule("nonquick", 1, "wan", "pass", True, False))
        self.assertEqual(status(e, "FW-04"), "PASS")

    def test_nonquick_last_match_wins(self):
        e = evidence()
        p = probe()
        a = fw.Rule("a", 1, "lan", "pass", True, False)
        b = fw.Rule("b", 2, "lan", "block", True, False)
        self.assertEqual(fw.effective_rule([b, a], p), b)
        self.assertEqual(fw.effective_rule([replace(a, quick=True), b], p).rule_id, "a")

    def test_block_scenario_uses_enabled_lab_block(self):
        e = add(evidence(), probe(outcome="blocked", scenario="block"))
        e.rules, e.complete_rules = rules(), True
        e.rules[2] = replace(e.rules[2], enabled=True)
        self.assertEqual(status(e, "FW-04"), "PASS")
        e.probes.clear()
        self.assertEqual(status(e, "FW-04"), "FAIL")

    def test_missing_default_and_ambiguous_order(self):
        e = evidence()
        e.rules, e.complete_rules = [rules()[0]], True
        self.assertEqual(status(e, "FW-04"), "NEEDS_REVIEW")
        e.rules = rules() + [replace(rules()[0], rule_id="duplicate")]
        self.assertEqual(status(e, "FW-04"), "ERROR")

    def test_aliases_not_silently_treated_as_any(self):
        e = evidence()
        e.rules, e.complete_rules = rules(), True
        e.rules[0] = replace(e.rules[0], source="UNRESOLVED_ALIAS")
        self.assertEqual(status(e, "FW-04"), "ERROR")

    def test_icmp_exception_must_be_host_scoped(self):
        e = evidence()
        e.rules, e.complete_rules = rules(), True
        e.rules[0] = replace(e.rules[0], source="any")
        self.assertEqual(status(e, "FW-04"), "FAIL")

    def test_port_scope_and_interface_are_distinct(self):
        p = probe("wan", "tcp", port=443)
        r = fw.Rule("r", 1, "wan", "block", True, True, port=22)
        self.assertIsNone(fw.effective_rule([r], p))
        self.assertIsNone(fw.effective_rule([replace(r, port=443, interface="lan")], p))


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.ca = tempfile.NamedTemporaryFile()
        self.addCleanup(self.ca.close)
        self.session_patch = patch.object(fw.requests, "Session")
        self.session = self.session_patch.start().return_value
        self.addCleanup(self.session_patch.stop)
        self.options = dict(account="audit-reader", key="SECRET_KEY", secret="SECRET_VALUE", ca_bundle=self.ca.name)

    def test_only_exact_approved_address(self):
        for target in ("http://10.77.40.1", "https://10.77.50.1", "https://example.org",
                       "https://10.77.40.1.evil", "https://10.77.40.1:444", "https://10.77.40.1@evil"):
            with self.assertRaisesRegex(fw.CollectionError, "target_rejected"):
                fw.ReadOnlyClient(**self.options, target=target)
        self.session.get.assert_not_called()

    def test_root_and_missing_credentials_rejected(self):
        for changes in (dict(account="root"), dict(account=" ROOT "), dict(account=None), dict(key=""), dict(secret=None)):
            with self.assertRaises(fw.CollectionError):
                fw.ReadOnlyClient(**(self.options | changes))

    def test_trusted_certificate_is_required(self):
        for value in (False, True, None, "missing-ca.pem"):
            with self.assertRaisesRegex(fw.CollectionError, "trusted_ca_required"):
                fw.ReadOnlyClient(**(self.options | dict(ca_bundle=value)))

    def test_verified_get_no_redirect_or_proxy(self):
        self.session.get.return_value = Mock(status_code=200, json=Mock(return_value={"rows": []}))
        client = fw.ReadOnlyClient(**self.options)
        client.get("rules")
        self.assertFalse(self.session.trust_env)
        args, kwargs = self.session.get.call_args
        self.assertEqual(args, (fw.TARGET + fw.ENDPOINTS["rules"],))
        self.assertEqual(kwargs["verify"], self.ca.name)
        self.assertIs(kwargs["allow_redirects"], False)
        client.close()
        self.session.close.assert_called_once()

    def test_write_endpoints_and_path_injection_rejected(self):
        client = fw.ReadOnlyClient(**self.options)
        for name in ("add_rule", "set_rule", "toggle_rule", "apply", "flush_states", "/api/firewall/filter/search_rule"):
            with self.assertRaisesRegex(fw.CollectionError, "endpoint_rejected"):
                client.get(name)
        for uuid in ("../apply", "", "abc?x=y"):
            with self.assertRaises(fw.CollectionError):
                client.get("rule", uuid)
        self.session.get.assert_not_called()

    def test_get_rule_uuid(self):
        self.session.get.return_value = Mock(status_code=200, json=Mock(return_value={"rule": {}}))
        fw.ReadOnlyClient(**self.options).get("rule", "12345678-1234-1234-1234-123456789abc")
        self.assertIn("/get_rule/", self.session.get.call_args.args[0])

    def test_authentication_and_acl_failures(self):
        for code in (401, 403):
            self.session.get.return_value = Mock(status_code=code, text="SECRET_KEY SECRET_VALUE")
            with self.assertRaisesRegex(fw.CollectionError, "^api_authentication_or_acl_failed$"):
                fw.ReadOnlyClient(**self.options).get("interfaces")

    def test_redirect_and_http_errors(self):
        for code in (302, 404, 500):
            self.session.get.return_value = Mock(status_code=code)
            with self.assertRaisesRegex(fw.CollectionError, "api_http_failed"):
                fw.ReadOnlyClient(**self.options).get("logs")

    def test_invalid_json_and_api_errors(self):
        for value in (None, "secret", {"status": "error"}, {"error": "secret"}):
            self.session.get.return_value = Mock(status_code=200, json=Mock(return_value=value))
            with self.assertRaises(fw.CollectionError):
                fw.ReadOnlyClient(**self.options).get("logs")
        self.session.get.return_value.json.side_effect = ValueError("SECRET_VALUE")
        with self.assertRaisesRegex(fw.CollectionError, "^api_json_invalid$"):
            fw.ReadOnlyClient(**self.options).get("logs")

    def test_tls_or_offline_failure_redacted(self):
        for exc in (requests.exceptions.SSLError("SECRET_KEY"), requests.ConnectionError("SECRET_VALUE")):
            self.session.get.side_effect = exc
            with self.assertRaisesRegex(fw.CollectionError, "^api_transport_or_tls_failed$"):
                fw.ReadOnlyClient(**self.options).get("interfaces")

    def test_independent_endpoint_failures(self):
        client = Mock()
        client.get.side_effect = [fw.CollectionError("api_authentication_or_acl_failed"), {}, {"rows": []}, [], {}]
        e = evidence()
        fw.collect_api(client, e)
        self.assertEqual(status(e, "FW-01"), "ERROR")
        self.assertEqual(status(e, "FW-04"), "NEEDS_REVIEW")
        self.assertEqual(status(e, "FW-02"), "NOT_TESTED")


class RunnerTests(unittest.TestCase):
    def invoke(self, argv):
        output = io.StringIO()
        with redirect_stdout(output):
            code = audit.main(argv)
        return code, json.loads(output.getvalue())

    def test_default_mode_makes_no_network_or_ping(self):
        with patch.object(fw, "ReadOnlyClient") as client, patch.object(fw, "ping_lan") as ping:
            code, result = self.invoke([])
        client.assert_not_called()
        ping.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual([r["status"] for r in result["results"]], ["NOT_TESTED"] * 6)

    def test_ping_requires_execute(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            audit.main(["--ping"])

    def test_missing_credentials_is_error(self):
        with patch.dict(audit.os.environ, {}, clear=True):
            code, result = self.invoke(["--execute"])
        self.assertEqual(code, 1)
        self.assertEqual([r["status"] for r in result["results"]], ["ERROR"] * 6)

    def test_execute_does_not_imply_ping(self):
        client = Mock()
        client.get.side_effect = [interfaces(), {}, {"rows": []}, [], {}]
        with patch.object(fw, "ReadOnlyClient", return_value=client), patch.object(fw, "ping_lan") as ping:
            _, result = self.invoke(["--execute"])
        ping.assert_not_called()
        self.assertEqual(result["results"][5]["status"], "NOT_TESTED")
        client.close.assert_called_once()

    def test_api_failures_are_exported_without_exception_secrets(self):
        client = Mock()
        client.get.side_effect = fw.CollectionError("api_transport_or_tls_failed")
        with patch.object(fw, "ReadOnlyClient", return_value=client):
            code, result = self.invoke(["--execute"])
        self.assertEqual(code, 1)
        self.assertEqual(result["results"][0]["status"], "ERROR")
        self.assertEqual(result["results"][3]["status"], "ERROR")
        self.assertEqual(result["results"][4]["status"], "ERROR")
        self.assertEqual(result["results"][1]["status"], "NOT_TESTED")

    def test_log_api_failure_and_unknown_rules_shape(self):
        client = Mock()
        client.get.side_effect = [interfaces(), {}, {"unexpected": []}, fw.CollectionError("api_http_failed"), {}]
        e = evidence()
        fw.collect_api(client, e)
        self.assertEqual(status(e, "FW-04"), "ERROR")
        self.assertEqual(status(e, "FW-05"), "ERROR")

    def test_execute_ping_without_verified_log_cannot_pass(self):
        client = Mock()
        client.get.side_effect = [interfaces(), {}, {"rows": []}, [], {}, []]
        def ping(run, scenario):
            now = datetime.now(timezone.utc)
            return replace(probe(), execution_id=run, started_at=now, finished_at=now, scenario=scenario)
        with patch.object(fw, "ReadOnlyClient", return_value=client), patch.object(fw, "ping_lan", side_effect=ping):
            _, result = self.invoke(["--execute", "--ping"])
        self.assertEqual(result["results"][5]["status"], "NEEDS_REVIEW")

    def test_credentials_and_raw_configuration_never_exported(self):
        e = evidence()
        e.interfaces["secret"] = "PRIVATE_BACKUP_AND_API_KEY"
        exported = json.dumps(audit.rows(e))
        self.assertNotIn("PRIVATE_BACKUP_AND_API_KEY", exported)
        self.assertNotIn("observed_value", exported)
        for row in audit.rows(e):
            self.assertTrue({"asset_id", "check_id", "status", "execution_id", "checked_at", "evidence_reference", "reason"} <= row.keys())

    def test_existing_engine_applies_all_six_checks(self):
        with patch.object(audit, "evaluate", wraps=audit.evaluate) as engine:
            result = audit.rows(evidence(), AuditAsset("other", "linux"))
        self.assertEqual(engine.call_count, 6)
        self.assertEqual([r["status"] for r in result], ["NOT_APPLICABLE"] * 6)

    def test_windows_ping_status_and_source_guard(self):
        for reply, expected in (("Success", "allowed"), ("TimedOut", "blocked"), ("DestinationHostUnreachable", "inconclusive")):
            result = subprocess.CompletedProcess([], 0, json.dumps({"status": reply}), "SECRET_VALUE")
            with patch.object(fw, "_is_windows", return_value=True), patch.object(fw.subprocess, "run", return_value=result) as run:
                p = fw.ping_lan(RUN, "pass")
            self.assertEqual(p.outcome, expected)
            self.assertFalse(p.control_ok)
            self.assertIn("Find-NetRoute", run.call_args.args[0][-1])
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_ping_source_failure_and_timeout(self):
        with patch.object(fw, "_is_windows", return_value=True), patch.object(fw.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "", "SECRET")):
            with self.assertRaisesRegex(fw.CollectionError, "^ping_source_or_execution_failed$"):
                fw.ping_lan(RUN, "block")
        with patch.object(fw, "_is_windows", return_value=True), patch.object(fw.subprocess, "run", side_effect=subprocess.TimeoutExpired("SECRET", 15)):
            with self.assertRaisesRegex(fw.CollectionError, "^ping_execution_failed$"):
                fw.ping_lan(RUN, "pass")

    def test_non_windows_ping_refused_before_process_execution(self):
        with patch.object(fw, "_is_windows", return_value=False), patch.object(fw.subprocess, "run") as run:
            with self.assertRaisesRegex(fw.CollectionError, "^windows_probe_required$"):
                fw.ping_lan(RUN, "pass")
        run.assert_not_called()

    def test_native_non_windows_guard(self):
        # On Ubuntu this exercises the real platform check, without any mock.
        if not fw._is_windows():
            with patch.object(fw.subprocess, "run") as run:
                with self.assertRaisesRegex(fw.CollectionError, "^windows_probe_required$"):
                    fw.ping_lan(RUN, "block")
            run.assert_not_called()
        else:
            self.assertTrue(fw._is_windows())


class ActualResponseCompatibilityTests(unittest.TestCase):
    """Only outer shapes/field names were supplied; all values here are synthetic."""

    def partial_rows(self):
        return {"rows": [
            {"identifier": name, "device": device, "flags": ["up"], "config": {},
             "status": "up", "description": name.upper(), "capabilities": [], "options": []}
            for name, (device, _) in fw.EXPECTED.items()
        ]}

    def collect(self, responses):
        client = Mock()
        client.get.side_effect = lambda name: self.response(responses[name])
        e = fw.Evidence(RUN, NOW, NOW + timedelta(seconds=10))
        fw.collect_api(client, e)
        return e, client

    @staticmethod
    def response(value):
        if isinstance(value, Exception):
            raise value
        return value

    def forbidden(self):
        return fw.CollectionError("api_authentication_or_acl_failed", http_status=403,
                                  stage="http", error_code="api_forbidden")

    def actual_access(self):
        return dict(interfaces=self.partial_rows(), export=deepcopy(self.partial_rows()["rows"]),
                    rules=self.forbidden(), logs=[], rule_ids=self.forbidden())

    def test_confirmed_outer_shapes_do_not_invent_missing_values(self):
        e, client = self.collect(self.actual_access())
        self.assertEqual(status(e, "FW-01"), "NEEDS_REVIEW")
        self.assertEqual(status(e, "FW-04"), "ERROR")
        self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")
        self.assertEqual(e.api_results["logs"]["status"], "COLLECTED")
        self.assertEqual(e.api_results["rule_ids"]["http_status"], 403)
        self.assertEqual(e.rule_id_mapping["status"], "ERROR")
        self.assertNotIn("config", [call.args[0] for call in client.get.call_args_list])

    def test_export_list_is_explicitly_supported(self):
        self.assertEqual(fw.interface_rows(interfaces()["rows"], exported=True), interfaces()["rows"])
        self.assertEqual(fw.interfaces_match(None, interfaces()["rows"]), True)

    def test_complete_export_can_fill_missing_overview_fields(self):
        data = self.actual_access()
        data["export"] = interfaces()["rows"]
        e, _ = self.collect(data)
        self.assertEqual(status(e, "FW-01"), "PASS")
        self.assertEqual(e.api_results["rules"]["error_code"], "api_forbidden")

    def test_export_failure_does_not_override_valid_overview(self):
        data = self.actual_access() | dict(interfaces=interfaces(), export=self.forbidden())
        e, _ = self.collect(data)
        self.assertEqual(status(e, "FW-01"), "PASS")
        self.assertEqual(e.api_results["export"]["status"], "ERROR")

    def test_overview_failure_can_use_complete_export(self):
        e, _ = self.collect(self.actual_access() | dict(interfaces=self.forbidden(), export=interfaces()["rows"]))
        self.assertEqual(status(e, "FW-01"), "PASS")
        self.assertEqual(e.api_results["interfaces"]["http_status"], 403)

    def test_bad_container_recorded_independently_from_fallback(self):
        for changes in (dict(interfaces=[], export=interfaces()["rows"]),
                        dict(interfaces=interfaces(), export={"rows": []})):
            e, _ = self.collect(self.actual_access() | changes)
            self.assertEqual(status(e, "FW-01"), "PASS")
            bad = "interfaces" if isinstance(changes["interfaces"], list) else "export"
            self.assertEqual(e.api_results[bad]["stage"], "response_schema")
            self.assertEqual(e.api_results[bad]["http_status"], 200)

    def test_both_interface_sources_unavailable(self):
        e, _ = self.collect(self.actual_access() | dict(interfaces=self.forbidden(), export=None))
        self.assertEqual(status(e, "FW-01"), "ERROR")
        self.assertEqual(e.errors["FW-01"], "interface_sources_unavailable")

    def test_empty_export_and_missing_assignment_need_review(self):
        for exported in ([], [{}], [{"device": "hn1", "config": {"identifier": "lan"}}]):
            self.assertIsInstance(fw.interfaces_match(None, exported), str)

    def test_invalid_export_elements_are_schema_errors(self):
        for exported in (None, {}, "secret", [None], ["secret"]):
            with self.assertRaises(fw.CollectionError):
                fw.interface_rows(exported, exported=True)

    def test_nested_config_and_flags_do_not_establish_enabled_or_ip(self):
        data = self.partial_rows()
        for row in data["rows"]:
            row["config"] = {"enable": "1", "ipaddr": fw.EXPECTED[row["identifier"]][1]}
            row["flags"] = 1
        self.assertIsInstance(fw.interfaces_match(data), str)

    def test_conflicting_complete_source_never_passes(self):
        exported = deepcopy(interfaces()["rows"])
        for change in (dict(device="hn9"), dict(enabled=False), dict(status="down"),
                       dict(ipv4=[{"ipaddr": "10.77.40.99/24"}])):
            modified = deepcopy(exported)
            modified[0].update(change)
            self.assertIs(fw.interfaces_match(interfaces(), modified), False)
        partial = deepcopy(exported)
        partial[0].pop("enabled")
        partial[0]["ipv4"] = [{"ipaddr": "10.77.40.99/24"}]
        self.assertIs(fw.interfaces_match(interfaces(), partial), False)

    def test_raw_ip_without_prefix_not_assumed_to_be_expected_mask(self):
        data = interfaces()
        data["rows"][0]["ipv4"] = [{"ipaddr": "10.77.40.1"}]
        self.assertIsInstance(fw.interfaces_match(data), str)

    def test_duplicate_export_identifiers_need_review(self):
        exported = interfaces()["rows"]
        exported.append(deepcopy(exported[0]))
        self.assertIsInstance(fw.interfaces_match(interfaces(), exported), str)

    def test_log_collection_and_mapping_have_separate_results(self):
        payload = [{"src": "10.77.40.10", "dst": "10.77.50.10", "protoname": "icmp", "interface": "hn1",
                    "action": "pass", "rid": "r1", "__timestamp__": "Nov 6 10:00:00"}]
        e, _ = self.collect(self.actual_access() | dict(logs=payload))
        self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")
        self.assertNotIn("FW-05", e.errors)
        self.assertEqual(e.api_log_state, "current_log_correlation_unverified")
        row = audit.rows(e)[4]
        self.assertEqual(row["api_results"]["logs"]["http_status"], 200)
        self.assertEqual(row["rule_id_mapping"]["status"], "ERROR")

    def test_mapping_success_still_requires_verification(self):
        for items in ([], {}, [{"uuid": "synthetic"}]):
            e, _ = self.collect(self.actual_access() | dict(rule_ids={"items": items}))
            self.assertEqual(e.api_results["rule_ids"]["status"], "COLLECTED")
            self.assertEqual(e.rule_id_mapping["status"], "NEEDS_REVIEW")
            self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")

    def test_only_logs_success_no_cross_api_error_overwrite(self):
        data = dict(interfaces=self.forbidden(), export=self.forbidden(), rules=self.forbidden(),
                    logs=[], rule_ids=self.forbidden())
        e, _ = self.collect(data)
        self.assertEqual(status(e, "FW-05"), "NEEDS_REVIEW")
        self.assertEqual(e.api_log_state, "firewall_log_snapshot_empty")
        self.assertEqual(e.api_results["logs"]["http_status"], 200)

    def test_unexpected_log_schema_is_separate_error(self):
        e, _ = self.collect(self.actual_access() | dict(logs={"rows": []}))
        self.assertEqual(status(e, "FW-05"), "ERROR")
        self.assertEqual(e.api_results["logs"]["error_code"], "log_response_invalid")
        self.assertEqual(e.api_results["logs"]["stage"], "response_schema")
        self.assertEqual(e.api_results["rule_ids"]["http_status"], 403)

    def test_rules_200_does_not_attest_whole_ruleset(self):
        e, _ = self.collect(self.actual_access() | dict(rules={"rows": [{"description": "Automation only"}]}))
        self.assertEqual(status(e, "FW-04"), "NEEDS_REVIEW")
        self.assertFalse(e.complete_rules)
        self.assertIn("complete_effective_ruleset_unverified", audit.rows(e)[3]["scope"])

    def test_structured_http_tls_transport_and_parse_diagnostics(self):
        with tempfile.NamedTemporaryFile() as ca, patch.object(fw.requests, "Session") as session:
            client = fw.ReadOnlyClient(account="reader", key="PRIVATE_KEY", secret="PRIVATE_SECRET", ca_bundle=ca.name)
            for http, code in ((401, "api_unauthorized"), (403, "api_forbidden"), (404, "api_not_found")):
                session.return_value.get.return_value = Mock(status_code=http, text="PRIVATE_KEY PRIVATE_SECRET Authorization")
                e = evidence()
                fw.collect_api_endpoint(client, e, "logs")
                self.assertEqual(e.api_results["logs"], dict(endpoint=fw.ENDPOINTS["logs"], http_status=http,
                                                           stage="http", status="ERROR", error_code=code))
            for exc, stage, code in ((requests.exceptions.SSLError("PRIVATE_SECRET"), "tls", "api_tls_failed"),
                                     (requests.Timeout("PRIVATE_KEY"), "transport", "api_timeout"),
                                     (requests.ConnectionError("Authorization"), "transport", "api_connection_failed")):
                session.return_value.get.side_effect = exc
                e = evidence()
                fw.collect_api_endpoint(client, e, "logs")
                self.assertEqual(e.api_results["logs"]["stage"], stage)
                self.assertEqual(e.api_results["logs"]["error_code"], code)
                self.assertIsNone(e.api_results["logs"]["http_status"])
                self.assertNotIn("PRIVATE", json.dumps(audit.rows(e)))
                self.assertNotIn("Authorization", json.dumps(audit.rows(e)))
            session.return_value.get.side_effect = None
            session.return_value.get.return_value = Mock(status_code=200, json=Mock(side_effect=ValueError("PRIVATE_SECRET")))
            e = evidence()
            fw.collect_api_endpoint(client, e, "logs")
            self.assertEqual(e.api_results["logs"]["stage"], "json_parse")
            self.assertEqual(e.api_results["logs"]["http_status"], 200)
            self.assertNotIn("PRIVATE_SECRET", json.dumps(e.api_results))

    def test_report_keeps_endpoint_failures_and_raw_secrets_out(self):
        client = Mock()
        data = self.actual_access()
        client.get.side_effect = lambda name: self.response(data[name])
        output = io.StringIO()
        with patch.object(fw, "ReadOnlyClient", return_value=client), redirect_stdout(output):
            code = audit.main(["--execute"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report["api_results"]["logs"]["status"], "COLLECTED")
        self.assertEqual(report["api_results"]["rules"]["http_status"], 403)
        self.assertEqual(report["results"][0]["status"], "NEEDS_REVIEW")
        self.assertEqual(report["results"][4]["status"], "NEEDS_REVIEW")
        self.assertNotIn("config", report["api_results"])


class BoundedLogRequestTests(unittest.TestCase):
    def setUp(self):
        self.ca = tempfile.NamedTemporaryFile()
        self.addCleanup(self.ca.close)
        session_patch = patch.object(fw.requests, "Session")
        self.session = session_patch.start().return_value
        self.addCleanup(session_patch.stop)
        self.client = fw.ReadOnlyClient(account="reader", key="PRIVATE_KEY", secret="PRIVATE_SECRET",
                                        ca_bundle=self.ca.name)
        self.addCleanup(self.client.close)

    def test_logs_get_has_limit_20_and_keeps_tls_validation(self):
        self.session.get.return_value = Mock(status_code=200, json=Mock(return_value=[]))
        self.assertEqual(self.client.get("logs"), [])
        self.session.get.assert_called_once_with(
            fw.TARGET + fw.ENDPOINTS["logs"], params={"limit": 20},
            auth=("PRIVATE_KEY", "PRIVATE_SECRET"), verify=self.ca.name,
            timeout=(3, 10), allow_redirects=False,
        )

    def test_other_api_parameters_are_unchanged(self):
        self.session.get.return_value = Mock(status_code=200, json=Mock(return_value={}))
        for name in fw.ENDPOINTS:
            if name == "logs":
                continue
            self.client.get(name)
            self.assertNotIn("params", self.session.get.call_args.kwargs)
            self.assertEqual(self.session.get.call_args.args[0], fw.TARGET + fw.ENDPOINTS[name])
        self.client.get("rule", "12345678-1234-1234-1234-123456789abc")
        self.assertNotIn("params", self.session.get.call_args.kwargs)

    def test_raw_incomplete_read_is_not_an_authentication_error(self):
        self.session.get.side_effect = IncompleteRead(b"RAW_PRIVATE_LOG", 20)
        e = evidence()
        self.assertFalse(fw.collect_api_endpoint(self.client, e, "logs"))
        self.assertEqual(e.api_results["logs"]["error_code"], "api_incomplete_response")
        self.assertEqual(e.api_results["logs"]["stage"], "response_read")
        self.assertIsNone(e.api_results["logs"]["http_status"])
        self.assertEqual(status(e, "FW-05"), "ERROR")
        self.assertNotIn("RAW_PRIVATE_LOG", json.dumps(audit.rows(e)))

    def test_requests_chunked_error_is_not_a_connection_error(self):
        self.session.get.side_effect = requests.exceptions.ChunkedEncodingError("RAW_PRIVATE_LOG")
        with self.assertRaises(fw.CollectionError) as caught:
            self.client.get("logs")
        self.assertEqual(str(caught.exception), "api_incomplete_response")
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertNotIn("RAW_PRIVATE_LOG", repr(caught.exception))

    def test_wrapped_incomplete_read_is_recognized_without_printing_partial_body(self):
        from urllib3.exceptions import ProtocolError
        self.session.get.side_effect = requests.ConnectionError(
            ProtocolError("PRIVATE_SECRET", IncompleteRead(b"RAW_PRIVATE_LOG", 40)))
        e = evidence()
        fw.collect_api_endpoint(self.client, e, "logs")
        self.assertEqual(e.api_results["logs"]["error_code"], "api_incomplete_response")
        self.assertNotIn("PRIVATE", json.dumps(audit.rows(e)))

    def test_http_200_read_failure_does_not_become_collection_success(self):
        self.session.get.return_value = Mock(status_code=200, json=Mock(side_effect=IncompleteRead(b"RAW_PRIVATE_LOG", 9)))
        e = evidence()
        fw.collect_api_endpoint(self.client, e, "logs")
        self.assertEqual(e.api_results["logs"]["http_status"], 200)
        self.assertEqual(e.api_results["logs"]["status"], "ERROR")
        self.assertEqual(e.api_results["logs"]["stage"], "response_read")
        self.assertIsNone(e.api_log_state)

    def test_real_json_parser_rejects_truncated_body_after_http_200(self):
        response = requests.Response()
        response.status_code = 200
        response._content = b'[{"sensitive": "RAW_PRIVATE_LOG'
        self.session.get.return_value = response
        e = evidence()
        fw.collect_api_endpoint(self.client, e, "logs")
        self.assertEqual(e.api_results["logs"]["http_status"], 200)
        self.assertEqual(e.api_results["logs"]["error_code"], "api_json_invalid")
        self.assertEqual(e.api_results["logs"]["stage"], "json_parse")
        self.assertEqual(status(e, "FW-05"), "ERROR")
        self.assertNotIn("RAW_PRIVATE_LOG", json.dumps(audit.rows(e)))

    def test_success_and_mapping_403_preserve_fw01_pass_without_fw05_pass(self):
        log_payload = [{"src": "10.77.40.10", "dst": "10.77.50.10", "protoname": "icmp", "interface": "hn1",
                        "action": "pass", "rid": "synthetic-id", "__timestamp__": "Nov 6 10:00:00",
                        "sensitive": "RAW_PRIVATE_LOG"}]
        def get(url, **kwargs):
            name = next(name for name, path in fw.ENDPOINTS.items() if fw.TARGET + path == url)
            if name in {"rules", "rule_ids"}:
                return Mock(status_code=403, text="PRIVATE_KEY PRIVATE_SECRET Authorization")
            if name == "logs":
                self.assertEqual(kwargs["params"], {"limit": 20})
                return Mock(status_code=200, json=Mock(return_value=log_payload))
            return Mock(status_code=200, json=Mock(return_value=interfaces() if name == "interfaces" else []))
        self.session.get.side_effect = get
        output = io.StringIO()
        with patch.object(fw, "ReadOnlyClient", return_value=self.client), redirect_stdout(output):
            audit.main(["--execute"])
        report = json.loads(output.getvalue())
        self.assertEqual(report["results"][0]["status"], "PASS")
        self.assertEqual(report["results"][4]["status"], "NEEDS_REVIEW")
        self.assertEqual(report["api_results"]["logs"]["status"], "COLLECTED")
        self.assertEqual(report["api_results"]["rule_ids"]["http_status"], 403)
        self.assertEqual(report["rule_id_mapping"]["status"], "ERROR")
        for secret in ("PRIVATE_KEY", "PRIVATE_SECRET", "Authorization", "RAW_PRIVATE_LOG"):
            self.assertNotIn(secret, output.getvalue())

    def test_mapping_403_cannot_overwrite_incomplete_log_error(self):
        self.session.get.side_effect = [IncompleteRead(b"RAW_PRIVATE_LOG", 9), Mock(status_code=403)]
        e = evidence()
        fw.collect_api_endpoint(self.client, e, "logs")
        fw.collect_api_endpoint(self.client, e, "rule_ids")
        self.assertEqual(e.errors["FW-05"], "api_incomplete_response")
        self.assertEqual(e.rule_id_mapping["reason"], "api_forbidden")


if __name__ == "__main__":
    unittest.main()
