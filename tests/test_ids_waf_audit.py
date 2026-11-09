from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from config_audit.collectors import modsecurity as waf
from config_audit.collectors import suricata as ids
from scripts import run_ids_waf_audit as audit

RUN = "a" * 32
WAF_ID, BACKEND_ID, NETWORK_ID, IDS_ID = (char * 64 for char in "bcde")
IDS_CONFIG = (
    "outputs.1.eve-log.enabled = yes\noutputs.1.eve-log.filename = eve.json\n"
    "outputs.1.eve-log.filetype = regular\noutputs.1.eve-log.types.0 = alert\n"
    "vars.address-groups.HOME_NET = [198.51.100.0/24]\n"
)
RULE_LOAD = "1 rule files processed. 1 rules successfully loaded, 0 rules failed, 0 rules skipped"
CRS_LOAD = "ModSecurity-nginx (rules loaded inline/local/remote: 0/854/0)"
CRS_SETUP = "setvar:'tx.blocking_paranoia_level=1',\nsetvar:'tx.inbound_anomaly_score_threshold=5'"
NGINX = f"modsecurity on;\nmodsecurity_rules_file {waf.SETUP};\nproxy_pass http://backend:8081;"
MODSEC = "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogFormat JSON\nSecRequestBodyAccess On"


def event(sid=ids.TEST_SID, packet=2):
    return json.dumps({"event_type": "alert", "pcap_cnt": packet, "alert": {"signature_id": sid},
                       "timestamp": "2023-11-14T22:13:22.000000+0000"})


def audit_log(run=RUN, rules=("911100", "949110"), code=403):
    return json.dumps({"transaction": {
        "request": {"uri": f"/day3-policy?run={run}", "method": "PUT",
                    "headers": {"Authorization": "never-export-this"}},
        "response": {"http_code": code},
        "messages": [{"details": {"ruleId": rule, "data": "never-export-this"}} for rule in rules],
    }})


def process(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def inspected(service, identifier, user, name=None, state="running", mode=audit.NETWORK):
    return process("|".join((
        identifier, "/" + (name or f"{audit.PROJECT}-{service}-1"), audit.PROJECT, service, state,
        audit.IMAGES[service], user, mode, "null", f"{audit.NETWORK}={NETWORK_ID}" if mode != "none" else "",
    )))


def waf_processes(log=None, policy=403):
    return [
        inspected("waf", WAF_ID, "nginx"), inspected("backend", BACKEND_ID, "65534:65534"),
        process(f"{audit.NETWORK}|true|{audit.PROJECT}|day3|{WAF_ID} {BACKEND_ID}"),
        process(NGINX, CRS_LOAD), process("\n".join(f"Include {path}" for path in waf.REQUIRED_INCLUDES)),
        process(MODSEC), process(), process(CRS_SETUP),
        process(json.dumps({"run": RUN, "control_status": 200, "policy_status": policy}), code=int(policy != 403)),
        process(audit_log() if log is None else log),
    ]


class Day3ParserTests(unittest.TestCase):
    def test_eve_sid_and_control_packet(self):
        self.assertIs(ids.parse_eve(event()), True)
        self.assertIs(ids.parse_eve(event(101)), False)
        self.assertIs(ids.parse_eve(event() + "\n" + event(101, 1)), False)
        self.assertIs(ids.parse_eve(event(packet=1)), False)
        self.assertEqual(ids.parse_eve(event(packet=None)), "uncorrelated_packet")

    def test_eve_missing_no_alert_and_invalid_are_distinct(self):
        self.assertIsNone(ids.parse_eve(""))
        self.assertIs(ids.parse_eve('{"event_type":"stats"}'), False)
        with self.assertRaises(ValueError):
            ids.parse_eve('{"event_type":"alert","alert":[]}')

    def test_home_net_and_eve_configuration(self):
        self.assertEqual(ids.parse_config(IDS_CONFIG), (True, True, True))
        self.assertEqual(ids.parse_config(IDS_CONFIG.replace("[198.51.100.0/24]", "any")), (True, True, False))
        self.assertEqual(ids.parse_config(IDS_CONFIG.replace("types.0 = alert", "types.0 = http")), (True, False, True))
        self.assertEqual(ids.parse_config(IDS_CONFIG.replace("enabled = yes", "enabled = no")), (False, False, True))
        self.assertEqual(ids.parse_config(""), (None, None, None))

    def test_rule_load_requires_actual_counts(self):
        self.assertIs(ids.parse_rule_load(RULE_LOAD), True)
        self.assertIs(ids.parse_rule_load(RULE_LOAD.replace("0 rules failed", "1 rules failed")), False)
        self.assertIsNone(ids.parse_rule_load("Configuration provided was successfully loaded"))

    def test_modsecurity_directives_and_override(self):
        self.assertEqual(waf.parse_directives(MODSEC, ""), (True, True, True, True))
        self.assertEqual(waf.parse_directives(MODSEC, "# ignore\nSecRuleEngine DetectionOnly"), (False, True, True, True))
        self.assertEqual(waf.parse_directives("", ""), (None,) * 4)

    def test_crs_requires_loaded_rules_and_rendered_threshold(self):
        self.assertIs(waf.parse_crs_setup(CRS_SETUP, CRS_LOAD), True)
        self.assertIs(waf.parse_crs_setup(CRS_SETUP.replace("=5", "=10"), CRS_LOAD), False)
        self.assertEqual(waf.parse_crs_setup(CRS_SETUP, ""), "crs_load_unverified")
        self.assertEqual(waf.parse_crs_setup("", CRS_LOAD), "crs_threshold_unverified")

    def test_audit_requires_same_run_status_and_both_rule_ids_in_one_event(self):
        self.assertIs(waf.correlate_audit(audit_log(), RUN), True)
        for output in (
            "", audit_log("f" * 32), audit_log(code=200),
            audit_log(rules=("911100",)) + "\n" + audit_log(rules=("949110",)),
        ):
            with self.subTest(output=bool(output)):
                self.assertEqual(waf.correlate_audit(output, RUN), "audit_event_unverified")


class Day3ExecutionTests(unittest.TestCase):
    @staticmethod
    def next_process(queue, *args, **kwargs):
        event = next(queue)
        if isinstance(event, Exception):
            raise event
        return event(*args, **kwargs) if callable(event) else event

    def run_audit(self, events):
        queue = iter(events)
        with patch.object(audit.subprocess, "run", side_effect=lambda *a, **kw: self.next_process(queue, *a, **kw)) as run, redirect_stdout(io.StringIO()) as out:
            with patch.object(audit, "artifact", side_effect=self.fixture_path):
                status = audit.main(["--execute"])
        return status, json.loads(out.getvalue())["results"], run

    def fixture_path(self, name):
        # Temporary test objects are unnecessary. Intercept only the approved PCAP digest read.
        path = audit.LAB / name
        if name == "artifacts/day3.pcap":
            return self.pcap
        return path

    def setUp(self):
        self.pcap = Mock(spec=Path)
        self.pcap.read_bytes.return_value = b"approved synthetic fixture"
        patcher = patch.object(audit, "PCAP_SHA256", hashlib.sha256(self.pcap.read_bytes()).hexdigest())
        patcher.start()
        self.addCleanup(patcher.stop)

    def ids_processes(self, output):
        def created_identity(args, **kwargs):
            name = args[-1]
            return inspected("suricata", IDS_ID, "suricata", name, "created", "none")
        return [process(IDS_ID), created_identity, process(output)]

    def test_requires_approval_and_disallows_target_arguments(self):
        for args in ([], ["--execute", "--target", "portscan-mysql"]):
            with patch.object(audit.subprocess, "run") as run, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                audit.main(args)
            run.assert_not_called()

    def test_fresh_ids_replay_and_waf_http_and_audit_end_to_end_mock(self):
        output = IDS_CONFIG + "@@config:0@@\n" + RULE_LOAD + "\n@@validate:0@@\nreplay\n@@replay:0@@\n" + event()
        status, rows, run = self.run_audit(self.ids_processes(output) + waf_processes())
        self.assertEqual(status, 0)
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(row["status"] == "PASS" for row in rows))
        self.assertTrue(all({"asset_id", "check_id", "status", "execution_id", "checked_at"} <= row.keys() for row in rows))
        self.assertNotIn("never-export-this", json.dumps(rows))
        self.assertNotIn("2023-", rows[5]["checked_at"])
        self.assertTrue(rows[5]["evidence_reference"].endswith(":/tmp/eve.json"))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("never", commands[0])
        self.assertIn("suricata", commands[0])
        self.assertIn("none", commands[0])
        self.assertEqual(commands[2][-4:], ["container", "start", "--attach", IDS_ID])
        self.assertFalse(any(call.kwargs.get("shell") for call in run.call_args_list))

    def test_failed_suricata_validation_has_no_replay_verdict(self):
        output = IDS_CONFIG + "@@config:0@@\nsyntax failure\n@@validate:1@@\n"
        _, rows, _ = self.run_audit(self.ids_processes(output) + waf_processes())
        self.assertEqual([row["status"] for row in rows[3:6]], ["NOT_TESTED", "FAIL", "NOT_TESTED"])

    def test_missing_audit_evidence_cannot_pass_and_http_mismatch_fails(self):
        output = IDS_CONFIG + "@@config:0@@\n" + RULE_LOAD + "\n@@validate:0@@\n@@replay:0@@\n" + event()
        for events, expected in ((waf_processes(log=""), "NEEDS_REVIEW"), (waf_processes(policy=200), "FAIL")):
            with self.subTest(expected=expected):
                status, rows, _ = self.run_audit(self.ids_processes(output) + events)
                self.assertEqual(status, 0)
                self.assertEqual(rows[-1]["status"], expected)

    def test_unapproved_container_is_not_executed(self):
        rejected = inspected("waf", WAF_ID, "nginx")
        rejected.stdout = rejected.stdout.replace("|infra-day3-lab|waf|", "|other|waf|")
        status, rows, run = self.run_audit([process(code=1), rejected])
        self.assertEqual(status, 1)
        self.assertEqual(rows[-1]["reason"], "target_rejected")
        self.assertFalse(any("exec" in call.args[0] or "start" in call.args[0] for call in run.call_args_list))

    def test_timeout_and_subprocess_failure_are_reported_without_raw_output(self):
        status, rows, _ = self.run_audit([
            subprocess.TimeoutExpired("docker", 20, stderr="never-export-this"),
            process(stderr="never-export-this", code=1),
        ])
        self.assertEqual(status, 1)
        self.assertEqual({row["status"] for row in rows}, {"ERROR"})
        self.assertEqual({row["reason"] for row in rows}, {"timeout", "target_unavailable"})
        self.assertNotIn("never-export-this", json.dumps(rows))

    def test_external_backend_in_rendered_config_blocks_http_probe(self):
        events = waf_processes()[:4]
        events[-1].stdout = NGINX.replace("http://backend:8081", "http://external.invalid")
        status, rows, run = self.run_audit([process(code=1)] + events)
        self.assertEqual(status, 1)
        self.assertEqual(rows[-1]["reason"], "backend_target_rejected")
        self.assertFalse(any("python" in call.args[0] for call in run.call_args_list))


RENDERED_SETUP = """Include /etc/modsecurity.d/modsecurity.conf
Include /etc/modsecurity.d/modsecurity-override.conf
Include /etc/modsecurity.d/owasp-crs/crs-setup.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-config.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-before.conf
Include /etc/modsecurity.d/owasp-crs/rules/*.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-after.conf
"""


class WafIncludeTests(unittest.TestCase):
    def test_accepts_rendered_seven_includes_and_inactive_plugins(self):
        self.assertTrue(waf.valid_setup_includes(RENDERED_SETUP))
        inactive = "\n".join("# " + line if "/plugins/" in line else line
                             for line in RENDERED_SETUP.splitlines())
        self.assertTrue(waf.valid_setup_includes(inactive))

    def test_rejects_missing_required_modsecurity_include(self):
        for path in (waf.MAIN, waf.OVERRIDE, waf.CRS_SETUP):
            with self.subTest(path=path):
                self.assertFalse(waf.valid_setup_includes(RENDERED_SETUP.replace(f"Include {path}\n", "")))

    def test_rejects_unexpected_or_malformed_include_even_if_required_paths_exist(self):
        for extra in ("Include /tmp/extra.conf", 'Include "/tmp/extra.conf"', "Include /tmp/x.conf extra"):
            with self.subTest(extra=extra):
                self.assertFalse(waf.valid_setup_includes(RENDERED_SETUP + extra + "\n"))

    def test_rejects_missing_crs_rules_glob(self):
        self.assertFalse(waf.valid_setup_includes(RENDERED_SETUP.replace(f"Include {waf.CRS_RULES}\n", "")))

    def test_rejects_out_of_order_or_duplicate_includes(self):
        lines = RENDERED_SETUP.splitlines()
        for changed in (
            lines[:3] + [lines[4], lines[3]] + lines[5:],
            lines[:4] + [lines[4], lines[4]] + lines[5:],
            lines + [lines[0]],
            lines[:5] + [lines[6], lines[5]],
        ):
            with self.subTest(changed=changed):
                self.assertFalse(waf.valid_setup_includes("\n".join(changed)))

    def test_full_include_chain_does_not_replace_waf_audit_evidence(self):
        for log, expected in (("", "NEEDS_REVIEW"), (audit_log(), "PASS")):
            with self.subTest(expected=expected):
                events = waf_processes(log=log)
                events[4] = process(RENDERED_SETUP)
                with patch.object(audit.subprocess, "run", side_effect=events) as run:
                    rows = audit.rows("WAF", audit.WAF_RULES, "waf", "modsecurity",
                                      audit.read_waf, RUN, audit.datetime.now(audit.timezone.utc))
                self.assertEqual(run.call_count, 10)
                self.assertEqual([row["status"] for row in rows], ["PASS"] * 5 + [expected])

    def test_nginx_load_failure_stops_before_include_or_probe_checks(self):
        events = waf_processes()[:4]
        events[3] = process(stderr="plugin configuration load failed", code=1)
        with patch.object(audit.subprocess, "run", side_effect=events) as run:
            with self.assertRaisesRegex(audit.CollectionError, "^nginx_validation_failed$"):
                audit.read_waf()
        self.assertEqual(run.call_count, 4)

    def test_nested_crs_include_prevents_waf_pass_and_probe(self):
        events = waf_processes()[:8]
        events[4] = process(RENDERED_SETUP)
        events[7] = process(CRS_SETUP + "\nInclude /tmp/unverified.conf")
        with patch.object(audit.subprocess, "run", side_effect=events) as run:
            rows = audit.rows("WAF", audit.WAF_RULES, "waf", "modsecurity",
                              audit.read_waf, RUN, audit.datetime.now(audit.timezone.utc))
        self.assertEqual(run.call_count, 8)
        self.assertEqual({row["status"] for row in rows}, {"NEEDS_REVIEW"})
