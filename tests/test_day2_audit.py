from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import subprocess
import unittest
from unittest.mock import patch

from config_audit.collectors.linux_ssh import parse_ssh_settings
from config_audit.collectors.mysql_config import MYSQL_COMMAND, parse_mysql_settings
from scripts.run_day2_audit import main


CONTAINER_ID = "a" * 64
SSH_OUTPUT = (
    "maxauthtries 6\npermitrootlogin without-password\npasswordauthentication yes\n"
    "x11forwarding yes\npermitemptypasswords no\n"
)
MYSQL_OUTPUT = "8.0.44\t0\t0\t1\t0\n"


def process(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def collection(service, outcome):
    return [
        process(CONTAINER_ID + "\n"),
        process(f"infra-day2-lab|{service}|true|/infra-day2-lab-{service}-1\n"),
        outcome,
    ]


class Day2ParserTests(unittest.TestCase):
    def test_ssh_parser_reads_five_selected_values(self):
        observations = parse_ssh_settings(SSH_OUTPUT + "unrelatedvalue private\n")
        self.assertEqual({key: item.observed_value for key, item in observations.items()}, {
            "maxauthtries": 6, "permitrootlogin": "without-password", "passwordauthentication": "yes",
            "x11forwarding": "yes", "permitemptypasswords": "no",
        })

    def test_ssh_parser_separates_missing_and_malformed_values(self):
        observations = parse_ssh_settings("maxauthtries broken\npermitrootlogin\n"
                                          "x11forwarding yes\nx11forwarding no\n")
        for key in ("maxauthtries", "permitrootlogin", "x11forwarding"):
            self.assertTrue(observations[key].collection_error)
        self.assertIsNone(observations["permitemptypasswords"].observed_value)
        self.assertFalse(observations["permitemptypasswords"].collection_error)

    def test_mysql_parser_preserves_version_and_zero(self):
        observations = parse_mysql_settings(MYSQL_OUTPUT)
        self.assertEqual({key: item.observed_value for key, item in observations.items()}, {
            "version": "8.0.44", "local_infile": 0, "require_secure_transport": 0,
            "skip_name_resolve": 1, "general_log": 0,
        })

    def test_mysql_parser_distinguishes_missing_field_from_bad_row(self):
        observations = parse_mysql_settings("8.0.44\t\t1\tbad\t0\n")
        self.assertIsNone(observations["local_infile"].observed_value)
        self.assertFalse(observations["local_infile"].collection_error)
        self.assertTrue(observations["skip_name_resolve"].collection_error)
        self.assertTrue(all(item.collection_error for item in parse_mysql_settings("wrong shape").values()))


class Day2ExecutionTests(unittest.TestCase):
    def run_approved(self, events):
        with patch("scripts.run_day2_audit.subprocess.run", side_effect=events) as run:
            with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
                code = main(["--execute"])
            self.assertEqual(errors.getvalue(), "")
        return code, json.loads(output.getvalue()), run

    def test_execution_requires_approval_and_accepts_no_target_override(self):
        for args in ([], ["--execute", "--target", "portscan-mysql"]):
            with self.subTest(args=args), patch("scripts.run_day2_audit.subprocess.run") as run:
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    main(args)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()

    def test_only_validated_local_services_are_executed_and_rules_evaluate(self):
        events = collection("ubuntu", process(SSH_OUTPUT)) + collection("mysql", process(MYSQL_OUTPUT))
        code, result, run = self.run_approved(events)

        self.assertEqual(code, 0)
        checks = {item["check_id"]: item["status"] for service in result.values() for item in service["checks"]}
        self.assertEqual(checks, {
            "LAB-SSH-001": "PASS", "LAB-SSH-002": "FAIL",
            "LAB-MYSQL-001": "PASS", "LAB-MYSQL-002": "FAIL",
        })
        commands = [call.args[0] for call in run.call_args_list]
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:3], ["docker", "--host", "npipe:////./pipe/dockerDesktopLinuxEngine"])
            self.assertFalse(call.kwargs.get("shell", False))
        self.assertIn("label=com.docker.compose.project=infra-day2-lab", commands[0])
        self.assertIn("label=com.docker.compose.service=ubuntu", commands[0])
        self.assertIn("label=com.docker.compose.service=mysql", commands[3])
        self.assertEqual(commands[2][3:], ["container", "exec", CONTAINER_ID, "/usr/sbin/sshd", "-T"])
        self.assertEqual(commands[5][3:], ["container", "exec", CONTAINER_ID, *MYSQL_COMMAND])
        self.assertEqual(MYSQL_COMMAND[-1].count("SELECT "), 1)
        self.assertIn("--protocol=SOCKET", MYSQL_COMMAND[-1])

    def test_mismatched_project_service_or_name_blocks_exec(self):
        identities = (
            "other|ubuntu|true|/infra-day2-lab-ubuntu-1",
            "infra-day2-lab|mysql|true|/infra-day2-lab-ubuntu-1",
            "infra-day2-lab|ubuntu|true|/portscan-mysql",
        )
        for identity in identities:
            with self.subTest(identity=identity):
                code, result, run = self.run_approved([
                    process(CONTAINER_ID), process(identity), process(),
                ])
                self.assertEqual(code, 1)
                self.assertEqual(result["ubuntu"]["settings"]["maxauthtries"]["error_code"], "target_rejected")
                self.assertFalse(any("exec" in call.args[0] for call in run.call_args_list))

    def test_multiple_target_matches_are_rejected(self):
        code, result, run = self.run_approved([process(CONTAINER_ID + "\n" + "b" * 64), process()])
        self.assertEqual(code, 1)
        self.assertEqual(result["ubuntu"]["settings"]["maxauthtries"]["error_code"], "target_rejected")
        self.assertEqual(run.call_count, 2)

    def test_timeout_marks_affected_checks_as_error(self):
        code, result, _ = self.run_approved(
            collection("ubuntu", subprocess.TimeoutExpired(["docker"], 20)) + collection("mysql", process(MYSQL_OUTPUT))
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["ubuntu"]["settings"]["permitrootlogin"]["error_code"], "timeout")
        self.assertEqual([row["status"] for row in result["ubuntu"]["checks"]], ["ERROR", "ERROR"])

    def test_missing_host_keys_and_mysql_connection_error_do_not_leak_stderr(self):
        secret = "password-fixture-never-export"
        events = collection("ubuntu", process(stderr=f"sshd: no hostkeys available -- exiting. {secret}", returncode=1))
        events += collection("mysql", process(stderr=f"ERROR 1045 (28000): {secret}", returncode=1))

        code, result, run = self.run_approved(events)

        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 6)
        self.assertEqual(result["ubuntu"]["settings"]["maxauthtries"]["error_code"], "ssh_host_keys_missing")
        self.assertEqual(result["mysql"]["settings"]["local_infile"]["error_code"], "mysql_connection_failed")
        self.assertNotIn(secret, json.dumps(result))
        for service in result.values():
            self.assertTrue(all(row["status"] == "ERROR" for row in service["checks"]))

    def test_missing_unrecognized_and_malformed_settings_have_distinct_outcomes(self):
        secret = "unknown-sensitive-token"
        events = collection("ubuntu", process(f"permitrootlogin {secret}\n"))
        events += collection("mysql", process("8.0.44\t\tinvalid\t1\t0\n"))

        code, result, _ = self.run_approved(events)

        self.assertEqual(code, 1)
        self.assertEqual([row["status"] for row in result["ubuntu"]["checks"]], ["NOT_TESTED", "NEEDS_REVIEW"])
        self.assertEqual([row["status"] for row in result["mysql"]["checks"]], ["NOT_TESTED", "ERROR"])
        self.assertEqual(result["mysql"]["settings"]["require_secure_transport"]["error_code"], "parse_error")
        self.assertNotIn(secret, json.dumps(result))
