"""Offline only: no Docker daemon, network or container mutations."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from config_audit.collectors import web_was as w
from config_audit.web_was_report import common_snapshot, write_pdf
from scripts.run_web_was_audit import main


class WebWasAuditTests(unittest.TestCase):
    def setUp(self):
        self.before = w.synthetic_bundle("before")
        self.after = w.synthetic_bundle("after")

    def test_synthetic_before_all_eight_fail(self):
        r = w.audit(self.before, synthetic=True)
        self.assertEqual(r["summary"], {"FAIL": 8})
        self.assertEqual(r["origin"], "synthetic")

    def test_synthetic_after_all_eight_pass(self):
        self.assertEqual(w.audit(self.after, synthetic=True)["summary"], {"PASS": 8})

    def test_default_preparation_no_collection(self):
        with patch("scripts.run_web_was_audit.collect_docker", side_effect=AssertionError()), redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        self.assertEqual(w.audit()["summary"], {"NOT_TESTED": 8})

    def test_common_engine_used_for_every_check(self):
        with patch.object(w, "evaluate", wraps=w.evaluate) as engine:
            w.audit(self.after, synthetic=True)
        self.assertEqual(engine.call_count, 8)

    def test_synthetic_not_accepted_as_actual(self):
        with self.assertRaises(w.WebInputError): w.audit(self.after)

    def test_missing_config_value_not_pass(self):
        self.after["nodes"]["tomcat"]["values"].pop("autodeploy_disabled")
        row = w.audit(self.after, synthetic=True)["results"][4]
        self.assertEqual(row["status"], "NEEDS_REVIEW")

    def test_missing_runtime_value_not_pass(self):
        self.after["http"].pop("nginx_version_hidden")
        self.assertEqual(w.audit(self.after, synthetic=True)["results"][1]["status"], "NEEDS_REVIEW")

    def test_runtime_conflicts_with_config_is_fail(self):
        self.after["http"]["nginx_version_hidden"] = False
        self.assertEqual(w.audit(self.after, synthetic=True)["results"][1]["status"], "FAIL")

    def test_collection_failure_is_error(self):
        self.after["nodes"]["nginx"]["error_code"] = "query_failed"
        statuses = [r["status"] for r in w.audit(self.after, synthetic=True)["results"]]
        self.assertEqual(statuses[:4], ["ERROR"] * 4)
        self.assertEqual(statuses[4:], ["PASS"] * 4)

    def test_unsupported_version_needs_review(self):
        self.after["nodes"]["tomcat"]["version"] = "11.0.1"
        self.assertEqual(w.audit(self.after, synthetic=True)["results"][4]["status"], "NEEDS_REVIEW")

    def test_unknown_nginx_include_not_inferred(self):
        raw = (w.ROOT / "lab/web-was-lab/after/nginx.conf").read_text()
        self.assertTrue(all(v is None for v in w.nginx_values(raw + "\ninclude /tmp/other.conf;").values()))

    def test_nginx_missing_directive_not_assumed_default(self):
        raw = (w.ROOT / "lab/web-was-lab/after/nginx.conf").read_text().replace("server_tokens off;", "")
        self.assertTrue(all(v is None for v in w.nginx_values(raw).values()))

    def test_tomcat_missing_autodeploy_not_assumed_safe(self):
        raw = (w.ROOT / "lab/web-was-lab/after/server.xml").read_text().replace('autoDeploy="false"', '')
        self.assertIsNone(w.tomcat_values(raw, {})["autodeploy_disabled"])

    def test_tomcat_malformed_and_entity_rejected(self):
        for raw in ("<Server>", '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><Server/>'):
            with self.subTest(raw=raw), self.assertRaises(w.WebInputError): w.tomcat_values(raw, {})

    def test_unknown_context_does_not_pass(self):
        raw = (w.ROOT / "lab/web-was-lab/after/server.xml").read_text().replace("</Host>", '<Context path="/manager" /></Host>')
        self.assertTrue(all(v is None for v in w.tomcat_values(raw, {}).values()))

    def test_default_apps_inventory_has_to_be_complete(self):
        raw = (w.ROOT / "lab/web-was-lab/after/server.xml").read_text()
        self.assertIsNone(w.tomcat_values(raw, {"manager": False})["default_apps_absent"])

    def test_json_missing_and_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            with self.assertRaises(w.WebInputError): w.load_bundle(p)
            p.write_text("{broken")
            with self.assertRaises(w.WebInputError): w.load_bundle(p)

    def test_json_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"; p.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(w.WebInputError, "duplicate_json_key"): w.load_bundle(p)

    def test_sensitive_unknown_metadata_rejected(self):
        self.after["nodes"]["nginx"]["Authorization"] = "SECRET_CANARY"
        with self.assertRaises(w.WebInputError): w.validate(self.after)

    def test_unknown_status_or_boolean_value_rejected(self):
        self.after["nodes"]["nginx"]["values"]["tokens_hidden"] = "PASS"
        with self.assertRaises(w.WebInputError): w.validate(self.after)

    def test_common_report_model_channels_and_times(self):
        report = w.audit(self.after, synthetic=True)
        snapshot = common_snapshot(report, "synthetic-after")
        self.assertEqual(len(snapshot["results"]), 8)
        self.assertIsNone(snapshot["results"][0]["manual"])
        self.assertEqual(snapshot["results"][0]["automatic"]["collected_at"], self.after["collected_at"])
        self.assertNotEqual(report["generated_at"], self.after["collected_at"])

    def test_comparison_observed_transitions_not_real_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "before.json"; p.write_text(json.dumps(self.before))
            original = p.read_bytes()
            result = w.compare(w.audit(self.after, synthetic=True), p)
            self.assertEqual(result["comparison"]["summary"], {"IMPROVED_OBSERVED": 8})
            self.assertTrue(all(not r["remediation_complete_in_LAB"] for r in result["comparison"]["results"]))
            self.assertEqual(p.read_bytes(), original)

    def test_time_reversal_incomparable(self):
        self.after["collected_at"] = "2025-01-01T00:00:00Z"
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "before.json"; p.write_text(json.dumps(self.before))
            report = w.compare(w.audit(self.after, synthetic=True), p)
        self.assertEqual(report["comparison"]["summary"], {"INCOMPARABLE": 8})

    def test_timezone_and_startup_time_checked(self):
        for value in ("2026-01-01T00:00:00", "unknown"):
            self.after["collected_at"] = value
            with self.assertRaises(w.WebInputError): w.validate(self.after)

    def test_http_proxy_failure_separate_and_comparison_blocked(self):
        self.after["http"]["proxy_ok"] = False
        r = w.audit(self.after, synthetic=True)
        self.assertEqual(r["http_verification"]["status"], "FAIL")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "before.json"; p.write_text(json.dumps(self.before))
            self.assertIn("proxy_path_not_verified_before_and_after", w.compare(r, p)["comparison"]["issues"])

    def test_outputs_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "keep.json"; p.write_text("PRESERVE")
            with redirect_stdout(io.StringIO()), patch("scripts.run_web_was_audit.collect_docker", side_effect=AssertionError()):
                self.assertEqual(main(["--execute", "--output", str(p)]), 2)
            self.assertEqual(p.read_text(), "PRESERVE")

    def test_cli_docker_error_sanitized(self):
        text = io.StringIO()
        with patch("scripts.run_web_was_audit.collect_docker", side_effect=OSError("SECRET_CANARY")), redirect_stdout(text):
            self.assertEqual(main(["--execute"]), 2)
        self.assertNotIn("SECRET_CANARY", text.getvalue())

    def test_subprocess_errors_sanitized(self):
        with patch.object(w.subprocess, "run", side_effect=OSError("SECRET_CANARY")):
            with self.assertRaisesRegex(w.WebInputError, "docker_query_failed"): w.run(["docker", "context", "show"])

    def test_remote_context_rejected_before_inspection(self):
        with patch.object(w, "run", return_value="production") as runner:
            with self.assertRaises(w.WebInputError): w.docker_scope()
        self.assertEqual(runner.call_count, 1)

    def test_remote_endpoint_rejected(self):
        with patch.object(w, "run", side_effect=["default", json.dumps([{"Endpoints": {"docker": {"Host": "tcp://remote:2375"}}}])]):
            with self.assertRaisesRegex(w.WebInputError, "remote_docker_rejected"): w.docker_scope()

    def test_compose_isolation_and_stages(self):
        compose = json.loads((w.ROOT / "lab/web-was-lab/compose.json").read_text())
        self.assertEqual(compose["name"], w.PROJECT)
        self.assertTrue(compose["networks"]["backend"]["internal"])
        for service in compose["services"].values():
            self.assertNotIn("ports", service); self.assertNotIn("volumes", service)
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertTrue(service["read_only"])
            self.assertNotIn("privileged", service)
        for name in ("nginx", "tomcat"):
            raw = (w.ROOT / f"lab/web-was-lab/start-{name}.sh").read_bytes()
            self.assertNotIn(b"\r", raw)

    def test_pdf_synthetic_label_and_eight_checks(self):
        from pypdf import PdfReader
        output = io.BytesIO()
        write_pdf(w.audit(self.after, synthetic=True), output)
        text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(output.getvalue())).pages)
        self.assertIn("합성 테스트", text)
        for check in w.CHECKS: self.assertIn(check, text)

    def simulated_live(self, stage="after", broken_startup=False, failed_http=False):
        base = w.ROOT / "lab/web-was-lab" / stage
        configs = {"nginx": (base / "nginx.conf").read_text(), "tomcat": (base / "server.xml").read_text()}
        nodes = {p: {"Id": p, "Image": "sha256:" + "a" * 64, "State": {"StartedAt": "2020-01-01T00:00:00Z"}} for p in w.VERSIONS}
        def query(args):
            self.assertEqual(args[:2], ["docker", "exec"])
            product, cmd = args[2], args[3:]
            if cmd == ["sh", "-c", "nginx -v 2>&1"]: return "nginx version: nginx/1.30.6"
            if cmd == ["catalina.sh", "version"]: return "Server version: Apache Tomcat/10.1.61"
            if cmd == ["nginx", "-t"]: return ""
            if cmd == ["cat", "/etc/nginx/nginx.conf"] or cmd == ["cat", "/usr/local/tomcat/conf/server.xml"]: return configs[product]
            if cmd == ["cat", "/tmp/startup-config.sha256"]:
                path = "/etc/nginx/nginx.conf" if product == "nginx" else "/usr/local/tomcat/conf/server.xml"
                return ("b" * 64 if broken_startup else w.sha(configs[product].encode())) + "  " + path
            if cmd[0] == "sh": return "yes" if stage == "before" and any("/webapps/" + app + '"' in cmd[-1] for app in ("docs", "examples")) else "no"
            if cmd[0] == "java":
                if failed_http: raise w.WebInputError("docker_query_failed")
                return json.dumps(w.synthetic_bundle(stage)["http"])
            if cmd[0] == "cat": return "SECRET_CANARY_RAW_LOG " + "c" * 32
            raise AssertionError(cmd)
        with patch.object(w, "docker_scope", return_value=(["docker"], nodes)), patch.object(w, "run", side_effect=query), patch.object(w, "uuid4", return_value=SimpleNamespace(hex="c" * 32)):
            return w.collect_docker()

    def test_simulated_live_collector_before_and_after(self):
        for stage, expected in (("before", {"FAIL": 8}), ("after", {"PASS": 8})):
            bundle = self.simulated_live(stage)
            report = w.audit(bundle)
            self.assertEqual(report["summary"], expected)
            self.assertNotIn("SECRET_CANARY", json.dumps(report))

    def test_startup_config_hash_mismatch_is_error(self):
        report = w.audit(self.simulated_live(broken_startup=True))
        self.assertEqual(report["summary"], {"ERROR": 8})

    def test_http_failure_does_not_create_runtime_pass(self):
        report = w.audit(self.simulated_live(failed_http=True))
        self.assertEqual(report["http_verification"]["status"], "NOT_TESTED")
        self.assertEqual(report["results"][0]["status"], "NEEDS_REVIEW")

    def scope_responses(self):
        nodes = []
        for name in w.VERSIONS:
            nodes.append({"Id": name, "State": {"Running": True}, "Config": {
                "Labels": {"com.docker.compose.project": w.PROJECT, "com.docker.compose.service": name},
                "User": "10001:10001", "Entrypoint": ["/bin/sh", "/opt/lab/start.sh"],
                "Cmd": ["nginx", "-g", "daemon off;"] if name == "nginx" else ["catalina.sh", "run"]},
                "HostConfig": {"ReadonlyRootfs": True}, "Mounts": [],
                "NetworkSettings": {"Networks": {w.PROJECT + "_backend": {}}}})
        net = {"Internal": True, "Driver": "bridge", "Labels": {"com.docker.compose.project": w.PROJECT}, "Containers": {"nginx": {}, "tomcat": {}}}
        return ["default", json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]), "linux", json.dumps([nodes[0]]), json.dumps([nodes[1]]), json.dumps([net])]

    def test_fixed_project_scope_accepted(self):
        with patch.object(w, "run", side_effect=self.scope_responses()):
            self.assertEqual(set(w.docker_scope()[1]), {"nginx", "tomcat"})

    def test_foreign_project_rejected(self):
        replies = self.scope_responses()
        obj = json.loads(replies[3]); obj[0]["Config"]["Labels"]["com.docker.compose.project"] = "other"
        replies[3] = json.dumps(obj)
        with patch.object(w, "run", side_effect=replies), self.assertRaisesRegex(w.WebInputError, "foreign_container_rejected"):
            w.docker_scope()

    def test_published_port_and_host_mount_rejected(self):
        for mutation in ("port", "mount"):
            replies = self.scope_responses(); obj = json.loads(replies[3])
            if mutation == "port": obj[0]["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            else: obj[0]["Mounts"] = [{"Type": "bind", "Destination": "/tmp"}]
            replies[3] = json.dumps(obj)
            with patch.object(w, "run", side_effect=replies), self.assertRaises(w.WebInputError): w.docker_scope()


if __name__ == "__main__": unittest.main()
