"""Regression coverage for transport evidence, bounded execution and safe exports."""
import contextlib
import errno
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.artifacts import load_scan_artifact, write_scan_artifact
from scanner.banner_grabber import sanitize_banner
from scanner.execution import bounded_scan
from scanner.fingerprints import identify_service
from scanner.scan_runner import DEFAULT_PORTS, PORT_PROFILES, run_scan
from scanner.tcp_scanner import PortScanResult, scan_single_port
from scanner.udp_scanner import scan_single_udp_port
from scanner.utils import parse_ports, socket_error, udp_probe
from scripts.run_scan import build_parser, main, render_results


class TransportEvidenceTests(unittest.TestCase):
    def test_tcp_errors_do_not_turn_into_closed(self):
        cases = [(ConnectionRefusedError(errno.ECONNREFUSED, "sensitive"), "closed", "connection_refused"),
                 (TimeoutError("sensitive"), "unknown", "timeout"),
                 (PermissionError(errno.EACCES, "sensitive"), "error", "permission_denied"),
                 (OSError(errno.ENETUNREACH, "sensitive"), "error", "network_unreachable"),
                 (OSError(errno.EHOSTUNREACH, "sensitive"), "error", "host_unreachable")]
        for error, state, reason in cases:
            with self.subTest(state=state, reason=reason), patch("scanner.utils.socket.create_connection", side_effect=error):
                row = scan_single_port("127.0.0.1", 4280)
                self.assertEqual((row.state, row.reason), (state, reason))
                self.assertNotIn("sensitive", json.dumps(row.to_dict()))
                self.assertGreaterEqual(row.elapsed_seconds, 0)

    def test_udp_timeout_refusal_and_unreachable_are_different(self):
        self.assertEqual(socket_error(TimeoutError(), udp=True)[:2], ("open|filtered", "no_response"))
        self.assertIsNone(socket_error(TimeoutError(), udp=True)[2])
        self.assertEqual(socket_error(ConnectionRefusedError(errno.ECONNREFUSED, ""), udp=True)[0], "closed")
        self.assertEqual(socket_error(OSError(errno.EHOSTUNREACH, ""), udp=True), ("error", "host_unreachable", "HOST_UNREACHABLE"))

    def test_udp_selects_ipv6_and_pins_peer(self):
        with patch("scanner.utils.socket.socket") as factory:
            factory.return_value.recv.return_value = b"echo"
            self.assertEqual(udp_probe("::1", 32123), ("open", "udp_response", None))
            factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
            factory.return_value.connect.assert_called_once_with(("::1", 32123))
            factory.return_value.close.assert_called_once()

    def test_udp_socket_creation_failure_stays_error(self):
        with patch("scanner.utils.socket.socket", side_effect=PermissionError(errno.EACCES, "")):
            row = scan_single_udp_port("127.0.0.1", 123)
        self.assertEqual((row.state, row.reason), ("error", "permission_denied"))

    def test_invalid_timeout_or_worker_count_rejected_before_probing(self):
        for value in (float("nan"), float("inf"), 0, -1):
            with patch("scanner.utils.socket.create_connection") as connect, self.assertRaises(ValueError):
                run_scan(["127.0.0.1"], ports="80", timeout=value)
            connect.assert_not_called()
        with self.assertRaises(ValueError):
            run_scan(["127.0.0.1"], ports="80", max_workers=1001)


class SafeIdentityTests(unittest.TestCase):
    def test_sensitive_unknown_headers_and_bodies_removed_identity_unchanged(self):
        raw = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nSet-Cookie: SESSION=private\r\n"
               b" folded-secret\r\nAuthorization: Bearer private\r\nX-Unknown-Token: private\r\n"
               b"Location: /?token=private\r\n\r\nprivate body")
        safe = sanitize_banner(raw)
        self.assertNotIn(b"private", safe)
        before, after = identify_service(raw), identify_service(safe)
        self.assertEqual((before["product"], before["version"]), (after["product"], after["version"]))

    def test_collect_and_scanner_defense_in_depth_for_mocked_banner(self):
        from scanner.banner_grabber import BannerObservation
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.20.0\r\nSet-Cookie: private\r\n\r\n"
        with patch("scanner.tcp_scanner.tcp_connect"), patch("scanner.tcp_scanner.collect_banner", return_value=BannerObservation(raw)):
            row = scan_single_port("127.0.0.1", 80, detect_versions=True)
        self.assertEqual((row.product, row.version, row.service_source), ("nginx", "1.20.0", "observed"))
        self.assertNotIn("private", json.dumps(row.to_dict()))

    def test_lab_http_identity_does_not_invent_version(self):
        elastic = identify_service("HTTP/1.1 200 OK\r\nX-Elastic-Product: Elasticsearch\r\n\r\n", "unknown")
        kibana = identify_service(sanitize_banner("HTTP/1.1 302 Found\r\nkbn-name: node\r\nkbn-license-sig: signature\r\n\r\n"))
        self.assertEqual((elastic["product"], elastic["version"]), ("elasticsearch", None))
        self.assertEqual((kibana["product"], kibana["version"]), ("kibana", None))
        self.assertIsNone(identify_service("HTTP/1.1 200 OK\r\n\r\n", "http")["product"])

    def test_truncated_or_duplicate_headers_never_promoted(self):
        self.assertIsNone(identify_service(sanitize_banner(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49"))["product"])
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.20.0\r\nServer: Apache/2.4.49\r\n\r\n"
        self.assertIsNone(identify_service(sanitize_banner(raw))["product"])

    def test_guessed_service_labeled(self):
        with patch("scanner.tcp_scanner.tcp_connect"):
            row = scan_single_port("127.0.0.1", 80)
        self.assertEqual((row.service, row.service_source, row.product), ("http", "guessed", None))


class ExecutionTests(unittest.TestCase):
    def test_huge_ranges_are_rejected_without_iteration(self):
        for expression in ("1-999999999999999", "0-65535", "65536", "1-65536"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                parse_ports(expression)
        self.assertEqual(len(parse_ports("1-65535")), 65535)
        self.assertEqual(parse_ports("443,82-80,80"), [80, 81, 82, 443])

    def test_queued_work_is_bounded_and_cancellation_preserves_observations(self):
        stop = threading.Event()
        called = []
        def worker(port):
            called.append(port)
            stop.set()
            return PortScanResult(port, "tcp", "open")
        rows = bounded_scan(list(range(1, 100)), worker, max_workers=1, protocol="tcp", stop_event=stop)
        self.assertEqual(called, [1])
        self.assertEqual(rows[0]["state"], "open")
        self.assertTrue(all(row["state"] == "not_tested" for row in rows[1:]))

    def test_expired_deadline_does_not_probe(self):
        worker = MagicMock()
        rows = bounded_scan([80, 443], worker, max_workers=2, protocol="tcp", deadline=time.monotonic()-1)
        worker.assert_not_called()
        self.assertEqual([r["reason"] for r in rows], ["deadline_exceeded"]*2)

    def test_utc_and_partial_status_with_precise_duration(self):
        with patch("scanner.scan_runner.threaded_scan", return_value=[{"port":80,"protocol":"tcp","state":"unknown","reason":"timeout"}]):
            result = run_scan(["127.0.0.1"], ports="80")
        self.assertEqual(datetime.fromisoformat(result["started_at"]).utcoffset().total_seconds(), 0)
        self.assertEqual(result["time_basis"], "UTC")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["coverage"] if "coverage" in result else result["targets"][0]["coverage"]["attempted_ports"]["tcp"], [80])
        self.assertGreaterEqual(result["duration_seconds"], 0)

    def test_default_and_lab_profiles_and_outside_range(self):
        self.assertEqual(DEFAULT_PORTS, "1-1024")
        ports = parse_ports(PORT_PROFILES["lab"])
        self.assertTrue(set((3306,4280,4281,4282,5601,8080,9200)) <= set(ports))
        stop=threading.Event();stop.set()
        result=run_scan(["127.0.0.1"],ports="4280",stop_event=stop)
        self.assertEqual(result["targets"][0]["results"][0]["state"],"not_tested")
        self.assertEqual(result["targets"][0]["coverage"]["outside_requested_range"],"NOT_TESTED")

    def test_cli_displays_uncertain_errors_and_guesses(self):
        result={"started_at":"2026-11-19T06:00:00+00:00","finished_at":"2026-11-19T06:00:00+00:00","duration_seconds":.123456,
                "targets":[{"ip":"127.0.0.1","results":[{"port":123,"protocol":"udp","state":"open|filtered","reason":"no_response","service":"ntp"}]}]}
        rendered="\n".join(render_results(result,False))
        self.assertIn("open|filtered",rendered);self.assertIn("no_response",rendered)
        self.assertIn("guessed",rendered);self.assertIn("0.123",rendered)


class ArtifactCliTests(unittest.TestCase):
    def result(self):
        return {"scan_id":"scan-fixture","started_at":"2026-11-19T06:00:00+00:00","finished_at":"2026-11-19T06:00:01+00:00","port_range":"80",
                "targets":[{"ip":"127.0.0.1","results":[{"port":80,"protocol":"tcp","state":"open","banner":"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nSet-Cookie: private\r\n\r\n"}]}]}

    def test_export_never_overwrites_and_import_sanitizes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"new.json"
            write_scan_artifact(self.result(),path)
            self.assertNotIn("private",path.read_text())
            with self.assertRaises(FileExistsError):write_scan_artifact(self.result(),path)
            self.assertEqual(load_scan_artifact(path)["scan_id"],"scan-fixture")

    def test_db_failure_retains_safe_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"new.json"
            with patch("scripts.run_scan.run_scan",return_value=self.result()), patch("db.save_scan_results.save_scan_results",side_effect=RuntimeError("private")),contextlib.redirect_stdout(io.StringIO()) as output:
                rc=main(["scan","--target","127.0.0.1","--ports","80","--output-json",str(path)])
            self.assertEqual(rc,1);self.assertTrue(path.exists())
            self.assertNotIn("private",path.read_text()+output.getvalue())

    def test_no_db_and_profile_preserve_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"new.json"
            with patch("scripts.run_scan.run_scan",return_value=self.result()) as scan,patch("db.save_scan_results.save_scan_results") as save,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan","--target","127.0.0.1","--profile","lab","--no-db","--output-json",str(path),"--asset-namespace","tenant:demo/vpc:a"]),0)
            save.assert_not_called()
            self.assertIn(9200,scan.call_args.kwargs["ports"])
            self.assertEqual(load_scan_artifact(path)["asset_namespace"],"tenant:demo/vpc:a")

    def test_reimport_has_no_scan_or_dns(self):
        from scripts.import_scan_results import main as import_main
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"saved.json";write_scan_artifact(self.result(),path)
            with patch("db.save_scan_results.save_scan_results",return_value=123) as save,patch("socket.create_connection") as connect,patch("socket.gethostbyaddr") as dns,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(import_main(["--input",str(path)]),0)
            self.assertEqual(save.call_count,1);connect.assert_not_called();dns.assert_not_called()


if __name__ == "__main__":unittest.main()
