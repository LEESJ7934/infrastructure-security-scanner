import socket
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from scanner.banner_grabber import collect_banner
from scanner.fingerprints import identify_service
from scanner.service_fingerprints import guess_service
from scanner.tcp_scanner import scan_single_port
from scripts.demo_banner_server import DemoHandler


class FingerprintTests(unittest.TestCase):
    def test_explicit_ftp_greeting_on_nonstandard_port(self):
        banner = "220 220 controlled-lab FTP ready\r\n"
        result = identify_service(banner, "unknown")
        self.assertEqual(result["service"], "ftp")
        self.assertIsNone(result["product"])
        self.assertEqual(identify_service("220 service ready\\r\\n", "unknown")["service"], "unknown")

    def test_http_product_and_version_come_from_server_header(self):
        for token, product, version in (("Apache/2.4.50 (Unix)", "apache_http_server", "2.4.50"),
                                        ("nginx/1.20.0", "nginx", "1.20.0"),
                                        ("Microsoft-IIS/10.0", "microsoft_iis", "10.0")):
            with self.subTest(token=token):
                result = identify_service(f"HTTP/1.1 200 OK\r\nsErVeR: {token}\r\n\r\n", "unknown")
                self.assertEqual((result["service"], result["product"], result["version"]),
                                 ("http", product, version))

    def test_body_and_powered_by_cannot_identify_http_server(self):
        result = identify_service("HTTP/1.1 200 OK\r\nX-Powered-By: Apache/2.4.50\r\n\r\nServer: Apache/2.4.50")
        self.assertIsNone(result["product"])

    def test_duplicate_or_ambiguous_server_headers_are_unknown(self):
        for headers in ("Server: nginx/1.20.0\r\nServer: Apache/2.4.50",
                        "Server: nginx/1.20.0 Apache/2.4.50"):
            self.assertIsNone(identify_service("HTTP/1.1 200 OK\r\n" + headers + "\r\n\r\n")["product"])

    def test_hidden_version_is_not_guessed(self):
        result = identify_service("HTTP/1.0 200 OK\r\nServer: Apache\r\n\r\n")
        self.assertEqual(result["product"], "apache_http_server")
        self.assertIsNone(result["version"])
        self.assertIsNone(identify_service(None, "http")["product"])

    def test_truncated_response_is_not_treated_as_a_complete_version(self):
        for banner in ("SSH-2.0-OpenSSH_9.1", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.50"):
            self.assertIsNone(identify_service(banner)["product"])

    def test_ssh_greeting_overrides_wrong_port_hint(self):
        result = identify_service("SSH-2.0-OpenSSH_9.1p1 Ubuntu-1\r\n", "http")
        self.assertEqual((result["service"], result["product"], result["version"]),
                         ("ssh", "openssh", "9.1p1"))

    def test_unrecognized_ssh_implementation_is_not_openssh(self):
        self.assertIsNone(identify_service("SSH-2.0-Dropbear_2022.83\r\n", "ssh")["product"])

    def test_ftp_product_is_explicit(self):
        self.assertEqual(identify_service("220 (vsFTPd 3.0.5)\r\n", "ftp")["product"], "vsftpd")
        self.assertIsNone(identify_service("220 mail.example ESMTP\r\n", "smtp")["product"])

    def test_mysql_and_mariadb_greeting_and_text_round_trip(self):
        for version, product, expected in (("8.0.46", "mysql", "8.0.46"),
                                            ("5.5.5-10.11.6-MariaDB", "mariadb", "10.11.6-MariaDB")):
            raw = b"\x80\x00\x00\x00\x0a" + version.encode() + b"\x00rest"
            for banner in (raw, raw.decode("latin1")):
                result = identify_service(banner)
                self.assertEqual((result["product"], result["version"]), (product, expected))

    def test_udp_port_does_not_inherit_tcp_hint(self):
        self.assertEqual(guess_service(22, "udp"), "unknown")
        self.assertEqual(guess_service(53, "udp"), "dns")
        self.assertEqual(guess_service(8443), "https")

    def test_basic_scan_does_not_probe_for_versions(self):
        with patch("scanner.tcp_scanner.tcp_connect"), patch("scanner.tcp_scanner.collect_banner") as probe:
            result = scan_single_port("127.0.0.1", 80)
        probe.assert_not_called()
        self.assertIsNone(result.product)
        self.assertEqual(result.fingerprint["probe_error"], "not_requested")


class LocalProbeTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_http_on_nonstandard_port_is_identified(self):
        result = scan_single_port("127.0.0.1", self.server.server_port, timeout=1, detect_versions=True)
        self.assertEqual((result.state, result.service, result.product, result.version),
                         ("open", "http", "apache_http_server", "2.4.50"))
        self.assertEqual(result.fingerprint["source"], "http_server")

    def test_host_header_does_not_change_numeric_destination(self):
        observation = collect_banner("127.0.0.1", self.server.server_port, "http", 1, "lab.invalid")
        self.assertIn(b"Apache/2.4.50", observation.data)

    def test_header_injection_is_rejected(self):
        observation = collect_banner("127.0.0.1", self.server.server_port, "http", 1, "lab\r\nX-Test: invalid")
        self.assertEqual(observation.error, "ValueError")

    def test_closed_port_has_no_product(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = scan_single_port("127.0.0.1", port, 0.2, True)
        self.assertEqual(result.state, "closed")
        self.assertIsNone(result.product)


if __name__ == "__main__":
    unittest.main(verbosity=2)
