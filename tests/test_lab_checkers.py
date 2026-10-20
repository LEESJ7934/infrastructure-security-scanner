"""Offline safety and behavior regression checks for opt-in laboratory probes."""
import unittest
from unittest.mock import patch, MagicMock
from verification.checker_ftp import FTPChecker
from verification.checker_http import HTTPChecker
from verification.checker_ssh import SSHChecker


PORT = {"host_ip": "127.0.0.1", "port": 2121, "service": "ftp"}


class FTPTests(unittest.TestCase):
    @patch("verification.checker_ftp.FTP")
    def test_anonymous_success_requires_opt_in(self, ftp_cls):
        conn = ftp_cls.return_value
        conn.connect.return_value = "220 ready"
        conn.login.return_value = "230 logged in"
        self.assertEqual(FTPChecker().run_check(PORT, {})["details"]["anonymous_login_attempted"], False)
        result = FTPChecker(allow_anonymous_login=True).run_check(PORT, {})
        self.assertTrue(result["details"]["anonymous_login_allowed"])
        self.assertEqual(result["details"]["finding_status"], "CONFIRMED")
        self.assertEqual(result["status"], "POTENTIAL")
        conn.login.assert_called_once()
        self.assertFalse(conn.storbinary.called or conn.delete.called)

    @patch("verification.checker_ftp.FTP")
    def test_denied_anonymous_is_not_detected(self, ftp_cls):
        from ftplib import error_perm
        ftp_cls.return_value.connect.return_value = "220 ready"
        ftp_cls.return_value.login.side_effect = error_perm("530 Login incorrect")
        result = FTPChecker(allow_anonymous_login=True).run_check(PORT, {})
        self.assertEqual(result["details"]["finding_status"], "NOT_DETECTED")

    @patch("verification.checker_ftp.FTP")
    def test_error_is_not_safe(self, ftp_cls):
        ftp_cls.return_value.connect.side_effect = TimeoutError("timeout")
        result = FTPChecker(allow_anonymous_login=True).run_check(PORT, {})
        self.assertEqual(result["status"], "ERROR")
        self.assertNotIn("finding_status", result["details"])


class HTTPTests(unittest.TestCase):
    @patch("verification.checker_http.requests.Session")
    def test_missing_headers_not_cve_confirmation(self, session_cls):
        response = MagicMock()
        response.headers = {"Server": "example"}
        response.status_code = 200
        response.__enter__.return_value = response
        session_cls.return_value.get.return_value = response
        result = HTTPChecker().run_check({**PORT, "service": "http"}, {})
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertIn("x-content-type-options", result["details"]["missing_headers"])
        self.assertEqual(result["details"]["finding_status"], "POTENTIAL")
        self.assertFalse(session_cls.return_value.get.call_args.kwargs["allow_redirects"])

    @patch("verification.checker_http.requests.Session")
    def test_configured_headers(self, session_cls):
        response = MagicMock()
        response.headers = {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        response.status_code = 200
        response.__enter__.return_value = response
        session_cls.return_value.get.return_value = response
        result = HTTPChecker().run_check({**PORT, "service": "http"}, {})
        self.assertEqual(result["details"]["finding_status"], "NOT_DETECTED")


class SSHTests(unittest.TestCase):
    @patch("verification.checker_ssh.socket.create_connection")
    def test_banner_only_does_not_infer_auth(self, connect):
        sock = connect.return_value.__enter__.return_value
        sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"
        result = SSHChecker().run_check(PORT, {})
        self.assertEqual(result["details"]["finding_status"], "INCONCLUSIVE")
        self.assertNotIn("attested_auth_policy", result["details"])
        result = SSHChecker(approved_auth_policy={
            "pubkeyauthentication": True, "passwordauthentication": False
        }).run_check(PORT, {})
        self.assertEqual(result["details"]["finding_status"], "NOT_DETECTED")


if __name__ == "__main__":
    unittest.main()
