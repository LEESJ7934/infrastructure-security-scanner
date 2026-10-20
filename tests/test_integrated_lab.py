"""Offline tests of bounded DVWA requests and two-scan report composition."""
import unittest
from unittest.mock import patch, MagicMock

from verification.dvwa_sqli_lab import verify_dvwa_sqli
from scripts.generate_integrated_lab_report import build_integrated_snapshot


class FakeResponse:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.content = text.encode()


class DummySession:
    def __init__(self):
        self.cookies = MagicMock()
        self.cookies.get.return_value = "mocked_session"
        self.trust_env = True
        self.requests = []

    def __enter__(self): return self
    def __exit__(self, *args): return None
    def get(self, url, **kwargs):
        self.requests.append((url, kwargs))
        if url.endswith("login.php"):
            return FakeResponse("<title>DVWA</title><input name='user_token' value='test'>")
        if url.endswith("index.php"):
            return FakeResponse("logout")
        if "vulnerabilities/sqli" in url:
            marker = kwargs["params"]["id"]
            if marker == "1":
                return FakeResponse("First name: A")
            return FakeResponse("First name: A <br> First name: B")
        return FakeResponse("Not found", 404)

    def post(self, url, **kwargs):
        return FakeResponse("", 302)


class DVWASQLiTests(unittest.TestCase):
    @patch("verification.dvwa_sqli_lab.requests.Session")
    def test_confirmed_requires_row_expansion(self, factory):
        session = DummySession()
        factory.return_value = session
        result = verify_dvwa_sqli(origin="http://127.0.0.1:8080",
                                  approved_ip="127.0.0.1", username="test", password="secret")
        self.assertEqual(result["details"]["finding_status"], "CONFIRMED")
        self.assertNotIn("secret", str(result))
        self.assertEqual(len(result["details"]["steps"]), 2)
        self.assertTrue(all(k["allow_redirects"] is False for _, k in session.requests))

    def test_scope_mismatch_does_not_contact(self):
        with self.assertRaises(ValueError):
            verify_dvwa_sqli(origin="http://203.0.113.3:8080",
                             approved_ip="127.0.0.1",username="x",password="y")


class FakeDB:
    def __init__(self):
        self.rows = [{"scan_id": 11, "environment_label": "LOCAL_BASELINE",
                      "evidence_json": "{}", "evidence_sha256": "0"*64,
                      "check_name": "HTTP_SECURITY_HEADERS", "asset_uid": "one",
                      "execution_status": "SUCCESS", "finding_status": "NOT_DETECTED",
                      "observed_at": "2026-10-20"}]
        self.actions = []

    def start_transaction(self, **kwargs): self.actions.append(("begin",kwargs))
    def cursor(self, **kwargs):
        db = self
        class Cur:
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def execute(self, sql, params): db.actions.append(("query",params))
            def fetchall(self): return db.rows
        return Cur()
    def rollback(self): self.actions.append(("rollback",None))
    def close(self): self.actions.append(("close",None))


class IntegratedReportTests(unittest.TestCase):
    @patch("scripts.generate_integrated_lab_report._read_rows")
    @patch("scripts.generate_integrated_lab_report._assemble")
    @patch("scripts.generate_integrated_lab_report.get_connection")
    def test_distinct_scans_one_read_only_snapshot(self, connect, assemble, read):
        connection = FakeDB()
        connect.return_value = connection
        read.return_value = ()
        assemble.side_effect = [
            {"schema_version":2,"generated_at":"today","selection":{},
             "summary":{},"scans":[],"assets":[],
             "integrity":{"snapshot_sha256":"x"}},
            {"schema_version":2,"generated_at":"today","selection":{},
             "summary":{},"scans":[],"assets":[],
             "integrity":{"snapshot_sha256":"y"}}
        ]
        report = build_integrated_snapshot(local_scan_id=11, ec2_scan_id=12)
        self.assertEqual([a["scan_id"] for a in [call[0][1] for call in read.call_args_list]],
                         [11, 12])
        self.assertTrue(connection.actions[0][1]["readonly"])
        self.assertEqual(connection.actions[1][1], (11,12))
        self.assertEqual(report["lab_comparison"]["scan_ids"]["EC2_LAB"], 12)
        self.assertEqual(report["lab_comparison"]["environments"]["EC2_LAB"]["coverage"]["HTTP_SECURITY_HEADERS"], "NOT_TESTED")


if __name__ == "__main__":
    unittest.main()
