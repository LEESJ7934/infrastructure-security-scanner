"""Database read-only preflight: mock both V6-only and V7-valid states."""
import unittest
from scripts.windows_v7_preflight import describe_local_database, NEEDED


class FakeCursor:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.result = None
        self.sql = []
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def execute(self, sql): 
        self.sql.append(sql)
        self.result = next(self.responses)
    def fetchone(self):
        if not isinstance(self.result, list):
            return self.result
        return self.result[0]
    def fetchall(self): return self.result


class FakeConnection:
    def __init__(self, responses):
        self.cursor_obj = FakeCursor(responses)
        self.closed = False
    def cursor(self, **kwargs): return self.cursor_obj
    def close(self): self.closed = True


class WindowsPreflightTests(unittest.TestCase):
    def test_v7_present_reports_existing_http_row_without_writes(self):
        responses = [
            {"database_name": "port_scan", "mysql_version": "8.0.40"},
            [{"table_name": name} for name in ("scans", "hosts", "ports", "lab_verification_results")],
            [{"column_name": col} for col in sorted(NEEDED)],
            {"n": 12}, {"n": 2}, {"n": 4}, {"n": 1},
            [{"port_id": 44, "port_number": 80, "service": "http", "scan_id": 11,
              "scan_status": "COMPLETED", "scanned_at": "2026-10-20",
              "asset_uid": "uid", "host_ip": "127.0.0.1", "original_scan_target": "127.0.0.1"}],
        ]
        db = FakeConnection(responses)
        info = describe_local_database(connect=lambda: db)
        self.assertTrue(info["v7_schema_complete"])
        self.assertFalse(info["writes_performed"])
        self.assertEqual(info["current_http_scan_port_candidates"][0]["port_id"], 44)
        self.assertTrue(all(q.lstrip().lower().startswith("select") for q in db.cursor_obj.sql))
        self.assertTrue(db.closed)

    def test_missing_v7_is_reported_not_created(self):
        responses = [
            {"database_name": "port_scan", "mysql_version": "8.0.40"},
            [{"table_name": name} for name in ("scans", "hosts", "ports")],
            {"n": 1}, {"n": 1}, {"n": 1}, [],
        ]
        db = FakeConnection(responses)
        info = describe_local_database(connect=lambda: db)
        self.assertFalse(info["v7_table_present"])
        self.assertFalse(info["v7_schema_complete"])
        self.assertNotIn("lab_verification_results", info["counts"])
        self.assertTrue(db.closed)

    def test_wrong_database_rejected(self):
        db = FakeConnection([{"database_name": "other", "mysql_version": "8.0.40"}])
        with self.assertRaises(ValueError):
            describe_local_database(connect=lambda: db)
        self.assertTrue(db.closed)


if __name__ == "__main__":
    unittest.main()
