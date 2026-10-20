import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from verification.reviewed_nuclei import execute_reviewed


class ReviewedNucleiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        (base / "safe.yaml").write_text("id: safe", encoding="utf-8")
        (base / "nuclei").write_text("mock binary", encoding="utf-8")
        self.params = dict(nuclei_binary=str(base/"nuclei"), template_root=str(base),
                           template_allowlist={"safe.yaml": hashlib.sha256(b"id: safe").hexdigest()},
                           template_name="safe.yaml",origin="http://127.0.0.1:8080",
                           approved_ips={"127.0.0.1"})

    @patch("verification.reviewed_nuclei.subprocess.run")
    def test_no_detection_is_not_confirmed(self, run):
        run.side_effect = [type("R", (), {"returncode":0,"stdout":"v3","stderr":""})(),
                           type("R", (), {"returncode":0,"stdout":"","stderr":""})()]
        out = execute_reviewed(**self.params)
        self.assertEqual(out["finding_status"], "NOT_DETECTED")
        self.assertFalse(any("shell" in str(x) for x in run.call_args.kwargs))
        self.assertIn("-no-interactsh", run.call_args.args[0])

    @patch("verification.reviewed_nuclei.subprocess.run")
    def test_detected_stays_potential(self, run):
        run.side_effect = [type("R", (), {"returncode":0,"stdout":"v3"})(),
                           type("R", (), {"returncode":0,"stdout":'{"template-id":"safe","info":{"severity":"low"},"matched-at":"http://127.0.0.1:8080"}'})()]
        out = execute_reviewed(**self.params)
        self.assertEqual(out["finding_status"], "POTENTIAL")

    @patch("verification.reviewed_nuclei.subprocess.run")
    def test_bad_scope_blocks_process(self, run):
        with self.assertRaises(ValueError):
            execute_reviewed(**{**self.params, "origin":"http://203.0.113.2:8080"})
        run.assert_not_called()

    @patch("verification.reviewed_nuclei.subprocess.run")
    def test_hash_mismatch_blocks_process(self, run):
        with self.assertRaises(ValueError):
            execute_reviewed(**{**self.params,"template_allowlist":{"safe.yaml":"0"*64}})
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
