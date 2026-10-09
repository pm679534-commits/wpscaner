"""Small offline checks for unsafe ZIPs and scan result handling."""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanner  # noqa: E402


class ScannerTests(unittest.TestCase):
    def test_rejects_zip_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../outside.php", "<?php echo 1;")
            with self.assertRaises(ValueError):
                scanner.extract_safely(archive, Path(temp) / "out")
            self.assertFalse((Path(temp) / "outside.php").exists())

    def test_accepts_normal_zip(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "good.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("plugin/main.php", "<?php echo 1;")
            destination = Path(temp) / "out"
            scanner.extract_safely(archive, destination)
            self.assertTrue((destination / "plugin/main.php").is_file())

    def test_no_scanned_files_is_error(self):
        result = type("Result", (), {
            "returncode": 0, "stdout": json.dumps({
                "results": [], "errors": [], "paths": {"scanned": []},
            }), "stderr": "",
        })()
        with patch.object(scanner.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError):
                scanner.scan("semgrep", Path("."))

    def test_findings_are_not_scan_errors(self):
        finding = {"check_id": "test", "path": "plugin/main.php"}
        result = type("Result", (), {
            "returncode": 0, "stdout": json.dumps({
                "results": [finding], "errors": [],
                "paths": {"scanned": ["plugin/main.php"]},
            }), "stderr": "",
        })()
        with patch.object(scanner.subprocess, "run", return_value=result):
            self.assertEqual(scanner.scan("semgrep", Path(".")), [finding])

    def test_codex_opens_with_report_context(self):
        report = {"plugins": [{
            "slug": "sample", "version": "1.0",
            "findings": [{"check_id": "rule", "path": "sample/main.php",
                          "start": {"line": 12}}],
        }]}
        result = type("Result", (), {"returncode": 0})()
        with patch.object(scanner.shutil, "which", return_value="codex"):
            with patch("builtins.print"):
                with patch.object(scanner.subprocess, "run", return_value=result) as run:
                    scanner.open_codex(Path("/tmp/results"), report)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:4], ["codex", "--sandbox", "read-only", "--search"])
        self.assertIn("sample/main.php:12", args[0][4])
        self.assertEqual(kwargs["cwd"], Path("/tmp/results"))


if __name__ == "__main__":
    unittest.main()
