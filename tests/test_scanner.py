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

    def test_php_files_without_coverage_stop_scan(self):
        result = type("Result", (), {
            "returncode": 0, "stdout": json.dumps({
                "results": [], "errors": [], "paths": {"scanned": []},
            }), "stderr": "0 files scanned",
        })()
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "main.php").write_text("<?php echo 1;", encoding="utf-8")
            with patch.object(scanner.subprocess, "run", return_value=result) as run:
                with self.assertRaises(scanner.ScanCoverageError) as caught:
                    scanner.scan("semgrep", Path(temp))
        self.assertIn("PHP faylı: 1", str(caught.exception))
        command = run.call_args.args[0]
        self.assertEqual(command.count("--config"), 2)
        self.assertIn("p/php", command)
        self.assertIn("--no-git-ignore", command)

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

    def test_codex_structured_review_uses_saved_chatgpt_login(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            def fake_run(command, **kwargs):
                answer_path = Path(command[command.index("--output-last-message") + 1])
                answer_path.write_text(json.dumps({
                    "verdict": "false_positive", "summary": "Protected by capability check",
                    "evidence": ["plugin/main.php:12"],
                }), encoding="utf-8")
                return type("Result", (), {"returncode": 0})()
            with patch.object(scanner.shutil, "which", return_value="codex"):
                with patch("builtins.print"):
                    with patch.object(scanner.subprocess, "run", side_effect=fake_run) as run:
                        review = scanner.review_with_codex(run_dir, "plugin", "1.0")
        self.assertEqual(review["verdict"], "false_positive")
        command = run.call_args.args[0]
        self.assertIn("--output-schema", command)
        self.assertIn("--skip-git-repo-check", command)
        self.assertEqual(command[-1], "-")

    def test_false_positive_continues_and_is_skipped_next_run(self):
        plugin = {
            "slug": "sample", "version": "1.0",
            "download_link": "https://downloads.wordpress.org/plugin/sample.zip",
        }
        finding = {
            "check_id": "rule", "path": "sample/main.php",
            "start": {"line": 12},
            "extra": {"severity": "WARNING", "message": "Possible issue"},
        }
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            run_dir = output / "old-run"
            archives = run_dir / "archives"
            extracted = run_dir / "extracted"
            archives.mkdir(parents=True)
            extracted.mkdir()
            progress_path = output / "progress.json"
            progress = {"completed": {}}
            report = {"created_at": "test", "pages_scanned": 1, "plugins": []}
            with patch.object(scanner, "download"):
                with patch.object(scanner, "extract_safely", side_effect=lambda _a, d: d.mkdir()):
                    with patch.object(scanner, "scan", return_value=[finding]):
                        with patch.object(scanner, "review_with_codex", return_value={
                            "verdict": "false_positive", "summary": "Guarded path",
                            "evidence": ["sample/main.php:12"],
                        }):
                            with patch("builtins.print"):
                                stopped = scanner.process_plugin(
                                    plugin, "semgrep", archives, extracted, run_dir,
                                    report, progress_path, progress, True,
                                )
            self.assertFalse(stopped)
            self.assertEqual(report["plugins"][0]["status"], "false_positive")
            self.assertFalse((extracted / "sample").exists())
            self.assertEqual(scanner.load_progress(progress_path)["completed"],
                             {"sample@1.0": "false_positive"})

            with patch.object(sys, "argv", ["scanner.py", "--count", "1", "--output", temp]):
                with patch.object(scanner, "ensure_tools", return_value="semgrep"):
                    with patch.object(scanner, "get_plugins", return_value=([plugin], 1)):
                        with patch.object(scanner, "process_plugin") as process:
                            with patch.object(scanner, "open_codex") as codex:
                                with patch("builtins.print"):
                                    result = scanner.main()
            self.assertEqual(result, 0)
            process.assert_not_called()
            codex.assert_not_called()

    def test_continues_to_next_page_and_stops_on_first_finding(self):
        pages = [
            ([{"slug": "clean-1"}, {"slug": "clean-2"}], 3),
            ([{"slug": "clean-2"}, {"slug": "found"}], 3),
        ]
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, "argv", ["scanner.py", "--count", "2", "--output", temp]):
                with patch.object(scanner, "ensure_tools", return_value="semgrep"):
                    with patch.object(scanner, "get_plugins", side_effect=pages) as get:
                        with patch.object(scanner, "process_plugin", side_effect=[False, False, True]) as process:
                            with patch.object(scanner, "open_codex") as codex:
                                with patch("builtins.print"):
                                    result = scanner.main()
        self.assertEqual(result, 0)
        self.assertEqual(get.call_count, 2)
        self.assertEqual([call.args[0]["slug"] for call in process.call_args_list],
                         ["clean-1", "clean-2", "found"])
        codex.assert_called_once()

    def test_stops_when_catalog_is_exhausted(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, "argv", ["scanner.py", "--count", "2", "--output", temp]):
                with patch.object(scanner, "ensure_tools", return_value="semgrep"):
                    with patch.object(scanner, "get_plugins", return_value=([{"slug": "clean"}], 1)) as get:
                        with patch.object(scanner, "process_plugin", return_value=False):
                            with patch.object(scanner, "open_codex") as codex:
                                with patch("builtins.print"):
                                    result = scanner.main()
        self.assertEqual(result, 0)
        get.assert_called_once_with(2, 1)
        codex.assert_not_called()

    def test_coverage_failure_does_not_advance_to_next_page(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, "argv", ["scanner.py", "--count", "1", "--output", temp]):
                with patch.object(scanner, "ensure_tools", return_value="semgrep"):
                    with patch.object(scanner, "get_plugins", return_value=([{"slug": "elementor"}], 5)) as get:
                        with patch.object(scanner, "process_plugin", side_effect=scanner.ScanCoverageError("no PHP coverage")):
                            with patch.object(scanner, "open_codex") as codex:
                                with patch("builtins.print"):
                                    result = scanner.main()
        self.assertEqual(result, 1)
        get.assert_called_once_with(1, 1)
        codex.assert_not_called()


if __name__ == "__main__":
    unittest.main()
