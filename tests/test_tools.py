import subprocess
import tempfile
import unittest
from pathlib import Path

from auditor.repository import AuditError, normalize_url
from auditor.safety import redact
from tools import InspectionTools


class RepositoryFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        (self.root / "README.md").write_text("# Demo\nSee tests\n", encoding="utf-8")
        (self.root / "config.py").write_text('password = "a-private-value"\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        self.tools = InspectionTools(self.root)

    def tearDown(self):
        self.temp.cleanup()


class ToolTests(RepositoryFixture, unittest.TestCase):
    def test_listing_and_numbered_reads(self):
        self.assertEqual(self.tools.execute("list_files", {})["files"], ["README.md", "config.py"])
        result = self.tools.execute("read_file", {"path": "README.md", "start_line": 2, "end_line": 2})
        self.assertEqual(result["lines"], [{"line": 2, "text": "See tests"}])
        self.assertEqual(self.tools.observed["README.md"], {2})

    def test_search_and_redaction(self):
        result = self.tools.execute("search_code", {"pattern": "PASSWORD"})
        self.assertEqual(result["matches"][0]["line"], 1)
        self.assertNotIn("a-private-value", str(result))
        self.assertIn("REDACTED", str(result))

    def test_unsafe_and_missing_paths_return_errors(self):
        for path in ("../outside", ".git/config", "C:/Windows/file", "missing.txt"):
            with self.subTest(path=path):
                self.assertIn("error", self.tools.execute("read_file", {"path": path}))

    def test_invalid_arguments_and_unknown_tool(self):
        self.assertIn("error", self.tools.execute("read_file", {"path": "README.md", "start_line": 0}))
        self.assertIn("error", self.tools.execute("search_code", {"pattern": ""}))
        self.assertIn("error", self.tools.execute("run_shell", {}))

    def test_binary_and_large_files(self):
        (self.root / "binary").write_bytes(b"a\x00b")
        (self.root / "large").write_bytes(b"x" * 512_001)
        for path in ("binary", "large"):
            self.assertIn("error", self.tools.execute("read_file", {"path": path}))

    def test_url_validation(self):
        self.assertEqual(normalize_url("https://github.com/owner/repo.git"), "https://github.com/owner/repo")
        for value in ("https://evil.com/a/b", "https://github.com/a/b?x=1", "file:///tmp/x", "https://github.com/a/.."):
            with self.assertRaises(AuditError):
                normalize_url(value)

    def test_known_token_redaction_preserves_lines(self):
        token = "ghp_" + "x" * 36
        value = "key: " + token + "\nnext"
        self.assertNotIn(token, redact(value))
        self.assertEqual(redact(value).count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
