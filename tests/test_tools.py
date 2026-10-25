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

    def test_symlink_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "private.txt"
            secret.write_text("outside repository content", encoding="utf-8")
            try:
                (self.root / "link.txt").symlink_to(secret)
            except OSError:
                self.skipTest("Creating symbolic links requires host privileges")
            result = self.tools.execute("read_file", {"path": "link.txt"})
            self.assertIn("error", result)
            self.assertNotIn("outside repository content", str(result))

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

    def test_credential_echo_without_label_is_redacted(self):
        redact('password="fabricated-private-password"')
        self.assertNotIn("fabricated-private-password", redact("echo: fabricated-private-password"))

    def test_environment_references_are_not_credentials(self):
        text = 'password = os.getenv("DB_PASSWORD")\napi_key: ${API_KEY}\n'
        self.assertEqual(redact(text), text)

    def test_echo_before_assignment_is_redacted(self):
        (self.root / "config.py").write_text('print("fictional-secret-echo")\npassword = "fictional-secret-echo"\n', encoding="utf-8")
        result = self.tools.execute("read_file", {"path": "config.py"})
        self.assertNotIn("fictional-secret-echo", str(result))

    def test_git_history_and_repository_unchanged(self):
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Add fixture"], check=True)
        before = subprocess.run(["git", "-C", str(self.root), "status", "--porcelain"], capture_output=True, check=True).stdout
        content = (self.root / "config.py").read_bytes()
        self.assertIn("Add fixture", self.tools.execute("git_log", {})["history"])
        self.tools.execute("list_files", {})
        self.tools.execute("read_file", {"path": "config.py"})
        self.tools.execute("search_code", {"pattern": "password"})
        after = subprocess.run(["git", "-C", str(self.root), "status", "--porcelain"], capture_output=True, check=True).stdout
        self.assertEqual(before, after)
        self.assertEqual((self.root / "config.py").read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
