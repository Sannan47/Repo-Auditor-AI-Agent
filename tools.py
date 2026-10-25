"""Read-only inspection tools. Repository code is never imported or executed."""

import json
from pathlib import Path, PurePosixPath

from auditor.repository import AuditError, git_command
from auditor.safety import redact, sanitize


MAX_FILE_BYTES = 512_000
MAX_OUTPUT_CHARS = 32_000
MAX_FILES = 10_000


class InspectionTools:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.observed: dict[str, set[int]] = {}
        self.listing_complete = False

    def _path(self, path: str) -> Path:
        relative = PurePosixPath(path)
        if not path or "\\" in path or relative.is_absolute() or any(
            part in {"..", ".git"} or ":" in part for part in relative.parts
        ):
            raise AuditError("Path must be repository-relative and outside .git")
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink() or current.is_junction():
                raise AuditError("Symbolic links and junctions are not followed")
        if not current.resolve().is_relative_to(self.root):
            raise AuditError("Path escapes repository")
        return current

    def _files(self) -> list[str]:
        # Git's tracked paths avoid walking .git or following directory links.
        raw = git_command(["ls-files", "-z"], cwd=self.root)
        return sorted(path for path in raw.split("\0") if path)

    def list_files(self) -> dict:
        paths = self._files()
        selected = paths[:MAX_FILES]
        self.listing_complete = len(paths) <= MAX_FILES
        return {"files": selected, "total_files": len(paths), "truncated": not self.listing_complete}

    def _read(self, path: str) -> list[str]:
        target = self._path(path)
        if not target.is_file():
            raise AuditError("File does not exist or is not a regular file")
        with target.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise AuditError(f"File exceeds the {MAX_FILE_BYTES}-byte inspection limit")
        if b"\0" in data:
            raise AuditError("Binary file is not supported by this text inspection tool")
        # Redact complete blocks BEFORE pagination or numbered-line construction.
        return redact(data.decode("utf-8", errors="replace")).splitlines()

    def read_file(self, path: str, start_line: int = 1, end_line: int = 200) -> dict:
        if type(start_line) is not int or type(end_line) is not int or start_line < 1 or end_line < start_line:
            raise AuditError("Use positive integer line numbers with end_line >= start_line")
        lines = self._read(path)
        selected = []
        chars = 0
        for number in range(start_line, min(end_line, len(lines)) + 1):
            entry = {"line": number, "text": lines[number - 1]}
            cost = len(json.dumps(entry))
            if chars + cost > MAX_OUTPUT_CHARS:
                break
            selected.append(entry)
            chars += cost
        self.observed.setdefault(path, set()).update(row["line"] for row in selected)
        last = selected[-1]["line"] if selected else start_line - 1
        return {"path": path, "total_lines": len(lines), "lines": selected,
                "truncated": last < min(end_line, len(lines)),
                "more_lines": last < len(lines), "next_line": last + 1 if last < len(lines) else None}

    def search_code(self, pattern: str) -> dict:
        """Case-insensitive literal search avoids untrusted regex execution."""
        if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
            raise AuditError("Search pattern must be a nonempty literal string of at most 256 characters")
        matches, skipped = [], []
        chars = 0
        paths = self._files()
        for path in paths[:MAX_FILES]:
            try:
                lines = self._read(path)
            except (AuditError, OSError) as exc:
                if len(skipped) < 50:
                    skipped.append({"path": path, "reason": str(exc)})
                continue
            for number, line in enumerate(lines, 1):
                if pattern.casefold() in line.casefold():
                    entry = {"file": path, "line": number, "text": line}
                    chars += len(json.dumps(entry))
                    if len(matches) >= 100 or chars > MAX_OUTPUT_CHARS:
                        return {"matches": matches, "truncated": True, "skipped": skipped}
                    matches.append(entry)
                    self.observed.setdefault(path, set()).add(number)
        return {"matches": matches, "truncated": len(paths) > MAX_FILES, "skipped": skipped}

    def git_log(self) -> dict:
        history = redact(git_command(["--no-pager", "log", "-30", "--format=%h %aI %s", "--no-decorate"], cwd=self.root))
        return {"history": history[:MAX_OUTPUT_CHARS], "scope": "Latest 30 commits from a shallow clone of at most 100 commits",
                "truncated": len(history) > MAX_OUTPUT_CHARS}

    def execute(self, name: str, arguments: dict) -> dict:
        if name not in {"list_files", "read_file", "search_code", "git_log"}:
            return {"error": "Unknown inspection tool"}
        try:
            return sanitize(getattr(self, name)(**arguments))
        except (AuditError, OSError, TypeError, ValueError) as exc:
            return sanitize({"error": str(exc)})
