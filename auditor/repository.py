"""Bounded, unattended cloning of public GitHub repositories."""

import os
import re
import subprocess
from pathlib import Path


class AuditError(Exception):
    """A useful, safe-to-display audit failure."""


def normalize_url(url: str) -> str:
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9_.-]+)/?", url)
    if not match:
        raise AuditError("Use a public repository URL: https://github.com/OWNER/REPOSITORY")
    owner, name = match.groups()
    if name.endswith(".git"):
        name = name[:-4]
    if not name or name in {".", ".."}:
        raise AuditError("Invalid GitHub repository name")
    return f"https://github.com/{owner}/{name}"


def git_environment() -> dict:
    env = os.environ.copy()
    # Ignore inherited configuration that could enable hooks, filters or URL rewrites.
    for key in list(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
        "GCM_INTERACTIVE": "Never",
    })
    return env


def git_command(args: list[str], cwd: Path | None = None, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "credential.helper=",
             "-c", "core.fsmonitor=false", *args],
            cwd=cwd, env=git_environment(), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise AuditError("Git is not installed or is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise AuditError(f"Git operation timed out after {timeout} seconds") from exc
    if result.returncode:
        # Remote output may contain secrets or adversarial content. Do not echo it.
        raise AuditError("Git operation failed. Check the public repository URL, network access, and Git installation.")
    return result.stdout


def clone_repository(url: str, destination: Path) -> None:
    git_command(["clone", "--depth", "100", "--single-branch", "--no-tags", "--",
                 normalize_url(url), str(destination)], timeout=120)
