"""mcp-devops-server — a "Development Workflow" MCP server.

Built with the official MCP Python SDK's high-level FastMCP API
(https://github.com/modelcontextprotocol/python-sdk). The general shape of
this file (instantiate FastMCP, register capabilities with the
@mcp.resource / @mcp.tool / @mcp.prompt decorators, run with
`mcp.run()`) follows the pattern demonstrated in the SDK's own example
servers (modelcontextprotocol/python-sdk, "examples/" directory). No code
is copied verbatim from that repo; only the decorator-based server
structure is reused.

Capabilities:
  - resource: repo://{repo_path}/report   — read-only git repo report
  - tool:     create_github_issue          — opens a GitHub issue via REST API
  - prompt:   code_review_checklist        — structured code-review template

See README.md for setup and usage instructions, and exploits/ for scripts
that import the validation and rate-limiting functions below directly to
demonstrate that they block path traversal and rate-limit abuse.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

load_dotenv()  # populates os.environ from a local .env file (python-dotenv)

mcp = FastMCP(
    "devops-workflow",
    dependencies=["python-dotenv", "requests"],
)

WORKSPACE_ROOT_ENV = "MCP_WORKSPACE_ROOT"


# ---------------------------------------------------------------------------
# repo_path validation (used by the repo://{repo_path}/report resource)
#
# These functions are plain, side-effect-free and imported directly by
# exploits/exploit_path_traversal.py to prove they reject traversal and
# shell-metacharacter attacks without needing a running MCP server.
# ---------------------------------------------------------------------------

# Whitelist-only: letters, digits, underscore, dot, dash and forward slash.
# Anything else (spaces, `; | & $ ( ) < > \` * ? ! # newlines, backslashes,
# URL-encoded sequences, etc.) is rejected outright. The path may not start
# or end with '.', '/', or '-' — this also rejects a bare "." or "..".
_SAFE_REPO_PATH_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.\-/]*[A-Za-z0-9_])?$")


def get_workspace_root() -> Path:
    """Resolve and validate the configured MCP_WORKSPACE_ROOT directory."""
    raw = os.environ.get(WORKSPACE_ROOT_ENV)
    if not raw:
        raise ValueError(f"{WORKSPACE_ROOT_ENV} environment variable is not set")
    root = Path(raw).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise ValueError(f"{WORKSPACE_ROOT_ENV} ({root}) is not a directory")
    return root


def validate_repo_path(repo_path: str, workspace_root: Path | None = None) -> Path:
    """Validate a repo_path segment and confine it to the workspace root.

    Raises ValueError for anything suspicious: empty/non-string input, null
    bytes, absolute paths, home-dir expansion, shell metacharacters, ".."
    traversal segments, symlink escapes, or a target that isn't an existing
    git repository (no .git directory). Returns the resolved, safe
    absolute Path on success.
    """
    if not isinstance(repo_path, str) or not repo_path:
        raise ValueError("repo_path must be a non-empty string")

    if "\x00" in repo_path:
        raise ValueError("repo_path must not contain null bytes")

    # Reject absolute paths / home-dir / Windows drive letters outright,
    # before any filesystem interaction.
    if repo_path.startswith(("/", "\\")) or repo_path.startswith("~") or re.match(r"^[A-Za-z]:", repo_path):
        raise ValueError("repo_path must be a relative path")

    if not _SAFE_REPO_PATH_RE.match(repo_path):
        raise ValueError(
            "repo_path contains characters outside the allowed set "
            "[A-Za-z0-9_.-/]; shell metacharacters are not permitted"
        )

    # Reject '..' or empty segments (e.g. "a//b", "a/../b") explicitly.
    # The regex above already blocks most of this structurally, but a
    # string like "foo/../etc" is made entirely of allowed characters, so
    # we also inspect path segments directly (defense in depth).
    segments = repo_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError("repo_path must not contain '..', '.', or empty path segments")

    root = workspace_root if workspace_root is not None else get_workspace_root()
    candidate = (root / repo_path).resolve(strict=False)

    # Confinement check: the fully resolved path (symlinks included) must
    # still live under the workspace root.
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError("repo_path escapes MCP_WORKSPACE_ROOT") from None

    if not candidate.is_dir():
        raise ValueError(f"repo_path '{repo_path}' does not exist under the workspace root")

    if not (candidate / ".git").is_dir():
        raise ValueError(f"repo_path '{repo_path}' is not a git repository (no .git directory)")

    return candidate


# ---------------------------------------------------------------------------
# repo://{repo_path}/report resource
# ---------------------------------------------------------------------------

GIT_TIMEOUT_SECONDS = 10

_LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (JSX)",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".c": "C",
    ".h": "C Header",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++ Header",
    ".cs": "C#",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".m": "Objective-C",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".md": "Markdown",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sql": "SQL",
    ".r": "R",
    ".lua": "Lua",
}


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run a git subcommand with an explicit argv list (never shell=True)."""
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def _run_git(args: list[str], cwd: Path) -> str:
    """Run a git subcommand, raising RuntimeError on non-zero exit."""
    result = _git(args, cwd)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _current_branch(repo_dir: Path) -> str:
    # symbolic-ref works even on a brand-new repo with no commits yet
    # (an "unborn" HEAD), unlike `rev-parse --abbrev-ref HEAD`.
    result = _git(["symbolic-ref", "--short", "HEAD"], repo_dir)
    if result.returncode == 0:
        return result.stdout.strip()

    detached = _git(["rev-parse", "--short", "HEAD"], repo_dir)
    if detached.returncode == 0:
        return f"(detached HEAD at {detached.stdout.strip()})"

    return "(unborn branch, no commits yet)"


def _uncommitted_summary(repo_dir: Path) -> tuple[list[str], str]:
    output = _run_git(["status", "--porcelain"], repo_dir)
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        return [], "clean (no uncommitted changes)"
    return lines, f"{len(lines)} changed path(s)"


def _last_commits(repo_dir: Path, count: int = 10) -> list[str]:
    result = _git(
        ["log", f"-{count}", "--pretty=format:%h %ad %an: %s", "--date=short"],
        repo_dir,
    )
    if result.returncode != 0:
        # No commits yet is not an error condition worth surfacing loudly.
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def _language_breakdown(repo_dir: Path) -> dict[str, int]:
    # Uses git itself (tracked + untracked-but-not-ignored files) rather
    # than a raw filesystem walk, so vendored/build directories that are
    # gitignored (.venv, node_modules, __pycache__, ...) don't drown out
    # the repo's actual source breakdown.
    result = _git(["ls-files", "--cached", "--others", "--exclude-standard"], repo_dir)
    if result.returncode != 0:
        return {}

    counts: dict[str, int] = {}
    for rel_path in result.stdout.splitlines():
        if not rel_path.strip():
            continue
        ext = Path(rel_path).suffix.lower()
        label = _LANGUAGE_BY_EXTENSION.get(ext, ext if ext else "(no extension)")
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


@mcp.resource("repo://{repo_path}/report")
def repo_report(repo_path: str) -> str:
    """Read-only git report for a repo inside MCP_WORKSPACE_ROOT.

    Includes the current branch, an uncommitted-change summary (from
    `git status --porcelain`), the last 10 commits, and a file/language
    breakdown.
    """
    repo_dir = validate_repo_path(repo_path)

    branch = _current_branch(repo_dir)
    changed_lines, changes_summary = _uncommitted_summary(repo_dir)
    commits = _last_commits(repo_dir)
    languages = _language_breakdown(repo_dir)

    lines: list[str] = []
    lines.append(f"# Git Repo Report: {repo_path}")
    lines.append("")
    lines.append(f"**Current branch:** {branch}")
    lines.append("")
    lines.append(f"## Uncommitted changes ({changes_summary})")
    if changed_lines:
        lines.extend(f"- {line}" for line in changed_lines)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Last 10 commits")
    if commits:
        lines.extend(f"- {commit}" for commit in commits)
    else:
        lines.append("- (no commits found)")
    lines.append("")
    lines.append("## File / language breakdown")
    if languages:
        lines.extend(f"- {lang}: {count} file(s)" for lang, count in languages.items())
    else:
        lines.append("- (no tracked files found)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# create_github_issue tool
#
# validate_github_repo() and RateLimiter are plain functions/classes,
# imported directly by exploits/exploit_rate_limit.py to prove the sliding
# window blocks a 6th rapid call.
# ---------------------------------------------------------------------------

GITHUB_API_BASE = "https://api.github.com"

# Pragmatic subset of GitHub's owner/repo naming rules: alphanumerics,
# single hyphens/underscores/dots, exactly one '/'. This is intentionally
# strict — the goal is to make it impossible to smuggle path traversal or
# extra URL segments into the request URL, not to fully replicate GitHub's
# username rules.
_GITHUB_OWNER_RE = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_GITHUB_REPO_NAME_RE = r"[A-Za-z0-9_.-]{1,100}"
_GITHUB_REPO_RE = re.compile(rf"^{_GITHUB_OWNER_RE}/{_GITHUB_REPO_NAME_RE}$")


def validate_github_repo(repo: str) -> str:
    """Validate that `repo` is a strict 'owner/repo' string. Raises ValueError."""
    if not isinstance(repo, str) or not repo:
        raise ValueError("repo must be a non-empty string")
    if "\x00" in repo or any(ch.isspace() for ch in repo):
        raise ValueError("repo must not contain whitespace or null bytes")
    if repo.count("/") != 1:
        raise ValueError("repo must contain exactly one '/' (owner/repo)")
    if not _GITHUB_REPO_RE.match(repo):
        raise ValueError("repo must match GitHub's 'owner/repo' naming format")
    _, name = repo.split("/")
    if name in (".", ".."):
        raise ValueError("repo name must not be '.' or '..'")
    return repo


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter (thread-safe).

    Allows at most `max_calls` within any trailing `window_seconds` window.
    """

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> tuple[bool, float]:
        """Attempt to record a call. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            while self._calls and now - self._calls[0] >= self.window_seconds:
                self._calls.popleft()
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return True, 0.0
            retry_after = self.window_seconds - (now - self._calls[0])
            return False, max(retry_after, 0.0)

    def reset(self) -> None:
        """Clear all recorded calls (used by tests/exploit demos)."""
        with self._lock:
            self._calls.clear()


github_issue_rate_limiter = SlidingWindowRateLimiter(max_calls=5, window_seconds=60.0)


@mcp.tool()
def create_github_issue(
    repo: str,
    title: str,
    body: str,
    labels: list[str] | None = None,
) -> dict:
    """Create a GitHub issue via the REST API.

    Args:
        repo: Target repository as "owner/repo".
        title: Issue title (required, non-empty).
        body: Issue body/description.
        labels: Optional list of label names to apply.

    Rate-limited to 5 calls per 60 seconds (in-memory sliding window).
    Requires GITHUB_TOKEN to be set (e.g. via a .env file).
    """
    validate_github_repo(repo)
    if not isinstance(title, str) or not title.strip():
        raise ValueError("title must be a non-empty string")

    allowed, retry_after = github_issue_rate_limiter.try_acquire()
    if not allowed:
        raise RuntimeError(
            f"Rate limit exceeded: create_github_issue allows "
            f"{github_issue_rate_limiter.max_calls} calls per "
            f"{int(github_issue_rate_limiter.window_seconds)}s. "
            f"Try again in {retry_after:.1f}s."
        )

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not set (add it to your .env file)")

    payload: dict = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels

    response = requests.post(
        f"{GITHUB_API_BASE}/repos/{repo}/issues",
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mcp-devops-server",
        },
        timeout=15,
    )

    if response.status_code >= 400:
        raise RuntimeError(f"GitHub API error {response.status_code}: {response.text[:500]}")

    data = response.json()
    return {
        "number": data.get("number"),
        "url": data.get("html_url"),
        "title": data.get("title"),
        "state": data.get("state"),
        "labels": [label.get("name") for label in data.get("labels", [])],
    }


# ---------------------------------------------------------------------------
# code_review_checklist prompt
# ---------------------------------------------------------------------------

_LANGUAGE_HINTS = {
    "python": "- Type hints and mutable default arguments\n"
    "- PEP 8 naming and layout\n"
    "- Correct use of context managers for resources (files, locks, connections)",
    "javascript": "- Strict equality (`===`) over loose equality\n"
    "- Unhandled promise rejections / missing `await`\n"
    "- Correct `this` binding and closures over loop variables",
    "typescript": "- Avoidance of `any`; soundness of type narrowing\n"
    "- Unhandled promise rejections / missing `await`\n"
    "- Correct use of union/discriminated types instead of casts",
    "go": "- Every returned `error` is checked or explicitly ignored\n"
    "- Goroutine lifetimes and possible leaks\n"
    "- Correct use of `defer` for cleanup",
    "java": "- Resource cleanup (try-with-resources)\n"
    "- Checked exception handling\n"
    "- Correct `equals`/`hashCode` overrides",
    "rust": "- Unnecessary `unwrap`/`expect` in non-test code\n"
    "- Ownership/borrowing correctness and unneeded `clone()`\n"
    "- `unsafe` blocks are justified and minimal",
}


@mcp.prompt()
def code_review_checklist(diff: str, language: str = "python") -> str:
    """Build a structured code-review prompt for the given diff."""
    language_key = language.strip().lower()
    language_hints = _LANGUAGE_HINTS.get(
        language_key, "- Idiomatic use of the language's standard patterns and conventions"
    )

    return f"""You are performing a rigorous code review of the following {language} diff.

## Diff
```diff
{diff}
```

## Review checklist

1. **Correctness** — Does the change do what it claims? Check edge cases,
   off-by-one errors, null/None handling, and boundary conditions.
2. **Security** — Look for injection risks (SQL, shell, command), unsafe
   deserialization, hardcoded secrets/credentials, missing input
   validation, and unsafe use of user-controlled data (paths, URLs).
3. **Error handling** — Are failures handled explicitly? Are exceptions
   too broad or silently swallowed? Are external calls (network, disk,
   subprocess) given timeouts and failure paths?
4. **Tests** — Is the change covered by tests? Do the tests exercise the
   new behavior and its edge cases, not just the happy path?
5. **Readability & naming** — Are names accurate and unambiguous? Is the
   change scoped to what's needed, without unrelated churn?
6. **Performance** — Any obvious inefficiencies (N+1 queries, unnecessary
   copies/allocations, quadratic loops over large inputs)?
7. **{language.title()}-specific idioms**
{language_hints}

## Output format

For each issue found, report:
- File and line (or diff hunk)
- Severity: blocker / major / minor / nit
- Explanation of the problem
- Suggested fix

If no issues are found in a category, state "No issues found" for that
category rather than omitting it.
"""


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
