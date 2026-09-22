# mcp-devops-server (sg2676)

A minimal **Development Workflow** MCP server built with the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)'s
high-level `FastMCP` API. It exposes one resource, one tool, and
one prompt:

| Capability | Name | What it does |
|---|---|---|
| Resource | `repo://{repo_path}/report` | Read-only git report: current branch, uncommitted-change summary, last 10 commits, file/language breakdown. |
| Tool | `create_github_issue(repo, title, body, labels=None)` | Creates a GitHub issue via the REST API. Rate-limited to 5 calls / 60s. |
| Prompt | `code_review_checklist(diff, language="python")` | Returns a structured code-review prompt template. |

The server code lives in [src/server.py](src/server.py).

> The `mcp` package renamed its high-level server class from `FastMCP` to
> `MCPServer` in v2.0. This project intentionally pins `mcp<2.0.0` (see
> [pyproject.toml](pyproject.toml) / [requirements.txt](requirements.txt))
> to use the `FastMCP` API as specified.

## Setup

### 1. Install dependencies

With [uv](https://docs.astral.sh/uv/) (recommended, matches the checked-in
`uv.lock`):

```bash
uv sync
```

Or with plain pip:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment variables

Copy the example env file and fill in real values:

```bash
cp .env.example .env
```

- `GITHUB_TOKEN` — a GitHub [personal access token](https://github.com/settings/tokens)
  with `repo` (or `public_repo`) scope. Loaded automatically at server
  startup via `python-dotenv`. Required only for `create_github_issue`.
- `MCP_WORKSPACE_ROOT` — an absolute path to a directory containing the
  git repositories you want to inspect (e.g. `~/code`). Required for the
  `repo://{repo_path}/report` resource. Every `repo_path` is validated and
  confined inside this directory (see [Security model](#security-model)).

`.env` is already listed in `.gitignore` — never commit it.

### 3. Run the server

Directly (stdio transport, the default for `mcp.run()`):

```bash
uv run python src/server.py
```

Or with the MCP CLI's dev inspector (hot-reload + a web UI to call the
resource/tool/prompt by hand):

```bash
uv run mcp dev src/server.py
```

### 4. Connect it to Claude Desktop

Edit your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS) using [config/claude_desktop_config.json](config/claude_desktop_config.json)
as a template — update the absolute paths and secrets, then restart
Claude Desktop.

## Capabilities in detail

### Resource: `repo://{repo_path}/report`

`repo_path` is a path *relative to* `MCP_WORKSPACE_ROOT`, e.g.
`repo://my-project/report` reads `$MCP_WORKSPACE_ROOT/my-project`.

Before touching the filesystem or shelling out to `git`, `repo_path` goes
through `validate_repo_path()` in [src/server.py](src/server.py), which:

- rejects null bytes, absolute paths, `~` expansion, and Windows drive
  letters;
- whitelists characters to `[A-Za-z0-9_.-/]` only (blocks shell
  metacharacters like `; | & $ \` ( ) < >` and spaces);
- rejects `..`, `.`, and empty path segments (blocks traversal even
  through the whitelist, e.g. `foo/../etc`);
- resolves the path (following symlinks) and re-confirms it is still
  inside `MCP_WORKSPACE_ROOT` (blocks symlink escapes);
- requires the resolved directory to exist and contain a `.git` folder.

All git commands are invoked via `subprocess.run([...])` with an explicit
argument list and `cwd` set to the repo directory — **never** `shell=True`
and never string-interpolated into a shell command.

The report includes:
- current branch (`git symbolic-ref` / `git rev-parse`, with a graceful
  fallback for brand-new repos with no commits yet or a detached HEAD);
- uncommitted changes (`git status --porcelain`);
- the last 10 commits (`git log`);
- a file/language breakdown, computed from `git ls-files --cached
  --others --exclude-standard` (so gitignored directories like `.venv` or
  `node_modules` don't drown out the real source breakdown) mapped
  through a file-extension → language table.

### Tool: `create_github_issue`

```python
create_github_issue(repo: str, title: str, body: str, labels: list[str] | None = None) -> dict
```

- `repo` must strictly match GitHub's `owner/repo` format
  (`validate_github_repo()`); anything else (extra path segments, shell
  metacharacters, whitespace, more than one `/`) is rejected before a URL
  is ever built.
- Requires `GITHUB_TOKEN` (loaded from `.env`); posts to
  `https://api.github.com/repos/{repo}/issues` with `requests.post(...)`.
- **Rate limited to 5 calls per 60 seconds** via an in-memory sliding
  window (`SlidingWindowRateLimiter` in [src/server.py](src/server.py)).
  A 6th call inside the window is rejected immediately (no HTTP request
  is made) with a `RuntimeError` stating how long to wait.
- Returns a dict with the created issue's `number`, `url`, `title`,
  `state`, and `labels` on success.

The rate limiter is global to the running server process (not per-caller)
— it exists to protect the configured `GITHUB_TOKEN` from being burned
through accidental or malicious bursts of calls, not to implement
per-user quotas.

### Prompt: `code_review_checklist`

```python
code_review_checklist(diff: str, language: str = "python") -> str
```

Returns a structured review template covering correctness, security,
error handling, tests, readability, performance, and language-specific
idioms (with tailored hints for Python, JavaScript, TypeScript, Go, Java,
and Rust), plus a required output format for reported issues.

## Exploit demos

The [exploits/](exploits/) folder contains two standalone scripts that
**import the server's validation and rate-limiting functions directly**
(no running server or network access required) and prove they block real
attacks. This works because `FastMCP`'s `.resource()` / `.tool()`
decorators register the function but return it unchanged, so the exact
functions used by the live server can be called directly from a script.

### `exploits/exploit_path_traversal.py`

Builds a temporary workspace with a legitimate git repo, a "secret" file
placed *outside* the workspace, and a symlink inside the workspace that
points to that outside directory. It then feeds `validate_repo_path()` 14
malicious/malformed `repo_path` payloads — `../../../etc/passwd`,
absolute paths, `~` expansion, `; rm -rf /`, `$(whoami)`, backticks,
`&&`, pipes, traversal hidden behind allowed characters, a null byte, and
the symlink escape — and asserts every one is rejected, while a
legitimate path still resolves correctly.

```bash
uv run python exploits/exploit_path_traversal.py
```

Exit code `0` and `RESULT: PASS` means every attack was blocked; a
nonzero exit / `RESULT: FAIL` would mean the confinement logic regressed.

### `exploits/exploit_rate_limit.py`

Monkeypatches `requests.post` with a deterministic stub (so no real
network call or GitHub token is needed) and then calls the **real**
`create_github_issue()` tool function six times back-to-back. It asserts
calls 1–5 succeed and call 6 is rejected with the rate-limit error,
proving the limiter is wired into the actual tool path, not just tested
in isolation.

```bash
uv run python exploits/exploit_rate_limit.py
```

## Project layout

```
src/server.py                        # the MCP server (FastMCP)
exploits/exploit_path_traversal.py   # proves repo_path confinement
exploits/exploit_rate_limit.py       # proves the sliding-window limiter
config/claude_desktop_config.json    # Claude Desktop MCP config template
requirements.txt                     # pip-installable dependency list
pyproject.toml / uv.lock             # uv-managed dependency lock
.env.example                         # required environment variables
```
