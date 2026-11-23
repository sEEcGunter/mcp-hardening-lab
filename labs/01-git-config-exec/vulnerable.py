"""Deliberately vulnerable Git tools for a local lab.

Do not point this at a repository you did not create, and do not deploy it.
`fixed.py` is the paired build that neutralizes repository-controlled Git sinks.

This is a simplified re-implementation of the pre-fix behavior described in
GHSA-6hqx-gqrx-c5r2, not the upstream `mcp-server-git` source. The advisory
says the server's only config override was `-c core.quotepath=false`
(`server.py:104` at revision 36380287). A repository can still set
`core.fsmonitor` or `diff.external` and have Git run that command.
"""

from __future__ import annotations

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("lab-git-vulnerable")


def _git(repo_path: str, *args: str) -> str:
    """Run git in the client-chosen repo, inheriting config and the environment."""
    proc = subprocess.run(
        ["git", "-C", repo_path, "-c", "core.quotepath=false", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return proc.stdout + proc.stderr
    return proc.stdout


def git_status(repo_path: str) -> str:
    """Return `git status --porcelain` for repo_path.

    Read-only in intent. A `core.fsmonitor` command in that repo's `.git/config`
    still runs, because this build never overrides it.
    """
    return _git(repo_path, "status", "--porcelain")


def git_diff_unstaged(repo_path: str) -> str:
    """Return `git diff` for repo_path.

    Read-only in intent. A `diff.external` command in that repo's `.git/config`
    still runs, because this build never passes `--no-ext-diff`.
    """
    return _git(repo_path, "diff")


mcp.tool()(git_status)
mcp.tool()(git_diff_unstaged)


if __name__ == "__main__":
    mcp.run(transport="stdio")
