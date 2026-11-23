"""Git tools with repository-controlled command sinks neutralized.

Simplified re-implementation of the fix shipped in `mcp-server-git` 2026.11.11
(GHSA-6hqx-gqrx-c5r2). The static override list, diff flags, and Git >= 2.31
refusal match the patched `src/git/src/mcp_server_git/server.py` read at
`e1dc4b18` (HARDENED_CONFIG lines 134-143, `_DIFF_FLAGS` line 168,
`_NO_SUBMODULE_STATUS` line 175, `_config_env` lines 178-185, the version
refusal lines 218-223). Repository-defined filter drivers, merge drivers, and
`branch.*.mergeOptions` are blanked the same way as upstream lines 145-160
and 191-226, but only when `git config --show-scope` reports `local` or
`worktree`. Global and system drivers, such as Git LFS, are left alone.
The listing here is line-oriented; upstream uses `-z`.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping, Sequence

from mcp.server.fastmcp import FastMCP

# GIT_CONFIG_COUNT exists since Git 2.31. Older Git ignores it, so the
# overrides below would silently do nothing.
MIN_GIT: tuple[int, int] = (2, 31)

# Highest-precedence overrides applied on every git invocation. Values are
# strings Git treats as "off" or as a program that does not execute a hook.
HARDENED_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.pager", "cat"),
    ("commit.gpgSign", "false"),
    ("merge.verifySignatures", "false"),
    ("submodule.recurse", "false"),
    ("status.submoduleSummary", "false"),
    ("merge.autoStash", "false"),
)

# `--no-ext-diff` disables diff.external and diff.<driver>.command.
# `--no-textconv` disables textconv filters. `--ignore-submodules=dirty`
# keeps status/diff from running git inside a submodule's own config.
DIFF_FLAGS: tuple[str, ...] = ("--no-ext-diff", "--no-textconv")
SUBMODULE_FLAG = "--ignore-submodules=dirty"

# Drivers whose names the repository chooses. Git prints keys in lowercase.
_DRIVER_KEY = re.compile(
    r"^(filter\..+\.(clean|smudge|process)|merge\..+\.driver|branch\..+\.mergeoptions)$",
    re.IGNORECASE,
)
_DRIVER_REGEXP = (
    r"^(filter\..+\.(clean|smudge|process)|merge\..+\.driver|branch\..+\.merge[Oo]ptions)$"
)
# `command` is our own override. `global` and `system` belong to the user
# (Git LFS lives there). Only the repository's own scopes are blanked.
_REPO_SCOPES = frozenset({"local", "worktree"})

mcp = FastMCP("lab-git-fixed")


def parse_git_version(text: str) -> tuple[int, int]:
    match = re.search(r"(\d+)\.(\d+)", text)
    if not match:
        raise RuntimeError(f"cannot parse git version from {text!r}")
    return int(match.group(1)), int(match.group(2))


def require_git_version(version: tuple[int, int]) -> None:
    if version < MIN_GIT:
        raise RuntimeError(
            "Git 2.31 or later is required. Older Git ignores GIT_CONFIG_COUNT, "
            "so a repository's own config would still be able to run programs."
        )


def installed_git_version() -> tuple[int, int]:
    try:
        text = subprocess.check_output(
            ["git", "--version"], text=True, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("git is not runnable; refusing to continue") from exc
    return parse_git_version(text)


def config_env(
    base: Mapping[str, str] | None = None,
    extra: Sequence[tuple[str, str]] = (),
) -> dict[str, str]:
    """Return env with HARDENED_CONFIG, then `extra`, appended via GIT_CONFIG_COUNT.

    Existing GIT_CONFIG_* entries are kept and ours are added after them, so
    a caller-supplied override cannot drop the sinks and our values win when
    the same key appears twice (later `-c` / GIT_CONFIG entries win).
    `extra` is where repository-local driver commands are blanked.
    """
    env = dict(os.environ if base is None else base)
    entries = [*HARDENED_CONFIG, *extra]
    try:
        start = int(env.get("GIT_CONFIG_COUNT", "0") or "0")
    except ValueError as exc:
        raise RuntimeError("GIT_CONFIG_COUNT is not an integer") from exc
    if start < 0:
        raise RuntimeError("GIT_CONFIG_COUNT is negative")
    env["GIT_CONFIG_COUNT"] = str(start + len(entries))
    for offset, (key, value) in enumerate(entries):
        env[f"GIT_CONFIG_KEY_{start + offset}"] = key
        env[f"GIT_CONFIG_VALUE_{start + offset}"] = value
    return env


def driver_overrides_from_listing(text: str) -> list[tuple[str, str]]:
    """Blank `local` and `worktree` driver keys found in `git config --show-scope` output.

    Each returned value is an empty string, which makes Git skip that filter
    or merge driver. Other scopes are ignored.
    """
    overrides: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if "\t" not in line:
            continue
        scope, rest = line.split("\t", 1)
        if scope not in _REPO_SCOPES:
            continue
        key, _, _value = rest.partition(" ")
        if not _DRIVER_KEY.match(key):
            continue
        folded = key.lower()
        if folded in seen:
            continue
        seen.add(folded)
        overrides.append((key, ""))
    return overrides


def local_driver_overrides(repo_path: str, env: Mapping[str, str]) -> list[tuple[str, str]]:
    """List driver commands defined by this repository, not by global or system config."""
    proc = subprocess.run(
        ["git", "-C", repo_path, "config", "--show-scope", "--get-regexp", _DRIVER_REGEXP],
        capture_output=True,
        text=True,
        env=dict(env),
        check=False,
    )
    # Exit 1 is "nothing matched".
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            "git config --show-scope --get-regexp failed "
            f"({proc.returncode}): {proc.stderr.strip()}"
        )
    return driver_overrides_from_listing(proc.stdout)


def _assert_overrides_applied(env: Mapping[str, str]) -> None:
    """Fail closed if this Git did not honor the command-scoped hooks path.

    `core.hooksPath` is always one of our overrides. A Git that ignores
    GIT_CONFIG_COUNT will not report it as scope `command`.
    """
    proc = subprocess.run(
        ["git", "config", "--show-scope", "--get", "core.hooksPath"],
        capture_output=True,
        text=True,
        env=dict(env),
        check=False,
    )
    expected = f"command\t{os.devnull}"
    if proc.stdout.strip() != expected:
        raise RuntimeError(
            "Git did not apply GIT_CONFIG_COUNT overrides "
            f"(core.hooksPath reported {proc.stdout.strip()!r}, expected {expected!r}). "
            "Refusing to run."
        )


def _runtime_env(repo_path: str) -> dict[str, str]:
    require_git_version(installed_git_version())
    env = config_env()
    _assert_overrides_applied(env)
    drivers = local_driver_overrides(repo_path, env)
    if drivers:
        env = config_env(extra=drivers)
    return env


def _git(repo_path: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo_path, "-c", "core.quotepath=false", *args],
        capture_output=True,
        text=True,
        env=_runtime_env(repo_path),
        check=False,
    )
    if proc.returncode != 0:
        return proc.stdout + proc.stderr
    return proc.stdout


def git_status(repo_path: str) -> str:
    """Return `git status --porcelain` with command-bearing config overridden."""
    return _git(repo_path, "status", "--porcelain", SUBMODULE_FLAG)


def git_diff_unstaged(repo_path: str) -> str:
    """Return `git diff` without external diff programs or textconv filters."""
    return _git(repo_path, "diff", *DIFF_FLAGS, SUBMODULE_FLAG)


mcp.tool()(git_status)
mcp.tool()(git_diff_unstaged)


if __name__ == "__main__":
    mcp.run(transport="stdio")
