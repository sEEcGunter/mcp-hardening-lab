"""Repo Git config runs a command on the vulnerable tools and not on the fixed ones."""

from __future__ import annotations

import asyncio
import os
import shutil

import pytest

SINKS = (
    ("fsmonitor", "git_status"),
    ("diff.external", "git_diff_unstaged"),
    ("filter.clean", "git_diff_unstaged"),
)


def _call(module, tool: str, repo) -> str:
    return getattr(module, tool)(str(repo))


@pytest.mark.parametrize("sink,tool", SINKS)
def test_vulnerable_tool_runs_the_repository_command(git_lab, sink, tool):
    repo, marker = git_lab.fixture.make_fixture(sink)
    try:
        assert marker.exists() is False
        _call(git_lab.vuln, tool, repo)
        assert marker.is_file()
        assert marker.read_text(encoding="utf-8") == "ok\n"
    finally:
        marker.unlink(missing_ok=True)
        shutil.rmtree(repo, ignore_errors=True)


@pytest.mark.parametrize("sink,tool", SINKS)
def test_fixed_tool_does_not_run_the_repository_command(git_lab, sink, tool):
    repo, marker = git_lab.fixture.make_fixture(sink)
    try:
        assert marker.exists() is False
        output = _call(git_lab.fix, tool, repo)
        assert marker.exists() is False
        if sink == "fsmonitor":
            assert "marker.sh" in output
        else:
            # diff.external and filter.clean both leave the real worktree
            # diff in place once the repository command is not run.
            assert "changed" in output
    finally:
        marker.unlink(missing_ok=True)
        shutil.rmtree(repo, ignore_errors=True)


def test_payload_script_only_writes_the_marker(git_lab):
    repo, marker = git_lab.fixture.make_fixture("fsmonitor")
    try:
        script = (repo / "marker.sh").read_text(encoding="utf-8")
        assert script.startswith("#!/bin/sh\n")
        assert str(marker) in script
        for banned in ("curl", "wget", "nc ", "socket", "ssh", "/etc/passwd", "base64"):
            assert banned not in script
    finally:
        marker.unlink(missing_ok=True)
        shutil.rmtree(repo, ignore_errors=True)


def test_refuses_git_older_than_2_31(git_lab):
    with pytest.raises(RuntimeError, match="2.31"):
        git_lab.fix.require_git_version((2, 30))
    with pytest.raises(RuntimeError, match="2.31"):
        git_lab.fix.require_git_version((1, 99))
    git_lab.fix.require_git_version((2, 31))
    git_lab.fix.require_git_version((2, 43))


def test_parse_git_version(git_lab):
    assert git_lab.fix.parse_git_version("git version 2.43.0") == (2, 43)
    with pytest.raises(RuntimeError):
        git_lab.fix.parse_git_version("not a version")


def test_installed_git_meets_the_minimum(git_lab):
    git_lab.fix.require_git_version(git_lab.fix.installed_git_version())


def test_config_env_appends_sink_overrides(git_lab):
    env = git_lab.fix.config_env(
        {
            "PATH": "/usr/bin",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "lab",
        }
    )
    assert env["GIT_CONFIG_COUNT"] == str(1 + len(git_lab.fix.HARDENED_CONFIG))
    assert env["GIT_CONFIG_KEY_0"] == "user.name"
    for offset, (key, value) in enumerate(git_lab.fix.HARDENED_CONFIG, start=1):
        assert env[f"GIT_CONFIG_KEY_{offset}"] == key
        assert env[f"GIT_CONFIG_VALUE_{offset}"] == value


def test_live_environment_still_forces_fsmonitor_off(git_lab):
    env = git_lab.fix.config_env()
    count = int(env["GIT_CONFIG_COUNT"])
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
    assert pairs["core.fsmonitor"] == "false"
    assert pairs["core.hooksPath"] == os.devnull
    assert pairs["core.pager"] == "cat"
    assert pairs["commit.gpgSign"] == "false"


def test_driver_listing_blanks_only_repo_scopes(git_lab):
    listing = "\n".join(
        [
            "global\tfilter.lfs.clean git-lfs clean -- %f",
            "system\tfilter.lfs.smudge git-lfs smudge -- %f",
            "system\tfilter.lfs.process git-lfs filter-process",
            "local\tfilter.lab.clean /tmp/marker.sh",
            "worktree\tmerge.ours.driver /tmp/merge.sh",
            "local\tbranch.main.mergeoptions --gpg-sign",
            "command\tfilter.lab.clean ",
        ]
    )
    assert git_lab.fix.driver_overrides_from_listing(listing) == [
        ("filter.lab.clean", ""),
        ("merge.ours.driver", ""),
        ("branch.main.mergeoptions", ""),
    ]


def test_live_repo_blanks_local_clean_filter_and_keeps_global(git_lab, tmp_path):
    repo, marker = git_lab.fixture.make_fixture("filter.clean")
    try:
        global_config = tmp_path / "global.gitconfig"
        global_config.write_text("[filter \"keep\"]\n\tclean = /bin/true\n", encoding="utf-8")
        env = git_lab.fix.config_env()
        env["GIT_CONFIG_GLOBAL"] = str(global_config)
        overrides = git_lab.fix.local_driver_overrides(str(repo), env)
        keys = {key.lower() for key, value in overrides}
        assert "filter.lab.clean" in keys
        assert all(value == "" for _, value in overrides)
        for kept in ("filter.keep.clean", "filter.lfs.clean", "filter.lfs.smudge", "filter.lfs.process"):
            assert kept not in keys
    finally:
        marker.unlink(missing_ok=True)
        shutil.rmtree(repo, ignore_errors=True)


def test_git_tools_are_registered(git_lab):
    expected = {"git_status", "git_diff_unstaged"}
    for module in (git_lab.vuln, git_lab.fix):
        tools = asyncio.run(module.mcp.list_tools())
        assert {tool.name for tool in tools} == expected
