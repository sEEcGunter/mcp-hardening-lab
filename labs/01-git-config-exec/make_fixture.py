"""Create a temporary Git repo whose config names a harmless marker script.

The repo is created at runtime under the system temp directory and is never
committed to this project. The script's only effect is to create one marker
file at `/tmp/mcp-lab-pwned-<id>`.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SINKS = ("fsmonitor", "diff.external", "filter.clean")


def marker_path(run_id: str) -> Path:
    return Path(f"/tmp/mcp-lab-pwned-{run_id}")


def make_fixture(sink: str, run_id: str | None = None) -> tuple[Path, Path]:
    """Return `(repo, marker)` for one sink.

    `fsmonitor` is hit by `git status`. `diff.external` and `filter.clean`
    are hit by `git diff`. The marker does not exist yet. It appears only if
    a later git command actually runs the repository-supplied script.
    """
    if sink not in SINKS:
        raise ValueError(f"unknown sink {sink!r}; expected one of {SINKS}")
    run_id = run_id or uuid.uuid4().hex
    marker = marker_path(run_id)
    marker.unlink(missing_ok=True)

    repo = Path(tempfile.mkdtemp(prefix=f"mcp-lab-{sink}-"))
    script = repo / "marker.sh"
    # One write, to the marker path only. No network and no other files.
    script.write_text(
        "#!/bin/sh\n" f"printf 'ok\\n' > {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    _git(repo, "init", "-q")
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    if sink == "diff.external":
        # An unstaged change is what makes `git diff` invoke diff.external.
        (repo / "README.md").write_text("hello\nchanged\n", encoding="utf-8")
        _git(repo, "config", "diff.external", str(script))
    elif sink == "filter.clean":
        # Attribute plus a dirty worktree file makes `git diff` run the clean
        # filter. Set both after the setup commit so that commit does not.
        (repo / ".gitattributes").write_text("README.md filter=lab\n", encoding="utf-8")
        (repo / "README.md").write_text("hello\nchanged\n", encoding="utf-8")
        _git(repo, "config", "filter.lab.clean", str(script))
    else:
        _git(repo, "config", "core.fsmonitor", str(script))
    return repo, marker


def _git(repo: Path, *args: str) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "lab"
    env["GIT_AUTHOR_EMAIL"] = "lab@example.com"
    env["GIT_COMMITTER_NAME"] = "lab"
    env["GIT_COMMITTER_EMAIL"] = "lab@example.com"
    subprocess.run(
        ["git", "-c", "user.name=lab", "-c", "user.email=lab@example.com", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def demo() -> int:
    here = Path(__file__).resolve().parent
    vulnerable = _load(here / "vulnerable.py", "lab01_vulnerable_demo")
    fixed = _load(here / "fixed.py", "lab01_fixed_demo")
    print("=== Lab 01: repository Git config -> code execution ===")
    print("payload: marker.sh writes one file and nothing else")
    failures = 0
    cases = (
        ("fsmonitor", "git_status"),
        ("diff.external", "git_diff_unstaged"),
        ("filter.clean", "git_diff_unstaged"),
    )
    for sink, tool in cases:
        for label, module, expect_marker in (
            ("vulnerable", vulnerable, True),
            ("fixed", fixed, False),
        ):
            repo, marker = make_fixture(sink)
            try:
                getattr(module, tool)(str(repo))
                wrote = marker.is_file()
            finally:
                marker.unlink(missing_ok=True)
                shutil.rmtree(repo, ignore_errors=True)
            state = "WRITTEN" if wrote else "absent"
            print(f"{label:<12} {tool:<20} {sink:<16} marker {state}  {marker}")
            if wrote != expect_marker:
                failures += 1
                print(f"  expected marker {'WRITTEN' if expect_marker else 'absent'}")
    if failures:
        print(f"lab 01 demo failed: {failures} unexpected result(s)")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run the vulnerable tools, then the fixed tools, and print the marker result",
    )
    args = parser.parse_args(argv)
    if not args.demo:
        parser.error("pass --demo")
    return demo()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
