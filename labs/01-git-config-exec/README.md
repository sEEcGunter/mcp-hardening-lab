# Lab 01 — repository Git config to code execution

Local copy of the bug class in [GHSA-6hqx-gqrx-c5r2](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-6hqx-gqrx-c5r2) (`mcp-server-git` before `2026.11.11`).

`git_status` and `git_diff_unstaged` are registered on a FastMCP server. Tests and the demo call those functions directly. No model is involved.

## What is vulnerable

`vulnerable.py` runs `git -C <repo> -c core.quotepath=false status` and `git diff`. That is the pre-fix shape the advisory describes (only `core.quotepath=false`, cited there as `server.py:104` at revision `36380287`). Git then honors the repo's `.git/config`:

- `core.fsmonitor` runs on status, when Git refreshes the index.
- `diff.external` runs on `git diff`.
- `filter.<name>.clean`, named from `.gitattributes`, runs on `git diff` for a dirty file. On Git 2.43, `git status` did not run that clean filter; the lab triggers it through `git_diff_unstaged`.

`make_fixture.py` builds a throwaway repo in a temp directory. Its script only creates `/tmp/mcp-lab-pwned-<id>`. The repo is not part of this project.

## What is fixed

`fixed.py` follows the patched `src/git/src/mcp_server_git/server.py` read at `e1dc4b18`:

- `HARDENED_CONFIG` (lines 134-143) is passed on every call through `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` (the helper is lines 178-185).
- Diffs get `--no-ext-diff --no-textconv` (line 168). Status and diff get `--ignore-submodules=dirty` (line 175).
- Git older than 2.31 is refused, and so is a Git that does not report the hooks-path override as scope `command` (the upstream refusal is lines 218-223).
- `filter.*.clean` / `smudge` / `process`, `merge.*.driver`, and `branch.*.mergeOptions` are read with `git config --show-scope --get-regexp` and blanked with an empty `GIT_CONFIG_VALUE` only when the scope is `local` or `worktree` (upstream does this at lines 145-160 and 191-226, using a `-z` listing). `global` and `system` drivers, including Git LFS, are not overridden.

## Run

From the repository root: `make test` and `make demo`. Captured demo output is in the root README.
