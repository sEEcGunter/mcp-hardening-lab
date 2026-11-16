# MCP hardening checklist

Use this when you ship or review an MCP server that shells out to Git, or that
gates cloud API calls on a name in a policy file. The two labs in this repo
are reduced local copies of the bug classes; this list is the operator habit
that goes with them.

## Git subprocesses

- Override command-bearing config on **every** Git invocation, including the ones Git itself starts. `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` (Git 2.31+) outranks `.git/config`, included files, and the global config, and child Git processes inherit it.
- At least: `core.fsmonitor=false`, `core.hooksPath` pointed at the null device, `core.pager=cat`, `commit.gpgSign=false`, `merge.verifySignatures=false`, `submodule.recurse=false`, `status.submoduleSummary=false`, `merge.autoStash=false`.
- Pass `--no-ext-diff --no-textconv` on every diff whose output you show. That turns off `diff.external`, `diff.<driver>.command`, and textconv filters.
- Pass `--ignore-submodules=dirty` on status and on diffs that compare the work tree, so Git does not run `git status` inside a submodule under that submodule's own config.
- Blank repository-defined `filter.*.clean` / `smudge` / `process`, `merge.*.driver`, and `branch.*.mergeOptions`. A static list cannot name drivers the repo invents. Read them with `git config --show-scope --get-regexp` and blank only `local` and `worktree` entries (empty `GIT_CONFIG_VALUE`). Leave `global` and `system` drivers, such as Git LFS, in place. Lab 01 does this on every status and diff.
- Append overrides after any `GIT_CONFIG_*` values already in the environment. Replacing `GIT_CONFIG_COUNT` from zero drops your entries when the count is already set, or keeps an attacker-controlled later key if you do not come last.
- Confirm the override actually applied (for example `git config --show-scope --get core.hooksPath` reports `command` and the null device). If it did not, do not run the command.

## Git version

- Refuse Git older than 2.31. Those builds ignore `GIT_CONFIG_COUNT`, so the overrides never happen and a version check that only prints a warning is not a fix.
- Do not trust a wrapper that reports a new version and then execs an old `git`. The scope check above catches a binary that ignores the variables.

## Environment and secrets

- A repository-supplied Git command inherits the MCP server's environment. Credentials the client passed in the server's `env` block, cloud tokens, and SSH agents are in that process.
- Do not pass secrets to a Git server that can be pointed at a repo you did not create. Prefer a dedicated low-privilege account and a stripped environment.
- A read-only tool name is not a sandbox. `git status` and `git diff` are enough to hit `core.fsmonitor` and `diff.external`.

## Roots and `--repository` scoping

- Confine the server to an allowlisted root. A tool argument that joins paths should stay inside that root.
- A root is not enough on its own. A nested checkout (`vendor/untrusted/`) still has its own `.git/config`, and one `git_status` on that path runs it. Treat unpacked archives, copied worktrees, and vendored trees as untrusted even when they sit inside the root. `git clone` does not copy the remote's `.git/config`; a zip or a copied folder does.
- The lab tools take a path and do not implement a root jail. Scoping is an operator control on top of the config overrides, not a substitute for them.

## Canonical names

- Normalize a policy entry and the requested operation with the **same** function, or compare both to the service model's canonical name.
- A hand-rolled "hyphen before every capital" split turns `CreateSAMLProvider` into `create-s-a-m-l-provider`, which does not equal the CLI name `create-saml-provider`. Consecutive capitals (SAML, MFA, DB, SSH, ID) are the cases that fall through.
- Add a regression that uses those names. A test with only `DescribeInstances` stays green while the bypass works.

## Fail closed

- Unknown operation names are denied, not allowed.
- A policy entry that does not resolve to a known operation is a startup error. Do not skip the list and keep serving.
- If the policy file or the data needed to enforce it cannot be loaded, refuse to start. A later, separate bug in the same server (1.5.1 changelog) was a denylist that was silently skipped for the life of the process when an index failed to load. Same habit: no policy data, no calls.
- Apply the decision at the sink that actually performs the call. Building a normalized string earlier and then invoking the original name is how a check gets skipped.
- `elicit` means the call does not run until a person confirms. If the client cannot ask, treat elicit as deny.

## Versions

- Pin the server, and upgrade when an advisory lands. `mcp-server-git` below `2026.11.11` is affected by GHSA-6hqx-gqrx-c5r2; `2026.11.11` is the fixed release. `awslabs.aws-api-mcp-server` `>=0.2.13,<1.5.1` is affected by GHSA-4wq9-grf3-qg2p; `1.5.1` is the fixed release.
- This lab pins `mcp>=1.20,<2` only because the example servers use FastMCP, which mcp 2 renamed. That pin is not a security boundary.
