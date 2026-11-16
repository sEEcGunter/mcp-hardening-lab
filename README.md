[![test](https://github.com/sEEcGunter/mcp-hardening-lab/actions/workflows/test.yml/badge.svg)](https://github.com/sEEcGunter/mcp-hardening-lab/actions/workflows/test.yml)

# MCP hardening lab

Small, local, educational lab for two MCP bugs published in November 2026. Each lab has a deliberately vulnerable minimal server, a fixed twin, and tests that show the bug on the vulnerable build and the block on the fixed one. Python, FastMCP (`mcp` 1.x), pytest.

This is a portfolio-style re-implementation. It is not the upstream source, and it does not call a model, AWS, or the network.

## Goal

Show two ways a "read" or a "policy" can still do the wrong thing:

1. A Git tool runs in a repository the client picked, and that repository's own `.git/config` names a program (`core.fsmonitor` on status, `diff.external` on diff).
2. A deny / elicit policy misses operation names that contain consecutive capitals, because the name is normalized one way and the policy entry is written another way.

Both fixes are in the repo. `CHECKLIST.md` is the operator list that goes with them.

## Advisories

- [GHSA-6hqx-gqrx-c5r2](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-6hqx-gqrx-c5r2) — `mcp-server-git` before `2026.11.11` (fixed in `2026.11.11`). Read-only Git tools executed a program named by the repository config. Lab: `labs/01-git-config-exec/`.
- [GHSA-4wq9-grf3-qg2p](https://github.com/awslabs/mcp/security/advisories/GHSA-4wq9-grf3-qg2p) — `awslabs.aws-api-mcp-server` `>=0.2.13,<1.5.1` (fixed in `1.5.1`). denyList / elicitList entries were not enforced for operation names with consecutive capital letters, because normalization did not match the policy. Lab: `labs/02-policy-normalization/`.

Citations of the upstream files that were read are in the lab READMEs. Where this lab does less or more than those files, the lab README says so.

## Demo

`make demo` runs each lab vulnerable, then fixed. Captured from this tree (`git version 2.43.0`). Each marker path's random id is written `<id>`:

```text
=== Lab 01: repository Git config -> code execution ===
payload: marker.sh writes one file and nothing else
vulnerable   git_status           fsmonitor        marker WRITTEN  /tmp/mcp-lab-pwned-<id>
fixed        git_status           fsmonitor        marker absent  /tmp/mcp-lab-pwned-<id>
vulnerable   git_diff_unstaged    diff.external    marker WRITTEN  /tmp/mcp-lab-pwned-<id>
fixed        git_diff_unstaged    diff.external    marker absent  /tmp/mcp-lab-pwned-<id>
vulnerable   git_diff_unstaged    filter.clean     marker WRITTEN  /tmp/mcp-lab-pwned-<id>
fixed        git_diff_unstaged    filter.clean     marker absent  /tmp/mcp-lab-pwned-<id>
=== Lab 02: policy bypass via operation-name normalization ===
naive kebab of CreateSAMLProvider = create-s-a-m-l-provider
policy deny entry                 = iam create-saml-provider
vulnerable   iam:CreateSAMLProvider               decision=allow   executed=True
fixed        iam:CreateSAMLProvider               decision=deny    executed=False
vulnerable   iam:DeactivateMFADevice              decision=allow   executed=True
fixed        iam:DeactivateMFADevice              decision=elicit  executed=False
vulnerable   rds:DeleteDBCluster                  decision=allow   executed=True
fixed        rds:DeleteDBCluster                  decision=deny    executed=False
vulnerable   rds:DeleteDBInstance                 decision=allow   executed=True
fixed        rds:DeleteDBInstance                 decision=deny    executed=False
vulnerable   iam:UploadSSHPublicKey               decision=allow   executed=True
fixed        iam:UploadSSHPublicKey               decision=deny    executed=False
vulnerable   ec2:TerminateInstances               decision=deny    executed=False
fixed        ec2:TerminateInstances               decision=deny    executed=False
vulnerable   ec2:DescribeInstances                decision=allow   executed=True
fixed        ec2:DescribeInstances                decision=allow   executed=True
```

The demo deletes the marker file and the temp repo after it prints the path. `make test` was 45 passed on the same tree.

Lab 01: the vulnerable status and diff runs write the marker. The fixed tools run the same Git commands with the sinks overridden, and the marker stays absent. Lab 02: `CreateSAMLProvider`, `DeactivateMFADevice`, and `DeleteDBCluster` run on the vulnerable policy and are denied or held for confirmation on the fixed one. `TerminateInstances` (no consecutive capitals) is denied on both, which shows the vulnerable file is actually consulting the policy.

## Install

Requires Python 3.10+, Git 2.31 or newer (the fixed Git lab refuses anything older), and nothing but `mcp` and `pytest` as direct dependencies. `mcp` 2 renamed FastMCP to `MCPServer`, so this project pins `mcp>=1.20,<2`.

Local:

```bash
python3 -m pip install -e ".[dev]"
make test
make demo
```

Docker (the image installs Git, checks that it is at least 2.31, then runs `make test` and `make demo`):

```bash
docker build -t mcp-hardening-lab .
docker run --rm mcp-hardening-lab
```

## Usage

- `make test` — pytest. The tests call `git_status`, `git_diff_unstaged`, and `invoke` directly.
- `make demo` — vulnerable then fixed, for both labs.
- `python3 labs/01-git-config-exec/vulnerable.py` and `fixed.py` speak MCP over stdio. Use them only against a repo you just built (see `make_fixture.py`). The vulnerable server will run a program named in that repo's config.
- `python3 labs/02-policy-normalization/fixed.py --demo` reruns lab 02. Without `--demo`, `vulnerable.py` and `fixed.py` speak MCP over stdio and expose `invoke_operation`.

`labs/02-policy-normalization/policy.json` is the operator policy for the simulated cloud. Names are the CLI spelling (`iam create-saml-provider`), which is what the advisory's deny list was compared against.

## How the fixes work

**Lab 01.** Every Git subprocess gets `GIT_CONFIG_COUNT` entries that outrank `.git/config`: `core.fsmonitor=false`, `core.hooksPath` on the null device, `core.pager=cat`, `commit.gpgSign=false`, `merge.verifySignatures=false`, `submodule.recurse=false`, `status.submoduleSummary=false`, `merge.autoStash=false`. The same call then runs `git config --show-scope --get-regexp` and appends an empty value for each `filter.*.clean` / `smudge` / `process`, `merge.*.driver`, and `branch.*.mergeOptions` whose scope is `local` or `worktree`. Global and system drivers stay. Diffs also get `--no-ext-diff --no-textconv`. Status and diff get `--ignore-submodules=dirty`. If Git is older than 2.31, or if `core.hooksPath` does not come back as a command-scoped null device, the tool raises and does not run the status or diff. Overrides are appended after any `GIT_CONFIG_*` values already in the environment so they are not dropped and they win on duplicate keys.

**Lab 02.** `resolve` strips separators and case, then looks the pair `(service, token)` up in a small service model. Policy entries and requested names both go through that function, so `CreateSAMLProvider`, `create-saml-provider`, and the mangled `create-s-a-m-l-provider` are the same operation. Unknown names are denied. A known name that is not allow-listed is denied. `elicit` returns without changing the simulated cloud. A policy entry that does not resolve raises at load. The simulated call runs only when the decision is allow.

## Limits

- Simplified re-implementations, written to show the bug class and the fix. They are not drop-in copies of `mcp-server-git` or `aws-api-mcp-server`.
- Lab 01 blanks `local` and `worktree` filter, merge, and `branch.*.mergeOptions` commands. It leaves global and system drivers in place. The listing is one entry per line, so a driver value that contains a newline is outside what this parser reads. Upstream uses a NUL-delimited listing for that case.
- Lab 01 does not confine `repo_path` to an allowlisted root. Path scoping is in the checklist; it does not replace the config overrides. A nested `.git` inside a trusted root is still that repo's config.
- Lab 02's fail-closed default is stricter than the patched upstream function, which still allows a call when no list matches. The lab does not use `botocore.xform_name`.
- The Git payload only creates a marker file. The cloud is a dict in memory.

## Legal and ethical use

Educational, local lab only. The fixture payload writes one marker file under `/tmp` and does nothing else: no shell access, no network, no credentials. Run it on a machine you control, against repositories you created for the lab. Do not point the vulnerable server at a repository you are not authorized to test, and do not use either lab against systems you are not authorized to test.
