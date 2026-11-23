# Lab 02 — policy bypass via operation-name normalization

Local copy of the bug class in [GHSA-4wq9-grf3-qg2p](https://github.com/awslabs/mcp/security/advisories/GHSA-4wq9-grf3-qg2p) (`awslabs.aws-api-mcp-server` `>=0.2.13,<1.5.1`, fixed in `1.5.1`).

The advisory says denyList and elicitList entries were not enforced for operation names with consecutive capital letters, because those names were normalized incorrectly before the comparison. The examples it gives are creating a federated identity provider, deactivating an MFA device, and deleting database clusters. This lab uses `CreateSAMLProvider`, `DeactivateMFADevice`, and `DeleteDBCluster` for those, plus a few more acronym names, on a fake in-memory cloud. There is no AWS SDK and no network call.

## What is vulnerable

`vulnerable.py` turns an API name into kebab-case by inserting a hyphen before every capital. That is the pre-fix conversion in `src/aws-api-mcp-server/awslabs/aws_api_mcp_server/core/security/policy.py` at the parent of commit `52bf00157e`, lines 116-117:

```python
operation_kebab = operation.replace("_", "-")
operation_kebab = re.sub("([A-Z])", r"-\1", operation_kebab).lower().lstrip("-")
```

`CreateSAMLProvider` becomes `create-s-a-m-l-provider`. `policy.json` stores the CLI spelling an operator would copy, `iam create-saml-provider`. The strings differ, the deny rule misses, and the default is allow, so the simulated call runs. `TerminateInstances` has no consecutive capitals, becomes `terminate-instances`, and stays denied. That is how you can tell the engine is not simply ignoring the file.

## What is fixed

Commit `52bf00157e` replaced that regex with `botocore.xform_name` (`policy.py` line 116 at `c3d28b01`). The patched function still allows the call when no list matches (lines 137-138). This lab does not depend on botocore.

`fixed.py` runs policy entries and requested names through one function, `resolve`, which maps both spellings onto the simulated service model (`CreateSAMLProvider` and `create-saml-provider` and even `create-s-a-m-l-provider`). Unknown names are denied. A known name that is not on the allow list is denied. `elicit` does not run the call. A policy entry that does not resolve raises at load. The fail-closed behavior is lab hardening, not a claim about the patched upstream default.

## Run

From the repository root: `make test` and `make demo`. Captured demo output is in the root README.
