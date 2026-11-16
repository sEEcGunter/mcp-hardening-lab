"""Deliberately vulnerable policy check for a simulated cloud.

Do not deploy this. `fixed.py` is the paired build.

GHSA-4wq9-grf3-qg2p: denyList / elicitList entries were not enforced for
operation names with consecutive capital letters, because the server
normalized those names incorrectly before comparing them to the policy.

The pre-fix conversion in awslabs/mcp
`src/aws-api-mcp-server/awslabs/aws_api_mcp_server/core/security/policy.py`
(parent of commit 52bf00157e, lines 116-117) was:

    operation_kebab = operation.replace('_', '-')
    operation_kebab = re.sub('([A-Z])', r'-\1', operation_kebab).lower().lstrip('-')

`CreateSAMLProvider` becomes `create-s-a-m-l-provider`, which is not the
CLI name `create-saml-provider` stored in the policy, so the deny rule misses
and the default allow stands. This file re-implements that bug on a fake
in-memory cloud. It is not the upstream server and it does not call AWS.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

POLICY_PATH = Path(__file__).with_name("policy.json")
mcp = FastMCP("lab-policy-vulnerable")


def naive_kebab(operation: str) -> str:
    """Insert a hyphen before every capital letter, then lowercase.

    Acronyms are split per letter. That is the bug.
    """
    text = operation.replace("_", "-")
    return re.sub(r"([A-Z])", r"-\1", text).lower().lstrip("-")


def load_string_policy(path: Path = POLICY_PATH) -> dict[str, set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        bucket: {str(item).strip() for item in data[bucket]}
        for bucket in ("deny", "elicit", "allow")
    }


POLICY = load_string_policy()


def new_cloud() -> dict:
    """A handful of simulated resources. Nothing here talks to a network."""
    return {
        "saml_providers": [],
        "mfa_devices": ["device-1"],
        "virtual_mfa": [],
        "ssh_keys": [],
        "oidc_clients": [],
        "db_clusters": ["prod"],
        "db_instances": ["prod-1"],
        "instances": ["i-lab"],
        "buckets": ["lab-bucket"],
        "account": "000000000000",
    }


def perform(operation: str, cloud: dict) -> str:
    """Apply one simulated API call. Unknown names raise KeyError."""
    if operation == "CreateSAMLProvider":
        cloud["saml_providers"].append("lab-provider")
        return "simulated CreateSAMLProvider recorded lab-provider"
    if operation == "DeactivateMFADevice":
        cloud["mfa_devices"].clear()
        return "simulated DeactivateMFADevice cleared MFA devices"
    if operation == "CreateVirtualMFADevice":
        cloud["virtual_mfa"].append("virtual-1")
        return "simulated CreateVirtualMFADevice recorded virtual-1"
    if operation == "UploadSSHPublicKey":
        cloud["ssh_keys"].append("ssh-1")
        return "simulated UploadSSHPublicKey recorded ssh-1"
    if operation == "AddClientIDToOpenIDConnectProvider":
        cloud["oidc_clients"].append("client-1")
        return "simulated AddClientIDToOpenIDConnectProvider recorded client-1"
    if operation == "DeleteDBCluster":
        cloud["db_clusters"].clear()
        return "simulated DeleteDBCluster removed prod"
    if operation == "DeleteDBInstance":
        cloud["db_instances"].clear()
        return "simulated DeleteDBInstance removed prod-1"
    if operation == "DescribeDBInstances":
        return f"simulated DescribeDBInstances {cloud['db_instances']}"
    if operation == "DescribeInstances":
        return f"simulated DescribeInstances {cloud['instances']}"
    if operation == "TerminateInstances":
        cloud["instances"].clear()
        return "simulated TerminateInstances removed i-lab"
    if operation == "ListBuckets":
        return f"simulated ListBuckets {cloud['buckets']}"
    if operation == "GetCallerIdentity":
        return f"simulated GetCallerIdentity account {cloud['account']}"
    raise KeyError(operation)


def policy_key(service: str, operation: str) -> str:
    return f"{service.strip().lower()} {naive_kebab(operation.strip())}"


def decide(service: str, operation: str) -> tuple[str, str]:
    """Return `(decision, detail)`. Unmatched names are allowed."""
    key = policy_key(service, operation)
    if key in POLICY["deny"]:
        return "deny", f"compared {key!r} -> deny"
    if key in POLICY["elicit"]:
        return "elicit", f"compared {key!r} -> elicit"
    if key in POLICY["allow"]:
        return "allow", f"compared {key!r} -> allow"
    return "allow", f"compared {key!r} -> allow (no policy entry matched)"


_CLOUD = new_cloud()


def invoke(service: str, operation: str, cloud: dict | None = None) -> dict:
    """Decide, then run the simulated call only when the decision is allow."""
    state = _CLOUD if cloud is None else cloud
    decision, detail = decide(service, operation)
    if decision != "allow":
        return {
            "service": service,
            "operation": operation,
            "decision": decision,
            "executed": False,
            "detail": detail,
        }
    try:
        outcome = perform(operation, state)
    except KeyError:
        return {
            "service": service,
            "operation": operation,
            "decision": decision,
            "executed": False,
            "detail": detail + "; cloud has no such operation",
        }
    return {
        "service": service,
        "operation": operation,
        "decision": decision,
        "executed": True,
        "detail": f"{detail}; {outcome}",
    }


def invoke_operation(service: str, operation: str) -> str:
    """MCP tool: policy check, then maybe the simulated cloud call. JSON result."""
    return json.dumps(invoke(service, operation))


mcp.tool()(invoke_operation)


if __name__ == "__main__":
    mcp.run(transport="stdio")
