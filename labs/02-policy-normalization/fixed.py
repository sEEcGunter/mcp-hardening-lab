"""Policy check that canonicalizes names before comparing, and fails closed.

The patched awslabs/mcp server (commit 52bf00157e) replaced the per-capital
regex with `botocore.xform_name` (`policy.py` line 116 at `c3d28b01`). That
produces the CLI spelling (`CreateSAMLProvider` -> `create-saml-provider`)
used in the deny list. This lab does not depend on botocore. Both the policy
file and the requested operation go through one function, `resolve`, which
maps them onto the simulated service model's canonical names.

Fail-closed on unknown names is extra lab hardening. The patched upstream
function still returns allow when no list matches (`policy.py` lines 137-138).
Here a name that is not in the service model, or a known name that is not
allow-listed, does not run.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

POLICY_PATH = Path(__file__).with_name("policy.json")
mcp = FastMCP("lab-policy-fixed")

# (service, letters-only lowercase) -> canonical API name.
# The same key is produced for `CreateSAMLProvider`, `create-saml-provider`,
# and the mangled `create-s-a-m-l-provider`.
OPERATIONS: dict[tuple[str, str], str] = {
    ("iam", "createsamlprovider"): "CreateSAMLProvider",
    ("iam", "deactivatemfadevice"): "DeactivateMFADevice",
    ("iam", "createvirtualmfadevice"): "CreateVirtualMFADevice",
    ("iam", "uploadsshpublickey"): "UploadSSHPublicKey",
    ("iam", "addclientidtoopenidconnectprovider"): "AddClientIDToOpenIDConnectProvider",
    ("rds", "deletedbcluster"): "DeleteDBCluster",
    ("rds", "deletedbinstance"): "DeleteDBInstance",
    ("rds", "describedbinstances"): "DescribeDBInstances",
    ("ec2", "describeinstances"): "DescribeInstances",
    ("ec2", "terminateinstances"): "TerminateInstances",
    ("s3", "listbuckets"): "ListBuckets",
    ("sts", "getcalleridentity"): "GetCallerIdentity",
}


def canonical_token(operation: str) -> str:
    """One normalization: drop separators and case. Used for both sides."""
    return re.sub(r"[^a-z0-9]", "", operation.lower())


def resolve(service: str, operation: str) -> str | None:
    """Return the canonical API name, or None when the name is not in the model."""
    return OPERATIONS.get((service.strip().lower(), canonical_token(operation)))


def load_policy(path: Path = POLICY_PATH) -> dict[str, set[str]]:
    """Load deny / elicit / allow, canonicalizing every entry.

    An entry that does not resolve, or a name listed in two buckets, raises.
    The process should not start with a policy it cannot enforce.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    resolved: dict[str, set[str]] = {}
    for bucket in ("deny", "elicit", "allow"):
        resolved[bucket] = set()
        for entry in data[bucket]:
            service, operation = str(entry).strip().split(None, 1)
            canonical = resolve(service, operation)
            if canonical is None:
                raise ValueError(
                    f"policy entry {entry!r} is not a known operation (fail closed)"
                )
            resolved[bucket].add(canonical)
    overlap = (
        (resolved["deny"] & resolved["elicit"])
        | (resolved["deny"] & resolved["allow"])
        | (resolved["elicit"] & resolved["allow"])
    )
    if overlap:
        raise ValueError(
            "operation listed in more than one policy list: " + ", ".join(sorted(overlap))
        )
    return resolved


POLICY = load_policy()


def new_cloud() -> dict:
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


def decide(service: str, operation: str) -> tuple[str, str, str | None]:
    """Return `(decision, detail, canonical_name)`. Unknown names are denied."""
    canonical = resolve(service, operation)
    if canonical is None:
        return "deny", f"{service} {operation!r} is not a known operation", None
    if canonical in POLICY["deny"]:
        return "deny", f"canonical {canonical} -> deny", canonical
    if canonical in POLICY["elicit"]:
        return "elicit", f"canonical {canonical} -> elicit", canonical
    if canonical in POLICY["allow"]:
        return "allow", f"canonical {canonical} -> allow", canonical
    return "deny", f"canonical {canonical} is not allow-listed", canonical


_CLOUD = new_cloud()


def invoke(service: str, operation: str, cloud: dict | None = None) -> dict:
    """Decide, then run the simulated call only when the decision is allow."""
    state = _CLOUD if cloud is None else cloud
    decision, detail, canonical = decide(service, operation)
    result = {
        "service": service,
        "operation": operation,
        "canonical": canonical,
        "decision": decision,
        "executed": False,
        "detail": detail,
    }
    if decision != "allow" or canonical is None:
        return result
    outcome = perform(canonical, state)
    result["executed"] = True
    result["detail"] = f"{detail}; {outcome}"
    return result


def invoke_operation(service: str, operation: str) -> str:
    """MCP tool: policy check, then maybe the simulated cloud call. JSON result."""
    return json.dumps(invoke(service, operation))


mcp.tool()(invoke_operation)


def _load(filename: str, name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def demo() -> int:
    vulnerable = _load("vulnerable.py", "lab02_vulnerable_demo")
    print("=== Lab 02: policy bypass via operation-name normalization ===")
    print(f"naive kebab of CreateSAMLProvider = {vulnerable.naive_kebab('CreateSAMLProvider')}")
    print("policy deny entry                 = iam create-saml-provider")
    cases = (
        ("iam", "CreateSAMLProvider", "allow", "deny"),
        ("iam", "DeactivateMFADevice", "allow", "elicit"),
        ("rds", "DeleteDBCluster", "allow", "deny"),
        ("rds", "DeleteDBInstance", "allow", "deny"),
        ("iam", "UploadSSHPublicKey", "allow", "deny"),
        ("ec2", "TerminateInstances", "deny", "deny"),
        ("ec2", "DescribeInstances", "allow", "allow"),
    )
    failures = 0
    for service, operation, expect_vuln, expect_fix in cases:
        for label, module, expected in (
            ("vulnerable", vulnerable, expect_vuln),
            ("fixed", sys.modules[__name__], expect_fix),
        ):
            cloud = module.new_cloud()
            result = module.invoke(service, operation, cloud)
            print(
                f"{label:<12} {service}:{operation:<32} "
                f"decision={result['decision']:<7} executed={result['executed']}"
            )
            if result["decision"] != expected:
                failures += 1
                print(f"  expected decision {expected}, detail={result['detail']}")
            if expected == "allow" and not result["executed"]:
                failures += 1
                print(f"  expected the simulated call to run, detail={result['detail']}")
            if expected != "allow" and result["executed"]:
                failures += 1
                print(f"  expected the simulated call not to run, detail={result['detail']}")
    if failures:
        print(f"lab 02 demo failed: {failures} unexpected result(s)")
    return failures


if __name__ == "__main__":
    if "--demo" in sys.argv:
        sys.exit(demo())
    mcp.run(transport="stdio")
