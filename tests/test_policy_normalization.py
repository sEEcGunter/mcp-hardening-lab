"""Acronym operation names bypass the vulnerable policy and hit the fixed one."""

from __future__ import annotations

import asyncio
import json

import pytest

# Advisory examples, plus the other consecutive-capital names from the
# upstream regression test (SSH, OpenID, virtual MFA).
ACRONYM_DENY = (
    ("iam", "CreateSAMLProvider", "saml_providers"),
    ("rds", "DeleteDBCluster", "db_clusters"),
    ("rds", "DeleteDBInstance", "db_instances"),
    ("iam", "UploadSSHPublicKey", "ssh_keys"),
    ("iam", "AddClientIDToOpenIDConnectProvider", "oidc_clients"),
)

ACRONYM_ELICIT = (
    ("iam", "DeactivateMFADevice", "mfa_devices"),
    ("iam", "CreateVirtualMFADevice", "virtual_mfa"),
)

NAIVE = (
    ("CreateSAMLProvider", "create-s-a-m-l-provider"),
    ("DeactivateMFADevice", "deactivate-m-f-a-device"),
    ("DeleteDBCluster", "delete-d-b-cluster"),
    ("DeleteDBInstance", "delete-d-b-instance"),
    ("CreateVirtualMFADevice", "create-virtual-m-f-a-device"),
    ("UploadSSHPublicKey", "upload-s-s-h-public-key"),
    ("AddClientIDToOpenIDConnectProvider", "add-client-i-d-to-open-i-d-connect-provider"),
    ("TerminateInstances", "terminate-instances"),
    ("DescribeInstances", "describe-instances"),
    ("DescribeDBInstances", "describe-d-b-instances"),
)


@pytest.mark.parametrize("operation,mangled", NAIVE)
def test_naive_kebab_splits_every_capital(policy_lab, operation, mangled):
    assert policy_lab.vuln.naive_kebab(operation) == mangled


@pytest.mark.parametrize("service,operation,field", ACRONYM_DENY)
def test_acronym_deny_executes_on_vulnerable_and_is_blocked_on_fixed(
    policy_lab, service, operation, field
):
    before = policy_lab.vuln.new_cloud()
    vulnerable_cloud = policy_lab.vuln.new_cloud()
    fixed_cloud = policy_lab.fix.new_cloud()

    vulnerable = policy_lab.vuln.invoke(service, operation, vulnerable_cloud)
    fixed = policy_lab.fix.invoke(service, operation, fixed_cloud)

    assert vulnerable["decision"] == "allow"
    assert vulnerable["executed"] is True
    assert "no policy entry matched" in vulnerable["detail"]
    assert vulnerable_cloud[field] != before[field]

    assert fixed["decision"] == "deny"
    assert fixed["executed"] is False
    assert fixed_cloud[field] == before[field]


@pytest.mark.parametrize("service,operation,field", ACRONYM_ELICIT)
def test_acronym_elicit_executes_on_vulnerable_and_stops_on_fixed(
    policy_lab, service, operation, field
):
    before = policy_lab.vuln.new_cloud()
    vulnerable_cloud = policy_lab.vuln.new_cloud()
    fixed_cloud = policy_lab.fix.new_cloud()

    vulnerable = policy_lab.vuln.invoke(service, operation, vulnerable_cloud)
    fixed = policy_lab.fix.invoke(service, operation, fixed_cloud)

    assert vulnerable["decision"] == "allow"
    assert vulnerable["executed"] is True
    assert vulnerable_cloud[field] != before[field]

    assert fixed["decision"] == "elicit"
    assert fixed["executed"] is False
    assert fixed_cloud[field] == before[field]


def test_non_acronym_deny_holds_on_both(policy_lab):
    """TerminateInstances has no consecutive capitals, so the naive split matches."""
    before = policy_lab.vuln.new_cloud()["instances"]
    for module in (policy_lab.vuln, policy_lab.fix):
        cloud = module.new_cloud()
        result = module.invoke("ec2", "TerminateInstances", cloud)
        assert result["decision"] == "deny"
        assert result["executed"] is False
        assert cloud["instances"] == before


@pytest.mark.parametrize(
    "service,operation",
    [
        ("ec2", "DescribeInstances"),
        ("s3", "ListBuckets"),
        ("sts", "GetCallerIdentity"),
    ],
)
def test_plain_allow_executes_on_both(policy_lab, service, operation):
    for module in (policy_lab.vuln, policy_lab.fix):
        cloud = module.new_cloud()
        result = module.invoke(service, operation, cloud)
        assert result["decision"] == "allow"
        assert result["executed"] is True


def test_acronym_allow_misses_the_vulnerable_list_and_still_runs(policy_lab):
    """DescribeDBInstances is allow-listed, but the naive key does not match it.

    The vulnerable engine default-allows the miss, so the call still runs.
    The fixed engine resolves both spellings to the same canonical name.
    """
    assert policy_lab.vuln.naive_kebab("DescribeDBInstances") == "describe-d-b-instances"
    vulnerable = policy_lab.vuln.invoke(
        "rds", "DescribeDBInstances", policy_lab.vuln.new_cloud()
    )
    fixed = policy_lab.fix.invoke("rds", "DescribeDBInstances", policy_lab.fix.new_cloud())
    assert "no policy entry matched" in vulnerable["detail"]
    assert vulnerable["executed"] is True
    assert fixed["decision"] == "allow"
    assert fixed["executed"] is True


def test_unknown_operation_fails_closed_only_on_fixed(policy_lab):
    vulnerable = policy_lab.vuln.invoke("iam", "DeleteSAMLProvider", policy_lab.vuln.new_cloud())
    fixed = policy_lab.fix.invoke("iam", "DeleteSAMLProvider", policy_lab.fix.new_cloud())
    assert vulnerable["decision"] == "allow"
    assert vulnerable["executed"] is False
    assert fixed["decision"] == "deny"
    assert fixed["executed"] is False
    assert fixed["canonical"] is None


def test_mangled_spelling_is_still_denied_on_fixed(policy_lab):
    cloud = policy_lab.fix.new_cloud()
    result = policy_lab.fix.invoke("iam", "create-s-a-m-l-provider", cloud)
    assert result["decision"] == "deny"
    assert result["executed"] is False
    assert result["canonical"] == "CreateSAMLProvider"
    assert cloud["saml_providers"] == []


def test_resolve_accepts_api_and_cli_spellings(policy_lab):
    assert policy_lab.fix.resolve("iam", "CreateSAMLProvider") == "CreateSAMLProvider"
    assert policy_lab.fix.resolve("IAM", "create-saml-provider") == "CreateSAMLProvider"
    assert policy_lab.fix.resolve("iam", "create_saml_provider") == "CreateSAMLProvider"
    assert policy_lab.fix.resolve("iam", "NoSuchCall") is None


def test_shipped_policy_canonicalizes(policy_lab):
    loaded = policy_lab.fix.load_policy()
    assert "CreateSAMLProvider" in loaded["deny"]
    assert "DeleteDBCluster" in loaded["deny"]
    assert "DeactivateMFADevice" in loaded["elicit"]
    assert "DescribeInstances" in loaded["allow"]


def test_unknown_policy_entry_is_rejected(policy_lab, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({"deny": ["iam delete-the-account"], "elicit": [], "allow": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not a known operation"):
        policy_lab.fix.load_policy(path)


def test_overlapping_policy_lists_are_rejected(policy_lab, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "deny": ["iam create-saml-provider"],
                "elicit": ["iam create-saml-provider"],
                "allow": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="more than one"):
        policy_lab.fix.load_policy(path)


def test_invoke_operation_tool_returns_json(policy_lab):
    for module in (policy_lab.vuln, policy_lab.fix):
        payload = json.loads(module.invoke_operation("ec2", "TerminateInstances"))
        assert payload["decision"] == "deny"
        assert payload["executed"] is False


def test_policy_tool_is_registered(policy_lab):
    for module in (policy_lab.vuln, policy_lab.fix):
        tools = asyncio.run(module.mcp.list_tools())
        assert {tool.name for tool in tools} == {"invoke_operation"}
