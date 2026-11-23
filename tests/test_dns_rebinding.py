"""Forged Host and Origin change the vulnerable admin route and not the fixed one.

The client is in-process. Headers are set on the request. No name is resolved
and no socket is opened.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient


@pytest.fixture(scope="module")
def dns_http(dns_lab):
    with (
        TestClient(dns_lab.vuln.build_app(), base_url=dns_lab.vuln.LOCAL_BASE) as vulnerable,
        TestClient(dns_lab.fix.build_app(), base_url=dns_lab.fix.LOCAL_BASE) as fixed,
    ):
        yield SimpleNamespace(vulnerable=vulnerable, fixed=fixed)


def _reset(dns_lab) -> None:
    dns_lab.vuln.reset_backend()
    dns_lab.fix.reset_backend()


def _mcp_headers(extra: dict[str, str]) -> dict[str, str]:
    return {"Accept": "application/json, text/event-stream", **extra}


def test_both_variants_share_the_sdk_localhost_allowlist(dns_lab):
    assert dns_lab.vuln.SECURITY.model_dump() == dns_lab.fix.SECURITY.model_dump()
    assert dns_lab.vuln.SECURITY.enable_dns_rebinding_protection is True
    assert dns_lab.vuln.LOCAL_BASE == dns_lab.fix.LOCAL_BASE == "http://127.0.0.1:8765"
    assert "attacker.example" not in dns_lab.fix.SECURITY.allowed_hosts
    assert "http://attacker.example" not in dns_lab.fix.SECURITY.allowed_origins


def test_only_the_fixed_app_wraps_every_route(dns_lab):
    vulnerable = dns_lab.vuln.build_app()
    fixed = dns_lab.fix.build_app()
    vulnerable_middleware = [middleware.cls.__name__ for middleware in vulnerable.user_middleware]
    fixed_middleware = [middleware.cls.__name__ for middleware in fixed.user_middleware]
    assert "HostOriginMiddleware" not in vulnerable_middleware
    assert "HostOriginMiddleware" in fixed_middleware


def test_forged_host_changes_the_marker_only_on_the_vulnerable_route(dns_lab, dns_http):
    _reset(dns_lab)
    forged = {"Host": "attacker.example", "Origin": "http://attacker.example"}
    body = {"backend": "memory://rebound", "marker": "rebound"}

    vulnerable = dns_http.vulnerable.put("/api/connect", headers=forged, json=body)
    assert vulnerable.request.headers["host"] == "attacker.example"
    assert vulnerable.status_code == 200
    assert vulnerable.json()["marker"] == "rebound"
    assert dns_lab.vuln.backend() == {"backend": "memory://rebound", "marker": "rebound"}

    dns_lab.fix.apply_connect(
        {"backend": "memory://local", "marker": "local-ok"}, dns_lab.fix.backend()
    )
    fixed = dns_http.fixed.put("/api/connect", headers=forged, json=body)
    assert fixed.status_code == 421
    assert fixed.text == "Invalid Host header"
    assert dns_lab.fix.backend()["marker"] == "local-ok"


def test_forged_origin_with_local_host_changes_the_marker_only_when_unguarded(
    dns_lab, dns_http
):
    """Host is the TestClient's loopback name. Only Origin is the attacker's.

    The SDK answers that with 403. The vulnerable route does not look.
    """
    _reset(dns_lab)
    forged = {"Origin": "http://attacker.example"}
    body = {"backend": "memory://rebound", "marker": "rebound"}

    vulnerable = dns_http.vulnerable.put("/api/connect", headers=forged, json=body)
    assert vulnerable.request.headers["host"] == "127.0.0.1:8765"
    assert vulnerable.status_code == 200
    assert dns_lab.vuln.backend()["marker"] == "rebound"

    dns_lab.fix.apply_connect(
        {"backend": "memory://local", "marker": "kept"}, dns_lab.fix.backend()
    )
    fixed = dns_http.fixed.put("/api/connect", headers=forged, json=body)
    assert fixed.status_code == 403
    assert fixed.text == "Invalid Origin header"
    assert dns_lab.fix.backend()["marker"] == "kept"


def test_mcp_rejects_forged_host_on_both(dns_lab, dns_http):
    _reset(dns_lab)
    dns_lab.vuln.apply_connect(
        {"backend": "memory://local", "marker": "before"}, dns_lab.vuln.backend()
    )
    dns_lab.fix.apply_connect(
        {"backend": "memory://local", "marker": "before"}, dns_lab.fix.backend()
    )
    headers = _mcp_headers({"Host": "attacker.example", "Origin": "http://attacker.example"})
    for module, client in (
        (dns_lab.vuln, dns_http.vulnerable),
        (dns_lab.fix, dns_http.fixed),
    ):
        response = client.post("/mcp", headers=headers, json=dns_lab.fix.INITIALIZE)
        assert response.status_code == 421
        assert response.text == "Invalid Host header"
        assert module.backend()["marker"] == "before"


def test_mcp_rejects_forged_origin_on_both(dns_lab, dns_http):
    _reset(dns_lab)
    headers = _mcp_headers({"Origin": "http://attacker.example"})
    for client in (dns_http.vulnerable, dns_http.fixed):
        response = client.post("/mcp", headers=headers, json=dns_lab.fix.INITIALIZE)
        assert response.request.headers["host"] == "127.0.0.1:8765"
        assert response.status_code == 403
        assert response.text == "Invalid Origin header"


def test_legitimate_requests_pass_on_the_fixed_variant(dns_lab, dns_http):
    _reset(dns_lab)
    local_origin = {"Origin": "http://127.0.0.1:8765"}
    connect = dns_http.fixed.put(
        "/api/connect",
        headers=local_origin,
        json={"backend": "memory://local", "marker": "local-ok"},
    )
    assert connect.status_code == 200
    assert connect.json()["marker"] == "local-ok"
    assert dns_lab.fix.backend()["marker"] == "local-ok"

    localhost = dns_http.fixed.put(
        "/api/connect",
        headers={"Host": "localhost:8765", "Origin": "http://localhost:8765"},
        json={"backend": "memory://local", "marker": "localhost-ok"},
    )
    assert localhost.status_code == 200
    assert dns_lab.fix.backend()["marker"] == "localhost-ok"

    missing_origin = dns_http.fixed.put(
        "/api/connect",
        json={"backend": "memory://local", "marker": "no-origin"},
    )
    assert missing_origin.status_code == 200
    assert dns_lab.fix.backend()["marker"] == "no-origin"

    initialized = dns_http.fixed.post(
        "/mcp",
        headers=_mcp_headers(local_origin),
        json=dns_lab.fix.INITIALIZE,
    )
    assert initialized.status_code == 200
    assert "protocolVersion" in initialized.text
    assert dns_lab.fix.backend()["marker"] == "no-origin"


def test_legitimate_mcp_initialize_passes_on_the_vulnerable_variant(dns_lab, dns_http):
    response = dns_http.vulnerable.post(
        "/mcp",
        headers=_mcp_headers({"Origin": "http://127.0.0.1:8765"}),
        json=dns_lab.fix.INITIALIZE,
    )
    assert response.status_code == 200
    assert "protocolVersion" in response.text


def test_non_memory_backend_is_rejected_on_both(dns_lab, dns_http):
    body = {"backend": "http://example.invalid/backend", "marker": "nope"}
    for module, client in (
        (dns_lab.vuln, dns_http.vulnerable),
        (dns_lab.fix, dns_http.fixed),
    ):
        module.reset_backend()
        response = client.put("/api/connect", json=body)
        assert response.status_code == 400
        assert module.backend() == {"backend": "memory://local", "marker": ""}


def test_handlers_do_not_import_a_client(dns_lab):
    for module in (dns_lab.vuln, dns_lab.fix):
        source = Path(module.__file__).read_text(encoding="utf-8")
        for banned in (
            "import socket",
            "import httpx",
            "import urllib",
            "import requests",
            "import aiohttp",
            "curl",
            "wget",
        ):
            assert banned not in source


def test_backend_tool_is_registered(dns_lab):
    for module in (dns_lab.vuln, dns_lab.fix):
        module.reset_backend()
        module.apply_connect(
            {"backend": "memory://local", "marker": "from-tool"}, module.backend()
        )
        assert json.loads(module.backend_status())["marker"] == "from-tool"
        tools = asyncio.run(module.mcp.list_tools())
        assert {tool.name for tool in tools} == {"backend_status"}
