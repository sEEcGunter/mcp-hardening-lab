"""Host and Origin allowlist on every route, including custom ones.

jupyter-mcp-server 1.0.3 added `ManagementRouteSecurityMiddleware` in
`jupyter_mcp_server/server.py`. That middleware covers `/api/connect`,
`/api/stop`, and `/api/healthz`, and it also requires a bearer credential
on the state-changing routes. This lab does not check a credential. It runs
the SDK's own `TransportSecurityMiddleware` as one ASGI middleware around
the whole app, so a route added later cannot skip the allowlist. Covering
every route, not only a path list, is the extra hardening. Legitimate
localhost Host and Origin values still pass, and a missing Origin (a
non-browser client) still passes, which is what the SDK validator does.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecurityMiddleware, TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

# These files are loaded by path, not as a package. Put this directory on
# the path so `backend` resolves next to this file.
_LAB_DIR = str(Path(__file__).resolve().parent)
if _LAB_DIR not in sys.path:
    sys.path.insert(0, _LAB_DIR)

from backend import BackendState, apply_connect, json_error, new_backend

# Same localhost allowlist as the vulnerable twin, and as FastMCP's own
# default when host is 127.0.0.1 (`TransportSecuritySettings` in mcp 1.30.0).
SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
)

LOCAL_BASE = "http://127.0.0.1:8765"
LOCAL_ORIGIN = "http://127.0.0.1:8765"
FORGED_HOST = "attacker.example"
FORGED_ORIGIN = "http://attacker.example"
LOCAL_BODY = {"backend": "memory://local", "marker": "local-ok"}
REBOUND_BODY = {"backend": "memory://rebound", "marker": "rebound"}
ACCEPT = "application/json, text/event-stream"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "lab", "version": "0"},
    },
}


class HostOriginMiddleware:
    """SDK Host/Origin check before any route reads the body."""

    def __init__(self, app: ASGIApp, settings: TransportSecuritySettings) -> None:
        self.app = app
        self.security = TransportSecurityMiddleware(settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            # Headers only. The body stays on `receive` for the route.
            error = await self.security.validate_request(
                Request(scope), is_post=scope["method"] == "POST"
            )
            if error is not None:
                await error(scope, receive, send)
                return
        await self.app(scope, receive, send)


class GuardedFastMCP(FastMCP):
    """FastMCP whose streamable HTTP app checks Host and Origin on every route."""

    def streamable_http_app(self) -> Starlette:
        # The session manager inside this app can run once. Reuse the app so
        # a second call does not stack another copy of the middleware.
        cached = getattr(self, "_guarded_app", None)
        if cached is None:
            app = super().streamable_http_app()
            # Outermost middleware: custom routes and /mcp both pass through it.
            app.add_middleware(HostOriginMiddleware, settings=SECURITY)
            self._guarded_app = app
            cached = app
        return cached


mcp = GuardedFastMCP(
    "lab-dns-fixed",
    host="127.0.0.1",
    port=8765,
    stateless_http=True,
    json_response=True,
    transport_security=SECURITY,
)

_STATE = BackendState()
reset_backend = _STATE.reset_backend
backend = _STATE.backend


@mcp.custom_route("/api/connect", methods=["PUT"])
async def connect(request: Request) -> Response:
    """Replace the in-memory backend. The app middleware already checked headers."""
    try:
        data = await request.json()
    except ValueError:
        return json_error("expected a JSON object", 400)
    if not isinstance(data, dict):
        return json_error("expected a JSON object", 400)
    try:
        apply_connect(data, backend())
    except ValueError as exc:
        return json_error(str(exc), 400)
    state = backend()
    return JSONResponse({"success": True, "backend": state["backend"], "marker": state["marker"]})


def backend_status() -> str:
    """MCP tool: the stored backend name and marker. JSON, no I/O."""
    return json.dumps(backend())


mcp.tool()(backend_status)


def build_app() -> Starlette:
    return mcp.streamable_http_app()


def _load(filename: str, name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _header_label(headers: dict[str, str]) -> str:
    if headers.get("Host") == FORGED_HOST:
        return "Host=attacker.example"
    if headers.get("Origin") == FORGED_ORIGIN:
        return "Origin=http://attacker.example"
    return "local Host and Origin"


def demo() -> int:
    import logging
    import warnings

    warnings.filterwarnings(
        "ignore",
        message="Using `httpx` with `starlette.testclient` is deprecated",
    )
    logging.disable(logging.CRITICAL)
    try:
        from starlette.testclient import TestClient

        vulnerable = _load("vulnerable.py", "lab03_vulnerable_demo")
        fixed = sys.modules[__name__]
        print("=== Lab 03: DNS rebinding on a custom MCP route ===")
        print("payload: PUT /api/connect sets an in-memory marker and does not open a socket")
        local_headers = {"Origin": LOCAL_ORIGIN}
        forged_host = {"Host": FORGED_HOST, "Origin": FORGED_ORIGIN}
        forged_origin = {"Origin": FORGED_ORIGIN}
        failures = 0

        def run(module, client, label, method, path, headers, body, expect_status, expect_marker):
            nonlocal failures
            if method == "PUT":
                response = client.put(path, headers=headers, json=body)
            else:
                response = client.post(path, headers=headers, json=body)
            marker = module.backend()["marker"]
            route = f"{method} {path}"
            print(
                f"{label:<12} {route:<20} {_header_label(headers):<34} "
                f"status={response.status_code:<3} marker={marker}"
            )
            if response.status_code != expect_status or marker != expect_marker:
                failures += 1
                print(
                    f"  expected status {expect_status} marker {expect_marker!r}, "
                    f"body={response.text!r}"
                )

        with (
            TestClient(vulnerable.build_app(), base_url=LOCAL_BASE) as vuln_client,
            TestClient(fixed.build_app(), base_url=LOCAL_BASE) as fix_client,
        ):
            vulnerable.reset_backend()
            fixed.reset_backend()
            run(
                vulnerable, vuln_client, "vulnerable", "PUT", "/api/connect",
                local_headers, LOCAL_BODY, 200, "local-ok",
            )
            run(
                vulnerable, vuln_client, "vulnerable", "PUT", "/api/connect",
                forged_host, REBOUND_BODY, 200, "rebound",
            )
            run(
                fixed, fix_client, "fixed", "PUT", "/api/connect",
                local_headers, LOCAL_BODY, 200, "local-ok",
            )
            run(
                fixed, fix_client, "fixed", "PUT", "/api/connect",
                forged_host, REBOUND_BODY, 421, "local-ok",
            )
            run(
                fixed, fix_client, "fixed", "PUT", "/api/connect",
                forged_origin, REBOUND_BODY, 403, "local-ok",
            )
            mcp_forged = {"Accept": ACCEPT, **forged_host}
            mcp_local = {"Accept": ACCEPT, **local_headers}
            run(
                vulnerable, vuln_client, "vulnerable", "POST", "/mcp",
                mcp_forged, INITIALIZE, 421, "rebound",
            )
            run(
                fixed, fix_client, "fixed", "POST", "/mcp",
                mcp_forged, INITIALIZE, 421, "local-ok",
            )
            run(
                vulnerable, vuln_client, "vulnerable", "POST", "/mcp",
                mcp_local, INITIALIZE, 200, "rebound",
            )
            run(
                fixed, fix_client, "fixed", "POST", "/mcp",
                mcp_local, INITIALIZE, 200, "local-ok",
            )
        if failures:
            print(f"lab 03 demo failed: {failures} unexpected result(s)")
        return failures
    finally:
        logging.disable(logging.NOTSET)


if __name__ == "__main__":
    if "--demo" in sys.argv:
        sys.exit(demo())
    mcp.run(transport="streamable-http")
