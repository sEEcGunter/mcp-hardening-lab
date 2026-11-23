"""Deliberately vulnerable streamable-HTTP server for a local lab.

Do not deploy this. `fixed.py` is the paired build.

GHSA-9x8x-crjq-g64h: jupyter-mcp-server before 1.0.3 rejects a forged Host
or Origin on `/mcp` and does not apply that check to custom routes on the
same app. `PUT /api/connect` in `jupyter_mcp_server/server.py` replaces the
Jupyter backend. This file re-implements that gap on an in-memory backend.
The handler stores a `memory://` name and a marker. It does not open a
connection, and it does not resolve DNS.

`transport_security` is the SDK allowlist (`TransportSecuritySettings` in
mcp 1.30.0, `src/mcp/server/fastmcp/server.py`). The streamable HTTP handler
consults it (`src/mcp/server/streamable_http.py`). `custom_route` is mounted
beside that handler (`routes.extend(self._custom_starlette_routes)` in
`server.py`), so `/api/connect` never sees the check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# These files are loaded by path, not as a package. Put this directory on
# the path so `backend` resolves next to this file.
_LAB_DIR = str(Path(__file__).resolve().parent)
if _LAB_DIR not in sys.path:
    sys.path.insert(0, _LAB_DIR)

from backend import BackendState, apply_connect, json_error, new_backend

# Same localhost allowlist FastMCP fills in when host is 127.0.0.1.
# It is applied to /mcp only. See the module docstring.
SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
)

LOCAL_BASE = "http://127.0.0.1:8765"

mcp = FastMCP(
    "lab-dns-vulnerable",
    host="127.0.0.1",
    port=8765,
    stateless_http=True,
    json_response=True,
    transport_security=SECURITY,
)

_STATE = BackendState()
reset_backend = _STATE.reset_backend
backend = _STATE.backend
_APP = None


@mcp.custom_route("/api/connect", methods=["PUT"])
async def connect(request: Request) -> Response:
    """Replace the in-memory backend. Host and Origin are not checked.

    That is the bug. `/mcp` on this same app does check them, because the
    SDK's streamable HTTP transport does. This route does not.
    """
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


def build_app():
    """Starlette app: protected `/mcp` plus the unguarded admin route."""
    global _APP
    if _APP is None:
        _APP = mcp.streamable_http_app()
    return _APP


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
