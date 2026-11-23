# Lab 03 — DNS rebinding on a custom MCP route

Local copy of the bug class in [GHSA-9x8x-crjq-g64h](https://github.com/advisories/GHSA-9x8x-crjq-g64h) (`jupyter-mcp-server` `<=1.0.2`, fixed in `1.0.3`, critical).

In streamable-http mode the SDK rejects a forged Host or Origin on `/mcp`. Before 1.0.3, `PUT /api/connect` was mounted on the same app and did not get that check, so a page whose hostname resolved to `127.0.0.1` could swap the Jupyter backend. This lab stores an in-memory `memory://` name and a marker instead of a Jupyter kernel.

Two related advisories are the same missing Host/Origin boundary on a local HTTP MCP server, without this custom-route split:

- [GHSA-833v-v58w-294h](https://github.com/advisories/GHSA-833v-v58w-294h) — `@doist/todoist-mcp` `<=10.3.2`, fixed in `10.3.3`, critical. `POST /mcp` itself accepted the browser headers.
- [GHSA-mx6p-3fg7-v6pj](https://github.com/advisories/GHSA-mx6p-3fg7-v6pj) — `obsidian-sync-mcp` `<=0.5.6`, fixed in `0.5.7`, high. No-auth mode did not validate Host or Origin before dispatching MCP methods.

## What is vulnerable

`vulnerable.py` passes the SDK `TransportSecuritySettings` localhost allowlist (mcp 1.30.0, `src/mcp/server/fastmcp/server.py`). The streamable HTTP handler applies it (`src/mcp/server/streamable_http.py`) and answers a bad Host with 421 and a bad Origin with 403. `custom_route` is added beside that handler. That is the pre-fix shape of `PUT /api/connect` in `jupyter_mcp_server/server.py` before 1.0.3: the route parses JSON and updates the backend with no Host or Origin check.

The payload is `{"backend": "memory://rebound", "marker": "rebound"}`. The handler records those strings. A name that is not `memory://` is rejected. Nothing is dialed.

## What is fixed

`fixed.py` runs the SDK's `TransportSecurityMiddleware` as one ASGI middleware around the whole app, so `/api/connect` and `/mcp` see the same allowlist. `stateless_http` and `json_response` are on so the in-process client can read one JSON body. They are not the fix. jupyter-mcp-server 1.0.3 instead added `ManagementRouteSecurityMiddleware` in `jupyter_mcp_server/server.py` for three management paths, and it also requires a bearer credential on the state-changing routes. This lab does not check a credential. Applying the allowlist to every route, rather than a path list, is the extra hardening. `127.0.0.1`, `localhost`, and `[::1]` still pass, including a request with no Origin header.

## Run

From the repository root:

```bash
python3 labs/03-dns-rebinding/fixed.py --demo
```

`make test` and `make demo` run the same check. Captured output:

```text
=== Lab 03: DNS rebinding on a custom MCP route ===
payload: PUT /api/connect sets an in-memory marker and does not open a socket
vulnerable   PUT /api/connect     local Host and Origin              status=200 marker=local-ok
vulnerable   PUT /api/connect     Host=attacker.example              status=200 marker=rebound
fixed        PUT /api/connect     local Host and Origin              status=200 marker=local-ok
fixed        PUT /api/connect     Host=attacker.example              status=421 marker=local-ok
fixed        PUT /api/connect     Origin=http://attacker.example     status=403 marker=local-ok
vulnerable   POST /mcp            Host=attacker.example              status=421 marker=rebound
fixed        POST /mcp            Host=attacker.example              status=421 marker=local-ok
vulnerable   POST /mcp            local Host and Origin              status=200 marker=rebound
fixed        POST /mcp            local Host and Origin              status=200 marker=local-ok
```

No real DNS rebinding is replayed. The demo sends forged Host and Origin headers to an in-process client. It does not bind a port, resolve a name, or open a socket.

## Legal and ethical use

Educational, local lab only. The payload sets one in-memory marker and does nothing else. Do not use this against a system you are not authorized to test.
