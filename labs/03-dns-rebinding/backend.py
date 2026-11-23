"""In-memory backend for the DNS-rebinding lab.

Shared by the vulnerable and fixed servers. This module does not check
Host or Origin and does not open a connection. Each server keeps its own
`BackendState`, so the two builds do not share a marker.
"""

from __future__ import annotations

from starlette.responses import JSONResponse


def new_backend() -> dict[str, str]:
    """Simulated backend. Nothing here talks to a network."""
    return {"backend": "memory://local", "marker": ""}


def apply_connect(payload: dict, state: dict[str, str]) -> None:
    """Record a simulated backend name and a marker.

    Names have to use the `memory://` scheme so this lab cannot be pointed
    at a real service. The values are stored and nothing is dialed.
    """
    name = payload.get("backend")
    marker = payload.get("marker")
    if not isinstance(name, str) or not name.startswith("memory://") or name == "memory://":
        raise ValueError("backend must be a memory:// name")
    if not isinstance(marker, str):
        raise ValueError("marker must be a string")
    state["backend"] = name
    state["marker"] = marker


def json_error(detail: str, status_code: int) -> JSONResponse:
    return JSONResponse({"success": False, "error": detail}, status_code=status_code)


class BackendState:
    """One server's stored backend."""

    def __init__(self) -> None:
        self._state = new_backend()

    def reset_backend(self) -> dict[str, str]:
        self._state = new_backend()
        return self._state

    def backend(self) -> dict[str, str]:
        return self._state
