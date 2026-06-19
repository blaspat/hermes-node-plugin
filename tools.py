"""Tool handlers — the code that runs when the LLM calls each tool.

All four tools are ``def`` (not ``async def``).  The async environment calls
(WS-based I/O with the WSS server) are bridged via ``asyncio.run()`` inside
each handler.  This avoids the ``is_async`` flag mismatch that caused
``async def`` tools to receive the args-dict as a single positional argument
instead of unpacked kwargs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

# Type-checker-only imports (same reasoning as before).
if TYPE_CHECKING:
    from .registry import NodeConnection, NodeRegistry


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def node_exec(
    target: str,
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_ms: int | None = None,
    registry: "NodeRegistry | None" = None,
    **kwargs: Any,
) -> str:
    """Run ``command`` on the named node."""
    if not target:
        return json.dumps({"error": "node_exec: target must be a non-empty string"})
    if not command:
        return json.dumps({"error": "node_exec: command must be a non-empty string"})

    try:
        from .environment import (
            DEFAULT_EXEC_TIMEOUT_SECONDS,
            NodeEnvironment,
        )

        timeout_s = (
            float(timeout_ms) / 1000.0
            if timeout_ms is not None
            else DEFAULT_EXEC_TIMEOUT_SECONDS
        )
        env_obj = NodeEnvironment(
            target, registry=_resolve_registry(registry), timeout=timeout_s
        )
        result = asyncio.run(env_obj.execute(command, cwd=cwd or "", env=env))
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": f"node_exec failed: {e}"})


def node_read(
    target: str,
    path: str,
    *,
    timeout_ms: int | None = None,
    registry: "NodeRegistry | None" = None,
    **kwargs: Any,
) -> str:
    """Read a file from the named node."""
    if not target:
        return json.dumps({"error": "node_read: target must be a non-empty string"})
    if not path:
        return json.dumps({"error": "node_read: path must be a non-empty string"})

    try:
        from .environment import (
            DEFAULT_EXEC_TIMEOUT_SECONDS,
            NodeEnvironment,
        )

        timeout_s = (
            float(timeout_ms) / 1000.0
            if timeout_ms is not None
            else DEFAULT_EXEC_TIMEOUT_SECONDS
        )
        env_obj = NodeEnvironment(
            target, registry=_resolve_registry(registry), timeout=timeout_s
        )
        result = asyncio.run(env_obj.read(path, timeout=timeout_s))
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": f"node_read failed: {e}"})


def node_write(
    target: str,
    path: str,
    content: str,
    *,
    mode: str = "overwrite",
    timeout_ms: int | None = None,
    registry: "NodeRegistry | None" = None,
    **kwargs: Any,
) -> str:
    """Write text to a file on the named node."""
    if not target:
        return json.dumps({"error": "node_write: target must be a non-empty string"})
    if not path:
        return json.dumps({"error": "node_write: path must be a non-empty string"})

    try:
        from .environment import (
            DEFAULT_EXEC_TIMEOUT_SECONDS,
            MAX_FILE_BYTES,
            NodeEnvironment,
        )

        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_FILE_BYTES:
            return json.dumps({
                "error": (
                    f"node_write: content is {len(content_bytes)} bytes, exceeds "
                    f"MAX_FILE_BYTES ({MAX_FILE_BYTES}); chunk or truncate first"
                )
            })

        timeout_s = (
            float(timeout_ms) / 1000.0
            if timeout_ms is not None
            else DEFAULT_EXEC_TIMEOUT_SECONDS
        )
        env_obj = NodeEnvironment(
            target, registry=_resolve_registry(registry), timeout=timeout_s
        )
        result = asyncio.run(
            env_obj.write(path, content, mode=mode, timeout=timeout_s)
        )
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": f"node_write failed: {e}"})


def node_list(
    registry: "NodeRegistry | None" = None,
    **kwargs: Any,
) -> str:
    """List paired nodes with their current connection state."""
    try:
        reg = _resolve_registry(registry)
        conns = asyncio.run(reg.list_connected())
        return json.dumps({
            "nodes": [_connection_summary(c) for c in conns],
            "count": len(conns),
        })
    except Exception as e:
        return json.dumps({"error": f"node_list failed: {e}"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_registry(override: "NodeRegistry | None") -> "NodeRegistry":
    """Return ``override`` if given, else the singleton runner's registry."""
    if override is not None:
        return override
    from .lifecycle import get_default_runner

    return get_default_runner()._registry  # type: ignore[attr-defined]


def _connection_summary(conn: "NodeConnection") -> dict[str, Any]:
    """Render a :class:`NodeConnection` as a JSON-serialisable dict."""
    return {
        "name": conn.name,
        "connected": True,
        "connected_at": conn.connected_at.isoformat(),
        "last_heartbeat": conn.last_heartbeat.isoformat()
        if conn.last_heartbeat is not None
        else None,
        "session_id": conn.session_id,
        "remote_addr": conn.remote_addr,
    }


# Public symbols.
__all__ = [
    "node_exec",
    "node_read",
    "node_write",
    "node_list",
]
