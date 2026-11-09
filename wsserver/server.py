"""WSS server for paired hermes-node connections.

Pair with ``hermes-node`` Go binary (``blaspat/hermes-node``).
``../hermes-node/PROTOCOL.md`` §1 (connection lifecycle) and §3.1-3.5
(message types ``hello`` / ``hello_ack`` / ``auth`` / ``auth_ok`` /
``auth_err``). The server is the dial-ee — nodes are outbound-only
and connect to ``/ws/nodes`` on this FastAPI app.

Subpackage structure
-------------------

* ``wsserver.server``   — FastAPI app factory, handshake, HTTP dispatch.
* ``wsserver.handlers`` — inbound message routing and waiter completion.

Security choices (matching REQUIREMENTS NFR-1.x and the Go-side
conventions in PROTOCOL.md §7):

  * Hello version check: the server compares ``MAJOR`` components
    only (per PROTOCOL §5 "a MAJOR bump is the only thing that can
    break compatibility"). A major mismatch → ``hello_err`` + close 4002.
  * Out-of-order messages close with 4003 ("Message out of order")
    per PROTOCOL §1 failure modes.
  * Auth failure closes with 4001 ("Auth failed") per PROTOCOL
    §3.5. The server sends ``auth_err`` *before* closing so the
    client gets a structured reason.
  * Token comparison is delegated to :meth:`TokenStore.validate`,
    which uses ``hmac.compare_digest`` (NFR-1.1).

WebSocket close codes are taken from PROTOCOL §4 verbatim.
"""

from __future__ import annotations

import asyncio
import base64 as _base64
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..config import NodeServerConfig
from ..errors import TokenStoreError
from ..ratelimit import _RateLimiter
from ..registry import ChunkState, NodeConnection, NodeRegistry, _WaiterCancelled
from ..tokens import TokenStore, token_store_from_config
from .handlers import route_inbound

logger = logging.getLogger(__name__)

# Close codes from PROTOCOL.md §4.
CLOSE_AUTH_FAILED = 4001
CLOSE_PROTOCOL_VERSION = 4002
CLOSE_MESSAGE_OUT_OF_ORDER = 4003
CLOSE_RATE_LIMIT_EXCEEDED = 4004
# 4005 is unassigned in PROTOCOL §4; allocated here for handshake-timeout
# so clients can distinguish it from rate-limit disconnects by close code
# alone (e.g. when the error frame is lost).
CLOSE_HANDSHAKE_TIMEOUT = 4005

# Field caps for Pydantic models (issue #14, DoS hardening).
MAX_NODE_NAME_LEN = 64
MAX_TOKEN_LEN = 64
MAX_PROTOCOL_VERSION_LEN = 32
MAX_NODE_VERSION_LEN = 32
MAX_PLATFORM_LEN = 32
MAX_ARCH_LEN = 32
MAX_CAPABILITIES = 16
MAX_CAPABILITY_LEN = 32
MAX_TS_LEN = 32

# Capabilities this server supports. read_chunk keeps big node→server
# transfers out of the HTTP response (PROTOCOL §3.9a).
_SERVER_CAPABILITIES = ["exec_chunk", "read_chunk"]

# Protocol version — accept any minor at the same major (PROTOCOL §5).
PROTOCOL_MAJOR = 0

# -- Internal endpoint auth (option B) ---------------------------------
# Secret shared between the server and tools.py via a file on disk.
def _internal_token_path() -> Path:
    """Return the path for the internal auth token file.

    Always uses the shared path ``~/.hermes/nodes-internal-token``.
    All profiles share the same token — the default gateway owns the
    WSS server and generates the token; other profiles read it.
    """
    return Path.home() / ".hermes" / "nodes-internal-token"


def _ensure_internal_token() -> str:
    """Generate a fresh internal auth token, write it to disk (mode 0600)."""
    token = secrets.token_hex(32)
    path = _internal_token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o600)
    try:
        os.write(fd, token.encode("utf-8"))
        with open(fd, "wb", closefd=False) as f:
            f.write(b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    return token


def _read_token_from_disk() -> str | None:
    """Read the internal auth token from the shared token file.

    Reads on every call so manual edits and auto-start regenerations
    take effect without a gateway restart.  Returns ``None`` when the
    file is missing or empty (server not yet initialised).
    """
    try:
        raw = _internal_token_path().read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError):
        return None
    if not raw:
        return None
    return raw.partition("\n")[0]


async def _verify_internal_auth(request: Request) -> None:
    """FastAPI dependency that guards internal HTTP endpoints.

    Reads the token from disk on every request so manual edits and
    auto-start regenerations take effect without a full gateway restart.
    Returns 401/503 if missing or wrong.  Uses ``hmac.compare_digest``
    for constant-time comparison.
    """
    expected: str | None = _read_token_from_disk()
    if expected is None:
        raise HTTPException(status_code=503, detail="Server not ready")
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    if not hmac.compare_digest(auth_header.removeprefix("Bearer "), expected):
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Message envelope (Pydantic models for validated inbound messages)
# ---------------------------------------------------------------------------


class _HelloMessage(BaseModel):
    """``hello`` from the node (PROTOCOL §3.1).

    Field caps (issue #14): every string field has a ``max_length``
    so a 1MB payload fails Pydantic validation before the server
    allocates the full string. ``extra="forbid"`` rejects unknown
    fields with a 4xx-shaped error instead of a 500.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(pattern=r"^hello$")
    protocol_version: str = Field(max_length=MAX_PROTOCOL_VERSION_LEN)
    ts: str | None = Field(default=None, max_length=MAX_TS_LEN)
    node_name: str = Field(max_length=MAX_NODE_NAME_LEN, min_length=1)
    node_version: str | None = Field(default=None, max_length=MAX_NODE_VERSION_LEN)
    platform: str | None = Field(default=None, max_length=MAX_PLATFORM_LEN)
    arch: str | None = Field(default=None, max_length=MAX_ARCH_LEN)
    capabilities: list[str] | None = None
    e2e: bool | None = Field(default=None)
    ecdh_pub: str | None = Field(default=None, max_length=MAX_TOKEN_LEN)

    @field_validator("node_name", mode="before")
    @classmethod
    def _strip_node_name(cls, value: Any) -> Any:
        """Reject whitespace-only node_name (issue #21)."""
        if isinstance(value, str) and not value.strip():
            raise ValueError("node_name must not be whitespace-only")
        return value

    @field_validator("capabilities", mode="before")
    @classmethod
    def _cap_capabilities(cls, value: Any) -> Any:
        """Bound the ``capabilities`` list to a sane size."""
        if value is None or not isinstance(value, list):
            return value
        if len(value) > MAX_CAPABILITIES:
            raise ValueError(
                f"capabilities must be a list of at most {MAX_CAPABILITIES} items, "
                f"got {len(value)}"
            )
        for i, item in enumerate(value):
            if not isinstance(item, str):
                raise TypeError(
                    f"capabilities[{i}] must be a string, got {type(item).__name__}"
                )
            if len(item) > MAX_CAPABILITY_LEN:
                raise ValueError(
                    f"capabilities[{i}] exceeds max length {MAX_CAPABILITY_LEN}"
                )
        return value


class _AuthMessage(BaseModel):
    """``auth`` from the node (PROTOCOL §3.4).

    Field caps (issue #14): ``node_name`` and ``token`` capped at 64
    chars; ``extra="forbid"`` rejects any other fields.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(pattern=r"^auth$")
    node_name: str = Field(max_length=MAX_NODE_NAME_LEN)
    token: str | None = Field(default=None, max_length=MAX_TOKEN_LEN)
    proof: str | None = Field(default=None, max_length=MAX_TOKEN_LEN)
    ts: str | None = Field(default=None, max_length=MAX_TS_LEN)


# ---------------------------------------------------------------------------
# exec_chunk helpers (issue #116)
# ---------------------------------------------------------------------------


def _chunk_dir_total_bytes(chunk_dir: str) -> int:
    """Return the total size in bytes of all ``exec-*.chunk`` files.

    Only exec assemblies count: read assemblies (§3.9a) are bounded per
    file by the node's ``fs_chunk_max_mb`` and pruned by age, so letting
    a 200 MiB read consume the exec budget would block every later exec.

    Runs synchronously — callers should wrap in ``asyncio.to_thread`` when
    the directory may contain large numbers of files.
    """
    import os as _os

    total = 0
    try:
        for entry in _os.scandir(chunk_dir):
            if entry.is_file() and entry.name.startswith("exec-"):
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


async def _handle_exec_chunk(
    registry: NodeRegistry,
    node_name: str,
    raw: dict[str, Any],
    config: NodeServerConfig,
) -> None:
    """Process an inbound ``exec_chunk`` message from a connected node.

    The node streams a large exec result in base64-encoded chunks.
    The server assembles them into a temporary file on disk and, when
    the final chunk arrives, completes the waiter with a reference to
    the temp file (rather than inlining the full output).

    Schema per PROTOCOL §3.7:

        {
          "type": "exec_chunk",
          "id": "<request_id>",
          "data": "<base64>",
          "more": true|false,
          "exit_code": <int>,       // only meaningful on more=false
          "status": "ok"|"timeout", // only meaningful on more=false
          "duration_ms": <int>,     // only meaningful on more=false
          "truncated": <bool>,      // only meaningful on more=false
        }
    """
    import time as _time

    request_id = raw.get("id")
    if not isinstance(request_id, str) or not request_id:
        logger.warning(
            "exec_chunk from %r missing or invalid request_id: %r",
            node_name,
            request_id,
        )
        return

    more = raw.get("more", True)

    data_b64 = raw.get("data")
    # The final chunk (more=false) carries empty data by design — its
    # payload is the exit_code/status/duration_ms/truncated metadata, not
    # output bytes. Only intermediate chunks (more=true) must carry data.
    # Rejecting empty data here would drop the completion metadata and
    # strand the waiter until the per-call timeout.
    if not isinstance(data_b64, str) or (not data_b64 and more):
        logger.warning(
            "exec_chunk from %r id=%r missing or invalid data",
            node_name,
            request_id,
        )
        return

    # -- Decode the chunk data -------------------------------------------
    # base64.b64decode("") returns b"" (empty bytes), so an empty-data
    # final chunk decodes cleanly and appends nothing.
    try:
        chunk_bytes = _base64.b64decode(data_b64)
    except Exception:
        logger.warning(
            "exec_chunk from %r id=%r base64 decode failed",
            node_name,
            request_id,
        )
        return

    # -- Get or create ChunkState ----------------------------------------
    cs = await registry.get_chunk_state(node_name, request_id)
    if cs is None:
        # First chunk — create a temp file and ChunkState.
        # Check the total size cap before creating.
        if config.exec_chunk_max_total_mb > 0:
            total_bytes = await asyncio.to_thread(
                _chunk_dir_total_bytes, config.exec_chunk_dir
            )
            cap_bytes = config.exec_chunk_max_total_mb * 1024 * 1024
            if total_bytes + len(chunk_bytes) > cap_bytes:
                logger.warning(
                    "exec_chunk from %r id=%r rejected: total chunk dir size "
                    "%d bytes would exceed cap of %d MiB",
                    node_name,
                    request_id,
                    total_bytes + len(chunk_bytes),
                    config.exec_chunk_max_total_mb,
                )
                # Complete the waiter with a size-limit error so the caller
                # doesn't hang.
                await registry.complete_waiter(
                    node_name,
                    request_id,
                    {
                        "status": "error",
                        "reason": "chunk_size_limit",
                        "total_bytes": total_bytes,
                        "cap_mb": config.exec_chunk_max_total_mb,
                    },
                )
                return

        # The chunk dir may vanish (e.g. /tmp cleared on reboot while the
        # gateway keeps running) — recreate it before the first write so a
        # missing dir can't wedge exec (mkstemp would raise FileNotFoundError
        # and drop the WSS mid-call).
        Path(config.exec_chunk_dir).mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(
            suffix=".chunk", prefix="exec-", dir=config.exec_chunk_dir
        )
        file_handle = os.fdopen(fd, "wb")
        cs = ChunkState(
            file=file_handle,
            path=path,
            last_chunk_at=_time.monotonic(),
            total_bytes=0,
        )
        await registry.set_chunk_state(node_name, request_id, cs)

    # -- Append data to the temp file (non-blocking — disk I/O in executor) -
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, cs.file.write, chunk_bytes)
        await loop.run_in_executor(None, cs.file.flush)
    except Exception:
        logger.warning(
            "exec_chunk from %r id=%r write to temp file failed",
            node_name,
            request_id,
        )
        await registry.remove_chunk_state(node_name, request_id)
        with suppress(Exception):
            cs.file.close()
        with suppress(Exception):
            Path(cs.path).unlink(missing_ok=True)
        return

    cs.total_bytes += len(chunk_bytes)
    cs.last_chunk_at = _time.monotonic()
    await registry.set_chunk_state(node_name, request_id, cs)

    # -- If more chunks are coming, we're done for now -------------------
    if more:
        return

    # -- Final chunk — close file, complete waiter ----------------------
    await registry.remove_chunk_state(node_name, request_id)
    with suppress(Exception):
        cs.file.close()

    exit_code = raw.get("exit_code", 0)
    status = raw.get("status", "ok")
    duration_ms = raw.get("duration_ms", 0)
    truncated = raw.get("truncated", False)

    await registry.complete_waiter(
        node_name,
        request_id,
        {
            "output_file": cs.path,
            "exit_code": exit_code,
            "status": status,
            "duration_ms": duration_ms,
            "truncated": truncated,
        },
    )


# ---------------------------------------------------------------------------
# read_chunk assembly (PROTOCOL §3.9a)
# ---------------------------------------------------------------------------


async def _handle_read_chunk(
    registry: NodeRegistry,
    node_name: str,
    raw: dict[str, Any],
    config: NodeServerConfig,
) -> None:
    """Assemble an inbound ``read_chunk`` stream into a local file.

    The node streams a large file in base64 chunks. Bytes go straight to
    disk, and the final frame completes the waiter with the temp file's
    path — the payload never travels back through an HTTP response, which
    is what made multi-hundred-MB reads expensive (PROTOCOL §3.9a).

    Schema per PROTOCOL §3.9a:

        {
          "type": "read_chunk",
          "id": "<request_id>",
          "seq": 3,
          "data": "<base64>",        // empty on the final frame
          "more": true,
          "status": "ok",            // final frame only
          "size_bytes": 1234,        // final frame only
          "sha256": "<hex>",         // final frame only
          "error": "io_error",       // final frame only, on failure
          "error_detail": "..."
        }
    """
    import hashlib as _hashlib
    import time as _time

    request_id = raw.get("id")
    if not isinstance(request_id, str) or not request_id:
        logger.warning(
            "read_chunk from %r missing or invalid request_id: %r",
            node_name,
            request_id,
        )
        return

    more = raw.get("more", True)
    data_b64 = raw.get("data")
    if not isinstance(data_b64, str) or (not data_b64 and more):
        logger.warning(
            "read_chunk from %r id=%r missing or invalid data",
            node_name,
            request_id,
        )
        return

    try:
        chunk_bytes = _base64.b64decode(data_b64)
    except Exception:
        logger.warning(
            "read_chunk from %r id=%r base64 decode failed", node_name, request_id
        )
        await _abort_read_chunk(
            registry,
            node_name,
            request_id,
            "bad_base64",
            "chunk payload is not valid base64",
        )
        return

    cs = await registry.get_chunk_state(node_name, request_id)
    if cs is None:
        # ponytail: same dir and sweep as exec_chunk. The total-dir cap is
        # deliberately not applied — a read is one file bounded by the
        # node's fs_chunk_max_mb, and a 50 MiB dir cap would reject the
        # very transfers this path exists for.
        # Read assemblies live in a subdirectory: the startup orphan sweep
        # unlinks every *.chunk in the chunk dir, which would delete files
        # the agent has just been handed a path to.
        read_dir = Path(config.exec_chunk_dir) / "reads"
        read_dir.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(suffix=".bin", prefix="read-", dir=read_dir)
        cs = ChunkState(
            file=os.fdopen(fd, "wb"),
            path=path,
            last_chunk_at=_time.monotonic(),
            total_bytes=0,
            hasher=_hashlib.sha256(),
        )

    # -- Ordering: seq starts at 1 and increments by one per frame --------
    want_seq = cs.seq + 1
    seq = raw.get("seq")
    if isinstance(seq, int) and seq != want_seq:
        await _abort_read_chunk(
            registry,
            node_name,
            request_id,
            "bad_sequence",
            f"got seq {seq}, want {want_seq}",
            state=cs,
        )
        return
    cs.seq = want_seq

    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, cs.file.write, chunk_bytes)
    except Exception:
        logger.warning(
            "read_chunk from %r id=%r write to temp file failed",
            node_name,
            request_id,
        )
        await _abort_read_chunk(
            registry, node_name, request_id, "io_error", "temp file write failed",
            state=cs,
        )
        return

    cs.total_bytes += len(chunk_bytes)
    if cs.hasher is not None:
        cs.hasher.update(chunk_bytes)
    cs.last_chunk_at = _time.monotonic()
    await registry.set_chunk_state(node_name, request_id, cs)

    if more:
        return

    # -- Final frame: verify, close, hand the path to the waiter ----------
    await registry.remove_chunk_state(node_name, request_id)
    with suppress(Exception):
        cs.file.close()

    status = raw.get("status", "ok")
    if status != "ok":
        reason = raw.get("error") or "io_error"
        detail = raw.get("error_detail") or ""
        with suppress(Exception):
            Path(cs.path).unlink(missing_ok=True)
        await registry.complete_waiter(
            node_name,
            request_id,
            {"status": "error", "reason": reason, "error_detail": detail},
        )
        return

    got_sha = cs.hasher.hexdigest() if cs.hasher is not None else ""
    want_sha = raw.get("sha256")
    want_size = raw.get("size_bytes")
    if isinstance(want_size, int) and want_size != cs.total_bytes:
        with suppress(Exception):
            Path(cs.path).unlink(missing_ok=True)
        await registry.complete_waiter(
            node_name,
            request_id,
            {
                "status": "error",
                "reason": "size_mismatch",
                "error_detail": f"got {cs.total_bytes} bytes, want {want_size}",
            },
        )
        return
    if isinstance(want_sha, str) and want_sha and want_sha.lower() != got_sha:
        with suppress(Exception):
            Path(cs.path).unlink(missing_ok=True)
        await registry.complete_waiter(
            node_name,
            request_id,
            {
                "status": "error",
                "reason": "sha_mismatch",
                "error_detail": f"computed {got_sha}, want {want_sha}",
            },
        )
        return

    await registry.complete_waiter(
        node_name,
        request_id,
        {
            "output_file": cs.path,
            "size_bytes": cs.total_bytes,
            "sha256": got_sha,
            "status": "ok",
        },
    )


async def _abort_read_chunk(
    registry: NodeRegistry,
    node_name: str,
    request_id: str,
    reason: str,
    detail: str,
    *,
    state: ChunkState | None = None,
) -> None:
    """Drop a half-assembled read and fail its waiter.

    Removes the temp file and closes the handle so a bad stream can't leak
    an fd or disk space, then completes the waiter so the caller gets the
    error instead of a timeout.
    """
    cs = state if state is not None else await registry.remove_chunk_state(
        node_name, request_id
    )
    if cs is not None:
        with suppress(Exception):
            cs.file.close()
        with suppress(Exception):
            Path(cs.path).unlink(missing_ok=True)
    await registry.remove_chunk_state(node_name, request_id)
    await registry.complete_waiter(
        node_name,
        request_id,
        {"status": "error", "reason": reason, "error_detail": detail},
    )


# ---------------------------------------------------------------------------
# write_chunk sending (PROTOCOL §3.11a)
# ---------------------------------------------------------------------------


_WRITE_CHUNK_BYTES = 1024 * 1024


def _sha256_file(path: str, block: int = _WRITE_CHUNK_BYTES) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    import hashlib as _hashlib

    h = _hashlib.sha256()
    with open(path, "rb") as fh:
        for piece in iter(lambda: fh.read(block), b""):
            h.update(piece)
    return h.hexdigest()


async def _send_write_chunk(
    websocket: Any,
    request_id: str,
    seq: int,
    piece: bytes,
    more: bool,
    header: dict[str, Any] | None = None,
) -> None:
    msg: dict[str, Any] = {
        "type": "write_chunk",
        "id": request_id,
        "seq": seq,
        "data": _base64.b64encode(piece).decode("ascii"),
        "more": more,
    }
    if header:
        msg.update(header)
    await websocket.send_json(msg)


async def _send_write_chunks(
    websocket: Any,
    request_id: str,
    path: str,
    mode: str,
    source: bytes,
) -> None:
    """Stream an in-memory payload as ``write_chunk`` frames."""
    import hashlib as _hashlib

    total = len(source)
    header = {
        "path": path,
        "mode": mode,
        "size_bytes": total,
        "sha256": _hashlib.sha256(source).hexdigest(),
    }
    seq = 0
    for off in range(0, total, _WRITE_CHUNK_BYTES):
        seq += 1
        await _send_write_chunk(
            websocket,
            request_id,
            seq,
            source[off : off + _WRITE_CHUNK_BYTES],
            off + _WRITE_CHUNK_BYTES < total,
            header if seq == 1 else None,
        )
    if seq == 0:
        # Empty file still needs a closing frame or the waiter hangs.
        await _send_write_chunk(websocket, request_id, 1, b"", False, header)


async def _send_write_from_file(
    websocket: Any,
    request_id: str,
    path: str,
    mode: str,
    from_path: str,
) -> None:
    """Stream a local file as ``write_chunk`` frames, one chunk at a time.

    Keeps the payload off the HTTP request body entirely: a 500 MiB write
    becomes one small POST plus frames the server reads straight off disk.
    """
    loop = asyncio.get_running_loop()
    size = Path(from_path).stat().st_size
    shasum = await loop.run_in_executor(None, _sha256_file, from_path)
    header = {"path": path, "mode": mode, "size_bytes": size, "sha256": shasum}

    count = (size + _WRITE_CHUNK_BYTES - 1) // _WRITE_CHUNK_BYTES
    if count == 0:
        await _send_write_chunk(websocket, request_id, 1, b"", False, header)
        return

    fh = await loop.run_in_executor(None, open, from_path, "rb")
    try:
        for seq in range(1, count + 1):
            piece = await loop.run_in_executor(None, fh.read, _WRITE_CHUNK_BYTES)
            await _send_write_chunk(
                websocket,
                request_id,
                seq,
                piece,
                seq < count,
                header if seq == 1 else None,
            )
    finally:
        await loop.run_in_executor(None, fh.close)


# ---------------------------------------------------------------------------
# Chunk timeout sweep (issue #116)
# ---------------------------------------------------------------------------


async def _chunk_timeout_sweep(
    registry: NodeRegistry,
    config: NodeServerConfig,
    *,
    interval: float = 5.0,
) -> None:
    """Background task that periodically prunes stale exec_chunk states.

    Every *interval* seconds, scans the registry's ``_chunk_states`` for
    entries whose ``last_chunk_at`` is older than
    ``config.exec_chunk_timeout_s`` seconds.  Each stale entry is removed,
    its temp file closed and unlinked, and the corresponding waiter
    completed with a timeout error (code 408).
    """
    import time as _time

    while True:
        try:
            await asyncio.sleep(interval)
            now = _time.monotonic()
            timeout_s = config.exec_chunk_timeout_s

            # Snapshot stale keys under the lock.
            stale_keys: list[tuple[str, str]] = []
            stale_states: list[ChunkState] = []
            async with registry._lock:
                for (key, cs) in list(registry._chunk_states.items()):
                    if now - cs.last_chunk_at > timeout_s:
                        stale_keys.append(key)
                        stale_state = registry._chunk_states.pop(key, None)
                        if stale_state is not None:
                            stale_states.append(stale_state)

            for (node_name, request_id), cs in zip(stale_keys, stale_states):
                # Close the file handle.
                with suppress(Exception):
                    cs.file.close()
                # Unlink the temp file.
                with suppress(Exception):
                    Path(cs.path).unlink(missing_ok=True)
                # Complete the waiter (if one is still waiting).
                await registry.complete_waiter(
                    node_name,
                    request_id,
                    {
                        "status": "error",
                        "code": 408,
                        "reason": (
                            f"chunked transfer timed out after {timeout_s}s "
                            f"without a closing chunk"
                        ),
                    },
                )
                logger.warning(
                    "exec_chunk timeout sweep: cleaned up stale chunk "
                    "node=%r id=%r age=%.1fs",
                    node_name,
                    request_id,
                    now - cs.last_chunk_at,
                )

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("exec_chunk timeout sweep error; continuing")


# ---------------------------------------------------------------------------
# Orphan chunk cleanup (issue #116)
# ---------------------------------------------------------------------------


async def _cleanup_orphan_chunks(chunk_dir: Path) -> int:
    """Remove any ``*.chunk`` files left behind by a previous crash.

    Runs the directory scan in a thread-pool executor so it never blocks
    the event loop on a slow filesystem.  Returns the count of removed
    files.
    """
    import os as _os

    def _scan_and_unlink() -> int:
        count = 0
        try:
            for entry in _os.scandir(str(chunk_dir)):
                if entry.is_file() and entry.name.endswith(".chunk"):
                    try:
                        _os.unlink(entry.path)
                        count += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return count

    return await asyncio.to_thread(_scan_and_unlink)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_hello_ack(
    protocol_version: str,
    session_id: str,
    *,
    ecdh_pub: str | None = None,
    salt: str | None = None,
    capabilities: list[str] | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "type": "hello_ack",
        "protocol_version": protocol_version,
        "session_id": session_id,
        "server_time": _now_rfc3339_ms(),
    }
    if ecdh_pub is not None:
        msg["ecdh_pub"] = ecdh_pub
    if salt is not None:
        msg["salt"] = salt
    if capabilities is not None:
        msg["capabilities"] = capabilities
    return msg


def _build_hello_err(
    reason: str, code: int, server_max_version: str
) -> dict[str, Any]:
    return {
        "type": "hello_err",
        "reason": reason,
        "code": code,
        "server_max_version": server_max_version,
    }


def _build_auth_ok(
    session_id: str,
    *,
    proof: str | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "type": "auth_ok",
        "session_id": session_id,
    }
    if proof is not None:
        msg["proof"] = proof
    return msg


def _build_auth_err(reason: str, code: int) -> dict[str, Any]:
    return {"type": "auth_err", "reason": reason, "code": code}


def _send_e2e_safe(
    websocket: WebSocket,
    msg: dict[str, Any],
    *,
    e2e_key: bytes | None = None,
) -> None:
    """Send a JSON message. If *e2e_key* is set, encrypt into an ``enc`` frame."""
    if e2e_key is not None:
        from .e2e import encode_b64, encrypt_e2e

        plain = json.dumps(msg).encode()
        ct = encrypt_e2e(e2e_key, plain)
        msg = {"type": "enc", "data": encode_b64(ct)}
    try:
        asyncio.create_task(websocket.send_json(msg))
    except Exception:  # noqa: S110
        pass


def _build_rate_limit_err(
    *, node_name: str, limit_per_second: int
) -> dict[str, Any]:
    """Structured ``rate_limit`` error frame (FR-2.6)."""
    return {
        "type": "rate_limit",
        "reason": "rate_limit_exceeded",
        "code": CLOSE_RATE_LIMIT_EXCEEDED,
        "node_name": node_name,
        "limit_per_second": limit_per_second,
    }


def _now_rfc3339_ms() -> str:
    """UTC RFC 3339 timestamp with millisecond precision."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _server_max_version() -> str:
    """The protocol version string the server advertises in ``hello_ack``/``hello_err``."""
    return f"{PROTOCOL_MAJOR}.1.0"


def _major_compatible(declared: str) -> bool:
    """True iff ``declared`` shares our major version (PROTOCOL §5)."""
    try:
        major_str = declared.split(".", 1)[0]
        return int(major_str) == PROTOCOL_MAJOR
    except (ValueError, IndexError):
        return False


async def _send_json_safe(websocket: WebSocket, payload: dict[str, Any]) -> None:
    """Send JSON without allowing send failures to crash the WS handler."""
    try:
        await asyncio.wait_for(websocket.send_json(payload), timeout=5.0)
    except Exception as exc:
        logger.warning(
            "WebSocket JSON send failed type=%r: %s",
            payload.get("type"),
            exc,
        )


async def _safe_close(websocket: WebSocket, code: int) -> None:
    """Close the WebSocket with ``code``, ignoring "already closed" errors."""
    try:
        await websocket.close(code=code)
    except (WebSocketDisconnect, RuntimeError):
        pass


# ---------------------------------------------------------------------------
# Request body models for internal HTTP endpoints.
# Defined at module level to avoid the `from __future__ import annotations`
# + inline-BaseModel interaction that causes FastAPI/Pydantic to treat body
# params as query params → silent 422 (see skill §2.7.0).
# ---------------------------------------------------------------------------


class _ExecRequest(BaseModel):
    command: str
    cwd: str | None = None
    env: dict[str, str] | None = None
    timeout_ms: int | None = None


class _ReadRequest(BaseModel):
    path: str
    timeout_ms: int | None = None


class _WriteRequest(BaseModel):
    path: str
    content: str | None = None
    mode: str = "overwrite"
    timeout_ms: int | None = None
    # Source file on this host — streamed as write_chunk frames instead
    # of travelling in the request body (PROTOCOL §3.11a).
    from_path: str | None = None


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    token_store: TokenStore | None = None,
    registry: NodeRegistry | None = None,
    config: NodeServerConfig | None = None,
    rate_limiter: _RateLimiter | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    """Build a FastAPI app for the WSS node server.

    Args:
        token_store: Token store used to validate the ``auth`` message.
            If ``None``, the app factory calls
            :func:`token_store_from_config` against ``config`` (or a
            default :class:`NodeServerConfig`). Tests inject a stub.
        registry: Connection registry. Defaults to a fresh
            :class:`NodeRegistry` per app.
        config: Server config. Consulted when ``token_store`` is
            not provided; seeds the rate limiter cap.
        rate_limiter: Per-node sliding-window rate limiter (FR-2.6).
            Defaults to a fresh :class:`_RateLimiter` constructed
            with ``config.rate_limit_per_node``.
        clock: Monotonic-clock callable threaded into the default
            :class:`_RateLimiter` so integration tests can drive
            the rate-limit window from a fake clock.

    Returns:
        A :class:`fastapi.FastAPI` with the ``/ws/nodes`` WebSocket
        route registered. The app is not started; the caller (CLI,
        plugin lifecycle, or test) runs it with uvicorn or
        ``httpx.ASGITransport``.
    """
    if config is None:
        config = NodeServerConfig()
    if registry is None:
        registry = NodeRegistry()
    if token_store is None:
        token_store = token_store_from_config(config)
    if rate_limiter is None:
        rate_limiter = _RateLimiter(
            max_calls=config.rate_limit_per_node,
            clock=clock,
        )

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Startup: generate internal auth token, start chunk sweep, cleanup orphans."""
        app.state.internal_token = _ensure_internal_token()

        # Start the exec_chunk timeout sweep as a background task.
        sweep_task = asyncio.create_task(
            _chunk_timeout_sweep(registry, config, interval=5.0)
        )

        # Clean up orphan chunk files from a previous crash.
        chunk_dir = Path(config.exec_chunk_dir)
        chunk_dir.mkdir(parents=True, exist_ok=True)
        cleaned = await _cleanup_orphan_chunks(chunk_dir)
        if cleaned:
            logger.warning(
                "lifespan: cleaned up %d orphan chunk files from %s",
                cleaned,
                chunk_dir,
            )

        try:
            yield
        finally:
            sweep_task.cancel()
            try:
                await sweep_task
            except asyncio.CancelledError:
                pass

    app = FastAPI(title="hermes-node WSS server", lifespan=_lifespan)
    app.state.token_store = token_store
    app.state.registry = registry
    app.state.config = config
    app.state.rate_limiter = rate_limiter

    @app.websocket("/ws/nodes")
    async def ws_nodes(websocket: WebSocket) -> None:
        await websocket.accept()
        session_id = str(uuid.uuid4())
        client = websocket.scope.get("client")
        remote_addr = client[0] if client else ""

        # ── 1. hello --------------------------------------------------------
        try:
            raw = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=config.handshake_timeout_seconds,
            )
        except TimeoutError:
            logger.warning(
                "WSS hello timeout (%.1fs) from %r; closing 4004",
                config.handshake_timeout_seconds,
                remote_addr,
            )
            await _send_json_safe(
                websocket,
                _build_hello_err(
                    reason="handshake_timeout",
                    code=CLOSE_HANDSHAKE_TIMEOUT,
                    server_max_version=_server_max_version(),
                ),
            )
            await _safe_close(websocket, CLOSE_HANDSHAKE_TIMEOUT)
            return
        except Exception:
            await _safe_close(websocket, CLOSE_MESSAGE_OUT_OF_ORDER)
            return

        try:
            hello = _HelloMessage.model_validate(raw)
        except ValidationError:
            msg_type = raw.get("type") if isinstance(raw, dict) else None
            if msg_type != "hello":
                await _send_json_safe(
                    websocket,
                    _build_hello_err(
                        reason="expected_hello",
                        code=CLOSE_MESSAGE_OUT_OF_ORDER,
                        server_max_version=_server_max_version(),
                    ),
                )
            await _safe_close(websocket, CLOSE_MESSAGE_OUT_OF_ORDER)
            return

        if not _major_compatible(hello.protocol_version):
            await _send_json_safe(
                websocket,
                _build_hello_err(
                    reason="unsupported_protocol_version",
                    code=CLOSE_PROTOCOL_VERSION,
                    server_max_version=_server_max_version(),
                ),
            )
            await _safe_close(websocket, CLOSE_PROTOCOL_VERSION)
            return

        # ── E2E: if client sent ecdh_pub, do key exchange ──
        e2e_handshake_key: bytes | None = None
        if hello.e2e and hello.ecdh_pub:
            from . import e2e as _e2e

            try:
                server_kp = _e2e.generate_e2e_keypair()
                client_pub = _e2e.decode_public_key(hello.ecdh_pub)
                shared = _e2e.ecdh(server_kp.private, client_pub)
                salt_bytes = _e2e.generate_salt()
                token = app.state.token_store.resolve_token(hello.node_name)
                e2e_handshake_key = _e2e.derive_handshake_key(
                    shared, salt_bytes, token
                )
            except TokenStoreError as exc:
                logger.warning(
                    "E2E token resolution failed for %r: %s — falling back to legacy auth",
                    hello.node_name, exc,
                )
                e2e_handshake_key = None
            except (ValueError, Exception) as exc:
                logger.warning("E2E key exchange failed for %r: %s", hello.node_name, exc)
                await _send_json_safe(
                    websocket,
                    _build_hello_err(
                        reason=f"e2e_keypair_failed: {exc}",
                        code=CLOSE_PROTOCOL_VERSION,
                        server_max_version=_server_max_version(),
                    ),
                )
                await _safe_close(websocket, CLOSE_PROTOCOL_VERSION)
                return

            if e2e_handshake_key is not None:
                await _send_json_safe(
                    websocket,
                    _build_hello_ack(
                        hello.protocol_version,
                        session_id,
                        ecdh_pub=_e2e.encode_public_key(server_kp.public),
                        salt=_e2e.encode_b64(salt_bytes),
                        capabilities=_SERVER_CAPABILITIES,
                    ),
                )
            else:
                await _send_json_safe(
                    websocket,
                    _build_hello_ack(hello.protocol_version, session_id, capabilities=_SERVER_CAPABILITIES),
                )
        else:
            e2e_handshake_key = None
            await _send_json_safe(
                websocket,
                _build_hello_ack(hello.protocol_version, session_id, capabilities=_SERVER_CAPABILITIES),
            )

        # -- 2. auth ---------------------------------------------------------
        try:
            raw = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=config.handshake_timeout_seconds,
            )
        except TimeoutError:
            logger.warning(
                "WSS auth timeout (%.1fs) from %r (node_name=%r); closing 4004",
                config.handshake_timeout_seconds,
                remote_addr,
                hello.node_name,
            )
            await _send_json_safe(
                websocket,
                _build_auth_err(
                    reason="handshake_timeout",
                    code=CLOSE_HANDSHAKE_TIMEOUT,
                ),
            )
            await _safe_close(websocket, CLOSE_HANDSHAKE_TIMEOUT)
            return
        except Exception:
            await _safe_close(websocket, CLOSE_MESSAGE_OUT_OF_ORDER)
            return

        try:
            auth = _AuthMessage.model_validate(raw)
        except ValidationError:
            logger.warning(
                "auth message validation failed from %r (node_name=%r)",
                remote_addr,
                raw.get("node_name") if isinstance(raw, dict) else "?",
            )
            await _safe_close(websocket, CLOSE_MESSAGE_OUT_OF_ORDER)
            return

        # Validate: presented node_name must match hello.
        if auth.node_name != hello.node_name:
            await _send_json_safe(
                websocket,
                _build_auth_err(reason="unknown_node", code=CLOSE_AUTH_FAILED),
            )
            await _safe_close(websocket, CLOSE_AUTH_FAILED)
            return

        # ── E2E auth: verify proof ──
        e2e_session_key: bytes | None = None
        if e2e_handshake_key is not None:
            from . import (
                e2e as _e2e,  # already imported above, re-assert for type checker
            )

            if not auth.proof:
                logger.warning("E2E auth missing proof from %r", hello.node_name)
                await _send_json_safe(
                    websocket,
                    _build_auth_err(reason="e2e_proof_missing", code=CLOSE_AUTH_FAILED),
                )
                await _safe_close(websocket, CLOSE_AUTH_FAILED)
                return

            try:
                client_pf = _e2e.decode_b64(auth.proof)
                expected = _e2e.compute_client_proof(e2e_handshake_key)
                _e2e.verify_proof(expected, client_pf, "client proof")
            except ValueError as exc:
                logger.warning(
                    "E2E proof mismatch for %r: %s", hello.node_name, exc
                )
                await _send_json_safe(
                    websocket,
                    _build_auth_err(reason="e2e_proof_mismatch", code=CLOSE_AUTH_FAILED),
                )
                await _safe_close(websocket, CLOSE_AUTH_FAILED)
                return

            # Derive session key
            e2e_session_key = _e2e.derive_session_key(e2e_handshake_key, session_id)
            server_proof = _e2e.compute_server_proof(e2e_handshake_key)
            is_valid = True  # proof verified — skip token store check
            logger.warning("E2E proof verified for %r session=%s", auth.node_name, session_id)
            # E2E bypasses token_store.validate() (the only place that
            # stamps last_used_at), so record the successful connect here
            # or `hermes node list` shows "-" forever for E2E nodes.
            # Best-effort; offloaded to a thread like the legacy path.
            try:
                await asyncio.to_thread(token_store.touch_last_used, auth.node_name)
            except Exception as exc:
                logger.debug(
                    "touch_last_used failed for %r: %s", auth.node_name, exc
                )
        else:
            # Legacy auth — validate token
            is_valid = False
            try:
                is_valid = await asyncio.to_thread(
                    token_store.validate, auth.node_name, auth.token
                )
            except TokenStoreError as exc:
                logging.getLogger(__name__).error(
                    "token store error during auth: %s", exc
                )
                await _send_json_safe(
                    websocket,
                    _build_auth_err(reason="invalid_token", code=CLOSE_AUTH_FAILED),
                )
                await _safe_close(websocket, CLOSE_AUTH_FAILED)
                return

        if not is_valid:
            await _send_json_safe(
                websocket,
                _build_auth_err(reason="invalid_token", code=CLOSE_AUTH_FAILED),
            )
            await _safe_close(websocket, CLOSE_AUTH_FAILED)
            return

        # -- 3. register and hold the connection ----------------------------
        conn = NodeConnection(
            name=auth.node_name,
            websocket=websocket,
            session_id=session_id,
            remote_addr=remote_addr,
            capabilities=list(hello.capabilities or []),
        )
        previous = await registry.register(conn)
        logger.warning(
            "node registered: name=%r session=%s previous=%s",
            auth.node_name,
            session_id,
            previous.session_id if previous is not None else "none",
        )
        if previous is not None and previous.websocket is not websocket:
            await _safe_close(previous.websocket, 1000)  # WS_1000_NORMAL_CLOSURE

        if e2e_session_key is not None:
            object.__setattr__(conn, "e2e_session_key", e2e_session_key)
            logger.warning("sending E2E auth_ok: name=%r session=%s", auth.node_name, session_id)
            await _send_json_safe(
                websocket,
                _build_auth_ok(
                    session_id,
                    proof=_e2e.encode_b64(server_proof),
                ),
            )
            logger.warning("sent E2E auth_ok: name=%r session=%s", auth.node_name, session_id)
        else:
            await _send_json_safe(websocket, _build_auth_ok(session_id))

        # -- 4. hold open; route inbound messages -------------------------
        e2e_key: bytes | None = (
            conn.e2e_session_key if hasattr(conn, "e2e_session_key") else None  # type: ignore[attr-defined]
        )

        def _send(msg: dict[str, Any]) -> None:
            _send_e2e_safe(websocket, msg, e2e_key=e2e_key)

        try:
            while True:
                raw = await websocket.receive_json()
                # ── E2E: decrypt enc frames ──
                if raw.get("type") == "enc" and e2e_key is not None:
                    try:
                        from .e2e import decode_b64, decrypt_e2e

                        ct = decode_b64(raw["data"])
                        plain = decrypt_e2e(e2e_key, ct)
                        raw = json.loads(plain)
                    except (ValueError, KeyError, Exception):
                        logger.warning("E2E decrypt failed for %r", auth.node_name)
                        await _safe_close(websocket, 4000)
                        break
                # Heartbeat: any inbound message counts.
                await registry.touch_heartbeat(auth.node_name)
                # Respond to ping.
                if raw.get("type") == "ping":
                    _send(
                        {
                            "type": "pong",
                            "ts": _now_rfc3339_ms(),
                            "echo_ts": raw.get("ts", ""),
                        },
                    )
                # FR-2.6 rate-limit check.
                if not rate_limiter.check(auth.node_name):
                    logger.warning(
                        "rate limit exceeded for node %r; closing 4004",
                        auth.node_name,
                    )
                    await _send_json_safe(
                        websocket,
                        _build_rate_limit_err(
                            node_name=auth.node_name,
                            limit_per_second=rate_limiter.max_calls,
                        ),
                    )
                    await _safe_close(websocket, CLOSE_RATE_LIMIT_EXCEEDED)
                    return
                # Handle exec_chunk streaming before general routing.
                if raw.get("type") == "exec_chunk":
                    await _handle_exec_chunk(
                        registry, auth.node_name, raw, config
                    )
                    continue
                # Same for chunked file reads.
                if raw.get("type") == "read_chunk":
                    await _handle_read_chunk(
                        registry, auth.node_name, raw, config
                    )
                    continue
                # Route to the waiter (if any).
                await route_inbound(registry, auth.node_name, raw)
        except WebSocketDisconnect:
            pass
        finally:
            await registry.unregister(
                auth.node_name, expected_session_id=session_id
            )

    # -- Status endpoint ---------------------------------------------------
    @app.get("/nodes")
    async def nodes_status(
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        """List all currently-connected nodes with their metadata.

        GET /nodes  →  list of connected node info
        """
        connected = await registry.list_connected()
        return {
            "nodes": [
                {
                    "name": c.name,
                    "connected_at": c.connected_at.isoformat(),
                    "last_heartbeat": (
                        c.last_heartbeat.isoformat() if c.last_heartbeat else None
                    ),
                    "session_id": c.session_id,
                    "remote_addr": c.remote_addr,
                    "state": "connected",
                }
                for c in connected
            ]
        }

    @app.get("/nodes/status")
    async def server_status(
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        """Simple server liveness + count check (used by hermes node status CLI)."""
        connected = await registry.list_connected()
        return {
            "server": "ok",
            "port": config.port,
            "connected_count": len(connected),
        }

    # -- Internal exec endpoint --------------------------------------------
    @app.post("/nodes/{node_name}/exec")
    async def nodes_exec(
        node_name: str,
        body: _ExecRequest,
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        conn = await registry.get(node_name)
        if conn is None:
            return {
                "status": "error",
                "code": 404,
                "reason": f"node {node_name!r} is not connected",
            }

        request_id = str(uuid.uuid4())
        timeout_ms = body.timeout_ms or 30_000
        try:
            future = await registry.register_waiter(node_name, request_id)
        except Exception as e:
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to register waiter: {e}",
            }

        exec_payload: dict[str, Any] = {
            "type": "exec",
            "id": request_id,
            "command": body.command,
        }
        if body.cwd:
            exec_payload["cwd"] = body.cwd
        if body.env:
            exec_payload["env"] = body.env

        try:
            await conn.websocket.send_json(exec_payload)
        except Exception as e:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to send exec: {e}",
            }

        try:
            result = await asyncio.wait_for(future, timeout=timeout_ms / 1000.0)
            return {"status": "ok", "exec_result": result}
        except _WaiterCancelled as wc:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 503,
                "reason": f"node disconnected mid-call: {wc}",
            }
        except TimeoutError:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 408,
                "reason": f"exec timed out after {timeout_ms}ms",
            }
        except Exception as e:
            return {"status": "error", "code": 500, "reason": str(e)}

    # -- Internal read endpoint -------------------------------------------
    @app.post("/nodes/{node_name}/read")
    async def nodes_read(
        node_name: str,
        body: _ReadRequest,
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        conn = await registry.get(node_name)
        if conn is None:
            return {
                "status": "error",
                "code": 404,
                "reason": f"node {node_name!r} is not connected",
            }

        request_id = str(uuid.uuid4())
        timeout_ms = body.timeout_ms or 30_000
        try:
            future = await registry.register_waiter(node_name, request_id)
        except Exception as e:
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to register waiter: {e}",
            }

        try:
            await conn.websocket.send_json(
                {"type": "read", "id": request_id, "path": body.path}
            )
        except Exception as e:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to send read: {e}",
            }

        try:
            result = await asyncio.wait_for(future, timeout=timeout_ms / 1000.0)
            return {"status": "ok", "read_result": result}
        except _WaiterCancelled as wc:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 503,
                "reason": f"node disconnected mid-call: {wc}",
            }
        except TimeoutError:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 408,
                "reason": f"read timed out after {timeout_ms}ms",
            }
        except Exception as e:
            return {"status": "error", "code": 500, "reason": str(e)}

    # -- Internal write endpoint -------------------------------------------
    @app.post("/nodes/{node_name}/write")
    async def nodes_write(
        node_name: str,
        body: _WriteRequest,
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        conn = await registry.get(node_name)
        if conn is None:
            return {
                "status": "error",
                "code": 404,
                "reason": f"node {node_name!r} is not connected",
            }

        request_id = str(uuid.uuid4())
        timeout_ms = body.timeout_ms or 30_000

        if not body.content and not body.from_path:
            return {
                "status": "error",
                "code": 400,
                "reason": "write requires content or from_path",
            }

        try:
            future = await registry.register_waiter(node_name, request_id)
        except Exception as e:
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to register waiter: {e}",
            }

        try:
            use_chunks = "write_chunk" in conn.capabilities
            if body.from_path:
                if not use_chunks:
                    await registry.unregister_waiter(node_name, request_id)
                    return {
                        "status": "error",
                        "code": 400,
                        "reason": "node does not advertise write_chunk",
                    }
                await _send_write_from_file(
                    conn.websocket,
                    request_id,
                    body.path,
                    body.mode,
                    body.from_path,
                )
            elif use_chunks:
                await _send_write_chunks(
                    conn.websocket,
                    request_id,
                    body.path,
                    body.mode,
                    (body.content or "").encode("utf-8"),
                )
            else:
                import base64 as _base64

                content_b64 = _base64.b64encode(
                    (body.content or "").encode("utf-8")
                ).decode("ascii")
                await conn.websocket.send_json(
                    {
                        "type": "write",
                        "id": request_id,
                        "path": body.path,
                        "content_b64": content_b64,
                        "mode": body.mode,
                    }
                )
        except Exception as e:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to send write: {e}",
            }

        try:
            result = await asyncio.wait_for(future, timeout=timeout_ms / 1000.0)
            return {"status": "ok", "write_result": result}
        except _WaiterCancelled as wc:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 503,
                "reason": f"node disconnected mid-call: {wc}",
            }
        except TimeoutError:
            await registry.unregister_waiter(node_name, request_id)
            return {
                "status": "error",
                "code": 408,
                "reason": f"write timed out after {timeout_ms}ms",
            }
        except Exception as e:
            return {"status": "error", "code": 500, "reason": str(e)}

    # -- Admin restart endpoint ------------------------------------------

    @app.post("/admin/restart")
    async def admin_restart(
        _: None = Depends(_verify_internal_auth),
    ) -> dict[str, Any]:
        """Drain and restart the WSS server in-place.

        Re-reads the internal auth token from disk, so manual edits to
        ``~/.hermes/nodes-internal-token`` take effect without a full
        gateway restart. WebSocket connections are closed during drain.
        """
        runner = getattr(app.state, "runner", None)
        if runner is None:
            raise HTTPException(
                status_code=503, detail="Server runner not available"
            )
        if not runner.is_running:
            raise HTTPException(
                status_code=409, detail="Server is not running"
            )
        try:
            await runner.drain(timeout=5.0)
            await runner.start()
        except Exception as exc:
            logger.error("hermes-node: admin restart failed: %s", exc)
            raise HTTPException(
                status_code=500, detail=f"Restart failed: {exc}"
            ) from exc
        return {"status": "restarted", "port": runner.port}

    return app


__all__ = [
    "CLOSE_AUTH_FAILED",
    "CLOSE_HANDSHAKE_TIMEOUT",
    "CLOSE_MESSAGE_OUT_OF_ORDER",
    "CLOSE_PROTOCOL_VERSION",
    "CLOSE_RATE_LIMIT_EXCEEDED",
    "PROTOCOL_MAJOR",
    "_ensure_internal_token",
    "_handle_exec_chunk",
    "_internal_token_path",
    "_read_token_from_disk",
    "_safe_close",
    "create_app",
]
