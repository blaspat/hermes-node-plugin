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
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
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
from ..registry import NodeConnection, NodeRegistry, _WaiterCancelled
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
                raise ValueError(
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
# Helpers
# ---------------------------------------------------------------------------


def _build_hello_ack(
    protocol_version: str,
    session_id: str,
    *,
    ecdh_pub: str | None = None,
    salt: str | None = None,
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
    except Exception:
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
    """Send JSON, swallowing client-gone errors."""
    try:
        await websocket.send_json(payload)
    except (WebSocketDisconnect, RuntimeError) as exc:
        logger.debug(
            "send_json after client disconnect (%s); payload dropped", exc
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
    content: str
    mode: str = "overwrite"
    timeout_ms: int | None = None


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
        """Startup: generate the internal auth token shared with tools.py."""
        app.state.internal_token = _ensure_internal_token()
        yield

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

            await _send_json_safe(
                websocket,
                _build_hello_ack(
                    hello.protocol_version,
                    session_id,
                    ecdh_pub=_e2e.encode_public_key(server_kp.public),
                    salt=_e2e.encode_b64(salt_bytes),
                ),
            )
        else:
            e2e_handshake_key = None
            await _send_json_safe(
                websocket,
                _build_hello_ack(hello.protocol_version, session_id),
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
        else:
            # Legacy auth — validate token
            is_valid = False
        try:
            # tokens.validate() does a full read-decrypt-write cycle with
            # os.fsync on the token store. That blocks the event loop if
            # called directly from async code. Push it to a thread.
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
        )
        previous = await registry.register(conn)
        if previous is not None and previous.websocket is not websocket:
            await _safe_close(previous.websocket, 1000)  # WS_1000_NORMAL_CLOSURE

        if e2e_session_key is not None:
            conn.e2e_session_key = e2e_session_key  # type: ignore[attr-defined]
            await _send_json_safe(
                websocket,
                _build_auth_ok(
                    session_id,
                    proof=_e2e.encode_b64(server_proof),
                ),
            )
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
        try:
            future = await registry.register_waiter(node_name, request_id)
        except Exception as e:
            return {
                "status": "error",
                "code": 500,
                "reason": f"failed to register waiter: {e}",
            }

        try:
            import base64 as _base64

            content_b64 = _base64.b64encode(body.content.encode("utf-8")).decode("ascii")
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
    "_internal_token_path",
    "_read_token_from_disk",
    "_safe_close",
    "create_app",
]
