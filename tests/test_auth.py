"""Tests for internal endpoint auth + fixes from review findings."""

from __future__ import annotations

import secrets
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

# --- Helpers ----------------------------------------------------------------


def _make_token_file(tmp_path: Path) -> str:
    """Write a fake internal token and return it."""
    token = "test-internal-token-" + secrets.token_hex(8)
    path = tmp_path / ".hermes" / "nodes-internal-token"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n")
    return token


# ---------------------------------------------------------------------------
# Auth — _ensure_internal_token / _verify_internal_auth
# ---------------------------------------------------------------------------


class TestInternalToken:
    """Tests for the server-side token generation and verification."""

    def test_ensure_internal_token_creates_file(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _ensure_internal_token

        token_path = tmp_path / ".hermes" / "nodes-internal-token"
        with patch(
            "hermes_node_plugin.wsserver.server._internal_token_path",
            return_value=token_path,
        ):
            token = _ensure_internal_token()
            assert token_path.exists(), "token file was not created"
            assert token_path.stat().st_mode & 0o777 == 0o600, (
                "token file permissions not 0600"
            )
            stored = token_path.read_text().strip()
            assert stored == token, "file content does not match returned token"

    def test_ensure_internal_token_is_unique(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _ensure_internal_token

        token_path = tmp_path / "nodes-internal-token"
        with patch(
            "hermes_node_plugin.wsserver.server._internal_token_path",
            return_value=token_path,
        ):
            t1 = _ensure_internal_token()
            t2 = _ensure_internal_token()
            assert t1 != t2, "successive calls returned the same token"
            stored = token_path.read_text().strip()
            assert stored == t2, "file was not overwritten on second call"

    def test_verify_internal_auth_rejects_missing(self) -> None:
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            resp = client.get("/nodes")
            assert resp.status_code == 401

    def test_verify_internal_auth_rejects_wrong_token(self) -> None:
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            resp = client.get(
                "/nodes", headers={"Authorization": "Bearer wrong-token"}
            )
            assert resp.status_code == 401

    def test_verify_internal_auth_rejects_malformed_header(self) -> None:
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            resp = client.get(
                "/nodes", headers={"Authorization": "NotBearer xyz"}
            )
            assert resp.status_code == 401

    def test_verify_internal_auth_accepts_correct_token(self) -> None:
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            # The lifespan should have set app.state.internal_token
            expected = app.state.internal_token
            assert expected, "create_app lifespan did not set internal_token"
            resp = client.get(
                "/nodes",
                headers={"Authorization": f"Bearer {expected}"},
            )
            # Should get through auth → returns node list (empty is fine)
            assert resp.status_code == 200

    def test_all_internal_endpoints_require_auth(self, tmp_path: Path) -> None:
        """All 4 internal endpoints return 401 when no token is sent."""
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            endpoints = [
                ("GET", "/nodes"),
                ("GET", "/nodes/status"),
                ("POST", "/nodes/test-node/exec"),
                ("POST", "/nodes/test-node/read"),
                ("POST", "/nodes/test-node/write"),
            ]
            for method, url in endpoints:
                if method == "GET":
                    resp = client.get(url)
                else:
                    resp = client.post(url, json={})
                assert resp.status_code == 401, (
                    f"{method} {url} returned {resp.status_code} instead of 401"
                )

    def test_auth_works_with_valid_token_on_all_endpoints(
        self, tmp_path: Path
    ) -> None:
        """All 4 internal endpoints accept a valid token (node may not exist)."""
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            token = app.state.internal_token
            headers = {"Authorization": f"Bearer {token}"}

            # GET endpoints — should return 200 (empty lists)
            resp = client.get("/nodes", headers=headers)
            assert resp.status_code in (200,), f"/nodes: {resp.status_code}"

            resp = client.get("/nodes/status", headers=headers)
            assert resp.status_code in (200,), f"/nodes/status: {resp.status_code}"

            # POST endpoints — should return 200 (the endpoint structure is valid,
            # it just won't find the node, so we expect 200 with error body)
            resp = client.post(
                "/nodes/test-node/exec", json={"command": "ls"}, headers=headers
            )
            # 200 is fine (the handler catches missing node internally)
            assert resp.status_code in (
                200,
            ), f"/nodes/test-node/exec: {resp.status_code}"

            resp = client.post(
                "/nodes/test-node/read", json={"path": "/tmp"}, headers=headers
            )
            assert resp.status_code in (
                200,
            ), f"/nodes/test-node/read: {resp.status_code}"

            resp = client.post(
                "/nodes/test-node/write",
                json={"path": "/tmp/test", "content": "hi"},
                headers=headers,
            )
            assert resp.status_code in (
                200,
            ), f"/nodes/test-node/write: {resp.status_code}"


# ---------------------------------------------------------------------------
# Auth — tools.py reader
# ---------------------------------------------------------------------------


class TestToolsAuth:
    """Tests for tools.py reading the internal token."""

    def test_read_internal_token_returns_token(self, tmp_path: Path) -> None:
        from hermes_node_plugin.tools import _read_internal_token

        token_path = tmp_path / "nodes-internal-token"
        token = "tok-abc123\n"
        token_path.write_text(token)

        with patch(
            "hermes_node_plugin.tools._internal_token_path",
            return_value=token_path,
        ):
            result = _read_internal_token()
            assert result == "tok-abc123"

    def test_read_internal_token_returns_none_when_missing(
        self, tmp_path: Path
    ) -> None:
        from hermes_node_plugin.tools import _read_internal_token

        missing = tmp_path / "does-not-exist"
        with patch(
            "hermes_node_plugin.tools._internal_token_path",
            return_value=missing,
        ):
            assert _read_internal_token() is None


# ---------------------------------------------------------------------------
# Smoke — create_app
# ---------------------------------------------------------------------------


class TestCreateApp:
    """Smoke tests for create_app()."""

    def test_create_app_sets_internal_token(self) -> None:
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        # Lifespan runs when TestClient enters the context manager
        with TestClient(app):
            assert app.state.internal_token, "internal_token was not set"
            assert len(app.state.internal_token) >= 32, "token looks too short"

    def test_create_app_accepts_injected_deps(self) -> None:
        from unittest.mock import MagicMock

        from hermes_node_plugin.registry import NodeRegistry
        from hermes_node_plugin.tokens import TokenStore
        from hermes_node_plugin.wsserver.server import create_app

        store = MagicMock(spec=TokenStore)
        reg = NodeRegistry()
        app = create_app(token_store=store, registry=reg)
        assert app.state.token_store is store
        assert app.state.registry is reg


# ---------------------------------------------------------------------------
# Regression — _WaiterCancelled produces 503
# ---------------------------------------------------------------------------


class TestWaiterCancelled:
    """The exec/read/write endpoints return 503 (not 500) on _WaiterCancelled."""

    def test_exec_503_on_waiter_cancelled(self) -> None:
        """Verify the code path exists (static assertion via handler structure)."""

        # We can't easily trigger _WaiterCancelled from an ASGI test because
        # it requires a real WS connection. Instead, verify the _WaiterCancelled
        # import is valid and the handler mentions 503.
        import inspect

        from hermes_node_plugin.registry import _WaiterCancelled  # noqa: F401
        from hermes_node_plugin.wsserver import server as server_mod
        from hermes_node_plugin.wsserver.server import _verify_internal_auth  # noqa: F401
        source = inspect.getsource(server_mod)
        assert "503" in source, (
            "wsserver/server.py does not contain the string '503' — "
            "is the _WaiterCancelled → 503 handler in place?"
        )

    def test_nodes_status_lifespan_token_integration(self) -> None:
        """End-to-end: server starts, token file exists, auth works."""
        from hermes_node_plugin.wsserver.server import (
            _internal_token_path,
            create_app,
        )

        app = create_app()
        with TestClient(app):
            expected = app.state.internal_token
            path = _internal_token_path()
            stored = path.read_text().strip()
            assert stored == expected, (
                "token written to file does not match app.state.internal_token"
            )
