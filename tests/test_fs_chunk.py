"""Tests for chunked file read/write on the server side (PROTOCOL §3.9a/§3.11a)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path

from hermes_node_plugin.config import NodeServerConfig
from hermes_node_plugin.registry import NodeConnection, NodeRegistry


def _run(coro):
    return asyncio.run(coro)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class TestReadChunkAssembly:
    """_handle_read_chunk writes bytes to disk and resolves the waiter."""

    def test_three_chunks_assemble_and_verify(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _handle_read_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))
        payload = b"".join(bytes([i % 256]) for i in range(3000))
        shasum = hashlib.sha256(payload).hexdigest()

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-r")
            for seq, off in enumerate(range(0, len(payload), 1000), start=1):
                piece = payload[off : off + 1000]
                last = off + 1000 >= len(payload)
                msg = {
                    "id": "req-r",
                    "seq": seq,
                    "data": _b64(piece),
                    "more": not last,
                }
                if last:
                    msg.update(
                        status="ok", size_bytes=len(payload), sha256=shasum
                    )
                await _handle_read_chunk(registry, "node-a", msg, cfg)

            result = await asyncio.wait_for(waiter, timeout=2)
            assert result["status"] == "ok"
            assert result["size_bytes"] == len(payload)
            assert result["sha256"] == shasum
            assert Path(result["output_file"]).read_bytes() == payload
            Path(result["output_file"]).unlink()

        _run(_test())

    def test_sha_mismatch_fails_and_removes_file(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _handle_read_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))
        payload = b"payload bytes"

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-r")
            await _handle_read_chunk(
                registry,
                "node-a",
                {
                    "id": "req-r",
                    "seq": 1,
                    "data": _b64(payload),
                    "more": False,
                    "status": "ok",
                    "size_bytes": len(payload),
                    "sha256": "0" * 64,
                },
                cfg,
            )
            result = await asyncio.wait_for(waiter, timeout=2)
            assert result["status"] == "error"
            assert result["reason"] == "sha_mismatch"
            assert list((tmp_path / "reads").glob("read-*.bin")) == []

        _run(_test())

    def test_size_mismatch_fails(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _handle_read_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))
        payload = b"abc"
        shasum = hashlib.sha256(payload).hexdigest()

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-r")
            await _handle_read_chunk(
                registry,
                "node-a",
                {
                    "id": "req-r",
                    "seq": 1,
                    "data": _b64(payload),
                    "more": False,
                    "status": "ok",
                    "size_bytes": 999,
                    "sha256": shasum,
                },
                cfg,
            )
            result = await asyncio.wait_for(waiter, timeout=2)
            assert result["reason"] == "size_mismatch"
            assert list((tmp_path / "reads").glob("read-*.bin")) == []

        _run(_test())

    def test_out_of_order_seq_aborts(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _handle_read_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-r")
            await _handle_read_chunk(
                registry,
                "node-a",
                {"id": "req-r", "seq": 1, "data": _b64(b"aa"), "more": True},
                cfg,
            )
            await _handle_read_chunk(
                registry,
                "node-a",
                {"id": "req-r", "seq": 5, "data": _b64(b"bb"), "more": False},
                cfg,
            )
            result = await asyncio.wait_for(waiter, timeout=2)
            assert result["reason"] == "bad_sequence"
            assert list((tmp_path / "reads").glob("read-*.bin")) == []

        _run(_test())

    def test_node_reported_error_fails_waiter(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _handle_read_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-r")
            await _handle_read_chunk(
                registry,
                "node-a",
                {
                    "id": "req-r",
                    "seq": 1,
                    "data": "",
                    "more": False,
                    "status": "error",
                    "error": "io_error",
                    "error_detail": "disk on fire",
                },
                cfg,
            )
            result = await asyncio.wait_for(waiter, timeout=2)
            assert result["status"] == "error"
            assert result["reason"] == "io_error"

        _run(_test())


class TestWriteChunkSending:
    """The server streams write_chunk frames, one chunk at a time."""

    def test_inline_payload_is_chunked(self) -> None:
        from hermes_node_plugin.wsserver import server as srv

        sent: list[dict] = []

        class FakeWS:
            async def send_json(self, msg):
                sent.append(msg)

        payload = b"x" * (srv._WRITE_CHUNK_BYTES + 10)

        async def _test():
            await srv._send_write_chunks(
                FakeWS(), "req-w", "/tmp/out", "overwrite", payload
            )

        _run(_test())

        assert len(sent) == 2
        assert sent[0]["seq"] == 1 and sent[0]["more"] is True
        assert sent[0]["size_bytes"] == len(payload)
        assert sent[0]["sha256"] == hashlib.sha256(payload).hexdigest()
        assert sent[1]["seq"] == 2 and sent[1]["more"] is False
        assert "path" not in sent[1]
        rebuilt = b"".join(base64.b64decode(m["data"]) for m in sent)
        assert rebuilt == payload

    def test_from_path_streams_file(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver import server as srv

        source = tmp_path / "src.bin"
        source.write_bytes(b"y" * (2 * srv._WRITE_CHUNK_BYTES))
        sent: list[dict] = []

        class FakeWS:
            async def send_json(self, msg):
                sent.append(msg)

        async def _test():
            await srv._send_write_from_file(
                FakeWS(), "req-w", "/tmp/out", "overwrite", str(source)
            )

        _run(_test())

        assert [m["seq"] for m in sent] == [1, 2]
        assert sent[-1]["more"] is False
        assert b"".join(base64.b64decode(m["data"]) for m in sent) == source.read_bytes()

    def test_empty_payload_still_sends_final_frame(self) -> None:
        from hermes_node_plugin.wsserver import server as srv

        sent: list[dict] = []

        class FakeWS:
            async def send_json(self, msg):
                sent.append(msg)

        async def _test():
            await srv._send_write_chunks(
                FakeWS(), "req-w", "/tmp/out", "overwrite", b""
            )

        _run(_test())

        assert len(sent) == 1
        assert sent[0]["more"] is False


class TestNodeCapabilities:
    def test_connection_records_capabilities(self) -> None:
        conn = NodeConnection(
            name="n", websocket=object(), capabilities=["read_chunk", "write_chunk"]
        )
        assert "write_chunk" in conn.capabilities

    def test_defaults_to_empty(self) -> None:
        assert NodeConnection(name="n", websocket=object()).capabilities == []


class TestWriteEndpoint:
    """nodes_write picks the wire shape from the node's capabilities."""

    def _post(self, caps: list[str], body: dict):
        from fastapi.testclient import TestClient
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        sent: list[dict] = []

        class FakeWS:
            async def send_json(self, msg):
                sent.append(msg)
                registry = app.state.registry
                if msg["type"] == "write" or not msg.get("more", True):
                    await registry.complete_waiter(
                        "fake-node", msg["id"], {"status": "ok", "bytes_written": 1}
                    )

        with TestClient(app) as client:
            registry = app.state.registry
            _run(
                registry.register(
                    NodeConnection(
                        name="fake-node",
                        websocket=FakeWS(),
                        capabilities=caps,
                    )
                )
            )
            headers = {"Authorization": f"Bearer {app.state.internal_token}"}
            resp = client.post(
                "/nodes/fake-node/write", json=body, headers=headers
            )
            assert resp.status_code == 200, resp.text
        return sent, resp.json()

    def test_chunked_when_node_advertises(self) -> None:
        sent, out = self._post(
            ["write_chunk"],
            {"path": "/tmp/x", "content": "hello", "mode": "overwrite"},
        )
        assert out["status"] == "ok"
        assert sent[0]["type"] == "write_chunk"
        assert sent[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()
        assert sent[0]["size_bytes"] == 5

    def test_legacy_when_node_does_not(self) -> None:
        sent, out = self._post(
            [],
            {"path": "/tmp/x", "content": "hello", "mode": "overwrite"},
        )
        assert out["status"] == "ok"
        assert sent[0]["type"] == "write"

    def test_from_path_requires_capability(self) -> None:
        from fastapi.testclient import TestClient
        from hermes_node_plugin.wsserver.server import create_app

        app = create_app()
        with TestClient(app) as client:
            _run(app.state.registry.register(NodeConnection(name="fake-node", websocket=object())))
            headers = {"Authorization": f"Bearer {app.state.internal_token}"}
            resp = client.post(
                "/nodes/fake-node/write",
                json={"path": "/tmp/x", "from_path": "/etc/hostname"},
                headers=headers,
            )
            assert resp.json()["status"] == "error"
            assert "write_chunk" in resp.json()["reason"]


class TestReadHeadPreview:
    """tools._read_local_head returns the head plus the local path."""

    def test_returns_head_and_path(self, tmp_path: Path) -> None:
        from hermes_node_plugin.tools import (
            MAX_READ_RETURN_BYTES,
            _read_local_head,
        )

        d = tmp_path / "reads"
        d.mkdir()
        f = d / "read-abc.bin"
        body = b"a" * (MAX_READ_RETURN_BYTES + 500)
        f.write_bytes(body)

        out = json.loads(_read_local_head(str(f), {"size_bytes": len(body)}))
        assert out["path"] == str(f)
        assert out["size_bytes"] == len(body)
        assert out["truncated"] is True
        assert len(out["content"]) == MAX_READ_RETURN_BYTES
