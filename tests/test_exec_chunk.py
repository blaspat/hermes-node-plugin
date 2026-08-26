"""Tests for exec_chunk streaming (issue #116)."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run a coroutine in a fresh event loop (works without pytest-asyncio)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ChunkState lifecycle tests
# ---------------------------------------------------------------------------


class TestChunkStateLifecycle:
    """set / get / remove round-trips on the chunk state registry."""

    def test_set_get_remove_roundtrip(self) -> None:
        from hermes_node_plugin.registry import ChunkState, NodeRegistry

        registry = NodeRegistry()

        # Create a temp file handle.
        fd, path = tempfile.mkstemp(suffix=".chunk", prefix="test-")
        fh = os.fdopen(fd, "wb")
        cs = ChunkState(file=fh, path=path, last_chunk_at=100.0, total_bytes=42)

        async def _test():
            await registry.set_chunk_state("node-a", "req-1", cs)
            got = await registry.get_chunk_state("node-a", "req-1")
            assert got is not None
            assert got.path == path
            assert got.total_bytes == 42

            removed = await registry.remove_chunk_state("node-a", "req-1")
            assert removed is not None
            assert removed.path == path

            # Should be gone now.
            assert await registry.get_chunk_state("node-a", "req-1") is None

        _run(_test())

        # Clean up.
        with suppress(Exception):
            fh.close()
        with suppress(Exception):
            Path(path).unlink(missing_ok=True)

    def test_get_nonexistent_returns_none(self) -> None:
        from hermes_node_plugin.registry import NodeRegistry

        registry = NodeRegistry()

        async def _test():
            assert await registry.get_chunk_state("no-such-node", "no-such-req") is None

        _run(_test())

    def test_remove_nonexistent_returns_none(self) -> None:
        from hermes_node_plugin.registry import NodeRegistry

        registry = NodeRegistry()

        async def _test():
            assert await registry.remove_chunk_state("nobody", "nothing") is None

        _run(_test())


# ---------------------------------------------------------------------------
# fail_node_chunks tests
# ---------------------------------------------------------------------------


class TestFailNodeChunks:
    """fail_node_chunks cleans up files and only targets the named node."""

    def test_fail_node_chunks_cleans_up_files(self, tmp_path: Path) -> None:
        from hermes_node_plugin.registry import ChunkState, NodeRegistry

        registry = NodeRegistry()

        file_paths: list[str] = []
        file_handles: list = []

        async def _test():
            for i in range(3):
                p = tmp_path / f"test-chunk-{i}.chunk"
                p.write_text(f"data-{i}")
                fh = open(str(p), "rb+")  # noqa: ASYNC230,SIM115
                file_handles.append(fh)
                file_paths.append(str(p))
                cs = ChunkState(
                    file=fh,
                    path=str(p),
                    last_chunk_at=100.0,
                    total_bytes=len(f"data-{i}"),
                )
                await registry.set_chunk_state("node-a", f"req-{i}", cs)

            count = await registry.fail_node_chunks("node-a")
            assert count == 3

            # Chunk states should be removed.
            for i in range(3):
                assert await registry.get_chunk_state("node-a", f"req-{i}") is None

        _run(_test())

        # Files should be gone.
        for p in file_paths:
            assert not Path(p).exists(), f"orphan file still exists: {p}"

    def test_fail_node_chunks_only_targets_named_node(self, tmp_path: Path) -> None:
        from hermes_node_plugin.registry import ChunkState, NodeRegistry

        registry = NodeRegistry()

        async def _test():
            p_a = tmp_path / "a.chunk"
            p_a.write_text("a")
            fh_a = open(str(p_a), "rb+")  # noqa: ASYNC230,SIM115
            await registry.set_chunk_state(
                "node-a", "r1",
                ChunkState(file=fh_a, path=str(p_a),
                           last_chunk_at=100.0, total_bytes=1),
            )
            p_b = tmp_path / "b.chunk"
            p_b.write_text("b")
            fh_b = open(str(p_b), "rb+")  # noqa: ASYNC230,SIM115
            await registry.set_chunk_state(
                "node-b", "r1",
                ChunkState(file=fh_b, path=str(p_b),
                           last_chunk_at=100.0, total_bytes=1),
            )

            # Fail only node-a.
            count = await registry.fail_node_chunks("node-a")
            assert count == 1

            # node-a's chunk should be gone.
            assert await registry.get_chunk_state("node-a", "r1") is None
            assert not p_a.exists()

            # node-b's chunk should still be there.
            assert await registry.get_chunk_state("node-b", "r1") is not None
            assert p_b.exists()

            # Clean up node-b.
            await registry.fail_node_chunks("node-b")

        _run(_test())


# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------


class TestExecChunkConfigDefaults:
    """Config defaults for chunk fields (integration sanity check)."""

    def test_defaults(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        cfg = NodeServerConfig()
        assert cfg.exec_chunk_dir == "/tmp/hermes-exec-chunks"
        assert cfg.exec_chunk_max_total_mb == 50
        assert cfg.exec_chunk_timeout_s == 30
        assert cfg.exec_chunk_size == 65536


# ---------------------------------------------------------------------------
# Dual-path exec result — tools.py
# ---------------------------------------------------------------------------


class TestDualPathExec:
    """_node_exec_impl reads from temp file when output_file is present."""

    def test_reads_from_output_file(self, tmp_path: Path) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        # Write a temp file simulating chunked output.
        output_path = tmp_path / "exec-output.chunk"
        output_path.write_text("hello chunked world\nline2\n")

        mock_result = {
            "status": "ok",
            "exec_result": {
                "output_file": str(output_path),
                "exit_code": 0,
                "status": "ok",
            },
        }

        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("test-node", "echo hello"))

        assert result["output"] == "hello chunked world\nline2\n"
        assert result["returncode"] == 0
        # File should have been unlinked.
        assert not output_path.exists()

    def test_output_file_missing_graceful(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        mock_result = {
            "status": "ok",
            "exec_result": {
                "output_file": "/nonexistent/path/output.chunk",
                "exit_code": 0,
            },
        }

        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("test-node", "echo hello"))

        assert "error" in result
        assert "failed to read exec_chunk output file" in result["error"]

    def test_legacy_stdout_stderr_still_works(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        mock_result = {
            "status": "ok",
            "exec_result": {
                "stdout": "hello world\n",
                "stderr": "some error\n",
                "returncode": 0,
            },
        }

        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("test-node", "echo hello"))

        assert "hello world\n" in result["output"]
        assert "some error\n" in result["output"]
        assert "[stderr]" in result["output"]
        assert result["returncode"] == 0

    def test_legacy_stdout_only(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        mock_result = {
            "status": "ok",
            "exec_result": {
                "stdout": "output only\n",
                "returncode": 1,
            },
        }

        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("test-node", "echo hello"))

        assert result["output"] == "output only\n"
        assert result["returncode"] == 1

    def test_non_ok_status(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        mock_result = {
            "status": "timeout",
            "reason": "exec timed out",
        }

        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("test-node", "echo hello"))

        assert result["output"] == "exec timed out"
        assert result["returncode"] == 1


# ---------------------------------------------------------------------------
# _handle_exec_chunk — empty-data final chunk
# ---------------------------------------------------------------------------


class TestHandleExecChunkEmptyFinal:
    """The final chunk (more=false) carries empty data by design — its payload
    is the exit_code/status/duration_ms/truncated metadata. It must complete
    the waiter rather than being rejected as "missing or invalid data".
    """

    def test_empty_final_after_intermediate(self, tmp_path: Path) -> None:
        from hermes_node_plugin.config import NodeServerConfig
        from hermes_node_plugin.registry import NodeRegistry
        from hermes_node_plugin.wsserver.server import _handle_exec_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))

        async def _test():
            waiter = await registry.register_waiter("node-a", "req-1")

            # Intermediate chunk with data (more=true).
            await _handle_exec_chunk(
                registry,
                "node-a",
                {"id": "req-1", "data": "aGVsbG8=", "more": True},
                cfg,
            )
            # Final chunk — empty data, metadata only.
            await _handle_exec_chunk(
                registry,
                "node-a",
                {
                    "id": "req-1",
                    "data": "",
                    "more": False,
                    "exit_code": 0,
                    "status": "ok",
                    "duration_ms": 42,
                    "truncated": False,
                },
                cfg,
            )

            result = await asyncio.wait_for(waiter, timeout=5.0)
            assert result["exit_code"] == 0
            assert result["status"] == "ok"
            assert result["duration_ms"] == 42
            assert result["truncated"] is False
            assert result["output_file"]

            # Assembled output should contain the intermediate data.
            with suppress(Exception):
                assert "hello" in Path(result["output_file"]).read_text()
                Path(result["output_file"]).unlink(missing_ok=True)

        _run(_test())

    def test_missing_chunk_dir_is_recreated(self, tmp_path: Path) -> None:
        from hermes_node_plugin.config import NodeServerConfig
        from hermes_node_plugin.registry import NodeRegistry
        from hermes_node_plugin.wsserver.server import _handle_exec_chunk

        registry = NodeRegistry()
        # Point the config at a subdirectory that does NOT exist yet — like
        # /tmp/hermes-exec-chunks after a reboot while the gateway kept
        # running. _handle_exec_chunk must recreate it, not raise.
        chunk_dir = tmp_path / "chunks"
        assert not chunk_dir.exists()
        cfg = NodeServerConfig(exec_chunk_dir=str(chunk_dir))

        async def _test():
            waiter = await registry.register_waiter("node-c", "req-missing-dir")

            await _handle_exec_chunk(
                registry,
                "node-c",
                {
                    "id": "req-missing-dir",
                    "data": "aGVsbG8=",
                    "more": False,
                    "exit_code": 0,
                    "status": "ok",
                    "duration_ms": 5,
                    "truncated": False,
                },
                cfg,
            )

            result = await asyncio.wait_for(waiter, timeout=5.0)
            assert result["exit_code"] == 0
            assert result["status"] == "ok"
            assert result["output_file"]
            assert chunk_dir.is_dir(), "chunk dir should have been recreated"
            assert Path(result["output_file"]).parent == chunk_dir
            with suppress(Exception):
                Path(result["output_file"]).unlink(missing_ok=True)

        _run(_test())

    def test_empty_final_as_only_chunk(self, tmp_path: Path) -> None:
        from hermes_node_plugin.config import NodeServerConfig
        from hermes_node_plugin.registry import NodeRegistry
        from hermes_node_plugin.wsserver.server import _handle_exec_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))

        async def _test():
            waiter = await registry.register_waiter("node-b", "req-2")

            # A command with no output sends a single empty-data final chunk.
            await _handle_exec_chunk(
                registry,
                "node-b",
                {
                    "id": "req-2",
                    "data": "",
                    "more": False,
                    "exit_code": 7,
                    "status": "error",
                    "duration_ms": 10,
                    "truncated": False,
                },
                cfg,
            )

            result = await asyncio.wait_for(waiter, timeout=5.0)
            assert result["exit_code"] == 7
            assert result["status"] == "error"
            assert result["duration_ms"] == 10
            # The temp file exists but is empty.
            with suppress(Exception):
                assert Path(result["output_file"]).read_text() == ""
                Path(result["output_file"]).unlink(missing_ok=True)

        _run(_test())

    def test_empty_intermediate_still_rejected(self, tmp_path: Path) -> None:
        from hermes_node_plugin.config import NodeServerConfig
        from hermes_node_plugin.registry import NodeRegistry
        from hermes_node_plugin.wsserver.server import _handle_exec_chunk

        registry = NodeRegistry()
        cfg = NodeServerConfig(exec_chunk_dir=str(tmp_path))

        async def _test():
            waiter = await registry.register_waiter("node-c", "req-3")

            # An intermediate chunk (more=true) with empty data is still
            # invalid — it must not create a chunk state.
            await _handle_exec_chunk(
                registry,
                "node-c",
                {"id": "req-3", "data": "", "more": True},
                cfg,
            )

            # No chunk state should have been created.
            assert await registry.get_chunk_state("node-c", "req-3") is None
            # And the waiter must still be pending.
            assert not waiter.done()

        _run(_test())


# ---------------------------------------------------------------------------
# Chunk state concurrent set (stress-test)
# ---------------------------------------------------------------------------


class TestChunkStateConcurrent:
    """Basic concurrent safety for chunk state operations."""

    def test_concurrent_set_different_keys(self) -> None:
        from hermes_node_plugin.registry import ChunkState, NodeRegistry

        registry = NodeRegistry()

        async def _test():
            fd, path = tempfile.mkstemp(suffix=".chunk", prefix="test-")
            fh = os.fdopen(fd, "wb")
            cs = ChunkState(file=fh, path=path, last_chunk_at=100.0, total_bytes=0)

            await registry.set_chunk_state("n1", "r1", cs)

            fd2, path2 = tempfile.mkstemp(suffix=".chunk", prefix="test-")
            fh2 = os.fdopen(fd2, "wb")
            cs2 = ChunkState(file=fh2, path=path2, last_chunk_at=200.0, total_bytes=1)
            await registry.set_chunk_state("n2", "r2", cs2)

            assert await registry.get_chunk_state("n1", "r1") is not None
            assert await registry.get_chunk_state("n2", "r2") is not None

            await registry.remove_chunk_state("n1", "r1")
            await registry.remove_chunk_state("n2", "r2")
            with suppress(Exception):
                fh.close()
            with suppress(Exception):
                fh2.close()
            with suppress(Exception):
                Path(path).unlink(missing_ok=True)
            with suppress(Exception):
                Path(path2).unlink(missing_ok=True)

        _run(_test())


# ---------------------------------------------------------------------------
# Orphan cleanup helper
# ---------------------------------------------------------------------------


class TestOrphanCleanup:
    """_cleanup_orphan_chunks removes leftover .chunk files."""

    def test_cleans_up_orphans(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _cleanup_orphan_chunks

        chunk_dir = tmp_path / "chunks"
        chunk_dir.mkdir()

        (chunk_dir / "a.chunk").write_text("data-a")
        (chunk_dir / "b.chunk").write_text("data-b")
        (chunk_dir / "other.txt").write_text("keep-me")

        count = _run(_cleanup_orphan_chunks(chunk_dir))
        assert count == 2
        assert not (chunk_dir / "a.chunk").exists()
        assert not (chunk_dir / "b.chunk").exists()
        assert (chunk_dir / "other.txt").exists()
        assert (chunk_dir / "other.txt").read_text() == "keep-me"

    def test_empty_dir_returns_zero(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _cleanup_orphan_chunks

        chunk_dir = tmp_path / "empty"
        chunk_dir.mkdir()

        count = _run(_cleanup_orphan_chunks(chunk_dir))
        assert count == 0

    def test_missing_dir_returns_zero(self, tmp_path: Path) -> None:
        from hermes_node_plugin.wsserver.server import _cleanup_orphan_chunks

        missing = tmp_path / "does-not-exist"
        count = _run(_cleanup_orphan_chunks(missing))
        assert count == 0
