"""Tests for plugin-side output truncation (context-flood guard)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import patch

from hermes_node_plugin.tools import (
    MAX_EXEC_OUTPUT_BYTES,
    MAX_READ_RETURN_BYTES,
)


def _big_text(n_chars: int = 100_000) -> str:
    return ("x" * 99 + "\n") * (n_chars // 100)


class TestExecOutputTruncation:
    def test_large_stdout_is_truncated(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        big = _big_text()
        mock_result = {
            "status": "ok",
            "exec_result": {"stdout": big, "returncode": 0},
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("node", "cat big"))

        assert result["truncated"] is True
        assert "truncated" in result["output"]
        assert len(result["output"]) < len(big)
        # cap + footer slack
        assert len(result["output"].encode("utf-8")) <= MAX_EXEC_OUTPUT_BYTES + 256

    def test_small_stdout_untouched(self) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        mock_result = {
            "status": "ok",
            "exec_result": {"stdout": "small\n", "returncode": 0},
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("node", "echo small"))

        assert result["truncated"] is False
        assert result["output"] == "small\n"

    def test_output_file_path_is_truncated(self, tmp_path: Path) -> None:
        from hermes_node_plugin.tools import _node_exec_impl

        big = _big_text()
        p = tmp_path / "out.chunk"
        p.write_text(big)

        mock_result = {
            "status": "ok",
            "exec_result": {"output_file": str(p), "exit_code": 0},
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_exec_impl("node", "cat big"))

        assert result["truncated"] is True
        assert "truncated" in result["output"]
        assert not p.exists()  # temp file still unlinked after read


class TestReadTruncation:
    def test_large_file_is_truncated(self) -> None:
        from hermes_node_plugin.tools import _node_read_impl

        big = _big_text()
        b64 = base64.b64encode(big.encode("utf-8")).decode()
        mock_result = {
            "status": "ok",
            "read_result": {
                "content_b64": b64,
                "size_bytes": len(big),
                "truncated": False,
            },
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_read_impl("node", "/tmp/big"))

        assert result["truncated"] is True
        assert "truncated" in result["content"]
        assert len(result["content"].encode("utf-8")) <= MAX_READ_RETURN_BYTES + 256

    def test_small_file_untouched(self) -> None:
        from hermes_node_plugin.tools import _node_read_impl

        b64 = base64.b64encode(b"hello").decode()
        mock_result = {
            "status": "ok",
            "read_result": {
                "content_b64": b64,
                "size_bytes": 5,
                "truncated": False,
            },
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_read_impl("node", "/tmp/small"))

        assert result["truncated"] is False
        assert result["content"] == "hello"

    def test_node_truncated_flag_preserved(self) -> None:
        from hermes_node_plugin.tools import _node_read_impl

        b64 = base64.b64encode(b"hello").decode()
        mock_result = {
            "status": "ok",
            "read_result": {
                "content_b64": b64,
                "size_bytes": 5,
                "truncated": True,  # node-side cap already fired
            },
        }
        with patch(
            "hermes_node_plugin.tools._request_with_retry",
            return_value=mock_result,
        ):
            result = json.loads(_node_read_impl("node", "/tmp/small"))

        assert result["truncated"] is True