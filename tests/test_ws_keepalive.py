"""uvicorn's WS transport ping must stay disabled.

It's a protocol-level Ping that only the transport answers, so a node
busy inside a long handler cannot pong it and uvicorn closes the socket
1011 mid-call. Reproduced live: a 50s exec died at ~40s with the ping
on, completed with it off. Liveness is the app-level heartbeat (§6).
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
import uvicorn
from hermes_node_plugin.config import NodeServerConfig
from hermes_node_plugin.lifecycle import ServerRunner
from hermes_node_plugin.registry import NodeRegistry
from hermes_node_plugin.tokens import token_store_from_config


class _Stop(Exception):
    """Sentinel: stop right after uvicorn.Config is built."""


def test_ws_transport_ping_disabled(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("HERMES_NODES_TOKEN_KEY", Fernet.generate_key().decode())
    cfg = NodeServerConfig(
        host="127.0.0.1",
        port=0,
        token_store_path=str(tmp_path / "tokens.json"),
        exec_chunk_dir=str(tmp_path / "chunks"),
    )
    runner = ServerRunner(
        config=cfg,
        token_store=token_store_from_config(cfg),
        registry=NodeRegistry(),
    )

    captured = {}

    def fake_config(*args, **kwargs):
        captured.update(kwargs)
        raise _Stop

    async def scenario():
        with patch.object(uvicorn, "Config", fake_config):
            await runner.start()

    with pytest.raises(_Stop):
        asyncio.run(scenario())

    assert captured["ws_ping_interval"] is None, (
        "uvicorn transport ping must stay off — a node busy in a long "
        "handler can't pong it and the socket dies mid-call"
    )
    assert captured["ws_ping_timeout"] is None
