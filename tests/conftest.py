"""pytest configuration — redirect internal token path to temp."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _redirect_internal_token(tmp_path: Path) -> None:
    """Redirect ``_INTERNAL_TOKEN_PATH`` to ``tmp_path`` for every test.

    This prevents tests from writing to ``~/.hermes/nodes-internal-token``
    and keeps each test isolated.
    """
    import hermes_node_plugin.tools as tools_mod
    import hermes_node_plugin.wsserver.server as server_mod

    token_path = tmp_path / ".hermes" / "nodes-internal-token"
    server_mod._INTERNAL_TOKEN_PATH = token_path
    tools_mod._INTERNAL_TOKEN_PATH = token_path
    yield
    # Restore the original paths (other concurrent tests may depend on them)
    tools_mod._INTERNAL_TOKEN_PATH = Path.home() / ".hermes" / "nodes-internal-token"
    server_mod._INTERNAL_TOKEN_PATH = (
        Path.home() / ".hermes" / "nodes-internal-token"
    )
