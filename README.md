# hermes-nodes-plugin
> A Hermes Agent plugin that turns any Hermes profile into a "brain" that can command remote nodes — laptops, NAS, headless boxes — over an authenticated WebSocket. Pairs with the [`hermes-nodes`](https://github.com/blaspat/hermes-nodes) Go binary.

## Quick Start
- **Install:** `python -m pip install hermes-nodes-plugin==0.1.0` (or `uv pip install hermes-nodes-plugin==0.1.0`)
- **Init:** Activate the Hermes venv:
  ```bash
  source ~/.hermes/hermes-agent/venv/bin/activate  # default profile
  # or for a named profile:
  # source ~/.hermes/profiles/<name>/venv/bin/activate
  ```
- **Verify installation:** `hermes node --help` should display the node subcommands.
- **Pair a node:**
  ```bash
  hermes node pair --name work-laptop
  # Server prints a one‑time token
  # Run on the laptop:
  hermes-node pair \
    --server wss://yourdomain.com:6969 \
    --token <token>
  ```
- **Check connectivity:** `hermes node list` should list the new node as *connected*.
- **Example command execution:**
  ```bash
  hermes node exec work-laptop "cd ~/code && pytest -q"
  ```

## Installation
### From a released package (recommended)
1. **Activate the Hermes venv** (see Quick Start).
2. Install the pinned version:
   ```bash
   python -m pip install hermes-nodes-plugin==0.1.0
   # or, using uv for speed:
   uv pip install hermes-nodes-plugin==0.1.0
   ```
   This pulls the pre‑built wheel from PyPI, guaranteeing compatible dependencies.

### From source (for development or pre‑release)
1. **Clone the repo** anywhere you like:
   ```bash
   git clone https://github.com/blaspat/hermes-nodes-plugin.git
   cd hermes-nodes-plugin
   ```
2. **Activate the Hermes venv** (default profile or the one you use for Hermes).
3. **Install in editable mode** so changes reflect instantly:
   ```bash
   python -m pip install -e .
   # or, with uv:
   uv pip install -e .
   ```
4. Verify the CLI tools appear:
   ```bash
   hermes node --help
   ```

## Configuration
The plugin reads its settings from `~/.hermes/hermes-nodes.yaml`. Environment variables prefixed with `HERMES_NODES_` override file values (e.g. `HERMES_NODES_PORT`). Minimal example:
```yaml
host: 127.0.0.1          # bind address (use 0.0.0.0 only behind a trusted proxy)
port: 6969               # WebSocket port
tls_cert_path: null      # path to PEM cert – null to rely on external TLS termination
tls_key_path: null       # path to PEM key – null if not terminating TLS here
token_store_path: ~/.hermes/nodes/tokens.json
audit_log_path: ~/.hermes/logs/nodes-audit.log
audit_retention_days: 365
handshake_timeout_seconds: 10
```
Key options:
- **host / port** – where the plugin listens.
- **tls_cert_path & tls_key_path** – enable the plugin to terminate TLS itself; leave null if you terminate TLS in nginx.
- **token_store_path** – encrypted token store (Fernet). The first `hermes node pair` will generate a key and store it here.
- **audit_log_path** – JSONL audit log for every node interaction.
- **handshake_timeout_seconds** – max seconds to await the node’s hello/auth frames.

## Core Features
- `node_exec(target, command)` — run shell commands on a paired node
- `node_read(target, path)` — read a file on a paired node
- `node_write(target, path, content, mode="overwrite")` — write a file on a paired node
- `node_list()` — list paired nodes and their connection state
- CLI subcommands: `hermes node pair`, `hermes node list`, `hermes node revoke`, `hermes node status`

## Usage
1. **TLS Configuration** – see the detailed nginx proxy example in the Quick Start or set `tls_cert_path`/`tls_key_path` for direct TLS.
2. **Node Pairing** – run the `pair` command on the server, then on the node with the provided token.
3. **Command Execution** – use `node_exec` inside an agent session or `hermes node exec <target> "<cmd>"` from the CLI.
4. **File Operations** – `node_read` and `node_write` work with absolute or home‑relative paths.
5. **Disconnecting** – `hermes node revoke --name <target>` drops the live connection and invalidates the token.

## Contributing
- Code Style: Follow `CONTRIBUTING.md`.
- Test it: `pytest tests/ -v` for unit tests, `pytest tests/e2e/ -v -m e2e` for end‑to‑end.
- Workflow: Fork → Branch → PR. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Roadmap / FAQ
- [ ] Stabilize TLS handling across environments.
- [ ] Add auto‑revoke stale connections.
- Q: Does it support Windows nodes? A: Not officially; only Linux/macOS via WSL or similar.

## Related
- **hermes-nodes:** Remote node binary (`github.com/blaspat/hermes-nodes`).
- **Hermes Agent:** Core agent framework (`github.com/NousResearch/hermes-agent`).
- **Documentation:** Full plugin docs (`~/.hermes/hermes-nodes-plugin/README.md`).

---
License: MIT | Author: © 2026 Blasius Patrick