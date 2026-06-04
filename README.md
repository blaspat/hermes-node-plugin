# hermes-nodes-plugin

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that turns any Hermes profile into a "brain" that can command remote nodes (laptops, NAS, headless boxes) over an authenticated WebSocket. Pairs with the [`hermes-nodes`](https://github.com/blaspat/hermes-nodes) Go binary.

> **Status:** pre-v0.1.0. Implementation in progress; see [`REQUIREMENTS.md`](./REQUIREMENTS.md) for the spec.

## What it does

Once installed, Kate (or any Hermes agent in any profile) gains four new tools:

- `node_exec(target, command)` — run a shell command on a paired node
- `node_read(target, path)` — read a file on a paired node
- `node_write(target, path, content)` — write a file on a paired node
- `node_list()` — show all known nodes and their connection state

This lets Kate do things like:
- Run tests on a laptop that don't fit in a container on the VPS
- Edit a project that lives on the user's machine
- Read a file from a NAS without going through SSH
- Pair as a brain-and-arm with machines that have no inbound network access

## Install

From GitHub (recommended during v0.x):

```bash
# Activate the Hermes profile's venv first
source ~/.hermes/profiles/kate/venv/bin/activate

# Install the plugin (editable mode for development)
pip install -e git+https://github.com/blaspat/hermes-nodes-plugin.git#egg=hermes-nodes-plugin

# OR from a local clone
git clone https://github.com/blaspat/hermes-nodes-plugin.git
cd hermes-nodes-plugin
pip install -e .
```

Once installed, the plugin auto-loads via Hermes's `hermes_agent.plugins` entry-point group — **no config file changes needed**. Verify with:

```bash
hermes --help | grep "node "
# should show: node        Pair, list, and revoke remote node connections.
```

## TLS configuration

The plugin does **not** need its own TLS cert in the common case. You have three options:

### Option A (recommended) — terminate TLS in nginx, run plugin on localhost

Nginx fronts the public WSS endpoint and proxies to the plugin on `127.0.0.1:6969` over plain HTTP. This is how almost every production deployment looks.

```nginx
# /etc/nginx/sites-enabled/hermes.yourdomain.com
upstream hermes_nodes {
    server 127.0.0.1:6969;
}

server {
    listen 443 ssl;
    server_name hermes.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location /ws/nodes {
        proxy_pass http://hermes_nodes;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;  # WSS connections are long-lived
    }
}
```

In this setup, the plugin binds to `127.0.0.1:6969` and `tls_cert_path` / `tls_key_path` are not used (use `0.0.0.0` for `host` is also unnecessary; `127.0.0.1` is the right choice for nginx-fronted deployments).

### Option B — plugin terminates TLS directly

If you're not using nginx (or another reverse proxy), point the plugin at your cert and key:

```yaml
host: 0.0.0.0
port: 6969
tls_cert_path: /etc/letsencrypt/live/yourdomain.com/fullchain.pem
tls_key_path: /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

You'll need to open port 6969 in your VPS firewall. Certbot with `--nginx` or `--standalone` both work; the plugin will read the resulting files on each start (no hot-reload in v1, restart on cert renewal).

### Option C — development / self-signed

For local testing without a real domain. Generate a cert, point the plugin at it, pin the CA on the node side. **Not recommended for production.**

## Configuration reference

```yaml
# ~/.hermes/hermes-nodes.yaml
host: 0.0.0.0
port: 6969
tls_cert_path: ~/.hermes/nodes/server.crt
tls_key_path: ~/.hermes/nodes/server.key
token_store_path: ~/.hermes/nodes/tokens.json
audit_log_path: ~/.hermes/logs/nodes-audit.log
audit_retention_days: 365
```

| Env var | Default | Purpose |
|---|---|---|
| `HERMES_NODES_HOST` | `0.0.0.0` | WSS bind address |
| `HERMES_NODES_PORT` | `6969` | WSS bind port |
| `HERMES_NODES_TLS_CERT` | `~/.hermes/nodes/server.crt` | TLS cert path |
| `HERMES_NODES_TLS_KEY` | `~/.hermes/nodes/server.key` | TLS key path |
| `HERMES_NODES_TOKEN_KEY` | *(required)* | Fernet key for encrypting tokens at rest. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `HERMES_NODES_AUDIT_RETENTION_DAYS` | `365` | How long to keep audit log entries |

**`HERMES_NODES_TOKEN_KEY` is required.** If unset, `hermes node pair` will guide you through generating one.

## Usage

```bash
# Pair a new node (laptop, NAS, etc.)
hermes node pair --name work-laptop
# Output:
#   Pairing token for "work-laptop":
#   aBcD1234eFgH5678...
#
#   Run on the laptop:
#     hermes-node pair \
#       --server wss://vps.yourdomain.com:6969 \
#       --token aBcD1234eFgH5678...

# List paired nodes + connection state
hermes node list
# Output:
#   work-laptop    connected    2026-06-04 10:00:00
#   home-nas       disconnected never seen

# Revoke a node
hermes node revoke --name work-laptop
# Output:
#   Revoked node "work-laptop". Active connection (if any) has been dropped.
```

From inside a Kate (or any Hermes) session:

```
> node_list()
["work-laptop (connected)", "home-nas (disconnected)"]

> node_exec("work-laptop", "cd ~/code/myapp && pytest -q")
"====== test session starts ======
 ...
 5 passed in 0.42s"

> node_read("work-laptop", "~/code/myapp/src/x.py")
"...file contents..."

> node_write("work-laptop", "~/code/myapp/src/x.py", new_content, mode="overwrite")
{"bytes_written": 1234, "status": "ok"}
```

## Architecture

```
┌──────────────────────────────────────┐         ┌──────────────────────────────────────┐
│ VPS (any Hermes profile)             │         │ Laptop (or any node device)          │
│                                      │         │                                      │
│  hermes-agent (Python)               │         │  hermes-node (Go binary)             │
│  ┌─────────────────────────────┐     │         │  ┌─────────────────────────────┐     │
│  │ hermes-nodes-plugin         │     │  WSS    │  │  - shell executor           │     │
│  │  - NodeServer (FastAPI)     │◄────┼────┐    ├────┤  - filesystem ops           │     │
│  │  - NodeRegistry             │     │    │    │    │  - audit log                │     │
│  │  - NodeEnvironment (Kate)   │     │    │    │    │  - path allowlist           │     │
│  │  - tokens (Fernet)          │     │    │    │    │                             │     │
│  └─────────────────────────────┘     │    │    │    └─────────────────────────────┘     │
│                                      │    │    │                                      │
└──────────────────────────────────────┘    │    └──────────────────────────────────────┘
                                            │
                              WSS over TLS 6969
```

**The protocol contract between them lives in [`hermes-nodes/PROTOCOL.md`](https://github.com/blaspat/hermes-nodes/blob/main/PROTOCOL.md).** Both sides pin to it for tests.

## Development

```bash
git clone https://github.com/blaspat/hermes-nodes-plugin.git
cd hermes-nodes-plugin
python3.11 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Unit tests
pytest tests/ -v

# E2E (requires the Go binary from hermes-nodes built and on PATH)
pytest tests/e2e/ -v -m e2e
```

## Related

- **[hermes-nodes](https://github.com/blaspat/hermes-nodes)** — the Go node binary (the "arm")
- **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** — the agent framework this plugs into
- **[OpenClaw](https://docs.openclaw.ai/nodes)** — the design pattern this is inspired by (different protocol, different ecosystem)

## License

MIT
