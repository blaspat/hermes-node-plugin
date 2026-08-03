# E2E Encryption for Hermes Nodes — PAKE Design

## Problem

The WebSocket connection carries operational messages in plain JSON. Transport
TLS encrypts the wire but breaks with proxies in the path (nginx, corporate).
Worse: if someone captures the `auth` message (which contains the pairing
token), they can decrypt all future traffic.

## Solution: ECDH + token-based key agreement

After the `hello ↔ hello_ack` exchange, both sides have established an
ephemeral ECDH shared secret. The pairing token (known to both sides from
initial pairing, **never sent on the wire**) is mixed into the session key
derivation. Both sides prove they derived the same key with an HMAC challenge.
The result is a **per-session** AES-256-GCM key with forward secrecy — even
if an attacker records the entire handshake, they cannot derive the session
key without the pairing token.

## Cryptographic primitives

| Primitive | Choice |
|---|---|
| Key agreement | X25519 (Curve25519 ECDH) |
| Key derivation | HKDF-SHA256 |
| AEAD | AES-256-GCM |
| Mutual authentication | HMAC-SHA256 |
| Nonce | 12 random bytes per message |

## Handshake (replaces current hello/auth flow)

```
Client                                    Server
  │                                         │
  │  ─── Step 1: ECDH exchange ───          │
  │                                         │
  │  hello {                                │
  │    version: 1,                          │
  │    e2e: true,                           │
  │    ecdh_pub: "<base64url X25519 pub>"   │
  │  }                                      │
  │ ──────────────────────────────────────► │  server generates ephemeral keypair
  │                                         │
  │  hello_ack {                            │
  │    session_id: "abc123",                │
  │    ecdh_pub: "<base64url X25519 pub>",  │
  │    salt: "<base64url 32 random bytes>"  │
  │  }                                      │
  │ ◄────────────────────────────────────── │
  │                                         │
  │  ─── Both sides independently compute:  │
  │                                         │
  │  shared_secret = X25519(my_priv, peer_pub)
  │  handshake_key = HKDF-SHA256(           │
  │      ikm  = shared_secret,              │
  │      salt = salt,                       │
  │      info = "hermes-node-e2e-v1"        │
  │               || pairing_token          │   ← never sent, known to both
  │  )                                      │
  │                                         │
  │  ─── Step 2: mutual auth ───            │
  │                                         │
  │  auth {                                 │
  │    node_name: "workmac",                │
  │    proof: HMAC-SHA256(handshake_key,    │
  │                       "client-auth")    │
  │  }                                      │
  │ ──────────────────────────────────────► │  verifies proof
  │                                         │
  │  auth_ok {                              │
  │    session_id: "abc123",                │
  │    proof: HMAC-SHA256(handshake_key,    │
  │                       "server-auth")    │
  │  }                                      │
  │ ◄────────────────────────────────────── │  verifies proof
  │                                         │
  │  ─── Step 3: derive session key ───     │
  │                                         │
  │  session_key = HKDF-SHA256(             │
  │      ikm  = handshake_key,              │
  │      salt = session_id,                 │
  │      info = "hermes-node-session-v1"    │
  │  )                                      │
  │                                         │
  │  ─── E2E ACTIVE ───                     │
  │                                         │
```

### Why this is secure

| Attack | Defense |
|---|---|
| Record entire handshake, replay later | Ephemeral ECDH keys → new shared secret each session. Old `proof` values don't match. |
| Record entire handshake, know token | Still can't derive key — `shared_secret` requires one party's private key (never transmitted) |
| Man-in-the-middle | Attacker can ECDH with both sides, but without token their `handshake_key` differs → `proof` fails → connection closed at auth step |
| Compromise old session | Forward secrecy: ephemeral keys discarded after session. Old ciphertext can't be retroactively decrypted. |

## Encrypted frame (unchanged from v1)

After the handshake, messages use:

```
{"type": "enc", "data": "<base64url(IV || ciphertext || tag)>"}
```

| Offset | Bytes | Content |
|---|---|---|
| 0 | 12 | Random IV |
| 12 | N | AES-256-GCM ciphertext |
| 12+N | 16 | GCM authentication tag |

## What is encrypted

**Encrypted:** `exec`, `exec_result`, `read`, `read_result`, `write`, `write_result`,
and any future operational types.

**Plaintext:** `hello`, `hello_ack`, `auth`, `auth_ok`, `auth_err`, `ping`, `pong`,
`rate_limit`.

## Backward compatibility

- Client sends `e2e: true` in `hello`. Server that doesn't support it omits
  `ecdh_pub` from `hello_ack` → client falls back to legacy plaintext auth.
- Server that supports E2E sends `ecdh_pub`. Client without E2E capability
  doesn't include `e2e: true` in `hello` → server skips ECDH and falls back.

## Message structures

### `hello` (client → server)

```json
{
  "type": "hello",
  "version": 1,
  "e2e": true,
  "ecdh_pub": "hJ2kM9xPqR..."
}
```

### `hello_ack` (server → client)

```json
{
  "type": "hello_ack",
  "session_id": "abc123-def456",
  "ecdh_pub": "qW7nB3xLzF...",
  "salt": "Rj8mK2pQw..."
}
```

### `auth` (client → server)

```json
{
  "type": "auth",
  "node_name": "workmac",
  "proof": "c2VydmVyLWF1dGg..."
}
```

### `auth_ok` (server → client)

```json
{
  "type": "auth_ok",
  "session_id": "abc123-def456",
  "proof": "Y2xpZW50LWF1dGg..."
}
```

### `auth_err` (server → client)

```json
{
  "type": "auth_err",
  "reason": "verification failed",
  "code": 4003
}
```

### `enc` (both directions, post-handshake)

```json
{
  "type": "enc",
  "data": "ZzdDazlN..."
}
```

## Error codes

| Code | Label | Meaning |
|---|---|---|
| 4000 | `E2E_DECRYPT_FAIL` | GCM tag verification failed — wrong key or tampered data |
| 4001 | `E2E_PROOF_MISMATCH` | HMAC proof mismatch — token differs or MITM |
| 4002 | `E2E_KEYPAIR_FAIL` | Failed to generate ephemeral X25519 keypair |
| 4003 | `E2E_PROTOCOL_ERROR` | Missing or malformed E2E fields in handshake |

## Implementation plan (~300 lines total)

### Go (`internal/wire/`)

| File | Change |
|---|---|
| `messages.go` | Add `E2E` / `ECDHPub` / `Proof` fields to handshake structs |
| `e2e.go` (new) | X25519 keygen, ECDH, HKDF derivation, encrypt/decrypt helpers |
| `handshake.go` | ECDH exchange in `hello`/`hello_ack`, proof exchange in `auth`/`auth_ok` |
| `client.go` | After auth_ok, wrap read/write with encrypt/decrypt |

### Python (`wsserver/`)

| File | Change |
|---|---|
| `e2e.py` (new) | X25519 keygen, ECDH, HKDF derivation, encrypt/decrypt helpers |
| `server.py` | ECDH exchange during hello handshake, proof verification, encrypt/decrypt wrappers |

### Tests (`e2e_test.go` + `test_e2e.py`)

- `TestFullHandshake` — happy path: connect, handshake, encrypt/decrypt roundtrip
- `TestWrongToken` — client with wrong token fails at proof verification (4001)
- `TestMITM` — attacker relays ECDH but can't forge proof → auth fails
- `TestBackwardCompat` — client without `e2e: true` gets plaintext legacy auth
- `TestKeyIsolation` — two sessions produce different session keys
- `TestDecryptFailure` — tampered `enc` data → close code 4000

## Dependency changes

**Go:** `golang.org/x/crypto` (already in go.mod — used for SSH terminal)

**Python:** `cryptography` (already in pyproject.toml — used by token encryption)

No new dependencies. X25519 and HKDF are in both existing crypto packages.
