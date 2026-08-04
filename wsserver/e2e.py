"""E2E encryption primitives — PAKE-style X25519 + HKDF + AES-256-GCM.

Implements the handshake from docs/e2e-spec.md:
1. Ephemeral X25519 keypair generation
2. ECDH shared secret computation
3. HKDF-SHA256 key derivation (handshake key → session key)
4. HMAC mutual authentication proofs
5. AES-256-GCM encrypt / decrypt for operational messages
"""

from __future__ import annotations

import base64
import hmac
import os
from hashlib import sha256
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

E2E_KEY_SIZE = 32       # AES-256
E2E_NONCE_SIZE = 12     # AES-GCM standard
E2E_SALT_SIZE = 32      # random salt in hello_ack

E2E_INFO_HANDSHAKE = b"hermes-node-e2e-v1"
E2E_INFO_SESSION   = b"hermes-node-session-v1"

E2E_PROOF_CLIENT = b"client-auth"
E2E_PROOF_SERVER = b"server-auth"


class E2EKeyPair(NamedTuple):
    public: X25519PublicKey
    private: X25519PrivateKey


# ── X25519 key generation & ECDH ────────────────────────────────────────────

def generate_e2e_keypair() -> E2EKeyPair:
    """Generate a fresh ephemeral X25519 keypair."""
    priv = X25519PrivateKey.generate()
    return E2EKeyPair(public=priv.public_key(), private=priv)


def ecdh(my_private: X25519PrivateKey, peer_public: X25519PublicKey) -> bytes:
    """Compute the X25519 ECDH shared secret."""
    return my_private.exchange(peer_public)


def decode_public_key(b64: str) -> X25519PublicKey:
    """Decode a base64url-encoded X25519 public key."""
    raw = base64.urlsafe_b64decode(b64 + "===")  # tolerate missing padding
    return X25519PublicKey.from_public_bytes(raw)


def encode_public_key(pub: X25519PublicKey) -> str:
    """Encode an X25519 public key as base64url (no padding)."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ── HKDF key derivation ─────────────────────────────────────────────────────

def derive_handshake_key(
    ecdh_shared: bytes,
    salt: bytes,
    token: str,
) -> bytes:
    """Derive the handshake key from ECDH shared secret + pairing token.

    The token is mixed into the HKDF info string so both sides must
    know it — an attacker who relays ECDH can't derive the same key.
    """
    info = E2E_INFO_HANDSHAKE + token.encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=E2E_KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(ecdh_shared)


def derive_session_key(handshake_key: bytes, session_id: str) -> bytes:
    """Derive the per-session AES-256 key from the handshake key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=E2E_KEY_SIZE,
        salt=session_id.encode(),
        info=E2E_INFO_SESSION,
    ).derive(handshake_key)


# ── HMAC mutual authentication ──────────────────────────────────────────────

def compute_client_proof(handshake_key: bytes) -> bytes:
    """Return HMAC-SHA256(handshake_key, 'client-auth')."""
    return hmac.new(handshake_key, E2E_PROOF_CLIENT, sha256).digest()


def compute_server_proof(handshake_key: bytes) -> bytes:
    """Return HMAC-SHA256(handshake_key, 'server-auth')."""
    return hmac.new(handshake_key, E2E_PROOF_SERVER, sha256).digest()


def verify_proof(
    expected: bytes,
    received: bytes,
    label: str = "proof",
) -> None:
    """Raise ValueError if the received proof doesn't match expected."""
    if not hmac.compare_digest(expected, received):
        raise ValueError(f"E2E {label} mismatch — token differs or MITM")


# ── AES-256-GCM encryption ──────────────────────────────────────────────────

def encrypt_e2e(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext || tag."""
    nonce = os.urandom(E2E_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_e2e(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext (nonce || ct || tag).

    Raises ValueError on tag verification failure.
    """
    if len(ciphertext) < E2E_NONCE_SIZE + 16:
        raise ValueError("e2e: ciphertext too short")
    nonce = ciphertext[:E2E_NONCE_SIZE]
    ct = ciphertext[E2E_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ── Encoding helpers ────────────────────────────────────────────────────────

def encode_b64(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_b64(s: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    return base64.urlsafe_b64decode(s + "===")


# ── Salt generation ─────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Return E2E_SALT_SIZE random bytes."""
    return os.urandom(E2E_SALT_SIZE)
