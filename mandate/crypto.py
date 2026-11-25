"""Ed25519 keys, canonical JSON and compact signed tokens (JWS-style, EdDSA)."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: Any) -> bytes:
    """Deterministic JSON so the same object always hashes and signs the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class KeyPair:
    def __init__(self, private: Ed25519PrivateKey | None = None):
        self.private = private or Ed25519PrivateKey.generate()

    @property
    def public_b64(self) -> str:
        raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return b64u(raw)

    @property
    def private_b64(self) -> str:
        raw = self.private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return b64u(raw)

    @classmethod
    def from_private_b64(cls, s: str) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(b64u_decode(s)))

    def sign(self, data: bytes) -> str:
        return b64u(self.private.sign(data))


def verify(public_b64: str, data: bytes, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(public_b64)).verify(
            b64u_decode(sig_b64), data
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


HEADER = {"alg": "EdDSA", "typ": "mandate+jws"}


def sign_token(payload: dict, key: KeyPair, typ: str = "mandate+jws") -> str:
    header = b64u(canonical({**HEADER, "typ": typ}))
    body = b64u(canonical(payload))
    signing_input = f"{header}.{body}".encode()
    return f"{header}.{body}.{key.sign(signing_input)}"


class TokenError(Exception):
    pass


def verify_token(token: str, public_b64: str, typ: str = "mandate+jws") -> dict:
    try:
        header_b64, body_b64, sig = token.split(".")
        header = json.loads(b64u_decode(header_b64))
        payload = json.loads(b64u_decode(body_b64))
    except Exception as e:  # malformed
        raise TokenError("malformed_token") from e
    if header.get("alg") != "EdDSA" or header.get("typ") != typ:
        raise TokenError("bad_token_header")
    if not verify(public_b64, f"{header_b64}.{body_b64}".encode(), sig):
        raise TokenError("bad_token_signature")
    return payload


def peek_token(token: str) -> dict:
    """Read a token payload WITHOUT verifying (for display / routing only)."""
    try:
        return json.loads(b64u_decode(token.split(".")[1]))
    except Exception as e:
        raise TokenError("malformed_token") from e
