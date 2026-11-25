"""Agent-side SDK: hold your own key, carry a mandate, sign every request.

    agent = AgentIdentity.new("grocery-bot")
    headers = agent.headers("POST", "shop.demo", "/shop/orders", body_bytes)
"""
from __future__ import annotations

import json
import secrets
import time

from ..crypto import KeyPair, canonical, peek_token, sha256_hex, sign_token, verify_token


class AgentIdentity:
    def __init__(self, name: str, key: KeyPair | None = None):
        self.name = name
        self.key = key or KeyPair()
        self.agent_id: str | None = None
        self.mandate: str | None = None

    @classmethod
    def new(cls, name: str) -> "AgentIdentity":
        return cls(name)

    @property
    def public_key(self) -> str:
        return self.key.public_b64

    @property
    def mandate_claims(self) -> dict:
        return peek_token(self.mandate) if self.mandate else {}

    def proof(self, method: str, aud: str, path: str, body: bytes = b"",
              iat: float | None = None, nonce: str | None = None,
              max_amount: float | None = None, currency: str = "INR") -> str:
        """A one-time signature over this exact request (like DPoP).

        For a purchase, pass max_amount: the most the agent agrees to pay this merchant. The service
        cannot charge more, even though it is the one that reports the price.
        """
        if not self.mandate:
            raise RuntimeError("agent has no mandate")
        extra = {"pay": {"to": aud, "cur": currency, "max": max_amount}} if max_amount is not None else {}
        return sign_token({
            **extra,
            "jti": self.mandate_claims["jti"],
            "aud": aud,
            "htm": method.upper(),
            "htu": path,
            "body_sha256": sha256_hex(body),
            "iat": int(iat if iat is not None else time.time()),
            "nonce": nonce or secrets.token_urlsafe(16),
        }, self.key, typ="mandate-proof+jws")

    def headers(self, method: str, aud: str, path: str, body: bytes = b"", **kw) -> dict:
        return {
            "Authorization": f"Mandate {self.mandate}",
            "Mandate-Proof": self.proof(method, aud, path, body, **kw),
            "Content-Type": "application/json",
        }


def quote(items: list[dict], catalog: list[dict]) -> float:
    """The agent's own total for a basket, from prices it read in the catalog."""
    prices = {p["id"]: p["price"] for p in catalog}
    return round(sum(prices[i["id"]] * i.get("qty", 1) for i in items if i.get("id") in prices), 2)


def body_bytes(obj: dict) -> bytes:
    """Serialise a JSON body once, so the signed bytes are exactly the sent bytes."""
    return json.dumps(obj, separators=(",", ":")).encode()


def verify_receipt(receipt: str, authority_public_key: str) -> dict:
    return verify_token(receipt, authority_public_key, typ="mandate-receipt+jws")


__all__ = ["AgentIdentity", "body_bytes", "quote", "verify_receipt", "canonical"]
