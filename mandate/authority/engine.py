"""The Mandate authority: issues mandates to agents and decides every action they attempt.

Every decision is one of:
  allow             -> a signed receipt the service can verify offline
  deny              -> a machine-readable reason code (+ hint) the agent can act on
  pending_approval  -> a human must approve; the agent retries with the approval_id
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from ..crypto import KeyPair, TokenError, canonical, sha256_hex, sign_token, verify_token
from .store import Store

PROOF_MAX_AGE_S = 120
CHARGE = "payments:charge"

# Reason codes -> short, agent-readable hints on how to recover.
HINTS = {
    "malformed_token": "Send the mandate as 'Authorization: Mandate <token>'.",
    "bad_mandate_signature": "The mandate was not issued by this authority or was altered. Request a new mandate.",
    "unknown_mandate": "This mandate is not known to the authority. Request a new mandate.",
    "mandate_revoked": "Your principal revoked this mandate. Stop and ask them for a new one.",
    "mandate_expired": "The mandate expired. Request a new mandate from your principal.",
    "missing_proof": "Sign each request with your agent key and send it as 'Mandate-Proof'.",
    "bad_proof_signature": "The proof was not signed by the agent key this mandate is bound to.",
    "proof_mandate_mismatch": "The proof refers to a different mandate.",
    "proof_request_mismatch": "The signed request does not match what the service received (method, path, audience or body changed).",
    "proof_stale": "The proof is too old or from the future. Sign a fresh proof with the current time.",
    "replayed_request": "This exact signed request was already used. Sign a fresh proof with a new nonce.",
    "scope_not_granted": "Your mandate does not include this permission. Ask your principal to grant it.",
    "currency_mismatch": "Pay in the mandate's currency.",
    "merchant_not_allowed": "Your mandate does not allow spending at this merchant.",
    "category_blocked": "Your mandate does not allow buying this category of item.",
    "invalid_amount": "Amount must be a positive number.",
    "over_per_tx_limit": "This single purchase is above your per-transaction limit. Reduce it or ask your principal.",
    "over_budget": "This purchase would exceed the mandate's remaining budget.",
    "approval_pending": "Your principal has not decided yet. Poll the approval and retry when approved.",
    "approval_denied": "Your principal denied this purchase. Do not retry it.",
    "approval_mismatch": "The approval was granted for a different purchase. Request a new approval.",
    "approval_already_used": "That approval was already used for a purchase.",
    "missing_payment_cap": "Sign the payment cap (payee, currency, max amount) into your proof for every purchase.",
    "payee_mismatch": "The service asked to be paid as a different merchant than the one you signed for.",
    "over_signed_amount": "The service asked for more than the maximum you signed. Re-read the prices; do not raise your cap blindly.",
    "idempotency_key_reused": "This idempotency key was already used for a different purchase. Use a new key.",
    "possible_duplicate": "An identical order was just placed. A human must confirm this repeat; poll the approval.",
}


class Decision(dict):
    @property
    def allowed(self) -> bool:
        return self["decision"] == "allow"


def deny(reason: str, **extra: Any) -> Decision:
    return Decision(decision="deny", reason=reason, hint=HINTS.get(reason, ""), **extra)


def intent_hash(intent: dict) -> str:
    """What a human approves: who is paid, how much, for what."""
    core = {k: intent.get(k) for k in ("action", "merchant", "amount", "currency", "categories", "items")}
    return sha256_hex(canonical(core))


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


@dataclass
class MandateSpec:
    scopes: list[str]
    currency: str = "INR"
    max_per_tx: float | None = None
    budget: float | None = None
    merchants: list[str] | None = None  # allowlist; None = any merchant
    categories_blocked: list[str] = field(default_factory=list)
    approval_above: float | None = None  # amounts above this need a human
    duplicate_window_s: int | None = 600  # identical basket repeated inside this window needs a human
    ttl_seconds: int = 24 * 3600
    purpose: str = ""


class Authority:
    def __init__(self, store: Store | None = None, issuer: str = "mandate-authority", principal: str = "Demo User"):
        self.store = store or Store()
        self.issuer = issuer
        self.principal = principal
        saved = self.store.kv_get("authority_key")
        if saved:
            self.key = KeyPair.from_private_b64(saved)
        else:
            self.key = KeyPair()
            self.store.kv_set("authority_key", self.key.private_b64)

    # ------------------------------------------------------------------ agents
    def register_agent(self, name: str, public_key: str, owner: str | None = None) -> dict:
        agent_id = new_id("agt")
        self.store.x(
            "INSERT INTO agents (id, name, public_key, owner, created) VALUES (?, ?, ?, ?, ?)",
            (agent_id, name, public_key, owner or self.principal, time.time()),
        )
        self.store.audit("agent.registered", {"agent_id": agent_id, "name": name})
        return {"agent_id": agent_id, "name": name, "public_key": public_key}

    def agent(self, agent_id: str) -> dict | None:
        r = self.store.one("SELECT * FROM agents WHERE id=?", (agent_id,))
        return dict(r) if r else None

    # ---------------------------------------------------------------- mandates
    def issue_mandate(self, agent_id: str, spec: MandateSpec) -> dict:
        agent = self.agent(agent_id)
        if not agent:
            raise ValueError("unknown_agent")
        now = int(time.time())
        jti = new_id("mdt")
        payload = {
            "iss": self.issuer,
            "sub": agent_id,
            "agent_name": agent["name"],
            "principal": agent["owner"],
            "jti": jti,
            "iat": now,
            "exp": now + int(spec.ttl_seconds),
            "cnf": {"ed25519": agent["public_key"]},  # bound to the agent's own key
            "scopes": sorted(set(spec.scopes)),
            "limits": {
                "currency": spec.currency,
                "max_per_tx": spec.max_per_tx,
                "budget": spec.budget,
                "merchants": spec.merchants,
                "categories_blocked": sorted(set(spec.categories_blocked)),
                "duplicate_window_s": spec.duplicate_window_s,
            },
            "approval_above": spec.approval_above,
            "purpose": spec.purpose,
        }
        token = sign_token(payload, self.key)
        self.store.x(
            "INSERT INTO mandates (jti, agent_id, payload, token, status, created) VALUES (?, ?, ?, ?, 'active', ?)",
            (jti, agent_id, json.dumps(payload), token, time.time()),
        )
        self.store.audit("mandate.issued", {"jti": jti, "agent_id": agent_id, "scopes": payload["scopes"],
                                            "limits": payload["limits"], "approval_above": spec.approval_above})
        return {"jti": jti, "token": token, "payload": payload}

    def revoke(self, jti: str) -> bool:
        if not self.store.one("SELECT 1 FROM mandates WHERE jti=?", (jti,)):
            return False
        self.store.x("UPDATE mandates SET status='revoked' WHERE jti=?", (jti,))
        self.store.audit("mandate.revoked", {"jti": jti})
        return True

    def spent(self, jti: str) -> float:
        r = self.store.one("SELECT COALESCE(SUM(amount), 0) AS s FROM ledger WHERE jti=?", (jti,))
        return float(r["s"])

    def mandates(self) -> list[dict]:
        out = []
        for r in self.store.q("SELECT * FROM mandates ORDER BY created DESC"):
            p = json.loads(r["payload"])
            status = r["status"]
            if status == "active" and p["exp"] < time.time():
                status = "expired"
            out.append({"jti": r["jti"], "status": status, "payload": p, "spent": self.spent(r["jti"])})
        return out

    # ------------------------------------------------- agent asks for a mandate
    def request_mandate(self, agent_id: str, spec: dict) -> dict:
        if not self.agent(agent_id):
            raise ValueError("unknown_agent")
        rid = new_id("req")
        self.store.x(
            "INSERT INTO mandate_requests (id, agent_id, request, status, created) VALUES (?, ?, ?, 'pending', ?)",
            (rid, agent_id, json.dumps(spec), time.time()),
        )
        self.store.audit("mandate.requested", {"request_id": rid, "agent_id": agent_id, "spec": spec})
        return {"request_id": rid, "status": "pending"}

    def decide_mandate_request(self, rid: str, approve: bool, overrides: dict | None = None) -> dict:
        r = self.store.one("SELECT * FROM mandate_requests WHERE id=?", (rid,))
        if not r or r["status"] != "pending":
            raise ValueError("not_pending")
        if not approve:
            self.store.x("UPDATE mandate_requests SET status='denied' WHERE id=?", (rid,))
            self.store.audit("mandate.request_denied", {"request_id": rid})
            return {"request_id": rid, "status": "denied"}
        spec = {**json.loads(r["request"]), **(overrides or {})}
        m = self.issue_mandate(r["agent_id"], MandateSpec(**spec))
        self.store.x("UPDATE mandate_requests SET status='approved', jti=? WHERE id=?", (m["jti"], rid))
        return {"request_id": rid, "status": "approved", "jti": m["jti"]}

    def mandate_request(self, rid: str) -> dict | None:
        r = self.store.one("SELECT * FROM mandate_requests WHERE id=?", (rid,))
        if not r:
            return None
        out = {"request_id": rid, "status": r["status"], "agent_id": r["agent_id"],
               "request": json.loads(r["request"])}
        if r["jti"]:
            m = self.store.one("SELECT token FROM mandates WHERE jti=?", (r["jti"],))
            out["token"] = m["token"]
        return out

    # ---------------------------------------------------------------- approvals
    def decide_approval(self, approval_id: str, approve: bool) -> dict:
        r = self.store.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if not r or r["status"] != "pending":
            raise ValueError("not_pending")
        status = "approved" if approve else "denied"
        self.store.x("UPDATE approvals SET status=?, decided=? WHERE id=?", (status, time.time(), approval_id))
        self.store.audit(f"approval.{status}", {"approval_id": approval_id, "jti": r["jti"]})
        return {"approval_id": approval_id, "status": status}

    def approval(self, approval_id: str) -> dict | None:
        r = self.store.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if not r:
            return None
        return {"approval_id": r["id"], "status": r["status"], "jti": r["jti"], "intent": json.loads(r["intent"])}

    def approvals(self, status: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM approvals", ()
        if status:
            sql, args = sql + " WHERE status=?", (status,)
        return [{"approval_id": r["id"], "status": r["status"], "jti": r["jti"], "intent": json.loads(r["intent"]),
                 "created": r["created"]} for r in self.store.q(sql + " ORDER BY created DESC", args)]

    # ---------------------------------------------------------------- decisions
    def authorize(self, mandate_token: str | None, proof_token: str | None, request: dict, intent: dict) -> Decision:
        t0 = time.perf_counter()
        d = self._authorize(mandate_token, proof_token, request, intent)
        d["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        self.store.audit("authorize", {
            "decision": d["decision"], "reason": d.get("reason"), "jti": d.get("jti"),
            "agent_id": d.get("agent_id"), "action": intent.get("action"), "merchant": intent.get("merchant"),
            "amount": intent.get("amount"), "categories": intent.get("categories"),
            "approval_id": d.get("approval_id"), "authz_id": d.get("authz_id"),
        })
        return d

    def _authorize(self, mandate_token, proof_token, request, intent) -> Decision:
        # 1. Is the mandate genuine, known, live?
        if not mandate_token:
            return deny("malformed_token")
        try:
            m = verify_token(mandate_token, self.key.public_b64)
        except TokenError as e:
            return deny(str(e) if str(e) == "malformed_token" else "bad_mandate_signature")
        jti = m.get("jti")
        row = self.store.one("SELECT status FROM mandates WHERE jti=?", (jti,))
        if not row:
            return deny("unknown_mandate", jti=jti)
        ctx = {"jti": jti, "agent_id": m["sub"]}
        if row["status"] == "revoked":
            return deny("mandate_revoked", **ctx)
        if m["exp"] < time.time():
            return deny("mandate_expired", **ctx)

        # 2. Is the request really from the agent the mandate was issued to? (proof of possession)
        if not proof_token:
            return deny("missing_proof", **ctx)
        try:
            p = verify_token(proof_token, m["cnf"]["ed25519"], typ="mandate-proof+jws")
        except TokenError:
            return deny("bad_proof_signature", **ctx)
        if p.get("jti") != jti:
            return deny("proof_mandate_mismatch", **ctx)
        for k_proof, k_req in (("aud", "aud"), ("htm", "htm"), ("htu", "htu"), ("body_sha256", "body_sha256")):
            if p.get(k_proof) != request.get(k_req):
                return deny("proof_request_mismatch", field=k_proof, **ctx)
        if abs(time.time() - float(p.get("iat", 0))) > PROOF_MAX_AGE_S:
            return deny("proof_stale", **ctx)
        if not p.get("nonce") or not self.store.use_nonce(p["nonce"], jti):
            return deny("replayed_request", **ctx)

        # 3. Is the action within what the human granted?
        action = intent.get("action", "")
        if action not in m["scopes"]:
            return deny("scope_not_granted", scope=action, granted=m["scopes"], **ctx)
        if action != CHARGE:
            return self._allow(m, intent, amount=0.0)
        # The agent, not the service, says who may be paid and how much at most.
        cap = p.get("pay")
        if not isinstance(cap, dict) or "max" not in cap:
            return deny("missing_payment_cap", **ctx)
        if intent.get("merchant") != cap.get("to") or cap.get("to") != p.get("aud"):
            return deny("payee_mismatch", **ctx)
        if intent.get("currency") != cap.get("cur"):
            return deny("currency_mismatch", expected=cap.get("cur"), **ctx)
        try:
            if float(intent.get("amount")) > float(cap["max"]) + 1e-9:
                return deny("over_signed_amount", signed_max=cap["max"], requested=intent.get("amount"), **ctx)
        except (TypeError, ValueError):
            return deny("invalid_amount", **ctx)
        return self._charge(m, intent, ctx)

    def _charge(self, m: dict, intent: dict, ctx: dict) -> Decision:
        lim = m["limits"]
        try:
            amount = float(intent.get("amount"))
        except (TypeError, ValueError):
            return deny("invalid_amount", **ctx)
        if not amount > 0:
            return deny("invalid_amount", **ctx)
        if intent.get("currency") != lim["currency"]:
            return deny("currency_mismatch", expected=lim["currency"], **ctx)
        if lim.get("merchants") is not None and intent.get("merchant") not in lim["merchants"]:
            return deny("merchant_not_allowed", merchant=intent.get("merchant"), **ctx)
        blocked = sorted(set(intent.get("categories") or []) & set(lim.get("categories_blocked") or []))
        if blocked:
            return deny("category_blocked", categories=blocked, **ctx)
        if lim.get("max_per_tx") is not None and amount > lim["max_per_tx"]:
            return deny("over_per_tx_limit", limit=lim["max_per_tx"], **ctx)

        with self.store.lock:  # budget check + spend must be atomic
            idem = intent.get("idempotency_key")
            if idem:
                prev = self.store.one("SELECT * FROM ledger WHERE jti=? AND idem_key=?", (m["jti"], idem))
                if prev and intent_hash(json.loads(prev["intent"])) != intent_hash(intent):
                    return deny("idempotency_key_reused", **ctx)
                if prev:  # safe retry: same result, no double charge
                    return Decision(decision="allow", authz_id=prev["id"], receipt=prev["receipt"],
                                    idempotent_replay=True, **ctx)
            spent = self.spent(m["jti"])
            if lim.get("budget") is not None and spent + amount > lim["budget"] + 1e-9:
                return deny("over_budget", budget=lim["budget"], spent=spent, remaining=lim["budget"] - spent, **ctx)

            ih = intent_hash(intent)
            aid = intent.get("approval_id")
            needs_human = None
            if m.get("approval_above") is not None and amount > m["approval_above"]:
                needs_human = "approval_required"
            elif lim.get("duplicate_window_s") and not aid and self._recent_duplicate(m["jti"], ih, lim["duplicate_window_s"]):
                needs_human = "possible_duplicate"
            if needs_human or aid:
                if not aid:
                    aid = new_id("apr")
                    self.store.x(
                        "INSERT INTO approvals (id, jti, intent_hash, intent, status, created) VALUES (?, ?, ?, ?, 'pending', ?)",
                        (aid, m["jti"], ih, json.dumps({**intent, "why": needs_human}), time.time()),
                    )
                    return Decision(decision="pending_approval", reason=needs_human, approval_id=aid,
                                    hint=HINTS.get(needs_human) or "A human must approve this purchase. "
                                         "Poll the approval, then retry with approval_id.", **ctx)
                a = self.store.one("SELECT * FROM approvals WHERE id=?", (aid,))
                if not a or a["jti"] != m["jti"] or a["intent_hash"] != ih:
                    return deny("approval_mismatch", **ctx)
                if a["status"] == "pending":
                    return deny("approval_pending", approval_id=aid, **ctx)
                if a["status"] == "denied":
                    return deny("approval_denied", approval_id=aid, **ctx)
                if a["used"]:
                    return deny("approval_already_used", approval_id=aid, **ctx)
                self.store.x("UPDATE approvals SET used=1 WHERE id=?", (aid,))
            return self._allow(m, intent, amount)

    def _recent_duplicate(self, jti: str, ih: str, window_s: int) -> bool:
        since = time.time() - window_s
        for r in self.store.q("SELECT intent FROM ledger WHERE jti=? AND created>=?", (jti, since)):
            if intent_hash(json.loads(r["intent"])) == ih:
                return True
        return False

    def _allow(self, m: dict, intent: dict, amount: float) -> Decision:
        authz_id = new_id("authz")
        receipt = sign_token({
            "iss": self.issuer, "authz_id": authz_id, "jti": m["jti"], "sub": m["sub"],
            "principal": m["principal"], "action": intent.get("action"), "merchant": intent.get("merchant"),
            "amount": amount, "currency": m["limits"]["currency"], "intent_hash": intent_hash(intent),
            "iat": int(time.time()),
        }, self.key, typ="mandate-receipt+jws")
        if amount > 0:
            self.store.x(
                "INSERT INTO ledger (id, jti, amount, merchant, idem_key, intent, receipt, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (authz_id, m["jti"], amount, intent.get("merchant", ""), intent.get("idempotency_key"),
                 json.dumps(intent), receipt, time.time()),
            )
        return Decision(decision="allow", authz_id=authz_id, receipt=receipt, jti=m["jti"], agent_id=m["sub"],
                        principal=m["principal"])
