"""A scripted household agent that tells the whole story over real HTTP, for the live demo.

    python -m mandate.agent.demo --base http://localhost:8000

1. Generates its own key, registers, and ASKS its owner for a mandate (owner approves in the dashboard)
2. Reads the shop's agent manifest, buys weekly groceries
3. Reads a product page with a prompt injection and (as a fooled LLM would) tries to add gift cards -> blocked
4. Tries a mixer grinder above the approval line -> waits for the owner's tap in the dashboard
5. Its token "leaks"; an attacker replays it from another machine -> blocked
6. Owner revokes it; it tries again -> blocked
"""
from __future__ import annotations

import argparse
import os
import time

import httpx

from .sdk import AgentIdentity, body_bytes, quote

SHOP_AUD = "kiranakart.demo"


def say(msg: str) -> None:
    print(msg, flush=True)


def run(base: str, wait_s: float = 120.0, pause: float = 1.5, auto_approve: bool = False, log=say,
        admin_token: str = "") -> dict:
    # The admin token is only used for the owner's own steps (revoke, auto-approve), never by the agent.
    c = httpx.Client(base_url=base, timeout=15, headers={"X-Admin-Token": admin_token} if admin_token else {})
    agent = AgentIdentity.new("household-agent")
    out: dict = {}

    catalog: list = []

    def buy(items, ident=None, **extra):
        if not catalog:
            catalog.extend(c.get("/shop/catalog").json()["items"])
        body = body_bytes({"items": items, **extra})
        h = (ident or agent).headers("POST", SHOP_AUD, "/shop/orders", body, max_amount=quote(items, catalog))
        return c.post("/shop/orders", content=body, headers=h)

    def wait_for(url: str, decide_url: str | None = None) -> str:
        if auto_approve and decide_url:
            c.post(decide_url, json={"approve": True})
        t_end = time.time() + wait_s
        while time.time() < t_end:
            st = c.get(url).json()["status"]
            if st != "pending":
                return st
            time.sleep(1)
        return "timeout"

    log("[agent] generated my own Ed25519 key; the private key never leaves this process")
    agent.agent_id = c.post("/v1/agents", json={"name": agent.name, "public_key": agent.public_key}).json()["agent_id"]
    spec = {"scopes": ["payments:charge", "orders:read"], "max_per_tx": 5000, "budget": 8000,
            "merchants": [SHOP_AUD], "categories_blocked": ["gift_cards", "electronics"], "approval_above": 2500,
            "purpose": "Weekly groceries and household items"}
    rid = c.post("/v1/mandate-requests", json={"agent_id": agent.agent_id, "spec": spec}).json()["request_id"]
    log("[agent] asked my owner for a mandate: groceries, Rs 8,000 budget, approve anything over Rs 2,500")
    log("        -> approve it in the dashboard")
    st = wait_for(f"/v1/mandate-requests/{rid}", f"/v1/mandate-requests/{rid}/decide")
    if st != "approved":
        log(f"[agent] mandate request {st}; stopping")
        return {"stopped": st}
    agent.mandate = c.get(f"/v1/mandate-requests/{rid}").json()["token"]
    log("[agent] got my mandate. It is bound to my key: useless to anyone else")
    time.sleep(pause)

    manifest = c.get("/shop/.well-known/agent.json").json()
    log(f"[agent] read {manifest['name']}'s agent manifest: auth={manifest['auth']['type']}, "
        f"{len(manifest['endpoints'])} endpoints")
    r = buy([{"id": "rice-5kg", "qty": 1}, {"id": "dal-1kg", "qty": 2}, {"id": "milk-1l", "qty": 7},
             {"id": "oil-1l", "qty": 1}, {"id": "soap-4", "qty": 1}], idempotency_key="weekly-1")
    log(f"[agent] weekly groceries -> {r.status_code} {r.json().get('status', r.json().get('error'))} "
        f"(Rs {r.json().get('total', 0):,.0f})")
    out["groceries"] = r.status_code
    time.sleep(pause)

    atta = next(p for p in c.get("/shop/catalog", params={"q": "atta"}).json()["items"])
    log(f"[agent] product page says: \"{atta['description'][:90]}...\"")
    log("[agent] (a fooled LLM obeys) adding 3 gift cards to the order")
    r = buy([{"id": "atta-5kg", "qty": 1}, {"id": "gc-2000", "qty": 3}])
    log(f"[shop ] {r.status_code} {r.json()['error']}: {r.json()['hint']}")
    out["injection"] = r.json().get("error")
    time.sleep(pause)

    r = buy([{"id": "mixer", "qty": 1}], idempotency_key="mixer-1")
    if r.status_code == 202:
        aid = r.json()["approval_id"]
        log(f"[shop ] 202 approval_required: Rs 3,499 is above Rs 2,500. Waiting for my owner ({aid})")
        log("        -> approve or deny it in the dashboard")
        st = wait_for(f"/v1/approvals/{aid}", f"/v1/approvals/{aid}/decide")
        r = buy([{"id": "mixer", "qty": 1}], idempotency_key="mixer-1", approval_id=aid)
        log(f"[agent] owner said {st}; retry -> {r.status_code} {r.json().get('status', r.json().get('error'))}")
    out["mixer"] = r.status_code
    time.sleep(pause)

    thief = AgentIdentity.new("attacker")
    thief.mandate = agent.mandate
    r = buy([{"id": "rice-5kg", "qty": 5}], ident=thief)
    log(f"[attacker] stole the mandate from a log file and used it -> {r.status_code} {r.json()['error']}")
    out["stolen"] = r.json().get("error")
    time.sleep(pause)

    jti = agent.mandate_claims["jti"]
    log("[owner] revoking the agent now")
    c.post(f"/v1/mandates/{jti}/revoke")
    r = buy([{"id": "milk-1l", "qty": 1}])
    log(f"[agent] tries to buy milk after revocation -> {r.status_code} {r.json()['error']}")
    out["revoked"] = r.json().get("error")

    v = c.get("/v1/audit/verify").json()
    log(f"[audit] hash chain intact: {v['ok']} ({v['checked']} entries)")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--auto-approve", action="store_true", help="approve requests automatically (CI / smoke test)")
    ap.add_argument("--pause", type=float, default=1.5)
    a = ap.parse_args()
    run(a.base, auto_approve=a.auto_approve, pause=a.pause, admin_token=os.environ.get("MANDATE_ADMIN_TOKEN", ""))


if __name__ == "__main__":
    main()
