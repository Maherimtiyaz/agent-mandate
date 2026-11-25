import json
import time

import pytest
from fastapi.testclient import TestClient

from mandate.agent.sdk import AgentIdentity, body_bytes, quote, verify_receipt
from mandate.merchant.app import CATALOG
from mandate.server import create_app

AUD = "kiranakart.demo"
PATH = "/shop/orders"


@pytest.fixture
def env():
    app = create_app(db_path=":memory:", admin_token="")
    c = TestClient(app)
    return c, app.state.authority


def make_agent(c, name="bot", **spec):
    a = AgentIdentity.new(name)
    a.agent_id = c.post("/v1/agents", json={"name": name, "public_key": a.public_key}).json()["agent_id"]
    base = dict(scopes=["payments:charge", "orders:read"], max_per_tx=2000, budget=3000,
                merchants=[AUD], categories_blocked=["gift_cards"], approval_above=1000)
    base.update(spec)
    r = c.post("/v1/mandates", json={"agent_id": a.agent_id, **base})
    assert r.status_code == 200, r.text
    a.mandate = r.json()["token"]
    return a


def order(c, agent, items, signer=None, **extra):
    body = body_bytes({"items": items, **extra})
    h = (signer or agent).headers("POST", AUD, PATH, body, max_amount=quote(items, CATALOG))
    if signer is not None:  # stolen-token attempt: thief's proof, victim's mandate
        h["Authorization"] = f"Mandate {agent.mandate}"
    return c.post(PATH, content=body, headers=h)


def test_legit_purchase_gets_verifiable_receipt(env):
    c, auth = env
    a = make_agent(c)
    r = order(c, a, [{"id": "rice-5kg", "qty": 1}], idempotency_key="k1")
    assert r.status_code == 201, r.text
    claims = verify_receipt(r.json()["receipt"], c.get("/.well-known/mandate-authority.json").json()["public_key"])
    assert claims["amount"] == 649.0 and claims["merchant"] == AUD


def test_blocked_category_from_prompt_injection(env):
    c, _ = env
    a = make_agent(c)
    r = order(c, a, [{"id": "atta-5kg", "qty": 1}, {"id": "gc-2000", "qty": 3}])
    assert r.status_code == 403 and r.json()["error"] == "category_blocked"


def test_per_tx_limit_and_budget(env):
    c, _ = env
    a = make_agent(c, approval_above=None)
    assert order(c, a, [{"id": "mixer", "qty": 1}]).json()["error"] == "over_per_tx_limit"
    assert order(c, a, [{"id": "rice-5kg", "qty": 3}]).status_code == 201  # 1947
    r = order(c, a, [{"id": "rice-5kg", "qty": 2}])  # 1298 -> 3245 > 3000
    assert r.json()["error"] == "over_budget"


def test_idempotent_retry_does_not_double_charge(env):
    c, auth = env
    a = make_agent(c)
    r1 = order(c, a, [{"id": "dal-1kg", "qty": 2}], idempotency_key="same")
    r2 = order(c, a, [{"id": "dal-1kg", "qty": 2}], idempotency_key="same")
    assert r1.status_code == 201 and r2.status_code == 200
    assert r1.json()["order_id"] == r2.json()["order_id"]
    assert auth.spent(auth.mandates()[0]["jti"]) == 330.0


def test_stolen_mandate_is_useless_without_agent_key(env):
    c, _ = env
    victim = make_agent(c, "victim")
    thief = AgentIdentity.new("thief")
    thief.mandate = victim.mandate
    r = order(c, victim, [{"id": "milk-1l", "qty": 1}], signer=thief)
    assert r.json()["error"] == "bad_proof_signature"


def test_replayed_request_is_rejected(env):
    c, _ = env
    a = make_agent(c)
    body = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    h = a.headers("POST", AUD, PATH, body, max_amount=56)
    assert c.post(PATH, content=body, headers=h).status_code == 201
    assert c.post(PATH, content=body, headers=h).json()["error"] == "replayed_request"


def test_tampered_body_is_rejected(env):
    c, _ = env
    a = make_agent(c)
    signed = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    h = a.headers("POST", AUD, PATH, signed, max_amount=56)
    sent = body_bytes({"items": [{"id": "milk-1l", "qty": 30}]})
    r = c.post(PATH, content=sent, headers=h)
    assert r.json()["error"] == "proof_request_mismatch"


def test_forged_mandate_rejected(env):
    c, _ = env
    a = make_agent(c)
    head, body, sig = a.mandate.split(".")
    from mandate.crypto import b64u, b64u_decode
    p = json.loads(b64u_decode(body))
    p["limits"]["budget"] = 10_000_000
    a.mandate = ".".join([head, b64u(json.dumps(p).encode()), sig])
    assert order(c, a, [{"id": "milk-1l", "qty": 1}]).json()["error"] == "bad_mandate_signature"


def test_stale_proof_rejected(env):
    c, _ = env
    a = make_agent(c)
    body = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    h = a.headers("POST", AUD, PATH, body, iat=time.time() - 3600, max_amount=56)
    assert c.post(PATH, content=body, headers=h).json()["error"] == "proof_stale"


def test_revocation_is_immediate(env):
    c, auth = env
    a = make_agent(c)
    jti = a.mandate_claims["jti"]
    assert c.post(f"/v1/mandates/{jti}/revoke").status_code == 200
    assert order(c, a, [{"id": "milk-1l", "qty": 1}]).json()["error"] == "mandate_revoked"


def test_expired_mandate_rejected(env):
    c, auth = env
    a = make_agent(c, ttl_seconds=60)
    auth.store.x("UPDATE mandates SET status='active'")
    # forge nothing: just move the clock by issuing with past exp via engine
    from mandate.authority.engine import MandateSpec
    m = auth.issue_mandate(a.agent_id, MandateSpec(scopes=["payments:charge"], ttl_seconds=-1))
    a.mandate = m["token"]
    assert order(c, a, [{"id": "milk-1l", "qty": 1}]).json()["error"] == "mandate_expired"


def test_human_approval_flow(env):
    c, _ = env
    a = make_agent(c, max_per_tx=10000, budget=20000, approval_above=1000)
    items = [{"id": "mixer", "qty": 1}]
    r = order(c, a, items)
    assert r.status_code == 202
    aid = r.json()["approval_id"]
    assert order(c, a, items, approval_id=aid).json()["error"] == "approval_pending"
    # cannot reuse the approval for a different, bigger basket
    c.post(f"/v1/approvals/{aid}/decide", json={"approve": True})
    assert order(c, a, [{"id": "mixer", "qty": 2}], approval_id=aid).json()["error"] == "approval_mismatch"
    assert order(c, a, items, approval_id=aid).status_code == 201
    assert order(c, a, items, approval_id=aid).json()["error"] == "approval_already_used"


def test_denied_approval(env):
    c, _ = env
    a = make_agent(c, max_per_tx=5000, budget=10000)
    r = order(c, a, [{"id": "mixer", "qty": 1}])
    aid = r.json()["approval_id"]
    c.post(f"/v1/approvals/{aid}/decide", json={"approve": False})
    assert order(c, a, [{"id": "mixer", "qty": 1}], approval_id=aid).json()["error"] == "approval_denied"


def test_scope_enforced(env):
    c, _ = env
    a = make_agent(c, scopes=["payments:charge"])
    h = a.headers("GET", AUD, PATH, b"")
    assert c.get(PATH, headers=h).json()["error"] == "scope_not_granted"


def test_agent_requests_mandate_human_approves(env):
    c, _ = env
    a = AgentIdentity.new("asker")
    a.agent_id = c.post("/v1/agents", json={"name": "asker", "public_key": a.public_key}).json()["agent_id"]
    rid = c.post("/v1/mandate-requests", json={"agent_id": a.agent_id,
                 "spec": {"scopes": ["payments:charge"], "budget": 500}}).json()["request_id"]
    assert c.get(f"/v1/mandate-requests/{rid}").json()["status"] == "pending"
    c.post(f"/v1/mandate-requests/{rid}/decide", json={"approve": True})
    a.mandate = c.get(f"/v1/mandate-requests/{rid}").json()["token"]
    assert order(c, a, [{"id": "milk-1l", "qty": 1}]).status_code == 201


def test_audit_chain_detects_tampering(env):
    c, auth = env
    a = make_agent(c)
    order(c, a, [{"id": "milk-1l", "qty": 1}])
    assert c.get("/v1/audit/verify").json()["ok"] is True
    auth.store.x("UPDATE audit SET data='{\"decision\":\"deny\"}' WHERE seq=2")
    assert c.get("/v1/audit/verify").json()["ok"] is False


def test_admin_token_required_when_set():
    c = TestClient(create_app(db_path=":memory:", admin_token="s3cret"))
    assert c.get("/v1/admin/state").status_code == 401
    assert c.get("/v1/admin/state", headers={"X-Admin-Token": "s3cret"}).status_code == 200


def test_concurrent_spend_cannot_exceed_budget(env):
    from concurrent.futures import ThreadPoolExecutor
    c, auth = env
    a = make_agent(c, budget=1000, approval_above=None, duplicate_window_s=0)
    with ThreadPoolExecutor(8) as ex:
        rs = list(ex.map(lambda _: order(c, a, [{"id": "oil-1l", "qty": 1}]), range(20)))
    assert sum(r.status_code == 201 for r in rs) == 6  # 6 * 155 = 930 <= 1000
    assert auth.spent(a.mandate_claims["jti"]) <= 1000


def test_repeat_basket_needs_human(env):
    c, _ = env
    a = make_agent(c)
    assert order(c, a, [{"id": "rice-5kg", "qty": 1}], idempotency_key="a").status_code == 201
    r = order(c, a, [{"id": "rice-5kg", "qty": 1}], idempotency_key="b")
    assert r.status_code == 202 and r.json()["reason"] == "possible_duplicate"
    aid = r.json()["approval_id"]
    c.post(f"/v1/approvals/{aid}/decide", json={"approve": True})
    assert order(c, a, [{"id": "rice-5kg", "qty": 1}], idempotency_key="b", approval_id=aid).status_code == 201


# --- fixes from the security audit ---------------------------------------------------------------

def _authorize_raw(auth, agent, body, intent, **proof_kw):
    from mandate.crypto import sha256_hex
    h = agent.headers("POST", AUD, PATH, body, **proof_kw)
    req = {"aud": AUD, "htm": "POST", "htu": PATH, "body_sha256": sha256_hex(body)}
    return auth.authorize(h["Authorization"][len("Mandate "):], h["Mandate-Proof"], req, intent)


def _intent(amount, merchant=AUD):
    return {"action": "payments:charge", "merchant": merchant, "amount": amount, "currency": "INR",
            "categories": ["grocery"], "items": [{"id": "milk-1l", "qty": 1}]}


def test_malicious_merchant_cannot_overcharge(env):
    """Audit finding: a merchant reused the agent's proof for Rs 56 and reported Rs 2,499."""
    c, auth = env
    a = make_agent(c, approval_above=None)
    body = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    d = _authorize_raw(auth, a, body, _intent(2499), max_amount=56)
    assert d["decision"] == "deny" and d["reason"] == "over_signed_amount"
    assert auth.spent(a.mandate_claims["jti"]) == 0


def test_merchant_cannot_claim_to_be_another_payee(env):
    c, auth = env
    a = make_agent(c, merchants=None)
    body = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    d = _authorize_raw(auth, a, body, _intent(56, merchant="other.shop"), max_amount=56)
    assert d["reason"] == "payee_mismatch"


def test_purchase_without_signed_cap_is_refused(env):
    c, auth = env
    a = make_agent(c)
    body = body_bytes({"items": [{"id": "milk-1l", "qty": 1}]})
    h = a.headers("POST", AUD, PATH, body)  # no max_amount
    assert c.post(PATH, content=body, headers=h).json()["error"] == "missing_payment_cap"


def test_price_rise_above_cap_is_refused_with_hint(env):
    c, _ = env
    a = make_agent(c)
    body = body_bytes({"items": [{"id": "rice-5kg", "qty": 1}]})
    h = a.headers("POST", AUD, PATH, body, max_amount=600)  # agent saw an older, lower price
    r = c.post(PATH, content=body, headers=h).json()
    assert r["error"] == "over_signed_amount" and "Re-read the prices" in r["hint"]


def test_idempotency_key_cannot_be_reused_for_another_basket(env):
    c, _ = env
    a = make_agent(c)
    assert order(c, a, [{"id": "milk-1l", "qty": 1}], idempotency_key="k").status_code == 201
    r = order(c, a, [{"id": "dal-1kg", "qty": 1}], idempotency_key="k")
    assert r.json()["error"] == "idempotency_key_reused"


def test_admin_refused_from_other_machines_without_token(monkeypatch):
    monkeypatch.delenv("MANDATE_OPEN_DEMO", raising=False)
    app = create_app(db_path=":memory:", admin_token="")
    remote = TestClient(app, client=("203.0.113.7", 50000))
    assert remote.get("/v1/admin/state").status_code == 401
    assert remote.post("/v1/demo/run").status_code == 401
    assert TestClient(app).get("/v1/admin/state").status_code == 200  # same machine is fine


def test_open_demo_must_be_explicit(monkeypatch):
    monkeypatch.setenv("MANDATE_OPEN_DEMO", "1")
    app = create_app(db_path=":memory:", admin_token="")
    assert TestClient(app, client=("203.0.113.7", 50000)).get("/v1/admin/state").status_code == 200


def test_old_nonces_are_purged_but_replays_still_blocked():
    from mandate.authority.store import Store
    st = Store()
    assert st.use_nonce("n1", "j") and not st.use_nonce("n1", "j")
    st.x("UPDATE nonces SET ts = ts - 10000")
    for i in range(600):
        st.use_nonce(f"x{i}", "j")
    assert st.one("SELECT 1 FROM nonces WHERE nonce='n1'") is None


# --- benchmark guards: CI fails if the headline claims stop being true ---------------------------

def test_benchmark_claims_hold():
    from mandate.eval.run import run_mode
    m = run_mode("mandate")
    assert m["legit_completed"] == m["legit_total"]
    assert m["attacks_succeeded"] == 0 and m["rupees_lost"] == 0
    k = run_mode("card")
    assert k["legit_completed"] == k["legit_total"]
    # Mandate must never be worse than a capped card, attack by attack, including the known limits
    for sm, sk in zip(m["scenarios"], k["scenarios"]):
        if sm["kind"] in ("attack", "limit"):
            assert sm["rupees_lost"] <= sk["rupees_lost"], sm["id"]


def test_virtual_card_enforces_what_a_card_can():
    from mandate.merchant.app import VirtualCard
    card = VirtualCard(per_tx=100, budget=150, merchants=["a"])
    assert card.charge("b", 10)["reason"] == "card_merchant_locked"
    assert card.charge("a", 101)["reason"] == "card_per_tx_limit"
    assert card.charge("a", 100, idem="k")["decision"] == "allow"
    assert card.charge("a", 100, idem="k")["decision"] == "allow" and card.spent == 100  # idempotent
    assert card.charge("a", 60)["reason"] == "card_budget_exhausted"
    card.frozen = True
    assert card.charge("a", 1)["reason"] == "card_frozen"
