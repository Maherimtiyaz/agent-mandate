"""HTTP API for the Mandate authority + the human dashboard, with the demo shop mounted at /shop.

Run:  uvicorn mandate.server:app --port 8000
"""
from __future__ import annotations

import os
from pathlib import Path

import secrets
import threading

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .authority.engine import Authority, MandateSpec
from .authority.store import Store
from .merchant.app import build_router

WEB = Path(__file__).parent / "web"


class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    public_key: str = Field(min_length=40, max_length=60)


class SpecIn(BaseModel):
    scopes: list[str] = ["payments:charge"]
    currency: str = "INR"
    max_per_tx: float | None = Field(default=None, ge=0)
    budget: float | None = Field(default=None, ge=0)
    merchants: list[str] | None = None
    categories_blocked: list[str] = []
    approval_above: float | None = Field(default=None, ge=0)
    duplicate_window_s: int | None = Field(default=600, ge=0, le=7 * 24 * 3600)
    ttl_seconds: int = Field(default=24 * 3600, ge=60, le=90 * 24 * 3600)
    purpose: str = Field(default="", max_length=300)


class MandateIn(SpecIn):
    agent_id: str


class MandateRequestIn(BaseModel):
    agent_id: str
    spec: SpecIn


class DecisionIn(BaseModel):
    approve: bool


class AuthorizeIn(BaseModel):
    mandate: str | None = None
    proof: str | None = None
    request: dict
    intent: dict


def create_app(db_path: str | None = None, admin_token: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("MANDATE_DB", "mandate.db")
    admin_token = admin_token if admin_token is not None else os.environ.get("MANDATE_ADMIN_TOKEN", "")
    authority = Authority(Store(db_path), issuer=os.environ.get("MANDATE_ISSUER", "mandate-authority"),
                          principal=os.environ.get("MANDATE_PRINCIPAL", "Demo User"))

    app = FastAPI(title="Mandate: delegated authority for AI agents", version="0.1.0")
    app.state.authority = authority

    open_demo = os.environ.get("MANDATE_OPEN_DEMO") == "1"
    local_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}

    def admin(request: Request, x_admin_token: str = Header(default="")):
        # The principal (the human). With a token set, the token is required. Without one, only requests
        # from this machine are trusted, unless MANDATE_OPEN_DEMO=1 is set explicitly.
        if admin_token:
            if not secrets.compare_digest(x_admin_token, admin_token):
                raise HTTPException(401, "admin token required")
            return
        host = request.client.host if request.client else ""
        if not open_demo and host not in local_hosts:
            raise HTTPException(401, "admin token required: set MANDATE_ADMIN_TOKEN on this server")

    # ------------------------------------------------------------ discovery
    @app.get("/.well-known/mandate-authority.json")
    def discovery():
        return {"issuer": authority.issuer, "alg": "EdDSA", "public_key": authority.key.public_b64,
                "authorize_endpoint": "/v1/authorize", "approvals_endpoint": "/v1/approvals/{id}",
                "token_types": ["mandate+jws", "mandate-proof+jws", "mandate-receipt+jws"]}

    # --------------------------------------------------------------- agents
    @app.post("/v1/agents")
    def register_agent(a: AgentIn):
        return authority.register_agent(a.name, a.public_key)

    @app.post("/v1/mandate-requests")
    def request_mandate(r: MandateRequestIn):
        try:
            return authority.request_mandate(r.agent_id, r.spec.model_dump())
        except ValueError as e:
            raise HTTPException(404, str(e))

    @app.get("/v1/mandate-requests/{rid}")
    def get_mandate_request(rid: str):
        r = authority.mandate_request(rid)
        if not r:
            raise HTTPException(404, "not_found")
        return r

    @app.get("/v1/mandates/{jti}/status")
    def mandate_live_status(jti: str):
        # Lets an agent learn its mandate was revoked or forgotten. Reveals only the status.
        m = next((x for x in authority.mandates() if x["jti"] == jti), None)
        return {"jti": jti, "status": m["status"] if m else "unknown", "spent": m["spent"] if m else 0}

    @app.get("/v1/approvals/{aid}")
    def get_approval(aid: str):
        a = authority.approval(aid)
        if not a:
            raise HTTPException(404, "not_found")
        return {"approval_id": a["approval_id"], "status": a["status"]}

    # -------------------------------------------------- services (relying parties)
    @app.post("/v1/authorize")
    def authorize(body: AuthorizeIn):
        return authority.authorize(body.mandate, body.proof, body.request, body.intent)

    # ------------------------------------------------------- the human (admin)
    @app.get("/v1/admin/state", dependencies=[Depends(admin)])
    def state():
        reqs = [dict(r) for r in authority.store.q(
            "SELECT id, agent_id, request, status, created FROM mandate_requests ORDER BY created DESC LIMIT 50")]
        agents = [dict(r) for r in authority.store.q("SELECT id, name, created FROM agents ORDER BY created DESC")]
        return {"mandates": authority.mandates(), "approvals": authority.approvals(), "mandate_requests": reqs,
                "agents": agents}

    @app.post("/v1/mandates", dependencies=[Depends(admin)])
    def issue(m: MandateIn):
        try:
            return authority.issue_mandate(m.agent_id, MandateSpec(**m.model_dump(exclude={"agent_id"})))
        except ValueError as e:
            raise HTTPException(404, str(e))

    @app.post("/v1/mandates/{jti}/revoke", dependencies=[Depends(admin)])
    def revoke(jti: str):
        if not authority.revoke(jti):
            raise HTTPException(404, "not_found")
        return {"jti": jti, "status": "revoked"}

    @app.post("/v1/mandate-requests/{rid}/decide", dependencies=[Depends(admin)])
    def decide_request(rid: str, d: DecisionIn):
        try:
            return authority.decide_mandate_request(rid, d.approve)
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.post("/v1/approvals/{aid}/decide", dependencies=[Depends(admin)])
    def decide_approval(aid: str, d: DecisionIn):
        try:
            return authority.decide_approval(aid, d.approve)
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.get("/v1/audit", dependencies=[Depends(admin)])
    def audit(limit: int = 100):
        rows = authority.store.q("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (min(limit, 500),))
        import json
        return {"entries": [{**dict(r), "data": json.loads(r["data"])} for r in rows]}

    @app.get("/v1/audit/verify")
    def audit_verify():
        return authority.store.verify_audit()

    # ------------------------------------------------- one-click demo agent
    demo = {"log": [], "running": False}

    @app.post("/v1/demo/run", dependencies=[Depends(admin)])
    def demo_run(req: Request):
        if demo["running"]:
            raise HTTPException(409, "demo already running")
        from .agent.demo import run as run_demo
        base = os.environ.get("MANDATE_PUBLIC_URL") or str(req.base_url).rstrip("/")
        demo.update(log=[], running=True)

        def go():
            try:
                run_demo(base, wait_s=180, pause=2.0, log=demo["log"].append, admin_token=admin_token)
            except Exception as e:  # surface failures in the UI instead of dying silently
                demo["log"].append(f"[demo] error: {e}")
            finally:
                demo["running"] = False

        threading.Thread(target=go, daemon=True).start()
        return {"started": True}

    @app.get("/v1/demo/log")
    def demo_log():
        return demo

    @app.get("/v1/benchmark")
    def benchmark():
        import json
        for f in (os.environ.get("MANDATE_RESULTS"), Path(__file__).resolve().parents[1] / "eval" / "results.json",
                  Path.cwd() / "eval" / "results.json"):
            if f and Path(f).exists():
                return json.loads(Path(f).read_text())
        return {}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # --------------------------------------------------------------- demo shop
    def in_process(mandate, proof, request, intent):
        return authority.authorize(mandate, proof, request, intent)

    app.include_router(build_router(in_process, authority_url="/"), prefix="/shop")

    @app.get("/")
    def dashboard():
        return FileResponse(WEB / "index.html")

    return app


app = create_app() if os.environ.get("MANDATE_NO_AUTOAPP") != "1" else None
