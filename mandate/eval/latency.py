"""Latency over real HTTP: the same order, through a real uvicorn server, with an API key vs with Mandate.

    python -m mandate.eval.latency

Each mode gets its own server process on localhost, a warm-up, then N sequential orders on a kept-alive
connection. The difference is what Mandate adds per request on the service side (one signature check on the
mandate, one on the proof, the policy, and a SQLite write), plus the agent signing the proof.
"""
from __future__ import annotations

import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time

import httpx
from fastapi import FastAPI

from ..agent.sdk import AgentIdentity, body_bytes
from ..merchant.app import build_router

SHOP = "kiranakart.demo"
ITEMS = [{"id": "milk-1l", "qty": 1}]


def baseline_app() -> FastAPI:
    """uvicorn factory: the same shop, authenticated with a plain API key."""
    app = FastAPI()
    app.include_router(build_router(None, merchant_id=SHOP, auth_mode="apikey", api_key="sk_live_demo"), prefix="/shop")
    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start(target: list[str], env: dict) -> tuple[subprocess.Popen, str]:
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", *target, "--port", str(port), "--log-level", "warning"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(base + "/shop/catalog", timeout=1).status_code == 200:
                return proc, base
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"server did not start: {target}")


def _measure(base: str, headers_for, n: int, warmup: int = 30) -> list[float]:
    times = []
    with httpx.Client(base_url=base, timeout=10) as c:
        for i in range(warmup + n):
            body = body_bytes({"items": ITEMS, "idempotency_key": f"lat-{i}"})
            t0 = time.perf_counter()
            r = c.post("/shop/orders", content=body, headers=headers_for(body))  # signing counts too
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code != 201:
                raise RuntimeError(f"order failed: {r.status_code} {r.text[:200]}")
            if i >= warmup:
                times.append(dt)
    return times


def _stats(t: list[float]) -> dict:
    return {"p50": round(statistics.median(t), 2), "p95": round(statistics.quantiles(t, n=20)[18], 2)}


def run(n: int = 300) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "MANDATE_NO_AUTOAPP"}
    tmp = tempfile.mkdtemp()
    procs = []
    try:
        p_base, base_url = _start(["mandate.eval.latency:baseline_app", "--factory"], env)
        procs.append(p_base)
        p_m, m_url = _start(["mandate.server:app"], {**env, "MANDATE_DB": os.path.join(tmp, "lat.db"),
                                                    "MANDATE_ADMIN_TOKEN": ""})
        procs.append(p_m)

        agent = AgentIdentity.new("latency-agent")
        with httpx.Client(base_url=m_url) as c:
            agent.agent_id = c.post("/v1/agents", json={"name": agent.name, "public_key": agent.public_key}).json()["agent_id"]
            agent.mandate = c.post("/v1/mandates", json={
                "agent_id": agent.agent_id, "scopes": ["payments:charge"], "budget": 10**9,
                "merchants": [SHOP], "duplicate_window_s": 0}).json()["token"]

        t_base = _measure(base_url, lambda b: {"Authorization": "Bearer sk_live_demo",
                                               "Content-Type": "application/json"}, n)
        t_m = _measure(m_url, lambda b: agent.headers("POST", SHOP, "/shop/orders", b, max_amount=56.0), n)
    finally:
        for p in procs:
            p.terminate()
            p.wait(timeout=10)
    sb, sm = _stats(t_base), _stats(t_m)
    return {"requests_per_mode": n, "api_key": sb, "mandate": sm,
            "overhead_p50_ms": round(sm["p50"] - sb["p50"], 2), "overhead_p95_ms": round(sm["p95"] - sb["p95"], 2),
            "setup": "localhost, one uvicorn worker per mode, sequential requests on a kept-alive connection, "
                     "SQLite on local disk"}


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
