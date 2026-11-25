# Mandate: delegated authority for AI agents

> **Homingo Hack Days, Edition 01 · Track: Agents · Problem statement A1, "Software built for agents"**

AI agents are starting to shop, book and pay for people. They do it with the tools we built for humans: a saved card, an API key, a password. That gives an agent **all of your authority, with no limits, no proof of who it acts for, and no way to take it back.** One prompt injection on a product page, one leaked log file or one runaway loop, and the money is gone.

**Mandate is the permission layer for agents.** A human grants an agent a *mandate*: what it may do, where, up to how much, until when. That grant is a signed credential bound to the agent's own key. Every service the agent calls checks it with one API call, and gets back an allow, a deny with a reason the agent can act on, or a "ask the human first". Every decision lands in a tamper-evident log.

It covers four of the gaps the A1 statement names: **identity** (who the agent acts for, proven by its key), **permissions** (scopes, merchants, categories), **payments** (per-purchase and total limits, approvals, idempotency) and **interfaces built for agents** (a machine-readable manifest and errors that tell the agent what to do next).

![Mandate dashboard after the demo run](docs/dashboard.png)

## Measured result

Same tasks, same attacks, three setups: an **API key or stored card** (how most agents are wired today), a **capped virtual card** (the strongest common control today: per-purchase limit, budget, merchant lock, freeze, with the same numbers as the mandate) and **Mandate**. Attacks assume the worst: the LLM *is* fooled and the credential *does* leak. Reproduce with `python -m mandate.eval.run`.

| | API key / stored card | Capped virtual card | **Mandate** |
|---|---|---|---|
| Legitimate tasks completed | 5/5 | 5/5 | **5/5** |
| Attacks that succeeded | 13/13 | 7/13 | **0/13** |
| Money lost to attacks | ₹1,08,709 | ₹30,483 | **₹0** |
| Known limits: money lost in attacks Mandate does *not* stop | ₹37,226 | ₹7,877 | ₹7,877 |

**Added latency, measured over real HTTP:** about 1.0 ms per request at p50 and 1.75 ms at p95 (300 orders per setup on localhost, one server worker, SQLite).

What the card already stops, Mandate stops too. The seven attacks only Mandate stops are the ones a card cannot see: a leaked credential used by someone else, a replayed request, an approval reused for a bigger basket, a purchase the owner said no to, a merchant charging more than the agent agreed to (found in our own security review, then fixed), a gift card slipped into a basket under the card's limit, and a runaway re-order loop.

**What Mandate does not stop**, measured in the same benchmark: an injection that stays inside the owner's rules (one extra item), and malware that steals both the agent's key and its mandate from the owner's computer. In both, Mandate limits the loss to what the owner granted, the same as a capped card. Per-scenario tables: [`docs/RESULTS.md`](docs/RESULTS.md).

**Security tests:** `python -m pytest -q tests`, 27 tests, including concurrent spending against a budget and tampering with the audit log.

## How it works

```mermaid
sequenceDiagram
    participant H as Human (dashboard)
    participant A as Agent (holds its own key)
    participant M as Mandate authority
    participant S as Service (e.g. a shop)
    A->>M: register public key, request a mandate
    H->>M: grant: groceries, ₹8,000, ask me above ₹2,500
    M-->>A: mandate (signed, bound to the agent's key)
    A->>S: POST /orders + mandate + proof signed by the agent's key
    S->>M: authorize(mandate, proof, what I received, price I computed)
    M-->>S: allow + signed receipt | deny + reason | approval needed
    Note over H,M: above the line: the human taps Approve or Deny
    S-->>A: 201 order / 403 {error, hint} / 202 {approval_id}
```

| Piece | What it does |
|---|---|
| **Mandate** (`mandate+jws`) | An Ed25519-signed credential: the principal, the agent, the agent's public key (`cnf`), scopes, currency, per-purchase limit, budget, allowed merchants, blocked categories, approval line, expiry. |
| **Proof of possession** (`mandate-proof+jws`) | The agent signs every request: audience, method, path, SHA-256 of the body, time, nonce, and for a purchase the payee, currency and maximum amount it agrees to pay (the same idea as DPoP). A stolen mandate is useless without the key, a captured request cannot be replayed or edited, and a service cannot charge more than the agent signed for. |
| **Policy engine** | Checks in order: signature, revocation, expiry, proof, freshness, replay, scope, currency, merchant, category, per-purchase limit, idempotency, budget (atomic), duplicate basket, approval line. |
| **Human approval** | Above the line, or for a repeat of the same basket within 10 minutes, the service gets `pending_approval`. The approval is bound to the exact basket and can be used once. |
| **Receipts** (`mandate-receipt+jws`) | A signed record of each allowed action, which the service can verify offline with the authority's public key. |
| **Audit log** | Every decision is hash-chained to the one before it. `/v1/audit/verify` detects any edit. |
| **Agent-native shop** | KiranaKart serves `/.well-known/agent.json` (endpoints, scopes, auth, error shape). Prices are computed by the shop, never taken from the agent. Every error is `{error, hint}`. |
| **MCP server** | Gives any MCP agent (Claude Desktop, Claude Code, Cursor) an identity and a mandate. The private key stays on the user's machine; the model never sees it. |

Design rule: **safety must not depend on the model behaving.** We don't try to detect prompt injection. We make it harmless.

## Quick start

```bash
pip install -e ".[dev]"
uvicorn mandate.server:app --port 8000
```

Open http://localhost:8000 and click **Run demo agent**. A household agent asks you for a mandate (click **Grant**), buys groceries, reads a product page with a prompt injection and tries to add gift cards (blocked), asks you about a ₹3,499 mixer (click **Approve**), has its credential stolen and replayed by an attacker (blocked), and is revoked (blocked). Watch the live activity feed and the audit chain badge.

Other ways to run it:

```bash
python -m pytest -q tests                                    # 27 security tests
python -m mandate.eval.run                                   # benchmark -> docs/RESULTS.md, eval/results.json
python -m mandate.agent.demo --base http://localhost:8000    # the demo agent, from a terminal
```

### With a real LLM (Claude)

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...
python -m mandate.agent.llm_agent --mode baseline --runs 5   # Claude shops with an API key
python -m mandate.agent.llm_agent --mode mandate  --runs 5   # Claude shops with a mandate
```

It records, per run, whether the model tried the injected gift-card purchase and whether money moved for it. Results go to `eval/llm_<mode>.json`.

### With your own Claude, no API key (MCP)

Claude Desktop or Claude Code becomes the agent through the MCP server, using your normal Claude login.
Step-by-step setup and the demo prompt: [`docs/CLAUDE_SETUP.md`](docs/CLAUDE_SETUP.md).

```bash
pip install -e ".[mcp]"
claude mcp add mandate -e MANDATE_URL=http://localhost:8000 -- "$(pwd)/.venv/bin/python" -m mandate.mcp_server
```

Tools: `mandate_status`, `request_mandate`, `wait_for_human`, `read_service_manifest`, `quote_basket`,
`signed_request`, `check_approval`. The agent's private key stays in `~/.mandate/agent.json`; the model never sees it.

**Real run** ([`eval/claude_mcp_run.json`](eval/claude_mcp_run.json)): Claude asked for a mandate, bought the
groceries (₹1,815), waited for the human's approval on a ₹3,499 mixer, had the gift card it was asked for refused
(`category_blocked`) and explained why without working around it. It also spotted the planted instruction in a
product description and ignored it. So the model is the first line of defence, and Mandate enforces the owner's
rules whether or not the model holds.

### Deploy

`Dockerfile` and `render.yaml` are included (Render: New, then Blueprint, then this repo). Set `MANDATE_ADMIN_TOKEN` before deploying: without a token, the dashboard and admin API answer only requests from the same machine (set `MANDATE_OPEN_DEMO=1` to override that on purpose).

## For a service: accept agents in one call

```python
d = requests.post(f"{AUTHORITY}/v1/authorize", json={
    "mandate": request.headers["Authorization"].removeprefix("Mandate "),
    "proof":   request.headers["Mandate-Proof"],
    "request": {"aud": "your-merchant-id", "htm": "POST", "htu": request.path, "body_sha256": sha256(raw_body)},
    "intent":  {"action": "payments:charge", "merchant": "your-merchant-id", "amount": total, "currency": "INR",
                "categories": cats, "items": lines, "idempotency_key": body.get("idempotency_key")},
}).json()
# d["decision"] is "allow" (with a receipt), "deny" (with reason + hint) or "pending_approval" (with approval_id)
```

## API

| Endpoint | Who calls it |
|---|---|
| `GET /.well-known/mandate-authority.json` | Anyone: issuer, public key, endpoints |
| `POST /v1/agents` | Agent: register its public key |
| `POST /v1/mandate-requests`, `GET /v1/mandate-requests/{id}` | Agent: ask for a mandate, then collect it |
| `POST /v1/authorize` | Service: decide an action |
| `GET /v1/approvals/{id}` | Agent: poll a pending approval |
| `POST /v1/mandates`, `POST /v1/mandates/{jti}/revoke` | Human: grant directly, revoke |
| `POST /v1/mandate-requests/{id}/decide`, `POST /v1/approvals/{id}/decide` | Human: grant or refuse, approve or deny |
| `GET /v1/audit`, `GET /v1/audit/verify` | Human / auditor |

## Project layout

```
mandate/crypto.py            Ed25519 keys, canonical JSON, compact signed tokens
mandate/authority/engine.py  issuing, policy decisions, approvals, receipts
mandate/authority/store.py   SQLite storage + hash-chained audit log
mandate/server.py            HTTP API + dashboard + the demo shop mounted at /shop
mandate/merchant/app.py      KiranaKart: an agent-native shop (manifest, catalog, orders)
mandate/agent/sdk.py         agent SDK: keys, mandate, per-request proofs
mandate/agent/demo.py        scripted demo agent (real HTTP)
mandate/agent/llm_agent.py   Claude shopping agent (tool use)
mandate/mcp_server.py        MCP server for any agent
mandate/eval/run.py          the benchmark
mandate/web/index.html       the human's dashboard
tests/                       security tests
```

## Limits and honest notes

- The attack scenarios script the worst case instead of waiting for an LLM to be fooled. That is deliberate: it measures what an attacker can get *when* the model slips. The optional `llm_agent` measures how often a real model slips.
- In this prototype the authority signs mandates after the human approves in the dashboard. In production the human would co-sign with a passkey (WebAuthn), so even the authority could not mint a mandate alone.
- Latency is measured on localhost. Over the internet, add one round trip from the service to the authority, or have services verify mandates locally and call the authority only to record spend.
- The authority holds no money. It decides; a payment provider (UPI, cards) moves funds only with a valid receipt. Connecting one is the next step.

## Where this fits

Big players are building agent payment rails: Google's **AP2** (signed Intent, Cart and Payment mandates as verifiable credentials), OpenAI and Stripe's **Agentic Commerce Protocol** with Shared Payment Tokens (limited to one merchant and a maximum amount, revocable), and **Visa Intelligent Commerce** and **Mastercard Agent Pay** (registered agents and agent tokens). Mandate shares their core idea and doesn't compete with them: it doesn't move money.

What Mandate offers is the layer a developer or small business can run **today**: open source, any MCP agent, one permission system for every action (not only checkout), rules a person would set (item categories, approval line, repeat-order detection), a proof on every request, agent-readable refusals, an audit log, and a published benchmark that includes what it doesn't stop. In production it sits in front of whatever rail the merchant already uses (AP2, a Stripe token, a card network token or UPI). Full comparison: [`docs/POSITIONING.md`](docs/POSITIONING.md).

## Why this can be a company

Every business that wants agent traffic needs to decide, per request, whether an agent's action should happen at all: who it acts for, what that person allowed, and proof it was really that agent. The payment rails answer "how does money move"; Mandate answers "should this happen", for payments and for every other action an agent takes.

- **Who pays:** merchants and API platforms (per authorized action), agent platforms (per active agent), and fintechs that want spend controls for agents.
- **Why India first:** UPI AutoPay already made "mandates" a familiar idea: a capped, revocable permission to debit. Agent mandates are the next step, and Indian consumers already approve and revoke such permissions from their phones.
- **Next:** passkey co-signing, a UPI/card payment connector, per-service rate limits, delegation chains (an agent hiring a sub-agent with a narrower mandate), and SDKs for Node and Go.
