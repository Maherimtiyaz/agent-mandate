# Where Mandate fits

Large companies are building the rails for agent payments. Mandate is not a rival rail: it is a small, open-source
permission layer that any developer can run today, with any MCP agent, in front of any service. This page says
plainly what already exists, where Mandate overlaps, and what it offers on top.

## What already exists (as of November 2026)

| | What it is | Overlap with Mandate |
|---|---|---|
| **AP2, Agent Payments Protocol** (Google, open protocol, contributed to the FIDO Alliance) | Signed "mandates" encoded as W3C Verifiable Credentials: an Intent Mandate (what the user asked for), a Cart Mandate (the exact items and price), and a Payment Mandate that tells the network an agent is involved. Human-present and human-not-present flows. | The same core idea, and the same word: a signed record of what the user authorized. We chose the name on purpose; UPI AutoPay uses it too. |
| **ACP, Agentic Commerce Protocol** (OpenAI with Stripe) and **Stripe Shared Payment Tokens** | Checkout inside ChatGPT. The token is limited to one merchant and a maximum amount, can expire, and can be revoked. The merchant stays merchant of record. Instant Checkout in ChatGPT is for approved partners; the protocol itself is open. | Our signed payment cap (payee + currency + maximum, signed by the agent) is the same protection against a merchant charging more. |
| **Visa Intelligent Commerce, Mastercard Agent Pay** | Registered, verified agents and agent tokens on the card networks. | Agent identity for payments. |

## What Mandate offers on top

1. **It runs today, for anyone.** Open source, self-hosted, one `pip install`. Any MCP agent (Claude Desktop, Claude
   Code, Cursor) gets an identity and a mandate with one config line. No partner approval and no payment-provider
   account needed to try it.
2. **One permission layer for every action, not only checkout.** Scopes such as `orders:read` work the same way
   as `payments:charge`, so the same mandate covers reading data and spending money.
3. **Rules a person would actually set, enforced per request:** item categories ("never gift cards"), merchants,
   per-purchase limit, budget, "ask me above ₹2,500", and repeat-order detection. Approvals are bound to the exact
   basket and work once.
4. **Every request is proven, not just authorized:** each one is signed with the agent's own key over the method,
   path, body and a one-time nonce, so a leaked credential, a replayed request or an edited request fails.
5. **Answers an agent can act on:** every refusal is `{error, hint}`, so the agent explains it or adjusts instead of
   retrying blindly. In our real Claude run, the model read the hint and told the user why.
6. **A tamper-evident audit log** for the person and for disputes.
7. **Published evidence, including what it does not stop:** a 13-attack benchmark against an API key and a capped
   virtual card, with a measured known-limits section (`docs/RESULTS.md`).

## How it would work with them

Mandate does not move money. A Mandate receipt says "this agent, for this person, may pay this merchant this much
for these items". In production that decision sits in front of the rail the merchant already uses:

- **AP2:** issue Mandate grants as AP2 Intent Mandates and accept AP2 credentials as input (roadmap).
- **Stripe SPT / card network tokens:** a merchant charges the token only after Mandate allows the order; the token's
  own merchant and amount limits remain a second check.
- **UPI:** the same pattern in front of a UPI AutoPay mandate, which Indian users already know how to approve and
  revoke.

## The honest summary

The big standards will decide how money moves between agents, merchants and banks. Mandate is the piece a developer
or a small business can run today to decide *whether an agent's action should happen at all*, with the person's
rules, a proof on every request, and a log. We would rather be compatible with those standards than compete with them.

Sources: Google Cloud's AP2 announcement; the FIDO Alliance post on AP2 and Verifiable Intent; Stripe's ACP and
Shared Payment Token announcements; OpenAI's commerce documentation; Visa and Mastercard press material (2025–2026).
Details may have changed since; check the primary sources.
