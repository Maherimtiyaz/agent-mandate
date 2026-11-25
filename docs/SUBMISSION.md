# Submission checklist (deadline: 6 Dec 2026, 23:59 IST; submission window 4-6 Dec)

The team captain submits from the Hack Days dashboard.

- [ ] Public GitHub repository containing this folder at its root, with this README and setup steps
- [ ] Demo video (YouTube unlisted, Loom, or Google Drive with link sharing on), following `docs/DEMO_VIDEO_SCRIPT.md`
- [ ] Optional: deployed link (Render via `render.yaml`)
- [ ] Optional: pitch deck (problem, approach, architecture, results): the 7-slide Mandate deck. Fill in the `[Team name]`, repo and video placeholders on slides 1 and 7, then export it as PDF (Share, then Export) and attach or link it
- [ ] Run `python -m pytest -q tests` and `python -m mandate.eval.run` one last time; commit `docs/RESULTS.md`
- [ ] If you have an Anthropic key: run `llm_agent` in both modes and add the numbers to the README

## How this maps to the judging criteria

| Criterion | Where it is answered |
|---|---|
| Problem fit & impact | A1 asks for identity, permissions, payments and interfaces built for agents. Mandate covers all four (README, first section). |
| Technical depth | Key-bound credentials, per-request proofs, replay protection, atomic budget, approvals bound to the exact basket, signed receipts, hash-chained audit log. |
| Reliability & evaluation | 27 security tests (including concurrency and the fixes from our own security review); a 13-attack benchmark against two baselines (an API key and a capped virtual card), with a measured known-limits section and latency over real HTTP; idempotent retries; CI workflow. |
| Product & experience | One-click demo in the dashboard; agents get `{error, hint}` they can act on; MCP server for any agent. |
| Demo & communication | `docs/DEMO_VIDEO_SCRIPT.md` |

Sponsor angle (optional): Keploy (testing partner) gives badges to the top 3 by tests; our test suite and CI help there.
