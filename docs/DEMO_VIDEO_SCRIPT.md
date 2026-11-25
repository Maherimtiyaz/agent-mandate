# Demo video script (about 3 minutes)

The star is a real Claude agent (Claude Desktop or Claude Code) using Mandate through MCP. Setup:
`docs/CLAUDE_SETUP.md`. Before recording: stop the server, delete `mandate.db`, start it again. Put Claude on the
left and the dashboard (http://localhost:8000) on the right. Record at 1080p.

| Time | Show | Say |
|---|---|---|
| 0:00-0:20 | Empty dashboard next to Claude | "Agents now shop and pay for us with a saved card or an API key. That gives them all of our authority: no limits, no proof of who they act for, no off switch. Mandate is the permission layer for agents." |
| 0:20-0:35 | Paste the demo prompt into Claude | "This is my normal Claude, connected to Mandate through MCP. No special agent code. I ask it for groceries, a mixer, and a gift card for my cousin." |
| 0:35-0:55 | Grant card appears; click **Grant** | "Before spending anything, it asks me for a mandate: groceries, ₹8,000, ask me above ₹2,500, never gift cards. The mandate is bound to a key on my machine; Claude never sees it." |
| 0:55-1:10 | Feed: ALLOW ₹1,815 | "Groceries go through. Every request is signed, and the shop checks it with Mandate in one call." |
| 1:10-1:30 | Approve card for ₹3,499; click **Approve** | "The mixer is above my line, so I'm asked, and the approval only works for this exact basket." |
| 1:30-1:50 | Feed: DENY category_blocked; Claude's explanation | "The gift card sounds legitimate, but it breaks my rule, so it's refused, and Claude tells me why instead of looking for a way around." |
| 1:50-2:05 | Claude's note about the planted instruction | "The atta listing hides a prompt injection. Claude caught it this time. Models don't always, and Mandate doesn't depend on it." |
| 2:05-2:20 | Click **Revoke**; ask Claude to buy milk | "One click and the agent is cut off everywhere." |
| 2:20-2:45 | Terminal: `python -m mandate.eval.run`, then the results card | "For when the model does slip, we measured it against today's setups. Thirteen attacks: an API key loses ₹1,08,709; even a capped virtual card loses ₹30,483; Mandate loses nothing, every normal task still completes, and it adds about a millisecond. We also publish what it doesn't stop." |
| 2:45-3:00 | README | "One call for services, an MCP server for any agent, a dashboard for people. Mandate: software built for agents." |

Backup: if Claude misbehaves on the day, the dashboard's **Run demo agent** button plays the same story with a
scripted agent.
