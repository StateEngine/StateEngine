# Agents collaborating in an existing project

Design proposal, 5 November 2026. A local agent asks a hosted colleague in the same project to test the app and report through ordinary mail. Provider, transport and session are connection attributes.

**Today’s trap:** an eligible process using the user’s account outside recorded agent trees is admitted as Owner, subject to session, provider-marker and protected-owner checks ([70 §§1.2–2.3](70-security.md)). A bot driving `se` through that desktop bridge appears as Owner, with no separate bot identity: the OS cannot distinguish them. Give bots a usable credential-authenticated door and document that route; same-user trust limits remain.

## One identity and mail contract

Each agent has a stable ID, owner, exact project memberships, permissions and verifiable connections. Protected owner controls register it and authorize connections. Replacing sessions/VMs preserves identity/inbox; external registration fabricates no native session.

Both mail directions show registered sender name and credential-derived agent ID with the same verification and format as local agents. Claimed names confer no authority. Local harnesses retain process/session proof; external connections prove their current grant. Protect credentials, never lend machine/owner credentials, and require owner-authorized re-enrollment after key loss.

Reuse [45’s grants](45-remote-clients.md) and [47’s authorization](47-r0-contract.md): exact scope, authenticated host, keyed sends, expiry and admission/output revocation fences. Add a grant-bound registered-agent subject without changing human-device/source-session lead grants. R1 adds recipient registration, read acknowledgement and registration-generation targeting without a provider session. Its fixed verbs are `message.inbox`, `message.list`, `message.read`, `message.ack`, `message.send`, `history.list` and `history.event_read`, limited to own mail/history and allowed colleagues. This explicitly extends R0’s List/Watch/Send surface; no generic invoke, shell, launch or repository access follows.

Existing history retains message ID, project, verified sender, recipient, references, body and durable receipt. Quoted content is data. Inbox unread/read/dismissed states differ from host acceptance, notice receipt, task acceptance and result commitment. Deferred, failed and unknown delivery remain explicit. Revocation fences admission/private output and notifications, preserving history.

## First connect for an external agent

First connect establishes the inbox through owner approval; launched agents keep existing setup. The owner chooses agent ID, projects, correspondents and permissions. The bot cannot self-register or choose its actor. Idempotently activate only that approved binding; return verified name/ID for confirmation.

| Route | Approval and credential custody |
| --- | --- |
| Remote MCP sign-in — preferred | User approves agent/grant in a protected browser flow; connector holds the scoped token. Verify issuer, audience, expiry, revision and scope per call. OAuth client registration alone grants no agent authority. |
| Owner-issued code | Owner creates a short-lived, single-use code bound to the pending agent/grant and connector proof. Proposed bootstrap-only `stateengine_agent_enroll` redeems atomically; replay creates no second identity. No code enters mail/chat/logs. Require protected input and connector-managed credential installation/persistence, never lasting credentials in ordinary tool results; otherwise use OAuth. |

One proven connection maps to one approved agent, possibly a team. Its bots share that principal’s inbox/permissions. Owner-registered labels alone are allowed in `self_reported_member`, never the verified name field or authority. Render `From: grok-team (ag_…)` and a separate `Self-reported member: scout`: the team is verified; “says: scout” is a claim. Member-addressed mail adds a routing label to the shared inbox, without private delivery or independent read acknowledgement. These optional fields need an R1 wire amendment; current closed DTOs reject them.

Names, thread IDs and codes cannot split shared credentials into verified actors. Later per-bot credentials permit owner-enrolled agent IDs/grants and explicit new routing in the same format; historical team attribution stays intact.

| Client | Documented support and limit |
| --- | --- |
| Grok Bot | URL/command MCP servers, browser authorization and backend-held OAuth tokens; app connections are account-wide and shared by its bots. Distinct bot credential isolation is not established. [Apps and connections](https://docs.x.ai/grok-bot/computer-and-apps#connect-an-app). |
| Dots / OpenAI | Remote MCP OAuth 2.1/PKCE, browser consent and per-call bearer validation. Multiple accounts use selected connection credentials; this does not establish per-dot isolation. [Authentication](https://developers.openai.com/plugins/build/auth). |
| Hermes | HTTP MCP OAuth/PKCE, browser first authorization, persistent refreshed tokens and separate OAuth connections per profile; configured HTTP headers also exist. Test actual hosted-profile custody and headless authorization. [Pinned reference](https://github.com/NousResearch/hermes-agent/blob/323c318c4eb4a22fd75e9172639d88379bbc3d42/website/docs/reference/mcp-config-reference.md). |

Plan for multiple bots per account: [Grok documents inter-bot handoffs](https://docs.x.ai/grok-bot/chat-and-collaboration), while OpenAI currently documents [one personal dot per member](https://help.openai.com/en/articles/20001530-getting-started-with-your-dot). [Claude Duet describes one ongoing thread](https://claude.com/resources/articles/claude-duet); that description does not establish a hard account quota. A future increase in dot count is not established by these sources and is not required by the contract.

These sources do not establish the proposed code-to-credential-install flow. Reuse seat tool names/shapes: `stateengine_msg_list`, `stateengine_msg_read`, `stateengine_msg_ack`, `stateengine_msg_send`, `stateengine_event_read`; preserve pages, marker effects, references and keyed receipts. Authentication supplies actor/scope; vendor prefixes change no contract.

## Delivery and reachability

| Declared capability | Contract |
| --- | --- |
| Push | Notify a verified destination; receipt is not read/completion. |
| Poll | Bounded inbox/history pages, cursors and explicit gaps. |
| Accept task / return result | Explicit linked acceptance/result under the verified identity, deduplicated. |
| Session required | Closed integration sessions leave mail pending. |

Persist mail before delivery. Signed webhook/email notices carry fixed hints/opaque references, no private bodies, credentials or owner instructions. Headers never authenticate mail. Poll through scheduled authenticated fetches, or check manually. Unknown, unsupported and unavailable differ.

Outbound notices from home do not make fetch/send reachable. The bot’s credential needs an authorized endpoint; its operator remains open:

| Option | Operator and consequence |
| --- | --- |
| User endpoint/tunnel | User operates host and HTTPS/tunnel route; unavailable with that host off. |
| Relay | User/service forwards through outbound home connectivity; authorization stays at the host, and relay receipt is not host acceptance or a hosted mailbox. |
| Hosted StateEngine | User/service operates the authoritative host/store away from home; choose credential custody, data location and cost explicitly. |

With the authoritative host off, accepted mail waits; remote attempts lack acceptance without its durable receipt. Pending results need durable queuing. Reconnect with saved cursors, current authorization, deduplication and explicit gaps. Never export the loopback machine-credential endpoint.

## Protocol and wake choices

MCP tools are the first integration. OpenAI documents signed subscribed dot/cloud Work [MCP Events](https://developers.openai.com/plugins/build/mcp-events): asynchronous processing, receipt-only `2xx`, out-of-order events and persisted/refreshed/expired subscriptions. This integration lacks polling/streaming/gap events. Public HTTPS or [Secure MCP Tunnel](https://developers.openai.com/plugins/deploy/connect-chatgpt) needs an actual route/subscription trial. [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) remains an optional task/result adapter; card/task IDs confer no scope or replacement inbox.

[Grok routines](https://docs.x.ai/grok-bot/skills-routines-and-automations) have five-minute minimum schedule spacing and bearer webhooks; `200` means run started, not finished, and signature verification is not documented. Its [email](https://docs.x.ai/grok-bot/computer-and-apps#give-your-bots-an-email-address) supports bodies/attachments and routine triggers; mail alone does not wake a bot. Metadata-only email is our notice policy, not a provider restriction. Email replies cannot replace authenticated sends. Demonstrate unattended behavior per integration.

## Proof with two genuinely different agents

Use real local and hosted agents in one project, separately enrolled. Before implementation verify actual tools, credential custody, first connect, subscription and route; command/SSH reports or timeouts prove neither mail nor authority.

1. Show the trap: independently read Owner attribution from a harmless owner-shell/bridge send, then the distinct credential-derived agent ID from the enrolled bot’s equivalent send.
2. The local agent requests app testing; the hosted agent fetches the verified request, performs observable work and returns a finding. Independently read both directions: ordinary mail, registered name/ID, no claimed-name substitution. Try two bots sharing a connection: owner-registered member labels remain separate self-reports under the same actor, scope and inbox; unknown labels refuse. Verify member-addressed mail reaches that shared inbox. Later separate enrollment changes new routing, never historical attribution.
3. Exercise enrollment denial, expiry/replay, refresh/reconnect, duplicate/out-of-order hints, session closure and host stop/restart. Accepted mail survives; offline attempts are not accepted; results stay linked without duplicates.
4. Revoke; try wrong identity/project, owner-looking notices and another agent’s result credential. Check every fixed verb and queued output against scope/revocation without Owner fallback. Record acceptance, delivery, read, task acceptance and completion separately.

This qualifies only the exercised integrations and declared capabilities, not universal vendor compatibility or current-R0 support.
