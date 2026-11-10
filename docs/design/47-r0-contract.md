# 47 — Native remote contract

[45](45-remote-clients.md) governs the approved behavior. This contract fixes the
trust and review boundaries for its implementation outcomes. Passing a
unit test or recording a receipt does not qualify a real consumer journey.

## 1. Connect and reuse

The public setup is `se remote add <ssh-alias> --name <machine>`. The native
adapter uses system SSH, normal configuration and host-key verification. It
discovers the platform, obtains the matching distribution, stages missing bytes,
then starts or reuses a compatible owned host. Bootstrap and connection material
travel only through the protected SSH return pipe and native protected storage.
No user-facing output, diagnostic, command argument or provider environment
contains those secrets.

A machine binding is published atomically and read back. An interrupted save
must leave a usable complete previous binding or an explicit incomplete/absent
state; an orphan credential must not be mistaken for successful setup. Repeated
setup reuses identity and session. Every application connection verifies its
saved environment identity before releasing private data. A changed endpoint,
foreign process, wrong host or incompatible incumbent refuses without replacement.

One authenticated destination link serves all agents, projects, CLI calls and
MCP calls on a source host. SSH is restored before reconnect/replay. Failed
connection never changes native provider custody. Disconnect and forget close
source transport only, preserving the remote host, lease, agents and conversation.

The system SSH forward is the sole persistent transport child. Opening an
application connection uses one bounded SSH authorization command that exits
after native channel verification; it carries credentials only through stdin.
Agents share the resulting connection rather than launching authorization per
agent or retaining a separate control helper.

## 2. Identity and the process boundary

Only protected native IPC/session admission constructs `VerifiedSourceSession`.
The immutable `RemoteCallContext` contains the actual source host, project,
agent, session and generation plus its shared session fence. A caller-selected
sender, stale credential, ended session, launch credential or remote principal
cannot become another source agent or machine Owner. Session failure has no
human-authority fallback.

The machine session identifies the admitted source broker, which vouches for
each actual caller. It is not an agent identity. `RemoteAgentAddress` is stable
across session changes; `remote_message_attribution` commits beside ordinary
mail with original host/store/principal/grant, target, authority revision and
source attribution. Readers expose the actual sender and do not label agent
mail as human Owner mail.

Mutation keys use stable authenticated origin, not session/generation. Distinct
agents may choose the same public key without collision. Original-key retries
from a successor session replay the original result, retaining original
attribution. A body/target disagreement refuses rather than mutating the retry.

## 3. Data surface and bounds

List, watch and send are closed typed operations. Scope is checked at each
admission/read/writer/output seam. Discovery is keyset-paged without a full-floor
scan or an enrolled-agent ceiling. An exact watch/send selection remains bounded.
A send names the target's expected active session and 1..32768 UTF-8 body bytes.
The target's ordinary native mail path supplies delivery and consumption.

The authenticated frame bound is 256 KiB; pre-authentication aggregate traffic
is 32 KiB. Each active link has bounded in-flight work, mutations, frame/byte
queues, parser depth and finite replay pages. A slow/disconnected reader cannot
stall the native writer or providers. Backpressure retains the original key;
gaps retain the last consumed cursor. No unlimited historical cache or maximum
buffer allocation per enrolled agent is permitted.

Current metadata, durable history and provisional provider output are distinct.
Current view includes actual pending state; live output need not wait for a
capture commit, but never claims durability prematurely. Unknown, absent,
unreadable, omitted and zero remain different facts. No empty success masks a
failed read, and no gap is called complete catch-up.

## 4. Replies and independent revocation

The replies outcome routes ordinary `reply_to` mail back to the originating agent's real
mailbox through durable outbox/receipt handling over the shared link. Disconnect,
restart and lost acknowledgement preserve delivery without duplication or a
local Owner mailbox substitute.

The revocation outcome stores independent per-agent permissions/revisions/tombstones and
link revocation. Revoke one agent without interrupting others; revoke the link
to fence all agents and queued output. Session end remains separate from stable
identity. Admission, writer enqueue and output release recheck current authority.
A revocation survives reconnect/restart and automatic discovery cannot clear it.
An authorized SSH login can explicitly create a new application session; SSH
account authority is a distinct boundary.

## 5. Outside-behavior review

Use actual system SSH with private configuration, not an in-process fake, for:

- Fresh setup and repeated compatible reuse; changed/unknown host keys,
  authentication failure, command injection and occupied forwarding ports.
- Wrong environment identity, interrupted protected save, changed image and an
  incompatible/unready incumbent, with unchanged native process births/leases.
- Concurrent real agents sharing one connection while retaining independent
  origins through default Claude/Codex agents using MCP; ordinary-terminal CLI
  forms; actual provider work and outside mailbox/file sentinels. A sandboxed
  CLI whose native ownership proof is unavailable refuses with MCP guidance;
  that refusal contributes no successful CLI journey.
- Reconnect, disconnect and forget preserving the host, agents and conversation.
- Native Linux and Windows VM journeys from the reviewed bytes, with separate
  correctness, architecture/craft, design-conformance and process-boundary verdicts.

Later reply/revocation reviews add source-session retries, cross-agent key
collisions, return-mailbox delivery, lost-reply catch-up, impersonation and
persistent agent/link admission/output fencing. Required checks bind to the
candidate bytes; repeat after relevant changes or a named uncertainty.

## 6. Four visible clocks

The connect/reuse outcome leaves all four clocks explicitly unqualified. Its
next delivery implements the native comparison consumer and qualifies the
100 matched local/remote pairs per clock and route required by [80 §7](80-performance-budgets.md#7-proposed-client-interaction-budgets).
This qualification must land before remote is considered complete. It does not
require a separate end-user command if the same native consumer and renderer
can supply the comparison.

The CLI-visible clocks retain their original absolute and paired-delta ceilings.
Attach ends after the authorized current view is written and flushed. Pending
echo ends after the labelled pending record is flushed. Live output ends after
the attributed provisional item is flushed. Reconnect ends after catch-up and
a new live item are flushed. MCP response availability is recorded separately;
a tool packet's arrival does not count as a visible terminal frame. These
measurements do not qualify UI paint.

The local and remote comparison show the same actual destination agent,
conversation and provider item IDs. The local consumer runs on the destination
against its local connector; the remote consumer runs on the second machine
through the shared SSH link. Both use the same candidate source, renderer,
selection, content and bounds. Report and charge hardware/OS differences rather
than subtracting them. Interleave local/remote pairs and retain sample order/load.

Compare records, content, order and form by provider item ID and durable
message/key, including pending, failures, omissions and gaps. Transport metadata
is measured separately. Missing records, special remote-only placeholders and
reordered output do not pass. Keep durable acceptance, provider inference,
cold startup, blackhole detection and larger backlog costs separate. Absolute
and paired-delta ceilings, cohort counts and every failure follow
[80 §7](80-performance-budgets.md#7-proposed-client-interaction-budgets).
