# 45 — Persistent machine connections

This is the approved remote-access design. Delivery starts with connect and
reuse with native agent identity and mail, followed by the native comparison
consumer and paired terminal timing qualification, ordinary cross-machine
replies, then per-agent and link revocation. A contract clause is not evidence
that its implementation has passed the required journeys.

## 1. The connection belongs to the machine

`se remote add <ssh-alias> --name <machine>` uses the system SSH client and the
user's existing SSH configuration, host-key verification and authentication.
It discovers the destination platform, stages a matching native image when
needed, and starts or reuses a compatible user-owned host. Bootstrap obtains a
protected application session over SSH. The client establishes a loopback
forward, checks the destination identity, and atomically saves the machine
binding and credential reference. There is no manual port, fingerprint,
invitation file, console paste or separately managed forward.

An incompatible, unready or differently owned incumbent is preserved and the
operation refuses with a reason. Connecting must never silently replace a host.
Changed or unknown SSH host keys follow SSH's configured verification policy;
the adapter never disables that policy or clears known-host records.

## 2. One link, many real agents

One source host shares one authenticated multiplexed connection per destination
machine. CLI, MCP, projects and agents use the same host-owned runtime. Adding
an agent creates no device grant, private key or SSH connection. Saved machine
sessions are reused; reconnect restores SSH before application authentication
and catch-up. The application session is authenticated inside SSH; there is no
second pinned TLS or challenge-signature protocol.

The machine session identifies a machine. Protected native IPC independently
verifies every agent caller's actual host, project, agent, session and generation.
`VerifiedSourceSession` constructs immutable `RemoteCallContext`; caller arguments
cannot select a sender. The broker retains credentials, and agents receive no
machine-owner authority or private connection material. Failed session admission
never falls back to human authority.

A stable agent address is `(host, project, agent)`. Session end fences that
session without deleting its agent identity or mailbox. Message and attribution
commit together through the ordinary mail writer; the target sees the actual
sending agent. Durable mutation keys are namespaced by stable authenticated
origin, excluding ephemeral session and generation. A retry keeps its original
public key and returns the original message and attribution.

## 3. Narrow operations and truthful views

The initial data surface is bounded list, watch and send. A machine session may
allow discovery across its owned projects while exact selections and verbs
remain enforced at admission, reads, writer submission and output. Per-agent
restrictions further attenuate machine authority; revocation cannot be undone
by automatic discovery. Neither transport nor remote credentials become an
ordinary local Owner or source-session capability.

Metadata is paged using authorized keyset cursors. Current view, durable replay
and provisional live output remain distinct. A live provider observation is
visibly provisional until capture commits. Gaps, unavailable sources, omitted
rows and unreadable state are explicit; reconnect cannot fabricate continuity.
A slow client retains bounded queues and receives backpressure or a gap.

Send targets an actual native agent and its expected current session. Admission
is not delivery; a durable receipt is not proof the provider consumed the mail.
The ordinary mailbox, provider work and outside file/mail readback establish
those separate effects. CLI and MCP share implementation and caller identity.

## 4. Replies preserve the return address

An ordinary reply retains `reply_to` and routes to the originating agent's real
mailbox over the same machine link. The existing durable mail/outbox and receipt
path retain replies through disconnect and restart. Retry cannot duplicate a
reply or substitute the destination's local Owner mailbox. Replies are the
separate implementation outcome; attribution alone does not implement them.

## 5. Revoke the intended authority

Durable per-agent permission, revision and tombstone records allow one agent's
access to end while other agents continue. Link revocation fences every agent
and queued output on that link. Both are checked before admission, writer
enqueue and output release, and survive host restart. Session fencing is
separate from stable agent identity. Automatic reconnect must not clear an agent
revocation. These independent controls are a separate implementation outcome.

Application-session revocation ends current access. An authorized SSH account
can explicitly bootstrap a new application session; removing SSH authority is
a separate action. Credential or database replacement invalidates old machine
sessions before opening a listener. Absent and unreadable protected records are
not interchangeable, and failed or uncertain revocation stays fenced.

## 6. Process and resource ownership

Disconnect and forget close source transport only. They do not stop the remote
host, its native lease, running agents or their conversations. Host stop is an
explicit separate operation. Each SSH child is owned by its source host, joined
on closure, and never found or killed by executable name or a process pattern.
A listening port alone is not proof the intended forward owns it.

Bound active bytes, requests, mutations, parser depth, output queues and replay
pages. There is no fixed enrolled-machine or enrolled-agent quota. Idle history
must not allocate maximum buffers, connection slots or credential caches.
Remote mode remains optional: disabled local reads add no remote listener,
network task, timer or resident maximum-sized buffer. Measure active SSH and
application transport costs under [80 §7](80-performance-budgets.md#7-proposed-client-interaction-budgets).

## 7. Acceptance and subtraction

Exercise real system SSH from Linux and the Windows VM. Sandboxed agents use
MCP; ordinary-terminal users exercise CLI forms. A sandboxed CLI whose native
ownership proof is unavailable refuses and names MCP as the working step.
Permissions and ownership checks remain unchanged; this refusal is not a
passing CLI journey. Cover fresh setup,
compatible reuse, concurrent agents, real default Claude/Codex CLI and MCP work,
identity preservation, actual mail delivery, reconnect and host restart, changed
host keys, authentication failure, command injection, occupied ports, a changed
environment and interrupted publication. Independently read process births,
leases, mailboxes and files. Reconnect, disconnect, forget and failed connection
to an incumbent must preserve its host and agents.

Later outcomes additionally prove real replies, original-key retries across
source sessions, different-agent key isolation, lost replies and catch-up,
ended-session impersonation refusal and durable agent/link output fences.
Report active-link memory. The connect/reuse outcome leaves all four CLI-visible
clocks explicitly unqualified; the next outcome implements the native comparison
consumer and qualifies the 100-pair timing cohorts under [47 §6](47-r0-contract.md#6-four-visible-clocks).
That outcome must land before remote is considered complete; real use remains
the final judgment. Native Linux behavior cannot qualify the Windows journey.

Retire invitation files and ACL repair, manually exchanged offers, terminal-only
pairing, user-managed forwards, inner TLS/proof keys, per-agent pairing credentials
and fixed device quotas in the first outcome that makes them unused. Unreleased
fixture databases require no migration or legacy pairing fallback. External
measurements are retained outside this repository and are not product evidence.
