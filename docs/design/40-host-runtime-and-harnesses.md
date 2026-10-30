# 40 — Host runtime and harnesses

Status: design candidate; no runtime implementation or production qualification.
Owner: Vera. Design-first assignment: `msg-4c7d56b553b90440a977c9e0`;
priority correction: `msg-9657215aa7eab8611485c076` and
`msg-ab5565a9cf46b93e6b552c91`. Base: `ee4b9bcaae555af60e5e7b7904c5ec5e251c0526`.
Verification tier: kernel boundary design, qualified here by compiling declarations;
reviewers own executable tests and the five journey scripts. No new gate machinery.

The outcome is one StateEngine host, embedded or standalone, that launches real
agents, captures their work, resumes the same conversations and delivers mail
without losing holds, confusing an offer with a read, or stealing another process.
This chapter specifies runtime ownership and adapter behavior. It does not claim
that declaring a trait implements any of those outcomes.

## 1. Governing contracts, scope and ownership

The accepted [operation inventory](../OPS.md), [types and linked API](10-types-and-host-api.md),
[data model](20-data-model.md) and [process ownership](30-process-ownership.md)
control their respective boundaries. In particular:

* The registry has 59 operations and 26 MCP tools. Transport handshakes, hooks and
  internal native nudges do not create public operations.
* The store has one hosted writer while the exclusive runtime lease is held;
  direct writes use the same store transaction implementation under a shared
  runtime lease only when no host owns that home. The older direct-everywhere
  draft is superseded. The fixed security-event set uses FULL; ordinary commits
  use NORMAL. Caller-selected durability is forbidden. Ordinary activation never
  migrates a store; only section 20's explicit owner-approved upgrade may do so.
* The SE Code-owned permissive API is the section-10 proposal until Alpha lands
  its real crate. HostServices feeds SE Code's existing input queue. There is no
  second queue, subscribe/settle protocol, private copy of its executor or mail
  server inside SE Code.
* se-proc owns native process identity, containment, reservation, launch, stop and
  outside witnesses. Host code never replaces these with PID/name matching.
* Accepted sections override the synthesized plan and original `01`–`05` drafts
  where those drafts disagree. No live daemon/SE Code handover is in alpha.

`se-host` is the proprietary adapter/composition crate: runtime supervision,
filesystem ownership, local IPC/HTTP, harness translation and the linked-API
implementation. `se-core` owns authorization and operation semantics; se-store
owns commits, snapshots and recovery; se-proc owns process custody. Host adapters
call these owners rather than importing CLI rendering or generating floor rows.
The binary owns argument parsing, presentation, daemon entry and transient hook
entry. SE Code owns its runtime, native session execution and prompt queue.

Out of scope: factory agents/campaigns/gates, PostgreSQL multiplayer, remote HTTP,
provider authentication management, telemetry, arbitrary runtime plugins, a
second runtime, a terminal emulator, and a new permission bypass mode. Atlas is
optional standalone work with a separate database/budget and is absent embedded.
Provider CLIs and their tools remain provider processes; the one-process promise
counts StateEngine processes, not Claude/Codex or user tool subprocesses.

### 1.1 Evidence behind the choices

The Linux S4 prototype used real Claude 2.1.312 hooks and stock Codex 0.166
app-server: task, capture, mail/steer and same-conversation resume worked there.
The direct hook fallback took roughly 90–101 ms. Hosted NORMAL sequential hook
p95 was 8.3–9.5 ms; FULL was 47.9–56.9 ms. Concurrent NORMAL p95 was 10.966 ms,
but 8/200 operations exceeded 20 ms, maximum 65.199 ms. Acknowledged ordinary
commits survived 100 exact writer-process kills with no observed loss. This is
process-crash evidence, never a power-loss claim or a Windows/macOS result.
Artifacts are project-local prototype records, not shipped dependencies:
`vera-s4-socket-20261030/REPORT.txt` and `vera-s4-normal-20261030/REPORT.txt`.

These results motivate the accepted store writer and incremental hooks. They do
not waive the CLI target or authorize weakening FULL activation/revocation.
No Windows/macOS app-server transport, macOS containment or embedded RSS result
is inferred from the Linux prototype.

## 2. Canonical compile-only Rust surface

The exact public declarations are the source files below. They are normative
parts of this design and compile in the workspace, rather than pseudocode copies
that can drift from the crate. There are no function implementations, default
method bodies, panic placeholders or test implementations in se-host.

| Source | Public declarations and responsibility |
| --- | --- |
| [model.rs](../../crates/se-host/src/model.rs) | HostFuture, EmbeddedFactoryBuilder, HostKind, HostPhase, HostConfig, HostLimits, ListenerConfig, Cancellation, CallContext, OpenContext, SessionIdentity, VerifiedCaller, BoundSession, HostStatus, DrainReport, RestartRequest, RestartReason, FaultReport, FaultStage |
| [runtime.rs](../../crates/se-host/src/runtime.rs) | PreparedRuntime, Integration, Adoption, AdoptionOutcome, RuntimeFactory, HostControl, RuntimeFilesystem |
| [session.rs](../../crates/se-host/src/session.rs) | HarnessKind, SessionPhase, Activity, MailTarget, HoldReason, HoldWitness, InterruptReport, ActiveExecution, BindingEligibility, BindingState, MailNotice, NativeAdmission, NoticeOutcome, NativeQueue, SessionLease, SessionGrant, SessionView, TakeoverRequest, TakeoverTicket, TakeoverReport, SessionControl, CaptureRole, CaptureInput |
| [harness.rs](../../crates/se-host/src/harness.rs) | ProviderVersion, ProbeRequest, ConfigPlan, IntegrationEdit, OwnedLaunchFile, HarnessLaunch, HarnessBinding, BindingWitness, LaunchOutcome, OfferStage, OfferWitness, BellOutcome, TranscriptSource, HarnessStop, Harness, ClaudeHookKind, ClaudeHookInput, HookOutput, ClaudeHookAdapter, CodexTransport, CodexInvocation |
| [ipc.rs](../../crates/se-host/src/ipc.rs) | IpcEndpoint, EndpointRecord, PeerProof, ServerChallenge, IpcPlatform, ClientHello, PresentedAuthority, ServerHello, AuthorizedConnection, RawOperation, AdmittedOperation, OperationOutput, IpcRequest, IpcEnvelope, LocalAdmission, OperationDispatcher, HttpRequestHead, HttpChannel, LocalListener |

These are internal proprietary Rust interfaces, not another version of the linked
public API or JSON schemas. Their fields deliberately do not implement serde;
a protected transport codec performs validated conversion. Shared IDs, NativePath,
Read, Window, receipts, errors and ProcessInstance come from se-types; store and
process types are referenced directly. Opaque handles have crate-private fields
and cannot be reconstructed from actor/session strings by an external caller.
Same-process callers are trusted under the project trust rule; these handles
prevent mistakes, not hostile code already owning the process.

### 2.1 Composition and dependency versions

The commercial entry must have section 10's exact constructor type, recorded in
[commercial-factory.rs](commercial-factory.rs): a supplied
`tokio::runtime::Handle` produces `Arc<dyn secode_stateengine_api::HostFactory>`.
`EmbeddedFactoryBuilder<Factory>` is its compiling generic function-pointer shape;
substitute the upstream trait object when Alpha publishes the actual dependency.
This candidate does not vendor the permissive proposal as a second crate, nor
pretend an unimplemented commercial function is usable.

`RuntimeFactory::configured` is the proprietary configuration port: retain the
explicit Handle/config without I/O, worker creation or native callbacks. The
constructor has no ambient process/environment authority. The declaration-only
workspace pins Tokio 1.53.3 with `rt` to compile Handle. At embedding integration,
the exact Tokio package must match SE Code's selected pin; do not ship duplicate
Tokio or bundled SQLite versions. Only the composition crate depends on Tokio;
its types do not enter the permissive API. The dependency adds a real runtime
handle contract, not a second executor. Inspect `cargo tree -d` with the actual
SE Code composition before claiming shared-runtime memory.

All async and blocking jobs use the retained Handle explicitly. No ambient
`tokio::spawn`, `Handle::current`, `Runtime::new`, nested executor or `block_on`
in callbacks/Drop. Standalone composition creates one current-thread executor;
embedded composition creates none. Tokio's [Handle contract](https://docs.rs/tokio/latest/tokio/runtime/struct.Handle.html)
provides explicit spawning on the supplied runtime. I/O/time features belong to
the eventual composition build; they are not enabled to hide implementations in
this declaration candidate.

### 2.2 Common call and result contract

`HostFuture<'a,T>` is an object-safe boxed Send future yielding the shared Result.
`OpenContext` alone permits unknown generation; `CallContext` requires the exact
known generation, relative timeout and cancellation handle. At admission, convert
timeout once to a monotonic deadline; subsequent stages use remaining time and
never reset it. Zero/overflow or policy-exceeding bounds refuse. Cancellation is
cooperative, checked before mutation and at bounded work boundaries. It cannot
undo a commit or prove an uncertain external effect did not happen.

`Cancellation::is_cancelled` and `HostControl::status` are nonblocking snapshots.
`cancelled` parks a future without a polling timer. Read::Absent requires a
successful lookup; Unreadable, Unknown and Present(None) retain their different
meanings. Page bounds include the serialized wrapper, JSON escaping, windows,
markers and error details; never fit an array and then append unbudgeted metadata.
No growing vector, body or diagnostic list escapes policy limits.

`VerifiedCaller` is core admission, `BoundSession` adds current capability,
identity and revision, `SessionLease` is exclusive in-flight launch ownership,
`HarnessBinding` is retained adapter/custody state, and `TakeoverTicket` identifies
one durable keyed replacement intent. None is a token encoded by a client.
`SessionGrant.capability` is returned once through protected transport, never Debug
or telemetry. Exact replay returns receipt facts, not regenerated secret bytes.

## 3. Runtime ownership and task model

### 3.1 One owner per home

One canonical local state home, selected by owner configuration, has
`runtime.lock` and `endpoint.json` beside the SQLite database. RuntimeFilesystem
owns their OS security and native file-lock implementation. Endpoint records are
routing hints, never lease or process proof. A PID existing, a stale socket, a
port responding or an elapsed timeout cannot establish ownership.

| Method | Required behavior |
| --- | --- |
| acquire_host | Exclusive OS lease for the canonical home, retained through writer/task closure; bounded wait for existing direct-client shared leases; never steal |
| acquire_direct | Shared OS lease, only when no exclusive owner; retained until direct connection/transaction closes; cannot outlive it through an unowned writer |
| endpoint | Bounded read/validate of protected record; absent, unreadable and malformed remain distinct; no connect-or-repair side effect |
| publish | Require matching exclusive lease/epoch; atomically install only the owned record/socket after bind/security readback; report actual endpoint |
| unpublish | Compare actual epoch/owned record under the retained lease; remove only our endpoint, preserve a changed/foreign entry |

The lease implements se_store::RuntimeLease and returns its actual store,
generation and host/direct identity. The worker owns an Arc of that lease.
Unlinking a lock pathname never unlocks a held native lock or authorizes a new
writer. Resolve/protect the home without following attacker-replaced path
components; refuse network/synced unsupported storage under section 20.

A CLI reader uses a bounded read-only SQLite snapshot. A mutation with a live
host uses IPC; while no host owns the home it acquires a shared lease and calls
the same DirectStore transaction path. On an acquisition race it re-resolves the
owner, bounded by the original deadline. It never silently falls back to a direct
writer after an IPC error while an exclusive host still exists. A custody command
requires a host: launch automatically starts standalone when appropriate; a
hostless stdio MCP custody request returns CustodyUnavailableHostless. Offline
inspection remains available; no hostless PID kill shortcut is added.

SE Code attach while standalone owns the home reports RuntimeOwnedElsewhere with
the actual owner. Standalone cannot kill SE Code to obtain its lease. Host
migration is explicit stop, witness closure, then start/adopt; live handover from
the original draft is deferred. Duplicate opens on one healthy factory share
only its registered owner; a second independent factory cannot impersonate it.

### 3.2 Resource ownership

| Resource | Owner / lifetime / closure proof |
| --- | --- |
| Tokio runtime | SE Code or standalone composition; engine never stops an embedding runtime |
| Runtime lease, endpoint and admission gate | Generation-independent factory supervisor; release only after real closure |
| HostStore / se-writer | Store start_writer consumes HostStore; WriterOwner/client/CommitWait remain its only write API |
| Native containment and process handles | se-proc arena; retained across generation replacement until explicit stop/adoption |
| Vendor stdin/stdout, WebSocket, transcript watch | Supervisor-retained transport arena; generation tasks borrow routes, Drop does not close them accidentally |
| Session coordinator | One async task per active route, selects committed-mail watch, provider/process events, capture and control |
| Mail pump | Bounded per-recipient ID debt lookup; coalesced high-water notification, no body queue |
| HTTP/local IPC | One listener each per home; bounded connections, per-request authorization |
| Capture watcher | One shared native watch service over live transcript directories; no polling scan |
| Backup | Store factory read connection with shared BackupContext; one bounded work-driven job |

The supervisor is not an immortal second runtime or per-seat process. It is
retained factory state and a small supervised task set on the supplied executor.
An owned task fault is joined and reported; it cannot disappear while status
stays Ready. A bounded shared blocking pool runs store reads/maintenance and native
operations that cannot complete promptly. Maximum two admitted blocking jobs by
default; no per-session blocking worker or readiness sleep in that pool.

The single store writer OS thread and section-30 native collector are counted
exceptions to async task execution, not new host-owned copies. No store
transaction, process lock, session mutex or native queue lock spans await or an
external effect. Snapshot bytes are released before rendering/tool callbacks.
Backpressure refuses/bounds admissions before allocating unbounded work; committed
debt stays in the store and is visible when memory pressure prevents delivery.

### 3.3 Writer, backup and shutdown ordering

Activation validates/opens a compatible schema with exclusive custody, calls
HostStore::start_writer once, obtains WriterOwner::client, and awaits each WriterClient::submit
completion. Only se-store creates commit receipts after COMMIT. Watch high-water
bumps occur after the actual commit; a lost bump is recovered from indexed debt,
not by claiming the write failed. Security events use the accepted fixed FULL
set even if that misses the 20 ms target on a particular disk.

WriterOwner::flush is a barrier over accepted work. Draining consumes the writer
and awaits its drain/join result to regain the unique maintenance HostStore;
join/close runs on the supplied bounded blocking facility where needed. Store
recovery after a writer panic verifies integrity and original request keys before
new writes. A joined panicked worker proves termination, never COMMIT outcome.

An older supported schema returns StoreMigrationRequired before writer start;
auto-start/status never upgrades it. The existing explicit owner doctor.repair
or application-upgrade path, with the old host down, holds the exclusive lease,
uses the accepted MigrationApproval/plan/backup protocol and validates the result
before a normal host activates. No new upgrade command or automatic approval.

Daily/startup rotation begins after readiness, never in a CLI write. The same
opaque BackupContext coordinates the writer and factory backup. Whole-copy stable
snapshot, 64-page steps and the accepted 64 MiB WAL pressure cancellation apply.
Cancel the backup rather than backpressuring ordinary writes; automatic retry is
the next start-of-day, never another attempt in this run. No minute timer or new backup per
hook. Migration/erasure/checkpoint use the drained maintenance owner as required
by section 20; a copy handle cannot bypass the live writer.

Shutdown gates new mutations, fences native generation callbacks, records all
accepted work/debt, joins generation tasks, flushes/drains/joins the writer, then
closes owned listeners/resources and releases the lease. `DrainReport` is checked
against the supervisor's actual state; caller-supplied booleans do not authorize
close/restart. Pending durable effects are counted and named. Drained can retain
a safely owned maintenance handle; Closed requires actual release. Dropping any
public handle is nonblocking and supplies none of these witnesses.

## 4. Generation state machine and recovery

HostEpoch describes native service/process identity; Generation describes an
engine service lifetime. Session/conversation identity survives a generation.
A new engine generation does not mean new model input, new conversation, cleared
hold or duplicate message. `HostStatus` reports exact epoch/G/phase and bounded
blockers plus aggregate obligations, never another generation's health.

| From | Input / condition | Next / effect |
| --- | --- | --- |
| No published handle | configured then prepare, read-compatible store and lease | Prepared returned, no writer/native mutation/callback |
| No published handle | absent/unreadable/foreign/newer store, preparation panic | Explicit Read/error; cleanup retains preparation custody until released |
| Prepared | Caller registers handle/G, fresh generation-bound services and correct epoch, activate | Activating; first permitted worker/native mutation, no automatic schema migration |
| Prepared | Invalid integration/G/epoch/features before start | Prepared plus error, no partial activation |
| Prepared | Explicit drain without activation | Draining then Drained; no invented writer |
| Activating | Ownership/schema/services verified, all routes resolved | Ready |
| Activating | Some route adoption/debt unresolved | Recovering; unaffected routes work |
| Activating | Global resource failure after resource start | Poisoned, named partial facts retained |
| Ready | Route becomes unresolved | Recovering with bounded route-specific facts |
| Recovering | All required route obligations resolved | Ready |
| Activating/Ready/Recovering | Caught edge/task fault | Poisoned; gate G, wake health wait, retain exact resources/debt |
| Ready/Recovering | Explicit drain after native routing fence closes | Draining |
| Draining | Tasks joined, writer flushed/drained, durable unfinished effects accounted | Drained |
| Draining | Deadline/live task/unreadable closure | Remain Draining; RuntimeDrainTimeout, no release |
| Drained | close with matching actual report | Closed after writer/resource closure and lease release |
| Drained/Poisoned | Factory restart with old G + stable key | Independently close/quarantine old resources, prepare G+1 only after safe closure |
| Restart closing | Unjoined writer/task or unreadable custody | Old ownership retained; explicit failure, no successor writer |
| Fresh Prepared | Register handle/fresh services then activate | Ready/Recovering by same rules |
| Closed | Repeated close of the same handle | Original closed result, no new resources |

All unlisted transitions refuse. Old handles remain fenced and never become the
new Ready handle. No private method on a Poisoned Host is necessary for recovery.

### 4.1 Runtime port method contracts

`RuntimeFactory::prepare` performs bounded read-only validation and may hold a
preparation lease. It returns Read<PreparedRuntime>, not automatic initialization.
`PreparedRuntime` carries host, epoch and proposed/known generation; activation
publishes generation facts through the accepted store protocol. No background
worker can begin after a failed/cancelled preparation.

`RuntimeFactory::restart` uses supervisor-owned resource handles, not calls to
old Host::drain/close. Validate exact old G/state/restart key, fence G, reconcile
in-flight keyed outcomes, stop/join old work, and prepare one successor. Exact
retry returns that same successor/result, never G+2. Reuse with changed request
is IdempotencyKeyReused. A live unjoinable worker cannot be portably abandoned:
return a named RuntimeDrainTimeout/TaskFailed with controlled process-restart
remedy while ordinary SE Code can remain usable. Never release its lease.

| HostControl method | Behavior |
| --- | --- |
| status | Nonblocking exact-handle snapshot; counts are actual cached committed state, unknown detail is a blocker |
| wait_status(after,cx) | Notification-driven phase change; immediately return if current differs, otherwise wait; timeout/cancel is error, not a manufactured transition |
| activate | Validate registration/integration/epoch/G; idempotent same source; may not replace services of an already active generation |
| poison | Record known stage/incident, gate G and retain obligations; no rollback fiction or private panic payload |
| native_state_changed | Validate target/G, schedule bounded binding/notice reconciliation; no body, admission ACK or hold release |
| adoptions | Owner-authorized bounded per-route recovery outcomes, preserving unreadable/unknown |
| drain | Close admission, join/flush using original deadline, return truthful report only when complete |
| close | Check actual Drained state/report; explicit join/release, idempotent; never create another generation |

`Integration::Secode` requires the exact native HostEpoch and a fresh NativeQueue
adapter bound to G. Its wrapper checks both supplied G and native current fence
inside each serialized native transition. Old queued calls fail before mutation;
an already-entered native transaction completes atomically and is recovered by
key. Integration::Standalone uses provider transports and no SE Code queue.

Panic containment requires unwind at the embedding boundary, including future
construction and every poll. Task panics reach the supervisor and health change.
Abort/OOM/OS kill require process-restart adoption; no API can catch them. A
captured incident ID is nonsecret. SE Code explicitly closes engine services
before shutting down its supplied runtime; Drop never blocks to compensate.

## 5. Local IPC, authority and wire formats

### 5.1 Protected endpoint and peer proof

Linux uses a Unix-domain stream socket in an owner-only runtime directory, socket
0600 and directory 0700. macOS uses the same protected namespace and native peer
credential API. Windows uses a local named byte-mode pipe with an explicit
current-user SID DACL, remote clients rejected and the server identity verified.
No world-readable temp socket, abstract globally named unauthenticated endpoint,
TCP hook bridge, inherited permissive ACL or fallback port is permitted.

EndpointRecord is `schema=1`, address, native HostEpoch, exact ApiVersion,
package_version and executable image SHA-256. NativePath uses section 10's
lossless OS encoding, not lossy UTF-8 conversion. The protected JSON record has
those exact snake_case fields; `address` is `{kind:"unix_socket",path:NativePath}`
or `{kind:"windows_pipe",name:string}`. Store no bearer or machine secret there.
HostEpoch supplies the full shared process instance; no extra PID-only identity.
The file is bounded to 16 KiB and atomically replaced with owner security checked
before publication. Reject duplicate/unknown fields and unsupported schema/API.

IpcPlatform::peer obtains proof from the already-open channel, never a request's
uid/SID/PID. IpcPlatform::verify_server additionally checks the endpoint's actual
native process identity against that channel. Linux uses SO_PEERCRED plus pinned
process-start identity; macOS uses peer UID/GID and available kernel PID/audit
identity, refusing any stronger assertion it cannot establish. Windows queries
pipe server/client PID, token SID and process start/image through native handles.
The safe port returns opaque PeerProof; native unsafe code belongs to the process
platform owner, not a new unsafe host implementation. Lack of a required native
identity primitive is an explicit admission failure, not same-user trust.

Same OS user is necessary, insufficient owner authority: agents run as that user
too. Core combines native proof with machine-credential owner proof or a verified
session/launch capability. Human-only commands additionally require an interactive
terminal outside owned agent ancestry. An unreadable ancestry check refuses that
power; it does not quietly select owner. Invalid/revoked/expired session authority
never becomes owner, even on a previously owner-authenticated connection.

### 5.2 Framing and handshake v1

Local IPC is a stream of **four-byte unsigned big-endian payload length followed
by exactly that many UTF-8 JSON bytes**. Length excludes prefix. No newline,
compression, executable object serialization or arbitrary Rust type name.
Reject length zero, more than 1,048,576 request bytes, malformed UTF-8/JSON,
duplicate fields, nesting beyond 64, unknown frame kind and truncated EOF before
dispatch. Readers never allocate directly from an unchecked length. Each
connection has at most one outstanding operation; clients needing parallelism
open bounded separate channels. Response writes are serialized complete frames.

Sequence:

1. Server obtains peer proof and client verifies the server before secrets flow.
2. Server sends `challenge`: exact API version, epoch, random 32-byte one-use
   nonce and image digest (`ServerChallenge`). Nonces/digests encode lowercase
   fixed-length hex. Challenge reveals no private history.
3. Client sends `hello`: `version`, optional `expected_generation`,
   `maximum_reply_bytes`, and protected `authority`. Owner authority contains a
   fresh client nonce and HMAC-SHA256 proof. The MAC covers a domain-separated,
   length-prefixed canonical encoding of `se.ipc.owner/v1`, API, server epoch and
   image digest, server nonce, client nonce and verified peer identity. The server
   challenge is channel-bound and consumed once. The machine secret never crosses
   IPC. Session/launch variants send their protected capability only after server
   verification; frame logging is forbidden.
4. Server validates version equality, home/user, proof and current credential
   scope/revision; sends `ready`: version, epoch, generation, effective
   maximum_reply_bytes (`ServerHello`). The effective cap is the smaller policy
   and request, never below space for a complete typed error. Wrong expected G
   returns SessionGenerationMismatch, not automatic rebind.
5. Calls carry `kind:"call"`, `version`, positive connection-local `request_id`,
   `generation`, optional protected `authority`, and `request`. Allowed request
   tags are `operation`, `hook`, `nudge`; they map exactly to IpcRequest.
6. A reply echoes `request_id`, API/G and either `result` or `error`, never both.
   Result is OperationOutput or hook/nudge result; error is shared ErrorEnvelope.
   No success envelope is emitted before COMMIT/outside facts it claims.

Operation request fields are `name`, `arguments` and optional `key`; only the
closed operation registry can decode them to AdmittedOperation. Hook request
carries exactly the ClaudeHookInput mapping below, not arbitrary event dispatch.
Nudge carries only committed `through` sequence; it cannot supply an actor,
message body, delivery result or write batch. All frames reject unknown fields;
absence of optional authority retains only that connection's admitted principal,
not ambient owner. A supplied authority is verified anew with no fallback. Both
binding revocation and generation are rechecked on every operation. Authority can
be narrowed per call; multiplexed session switching requires an explicit valid
per-call credential and cannot inherit another principal's last request.

The default local result cap is 262,144 bytes; hard cap 1,048,576. MCP adapts to
32,768 bytes by default, including its JSON-RPC/content/structured wrapper.
Request IDs deduplicate transport responses only within this connection; durable
mutations require the operation's stable idempotency key. After a broken reply,
repeat the same key or read its receipt. An unknown outcome is never a fresh key.

### 5.3 IPC ports and error direction

| Port | Contract |
| --- | --- |
| LocalAdmission::connect | Validate native PeerProof + hello under current G; issue AuthorizedConnection and negotiated ready frame |
| LocalAdmission::caller | Reverify supplied or connection authority, revocation, current scope and G for this call |
| LocalAdmission::session | Require an actual bound session, no claimed IDs/owner substitution |
| OperationDispatcher::decode | Registry validation, unknown-field refusal, auth/effect/runtime policy; only producer of AdmittedOperation |
| OperationDispatcher::dispatch | Invoke the single core executor; no second CLI or MCP semantic implementation |

Handshake/idle-write budgets are five seconds; ordinary calls have a 30-second
maximum unless the registered operation has an explicit longer custody deadline.
An external provider launch may return pending readiness rather than occupy an
unbounded transport call. A cancellation closes only that request's wait and
retains accepted work/debt under supervisor custody. A mid-frame disconnect
causes no dispatch; a post-COMMIT disconnect leaves a recoverable committed key.
Oversized responses fail before a read marker is committed; no invalid JSON cuts.

## 6. Sessions, launch and takeover

SessionIdentity is durable project/agent/session. ProviderSessionId identifies
one real vendor conversation. LifecycleId identifies se-proc custody.
Native MailTarget adds SE Code native session/epoch and binding fingerprint.
These identifiers are different dimensions, never interchangeable strings.
`SessionView` retains Read facts for unavailable activity/conversation/lifecycle/
target; Ended is not inferred from an unreadable process query.

| From | Trigger and required witness | Next |
| --- | --- | --- |
| None | Authorized keyed binding/launch reservation, expected absent/CAS revision | Prepared |
| Prepared | Process reservation and launch or native binding start | Starting |
| Prepared | Owner revokes/cancels before start | Revoked or Ended, actual intent recorded |
| Starting | Real provider/native binding, consent, readiness and FULL activation verified | Active |
| Starting | Readiness still unproven/deadline | RecoveryPending; child remains owned, launch reports pending |
| Starting | Verified failed/closed launch and durable end | Ended; no readiness claim |
| Active | Durable human/takeover/revocation hold | Holding |
| Holding | Exact point observation proves no execution while same hold applies | Held |
| Held | Genuine human input promotes under still-valid native binding | Active; engine cannot synthesize this trigger |
| Active/Holding/Held | Explicit stop/end | Ending; hold first when queue/execution exists |
| Ending | Outside process closure + flush/end commit, or actual native end | Ended |
| Any nonterminal | Explicit capability/target revocation commit | Revoked; process effect tracked separately until witnessed |
| Any live state | Restart/crash/unknown target/custody | RecoveryPending; prior hold/revocation persisted separately |
| RecoveryPending | Exact binding + strong custody/native observations | Actual Active/Held/Revoked/Ended, never unconditional Active |

All unlisted transitions refuse. Revoked/Ended cannot be revived by a reconnect;
a legitimate new binding gets a fresh session/capability. Activity is orthogonal:
Idle -> Executing on real turn start; Executing -> Interrupting after accepted
interrupt request; either -> Idle only on authoritative completion/absence.
Unknown/unreadable activity cannot transition to Idle by timeout. Native
BindingEligibility is Eligible, Held(reason), Revoked; revocation dominates.
Human resume can clear a hold only while the native target remains valid.

### 6.1 Launch ordering and permission mirrors

For owner or creator-authorized target, core resolves agent/profile/conversation
and obtains a revision-bound SessionLease before creating native work. Current
create grant plus immutable same-project `created_by` is required for a session
to control its direct child. No grandchild/all-agent authority or private inbox
inspection follows from creation. Self rules remain OPS rules on both CLI/MCP.

Provider probe/config validation occurs before incumbent interruption or
credential rotation. The safe saved profile determines se_proc::LaunchPolicy;
bypass requires an explicitly named persisted opt-in. CLI and MCP, attended and
headless, use the same policy. No environment variable, provider flag default or
retry silently weakens it. No global provider credential/config mutation.

The process path uses section 30's reservation, persistent lifecycle/scope
checkpoint, suspended/pre-exec custody barrier and authorized execution ordering.
No user/vendor code executes before containment and durable launch ownership.
An attended terminal bootstrap uses its one-use protected registration channel,
never a bearer in argv. Headless uses the same process owner without a window.
The terminal/window opening is not agent readiness. Keep partial failures owned;
never drop a child handle to turn failure into apparent absence.

Establish the exact provider-native conversation selection and owned process/
native target before enabling the binding/capability under FULL. For Claude new
launch, select the provider-supported explicit session UUID in the owned argv;
resume uses the verified saved ID. The launch coordinator establishes that
binding under its trusted reservation before authorizing provider execution.
The session-start hook checks the actual echoed conversation/process against
it and performs only a read; mismatch returns no private context and triggers
coordinator-side revocation. Codex can obtain the real thread ID before starting
a turn. Neither preparation is a launch-readiness claim: LaunchOutcome still
requires the actual provider echo/binding and acceptance of work. No session-start
read implicitly calls begin or activates a credential. A lost capability reply
cannot replay secret bytes: trusted rebind uses fresh key and expected revision,
revokes prior capability, and preserves the conversation. Credential first-use
activation is one keyed transaction with scope/revision checks. Prepared launch
credentials expire at ten minutes; expiration is checked at use, not by a timer.

Default launch resumes a saved provider conversation; `--new` alone requests a
new one. Missing/unverifiable reference refuses with an explicit new-conversation
alternative. Provider changes cannot pretend to resume another provider's thread.
Readiness means the bound agent actually accepts work, not merely PID/port exists.

### 6.2 Takeover algorithm

Takeover crosses store/native/process boundaries using durable keyed intents;
no transaction spans callbacks. SessionControl::prepare_takeover validates caller,
profile, expected binding Revision, generation and exact conversation choice,
commits a replacement intent/reservation and returns one opaque ticket.
SessionControl::finish_takeover performs the following recoverable steps:

1. Re-read the ticket/reservation/current binding and native target. On conflict,
   stop before changing the incumbent; never update by unchecked overwrite.
2. NativeQueue::hold commits the predecessor's session-wide/per-input hold even
   if zero mail is pending. Validate target, original key, event and sequence.
3. NativeQueue::interrupt verifies that exact durable hold before signalling.
   InterruptReport.requested proves request admission only, not idle or exit.
4. NativeQueue::active must return **Read::Present(None)** for that exact target,
   epoch and G. Absent, Unreadable, Unknown, empty diagnostic pages and elapsed
   deadlines do not prove no execution.
5. Where an owned provider/client lifecycle must stop, se-proc proves exact
   instance and required descendant absence under the original containment scope.
6. Recheck reservation/G/revision, then NativeQueue::select atomically checks all
   superseded targets still held and not executing, revokes them and selects the
   successor. Read back the exact selected binding. A human resume between the
   point read and select makes select refuse rather than overlap execution.
7. Only after these witnesses commit/enable the successor binding under FULL and
   return TakeoverReport with actual activation event/predecessor/hold facts.

The opaque ticket is recoverable by original key; dropping it does not cancel
native effects. `SessionControl::fail_takeover` records the intent's failure and
preserves actual custody/debt/hold; it **cannot release a hold**, select a target,
re-enable a predecessor or claim successful takeover. If the human has already
changed native state, report that state without re-holding as cleanup. Failed
replacement after an intact hold is shown as awaiting human input. There is no
abort/release-hold escape, automatic reconnect resume or synthetic human action.

Standalone provider takeover uses the same intent/generation/CAS and se-proc
outside-stop rules. Its hold is a durable host admission gate, and native provider
interrupt/completion is still verified. It cannot claim the SE Code-specific
HostServices atomic select witness; successful outside closure supplies the
standalone predecessor exclusion witness instead.

## 7. Mail, native queue and capture

### 7.1 Independent facts

Message commit, offered notice, native queue admission, delivered model input,
recipient read, dismissal, reply and task completion are separate facts. No host
restart, owner inspection, full list, EOF, successful callback or empty unread
page can manufacture another fact. `message.list`/inbox including full bodies is
read-only in this Rust contract. Only recipient-bound message.read/ack/dismiss
changes its disposition; owner inspection cannot impersonate the recipient.

| Debt state | Input / witness | Next / durable action |
| --- | --- | --- |
| Unoffered | Message COMMIT | Recipient watch bump; bounded indexed debt exists even if no session |
| Unoffered | Reserve distinct (session,message) set for stable NoticeId | Pending intent with target, digest, cursor before callback |
| Pending | Provider transport writes complete notice frame | Offered, still unread; uncertain acceptance remains visible |
| Pending | SE Code Admitted/Replayed exact native result | Record original native admission once; still unread, promotion not presumed |
| Pending/Offered | Held or Refused | Keep original intent/debt and cause; no offer cursor/read advance from refusal |
| Pending/Offered | Lost reply, panic, timeout | Uncertain, query exact-key status before retry |
| Uncertain | Verified original admission/input witness | Record original result, no duplicate queue input |
| Uncertain | Exact successful Absent and eligible target | Retry original ID/digest, never invent replacement ID |
| Uncertain | Unreadable/Unknown | Remain uncertain; surface cause, no absence inference |
| Offered/admitted | Actual provider/native promotion input evidence | Delivered; retain witness correlation, still not recipient read |
| Any unresolved | Genuine human eligibility/control-plane event | Recheck actual binding/status and retry original eligible debt |
| Any | Recipient complete read/explicit ack | Idempotent recipient read marker; no completion claim |
| Any | Recipient dismiss | Dismissal marker; no read claim |
| Any | Permanent revocation | Preserve debt/history; new legitimate target has a new explicit intent |

A body too large for a complete message.read response is explicitly incomplete
and cannot mark that truncated content as read. Fit the entire final envelope
before committing its read marker. An explicit ACK is the recipient's deliberate
acknowledgment even if it did not fetch a body. SessionControl::acknowledge requires
BoundSession, exact recipient, key and current G; it shares the core operation.
Body text never enters wake notices; the recipient retrieves it through its own
authenticated tools. No polling delivery process or stale inbox window can hide
older unresolved debt: lookup uses the recipient's indexed debt with bounded
continuation rather than a newest-N floor scan.

### 7.2 NativeQueue mapping, exact witness validation

NativeQueue is a proprietary adapter of accepted section-10 HostServices, not an
alternative provider-input queue. HarnessKind::Secode selects this binding path;
the external Harness trait is for Claude/Codex, not an extra SE Code subprocess.

| NativeQueue method | Section-10 owner method / exact result |
| --- | --- |
| hold | hold: target/hold reason/key, durable session-wide and per-input hold even with zero pending input |
| interrupt | interrupt: same held witness still active before signal, requested only |
| active | active_session: authoritative point result for this exact target; only Present(None) proves no active execution |
| binding | binding_state: actual eligibility/activity and monotonic native revision |
| select | update_mail_target Select: atomic target CAS, every superseded route held/nonexecuting, preserve human holds |
| revoke | update_mail_target Revoke: permanent revocation without clearing held pending input |
| adopt | adopt_binding: verify persisted prior fingerprint/identity/epoch mapping, CAS into current epoch; retain original admissions/holds/revocation |
| offer | deliver_notice: IDs only into the existing durable pending-input queue |
| notice | notice_status: keyed lookup after uncertainty, never a new input/settlement |

MailTarget is epoch/native session/durable identity/fingerprint. MailNotice holds
stable NoticeId, that target, ordered distinct MessageIds, through Cursor and
SHA-256 digest. Use section 10's versioned canonical digest over store/project/
agent, durable SessionId, native HostSessionId, ordered IDs and durable cursor;
transient service/process generations are excluded. Epoch is checked separately.
A changed payload under one NoticeId is IdempotencyKeyReused. Bound default batch:
at most 32 IDs and 8 KiB encoded notice, lower if consumer budget requires it.

NativeAdmission contains actual committed epoch, original notice/target/pending
ID/digest/event and admitted/committed Sequence values. Check equality of all
identity/digest/key fields against the reserved intent, accepted event ordering
and original admission sequence. Never mint a native ID or synthesize a receipt
from an HTTP status. On adoption preserve original committed epoch/event/sequence;
a verified native adoption map links it to the current target. Held carries a
real HoldWitness; Refused carries ErrorBody; neither acknowledges admission.

A callback ACK proves native queue commit, not promotion. Section 10 exposes no
new promotion settlement API, so StateEngine leaves `delivered` unwitnessed unless
an actual captured native/provider input correlation supplies that fact or the
recipient itself reads/acks. It must not fabricate a promotion event to fill a
status column. SE Code continues to promote its own queued steer at safe boundaries
and ordinary input only at idle. Native eligibility nudges contain no bodies and
merely schedule exact binding/notice readback.

Every callback checks immutable wrapper G and native current fence inside its
serialized atomic transition. No await escapes a half-applied native hold/target/
queue commit. The host never holds a store transaction while waiting. Reconnect,
fresh mail and engine restart do not clear a human hold. A Held/Refused/Unknown
route blocks only its own delivery; other admitted sessions continue.

### 7.3 Scheduling and capture records

At activation, committed pending-effect and per-recipient debt indexes drive
bounded reconciliation. Live commits signal coalesced high-water watches. One
session coordinator fairly drains at most one bounded batch per scheduling turn;
a busy recipient cannot monopolize the writer. Limits constrain resident notice
IDs, not durable mailbox size. If a queue is full, retain debt and report pending;
never discard the oldest unread message. Retries are triggered by actual work,
native eligibility change, authenticated repair or a recorded bounded retryable
failure, not an idle timer. There is no floor-wide poll or per-seat HTTP daemon.

CaptureInput validates provider conversation, stable vendor_turn ID, role,
consent, canonical Body and source_digest before commit. The dedupe key includes
provider conversation, vendor event/item, role and content digest; changed bytes
under a reused identity are an error, never silently replaced. Turn text has
section-20 storage limits and can use staged streaming outside transactions.
CaptureRole User/Assistant/Tool does not authorize impersonating a human.

TranscriptSource identifies a real file when one exists, next committed byte
offset, conversation and file incarnation digest. Read incrementally in bounded
chunks. Commit captured turns and cursor advancement atomically; a decode/write
failure leaves the old cursor. Incomplete final JSON line waits for a real
change/close signal; malformed complete lines are explicit unreadable facts.
Rotation/truncation preserves old captured events and records the mismatch before
new incarnation handling. No zero-offset reset, full transcript reread each hook
or catch-and-return-empty. Provider completion/hook is the primary signal; one
shared native watch catches missed events with an event-armed debounce, never a
periodic scan. Consent missing suppresses capture visibly and grants no history.

## 8. Harness ports and owned configuration

| Harness method | Required semantics |
| --- | --- |
| kind | Closed provider kind; composition selects Claude or Codex implementation, no dynamic loader |
| probe | Resolve the configured actual executable, execute bounded version/protocol probe, return ProviderVersion; reject old/unrecognized/missing required capability before takeover |
| configuration | Produce ConfigPlan for this exact launch/profile without applying it; no global provider authentication changes |
| launch | Consume session reservation into retained process/transport custody; return LaunchOutcome only with BindingWitness from actual conversation/readiness |
| adopt | Verify supplied prior binding against live process/native transport and provider conversation; Read::Absent/Unreadable/Unknown remain distinct |
| bell | Attempt one stable IDs-only notice; return BellOutcome with actual stage or Held/Refused, not a fabricated SE Code queue admission |
| transcript | Return actual TranscriptSource or honest absence/unreadable state; no guessed vendor path |
| capture | Bound identity/consent/source/dedupe through core/store, committed receipt only after writer completion |
| graceful_stop | Provider graceful request followed by se-proc outside witness; Exited/Bounded preserve exact StopWitness, StillOwned names why closure is incomplete |

ProviderVersion carries kind, actual executable NativePath, version text and
selected protocol version. ProbeRequest.command is a native literal PathBuf,
not shell source. A probe has a five-second cap and 16 KiB bounded diagnostic
output; stdout/stderr are never parsed through a pipeline that loses exit status.
Cache only by executable identity/version plus host generation; changed bytes
invalidate it. Required features are checked in addition to semver. The initial
qualification floor is Claude mods-capable 2.1.287 and Codex HTTP-tools-capable
0.163.0, based on the existing journey work; no claim every build above that
number implements an optional private attended transport. Unknown version is a
refusal with path and remedy, not optimistic compatibility.

HarnessStop::Exited maps only a se-proc Complete observation with its stated
achieved containment guarantee. Bounded is incomplete at the requested guarantee,
even if the root exited; it cannot satisfy all-descendant absence or successful
Remove. Retain its scope/unknown descendants and legal retry in the user result.

HarnessLaunch contains exact session lease/identity, executable/cwd, saved profile,
se-proc policy/mode, explicit resume Read, initial bounded Body, protected launch
credential and stable key. Unknown/Unreadable resume is an error; it does not
mean new conversation. OwnedLaunchFile contains protected Secret bytes; neither
it nor HarnessLaunch is Debug/serialized to a public receipt. IntegrationEdit
contains path, owned key, expected prior digest Read and replacement bytes;
ConfigPlan has owned edits and ephemeral launch files, not a generic file writer.

Apply a plan with no-follow path checks, compare expected entry/file digest,
write atomically and read back. Record ownership only for the exact installed
key/marker bytes. Preserve unrelated keys, comments where format permits, user
files, Git history, global provider login and existing CODEX_HOME. Unreadable
prior bytes are not absent. Conflicting edits return IntegrationConflict without
overwrite. Managed launch uses per-launch settings; persistent edits are reserved
for explicit unmanaged adoption/repair and are reversible by their recorded owner.

Removal first stops/revokes the actual route, then removes only matching owned
entries/files and reads the result back. Changed user bytes are retained with a
conflict, not overwritten by an old full-file backup. Never recursively remove a
provider home or a directory that gained foreign entries. A secret file's unlink
is not credential revocation; revoke first. Remove preserves work/history and is
separate from explicit store.forget erasure.

OfferWitness contains notice, durable identity, actual conversation, digest,
OfferStage and Read of correlated vendor event. TransportWritten is just a full
frame/request accepted by the transport. InputAccepted additionally requires the
provider's matching input/turn response or captured input event. Neither is
recipient read. Missing vendor correlation stays Unknown, never a fake event ID.
BellOutcome::Held has an actual hold reason; Refused has the shared precise cause.

### 8.1 Claude launch and command-hook protocol

Managed launch composes literal arguments from the validated profile and actual
CLI feature probe. Use per-launch `--settings`, `--mcp-config` and `--plugin-dir`
files/paths as supported, without adding StateEngine secrets to argv. Their
contents refer to the installed `se` binary and protected credential handoff;
no worktree path, fleet identity, bundled Node or machine-specific drive appears.
Headless uses the provider's stream-json input/output mode and persistent stdin;
attended uses the user's terminal and plugin. Both retain default permission and
sandbox behavior. Never append dangerous skip-permission flags on retry. A
saved bypass profile maps only its explicitly requested semantics.

The four closed native hook mappings are SessionStart -> `session-start`,
UserPromptSubmit -> `prompt`, Stop -> `stop`, StopFailure -> `stop-failure`, all
through `se hook claude EVENT`. Native stdin JSON is bounded to 1 MiB and mapped
to ClaudeHookInput: expected event kind, `session_id` conversation, real
`transcript_path` NativePath and bounded vendor payload. The integration resolves
its protected binding/capability outside the model payload and verifies matching
conversation, process lifecycle, project, agent, consent and G. Payload identity
strings alone never bind. No arbitrary event or shell command is accepted.

ClaudeHookAdapter::hook returns HookOutput: protocol stdout, actual capture event
Read and optional explicit failure. SessionStart is read-only: return bounded
context JSON `hookSpecificOutput` with the matching native `hookEventName` and
`additionalContext`. Prompt captures newly available user input under its real
vendor identity and may return bounded additional context. Stop/StopFailure
incrementally capture completed transcript records and return **empty stdout**;
no decision/block/continue field, recursive prompt or synthetic turn is emitted.
Native hook field/event semantics are taken from the installed version and the
[Claude hook reference](https://code.claude.com/docs/en/hooks).

The binary preserves provider availability by exiting zero for hook-adapter
failure with a bounded nonsecret stderr diagnostic. This is explicitly not a
capture success receipt. Keep cursor/debt unchanged on failure and expose the
actual failed/suppressed capture through status. If persistence is itself broken,
report that diagnostic rather than claiming a durable failure record exists.
An invalid pre-decode payload uses the shared input error; HookPayloadInvalid
is used only when an actual trusted event reference is available for its typed
detail. No invented event ID satisfies an error constructor.

Hosted hooks use short IPC calls to the existing writer; session-start uses a
bounded read. When no host owns the home, a transient hook may take a shared
lease and use the same direct transaction implementation, within its deadline.
It cannot race an exclusive writer or silently substitute unauthenticated private
context. Host-not-ready/fence errors carry retry/readback facts; provider stdout
stays valid. Full store sync and cold process startup are measured separately;
no claim that the slower direct fallback already meets 20 ms.

### 8.2 Claude mod JS and headless input

The shipped plugin is a small provider-native JS adapter, not a Node process or
operation executor. Manifest plus `hooks/hooks.json` module registration loads
its `register(on,options)` entry. It holds only its session-scoped renewable
credential, one cancellation-aware wait and the last committed change cursor.
It does not read another agent's mailbox, execute commands, manage grants or
persist message bodies. API types come from the installed Claude build.

Attended idle flow: authenticate to the local listener, arm one internal
change wait after the known cursor, receive bounded NoticeId/message-ID metadata,
and submit attributed mod text telling the agent to read its inbox. A successful
submit records only the stage the real API proves. Never set `asUser:true` to
impersonate a human or clear holds. No body/credential in the prompt. Submission
runs after a blocking hook returns, avoiding a hook waiting on its own prompt.
While execution is active, retain notice debt until a safe supported steer/idle
boundary rather than starting a concurrent turn. Session end, human stop or
revocation cancels the wait and preserves held debt.

The [current mods reference](https://code.claude.com/docs/en/plugins/mods/reference)
limits an entire HTTP fetch to 30 seconds and warns that installed types are
canonical. Therefore this design uses at most **25 seconds** per change wait;
the old draft's 25-minute request is not implementable on that API. This creates
up to 2.4 timeout renewals/minute per attended Claude session. They are vendor
request renewal, not database polling, but they still count in measured CPU and
wakeups. No idle-cost acceptance is claimed until the real client meets <0.1%
CPU including renewal. A longer future supported wait may replace it only after
version probing and journey qualification; no undocumented timeout assumption.

The wait response contains no message body and is never a read marker. Zero debt
at timeout returns an explicit unchanged result, not source absence. One wait per
session is enforced; reconnect reuses the stable intent/status readback. The
server never redirects, and the mod verifies the final private origin before
accepting a response. The registered local route cannot be a generic fetch proxy.
Do not place a bearer in a URL or follow a server-selected remote endpoint.

Headless Claude receives complete stream-json input frames on the supervisor-
owned persistent stdin. Stdin write success is TransportWritten; a correlated
native input echo/capture is InputAccepted. The coordinator serializes input and
respects human/takeover holds. EOF may cause provider exit; generation-only
restart keeps the transport arena alive. After actual process loss, resume the
verified original conversation only after required old-scope absence. Never spawn
one query/helper per message or claim cold restart preserves a still-live pipe.

### 8.3 Codex app-server protocol

CodexInvocation holds actual executable, literal OsString argv, selected transport
and optional private endpoint. Required headless path is stock
`codex app-server --listen stdio://`, bidirectional newline-delimited JSON.
Optional attended/reconnect path uses a private `unix://PATH` endpoint and the
real WebSocket upgrade, never raw JSONL written to a Unix socket. The
[official app-server contract](https://learn.chatgpt.com/docs/app-server) documents
that distinction and labels WebSocket transport experimental. Alpha qualification
must exercise the installed stock build; Linux prototype success supplies no
Windows/macOS transport guarantee. No unsecured TCP fallback is substituted.

Protocol sequence and host obligations:

| Step | Request/notification | Required host action |
| --- | --- | --- |
| Connect | initialize request, then initialized notification | Once per connection; identify client/capabilities, validate negotiated protocol and provider version |
| New conversation | thread/start | Explicit safe cwd/model/approval/sandbox/MCP config; persist actual returned thread.id before claiming a resume reference |
| Existing conversation | thread/resume with exact saved threadId | Check actual returned thread identity and existing status; never substitute thread/start after a failure |
| Real work/idle mail | turn/start with threadId and text input items | Serialize against actual activity; preserve NoticeId correlation and returned turn ID |
| Mid-turn mail | turn/steer with threadId, expectedTurnId and attributed text input | Require exact active turn; stale response re-reads actual status before deciding retry, no new notice key |
| Capture | item/started, item/completed, turn/completed | Join real item/turn/thread identity; capture bounded user/assistant/tool records and final status, not just deltas as independent turns |
| Interrupt | turn/interrupt for exact threadId/turnId | Hold first; response is request ACK only; wait for authoritative completion/status and outside process closure where required |
| Reconnect | initialize/initialized, exact thread/resume or read | Verify actual saved thread/status; reconcile original pending input before retry |

Wire frames have `id`, `method`, `params` requests and correlated result/error
responses; the vendor omits the JSON-RPC version header. Notifications omit id.
These protocol names are provider API calls, not new StateEngine public operations.
Use generated schemas for the qualified provider version; bound JSON size/depth,
redact errors and never accept an unknown response as readiness. A code-mode
provider may not expose tools under older versions; probe before launch so the
user receives ProviderCliTooOld/ProviderProtocolUnsupported rather than an agent
silently working without its coordination tools.

StateEngine-managed MCP configuration is supplied per launch/thread where the
qualified version supports it. The header helper is installed `se mcp token` with
protected authority, never a bearer argument or per-seat replacement CODEX_HOME.
The user's existing provider login/home remains authoritative. Missing transport
or per-launch config capability is a visible protocol refusal, never a forked
Codex binary, hooks.json injection or a second state root to hide missing auth.

Vendor requests for approval/permissions are routed to the actual interactive
owner or the saved safe profile's supported provider policy. Headless cannot
invent approvals; it reports waiting/refusal/pending when no legal decision path
exists. Turn completion is not process exit or task success; inspect actual final
status and the requested external effect. App-server/server/client process
custody stays in se-proc; stderr has a bounded redacted tail, not unlimited logs.

### 8.4 Direct SE Code binding

Embedded SE Code calls the section-10 typed HostFactory/Host API directly. It
registers Prepared host/G before activate and supplies its exact native epoch
and generation-fenced HostServices adapter. Native model tool calls always use
BoundSession. OwnerAuthority is trusted native control-plane intent, never a
model argument or a serialized owner flag. There is no generated local MCP
config, mail HTTP hop, StateEngine child or per-agent CLI helper in this path.

Open project is an authorized existing lookup. Bind verifies native target,
conversation, consent, expected binding revision and exact identity. Capture
uses the canonical native vendor event/capture API, not transcript scraping if
there is no file. Tools/continuity use the same core operation registry and body
windows as standalone. Native queue/callbacks follow section 7. Opaque API errors
preserve the engine cause/remedy without linking proprietary types into SE Code's
permissive crate. The public stub immediately returns NotIncluded with a plain
manual remedy; normal SE Code remains usable.

## 9. MCP and listener security

One runtime-owned HTTP listener binds literal **127.0.0.1** only; the accepted
catalog currently refuses other addresses, including a guessed IPv6 alternate.
Port comes from protected product configuration, never fleet defaults. Validate
all listening sockets before publication. A port in use is ListenerPortInUse;
there is no silent port change that leaves installed clients pointing elsewhere.
No floor-push, mail-door, warm-backend or separate listener process is retained.

Admission order is fixed so browser-origin or Host attacks never reach private
lookups: parse bounded head -> origin-form target -> exact Host allowlist ->
Origin -> method/content/Accept -> credential -> typed operation authorization.
Allow Host `127.0.0.1:P` or `localhost:P` for this actual port only; reject duplicate
Host, userinfo, absolute-form targets, alternate IP spellings, trailing-dot/DNS
aliases and forwarded-header authority. Origin is absent or this exact local
origin after normal URL parsing, never wildcard/reflected CORS or suffix matching.
An allowed local Host alone grants no credential authority.

| Route | Method / auth / payload / effect |
| --- | --- |
| `/mcp` | POST plus negotiated Streamable HTTP methods; per-call session bearer in protected headers, closed JSON-RPC/tools registry; no actor/project override in tool input |
| `/stateengine/livez` | GET; non-private availability/version only, no projects, conversations, mail counts or readiness-as-task-success |
| `/stateengine/local-http-proof` | POST bounded nonce challenge; machine-credential HMAC proof of exact image/epoch/G/channel origin, no secret returned; replay-bound/rate-limited |
| `/stateengine/mcp-token` | POST authenticated helper only, no-store protected bearer result; never a model tool or anonymous token mint |
| `/stateengine/mail/next_change` | POST bound Claude integration only; one ≤25 s change wait, bounded cursor/IDs, no body/read marker, not a public mail operation |

The public livez/proof exceptions contain no private data. Credential-required
routes reject missing/invalid/revoked credentials before dispatch; no anonymous
fallback to a previously used session. Prepared launch credential first-use
activation and renewable session credentials follow core's credential record,
scope, revision, expiry, FULL activation/revocation and constant-time verifier
rules. Preserve supported sec1/selp-/sels- credential compatibility only through
that verifier; they are not public IDs. Never place secrets in URL/query, process
argv, stdout intended for humans, error cause text, support bundles or logs.

Protected credential handoff is managed-launch state, not a new global config:
use the platform's explicitly inherited restricted handle/channel or an owned
short-lived secret file allowed by the saved sandbox profile. Only its nonsecret
handle/path reference reaches the provider/helper configuration. Verify binding
and process lineage when exchanging launch authority; a claimed PID or copied
session label cannot redeem it. Restrict handle inheritance to the intended
launch path. A required credential handoff incompatible with that profile is a
visible refusal, never permission relaxation. Secret-file bytes are owner-only,
excluded from diagnostics, revoked before cleanup, and retained only as long as
the declared helper needs them. No machine credential is handed to a model or
provider process to make owner requests on its behalf.

The HTTP proof response is server authentication only. Domain-separate its HMAC
as `se.http.server/v1` from IPC/client owner proof and any `se.http.owner/v1`
request proof. Bind challenge, exact origin/route, image, epoch and G with bounded
one-use nonces. It cannot be replayed as an owner request or used as an HMAC oracle
for credential issuance. HTTP token exchange accepts an already proved protected
launch/session helper, never anonymous server-proof bytes as caller authority.

LocalListener::admit_head returns opaque HttpChannel only after syntactic/origin
admission; it does not authorize a tool. authenticate verifies PresentedAuthority
and returns the per-call VerifiedCaller. status is a nonprivate local snapshot
used by trusted composition; the HTTP adapter redacts it for public livez.
stop gates new connections and joins actual listener work under the deadline.

Defaults: at most 64 total IPC/HTTP connections, 16 KiB HTTP headers, 1 MiB body,
64 JSON nesting, ten-second headers, 30-second ordinary request and one outstanding
mail wait per session. The header/body deadline remains absolute under slow
streaming. Enforce actual bytes even without Content-Length; reject ambiguous
framing/duplicate length and unsupported content coding. Errors retain typed
cause/remedy but redact secrets/private input. Authorization headers are never
request logs. Backpressure is bounded refusal, not unlimited spawned tasks.

MCP initialize/ping/catalogue are protocol behavior, not owner powers. tools/list
advertises only available authorized registry rows, with generated schemas and
bounded full response; no unknown tool aliases or actor override fields. Each
call verifies its current capability, including stdio or a multiplexed HTTP
connection. Structured output and text are rendered from one typed outcome;
measure the final wire result, including both content copies and envelope. If a
full first item cannot fit, return InputTooLarge with a legal larger-budget or
explicit read alternative. Never silently trim a complete body or mutate markers
after budgeting. Protocol errors use standard JSON-RPC errors; domain failures
retain the shared ErrorEnvelope rather than becoming a successful empty result.

A hostless stdio server may perform authorized reads/direct writes under the
shared lease and same core/store path. It advertises push unavailable and refuses
custody operations. It does not impersonate a resident delivery owner. Installed
provider MCP configuration must be qualified through actual tool discovery and
call, not merely a reachable endpoint. Remote access, OAuth proxying and exposing
machine credentials through a browser are outside alpha.

## 10. Process adoption and OS differences

Cold activation walks bounded indexed live-session/effect records, not the
machine process table or all historical turns. For each route validate store
incarnation, project/agent, credential revocation, saved conversation and native
binding revision; then ask se-proc to reobserve/pin full process identity and
containment. Its checkpoint schema and lifecycle state machine remain section 30's
single source. Host conversion persists the full checkpoint and required compact
containment metadata without inventing another process/lease schema.

Adoption reports are Pending, Reattached, Held, Revoked, Exited or
Unreadable(ErrorBody). Pending is unresolved work, Exited requires actual outside
absence, and Unreadable cannot become Exited. An imported historical process row
provides no present custody. A recreated native session requires exact persisted
fingerprint/epoch adoption mapping, never just an equal display name/thread ID.
A held route adopts as held; revoked stays revoked. On uncertain notice delivery,
query the original target/NoticeId before retrying. Absence under an old epoch is
not absence under an arbitrary new target.

| Concern | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Process identity | Native process handle, creation FILETIME, image/argv identity; no PowerShell per check | Boot/start identity, pidfd when available, exe/argv and native events | Native start identity and process observation; unreadable fields stay unreadable |
| Containment | Named section-30 job, no KILL_ON_CLOSE; own suspended launch assigned before execution | Section-30 cgroup/scope where available, recorded identity and pre-exec barrier | Section-30 tracked containment/group with declared escape limitations; never stronger than its witness |
| Host job ancestry | Required breakaway refusal is explicit; do not retry without containment | No terminal-owned implicit custody | Native terminal bootstrap must prove exact registered process |
| IPC | Current-user local named pipe DACL, peer SID/PID/start verification | Protected Unix socket + SO_PEERCRED/start verification | Protected Unix socket + native peer credentials/PID facilities |
| Exit/watch | Native completion/handle wait and job accounting | pidfd/cgroup/inotify events | Native process/file events; no polling replacement |
| Attended terminal | Native owned console/terminal path, exact bootstrap registration | Terminal adapter and owned attach/exec registration | Terminal.app adapter and owned registration, literal argument handling |
| Codex transport | Stdio headless required; private attended transport capability must be demonstrated on stock build | Stdio supported prototype path; private Unix WebSocket optional qualification | Stdio headless required; Unix WebSocket/terminal attach must be qualified |
| Path encoding | Lossless UTF-16 NativePath, verified ACL/no reparse traversal | Lossless byte path, no-follow/owner permissions | Lossless native path, no-follow/owner permissions |

No host shutdown automatically invokes a kill-on-Drop containment policy. A
same-process generation restart retains its transport/process arena; a process
crash loses pipes and may cause provider EOF exit. If the provider exits, preserve
captured history and resume its verified original conversation after old-scope
closure. If it survives, adopt only with actual custody/transport proof; never
start a duplicate worker because reconnection is difficult. A stale/reused PID
is a refusal, not a candidate to kill. Se-proc's observed group-empty result
cannot prove descendants that escaped that group are absent. Stop/Remove report
incomplete scope exactly as that process owner requires.

Without a supported private attended Codex attach on a platform, expose a clear
ProviderProtocolUnsupported or WindowUnavailable with the supported detached
launch path. This is a bounded implementation fallback, **not acceptance of a
missing required journey**: all alpha-supported modes still need their real
platform witnesses. The design cannot confer vendor transport support.

## 11. Errors raised at this boundary

Use existing se_types::Code/Detail/ErrorBody and their typed cause fields; no
ad hoc string error namespace. Domain error text and remedies are rendered by
the shared registry for CLI/MCP/library. Preserve underlying nonsecret OS cause
locally with SeError; do not expose raw secret-bearing stderr/argv. This table
names the host's causes and legal next action. Specific detail fields remain the
canonical catalog, not a second untyped map. Upstream store/process codes pass
through without relabeling unreadable as unavailable/absent.

| Code(s) | Cause here | Remedy / retry direction |
| --- | --- | --- |
| usage-invalid-value, input-unknown-field, input-too-large | Invalid frame/options/closed operation, cap cannot fit item or payload | Correct input/budget using registry schema; no dispatch/read marker |
| api-version-unsupported | Exact linked or IPC API mismatch | Upgrade older side; no range negotiation/source swap |
| runtime-version-mismatch | Different running package/image protocol | Controlled down/closure then matching version; no forced takeover |
| os-user-mismatch | Kernel peer/home ownership differs | Use own home/user; never trust claimed SID/UID |
| machine-credential-missing / machine-credential-unreadable | Owner proof cannot load its real secret | init/doctor as appropriate, no owner fallback |
| owner-required / human-terminal-required | Session requested owner/human-only operation or ancestry unproven | Genuine owner terminal; no flag bypass |
| listener-admission-refused | Host/Origin/target/auth/native peer proof rejected | Reconnect through protected local integration; no remote URL fallback |
| listener-non-loopback / listener-port-in-use | Invalid address or actual bind conflict | Correct explicit runtime config, preserve incumbent |
| ipc-unavailable | Channel/socket/pipe/protected endpoint unavailable | Inspect actual status/owner, bounded reconnect; do not direct-write under live host |
| runtime-not-running / custody-unavailable-hostless | No admitted resident custody owner | up/launch-supported auto-start, no PID shortcut |
| runtime-owned-elsewhere | Another actual factory/daemon holds home | Close named owner through its legal route; no timeout theft |
| runtime-start-failed / runtime-start-pending | Start failed or readiness still pending | Status/doctor with bounded actual diagnostics; never launch-success on PID alone |
| runtime-handover-in-progress | G fenced during replacement | Retry when ready with original key; not live host migration |
| runtime-drain-timeout / runtime-stop-unwitnessed | Unjoined tasks/writer or absent outside host-stop witness | Retain lease/custody; inspect/retry, controlled process restart if truly stuck |
| session-generation-mismatch | Old G at operation/native callback | Reopen/rebind through trusted control plane and reconcile original key |
| session-binding-unproven / session-required | Claimed conversation/session lacks protected binding | Legal launch/begin/rebind, no private neutral-context fallback |
| capability-invalid / revoked / expired | Credential fails current verifier/revision/expiry | Authenticated renewal/relaunch as applicable; never owner fallback |
| session-unknown / session-already-ended | Actual missing/ended bound session | Inspect/rerun legal launch; absence is not activation |
| grant-required / tool-not-available / tool-unknown | Missing creator grant or non-registry/tool scope | Owner grant/available catalogue; no target actor override |
| project-conflicts-session / message-scope-denied / not-recipient | Claimed scope/read marker exceeds caller | Drop conflicting selector or inspect as owner without recipient markers |
| revision-conflict / launch-in-flight / agent-already-running | CAS changed or exact active reservation/incumbent | Reread actual binding/intent; preserve original key and incumbent |
| idempotency-key-reused | Same durable key/notice ID, changed canonical request | New authorized operation/key; never overwrite original result |
| provider-cli-not-found / too-old / unrecognized | Actual executable missing/unqualified version | Install/upgrade/configure real CLI; probe before disturbing incumbent |
| provider-protocol-unsupported / codex-app-server-failed | Required feature absent or real RPC phase failed | Upgrade/fix provider; use explicitly supported mode, no TCP/bypass substitution |
| provider-change-breaks-resume / resume-reference-missing / unverifiable | Saved conversation cannot legally resume | Inspect and explicitly choose --new if desired; no silent fresh thread |
| launch-failed / launch-readiness-timeout | Real exit or unresolved provider readiness | Fix provider or inspect owned pending launch; no child abandonment |
| window-unavailable / job-breakaway-refused | Terminal missing or required safe containment impossible | Detached supported launch/up route; no weakened job policy |
| stop-unwitnessed / stop-partial / stop-deadline-exceeded | Exact root/descendant closure incomplete | Inspect remaining exact observations, retry bounded stop; never name kill |
| process-identity-changed / unreadable / bare-pid-refused | Reused/missing strong identity | Reobserve exact owned lifecycle; no action on uncertain PID |
| integration-conflict / write-failed / readback-mismatch | User changed owned entry, filesystem failed or bytes differ | Preserve edits; doctor/explicit repair, no stale backup overwrite |
| capture-consent-missing / turn-invalid | No consent or invalid canonical vendor capture | Obtain explicit capture choice/fix integration; no private turn ingestion |
| transcript-unreadable / truncated / hook-payload-invalid | Actual source inaccessible/rotated or trusted payload malformed | Preserve cursor/history, diagnose real source; hook exit 0 is not capture proof |
| remove-incomplete | Some revocation/stop/config cleanup unproven | Report each residual and retry idempotently; preserve user work |
| deadline-exceeded / cancelled | Bounded wait ended; outcome may already have committed | Original-key readback/status before retry, no new effect key |
| task-failed / internal | Supervised panic/invariant failure in known G/stage | Poison/fence G, preserve incident and use independent factory recovery |

StoreAbsent/Unreadable/TooNew/MigrationRequired/Busy/DiskFull/ReadOnly/Corrupt,
backup/recovery and erasure codes retain section-20 semantics. In particular,
FULL sync failure is never a successful security commit, and an unreadable
pending-effect query never reports zero debt. A poison condition maps to the
accepted precise engine error plus linked ApiFailure::GenerationPoisoned or
EnginePanicked; do not invent an unregistered se-types code to match that label.
Errors block their affected route unless the host-wide writer/ownership boundary
itself is unsafe, in which case mutations are globally gated.

## 12. Performance allocation and bounded work

Hard shared targets: ≤30,000,000 added RSS bytes embedded, ≤100 ms added startup,
<0.1% settled idle CPU, no StateEngine Node, no per-seat engine process, CLI
<20 ms. Standalone planning envelope is ≤25,000,000 attributable RSS bytes so its
own executor/allocator cannot consume the embedded margin. These are targets to
measure through journeys, not results established by cargo check.

| Resource | Section-40 allocation / bound |
| --- | --- |
| Host/transport/IPC/HTTP code, allocator and task state | 5 MiB resident planning share |
| Store buffers/caches/writer stack | 8 MiB shared reservation; section 20 controls exact cache/connection use |
| Process custody/reactor/native collector | 2 MiB reservation; section 30 controls native implementation |
| Native watch + session state + ID-only notice debt | 2 MiB; no retained transcript/message bodies per session |
| Shared blocking stacks/buffers | 4 MiB planning reserve for two admitted jobs; account actual runtime stacks |
| Remaining startup/embedding overhead | Standalone ~2.8 MiB margin; embedded larger shared-runtime margin |

These planning reservations total 21 MiB (~22.02 MB), leaving margin under 25 MB;
measure shared pages/RSS and incremental embedding consistently, never add unlike
PSS/private-working-set counters to claim a pass. A pooled buffer counts once;
concurrent per-connection maxima are not all preallocated. Under pressure reject
new in-memory work before exhausting the aggregate cap, retaining durable debt.
Any store/process budget correction is reconciled in the aggregate before release.

Default HostLimits: 128 sessions, 64 connections, 1 MiB aggregate resident queued
payload, 32 notice IDs/session, 512 aggregate resident notice IDs, 262,144 local
response bytes and two blocking jobs. Validate all NonZero fields against these
policy ceilings before allocation; session/task metadata targets ≤8 KiB/session.
Provider transcript buffers and response bodies are streamed/bounded globally,
not allocated at 1 MiB × 64 connections. A caller cannot select a larger profile
that silently breaks the process memory budget. Model/provider memory is outside
the engine share but is reported separately in journey measurements.

Startup envelope: config/home/version/lease checks ≤10 ms; store validation/open
≤20 ms; IPC/listener/native watch ≤10 ms; initial bounded 50-route custody
inspection ≤30 ms; composition margin ≤30 ms. Expensive reconnect/debt and backup
work continues in Recovering after truthful readiness, with route status visible.
Never call all routes Ready merely to stop the startup clock. New schema migration
is separately explicit and not counted as a normal warmed compatible open.

Ordinary CLI budget: parse/open ≤5 ms, bounded auth/read or one IPC round trip
≤10 ms, render/write ≤5 ms, with total strictly <20 ms on qualified machines.
Cold direct writes and FULL security commits currently have contrary prototype
evidence; they remain named performance risks for qualification. We do not weaken
durability, omit auth or hide writes in a background unacknowledged queue to pass.
Launch/stop include external readiness/exit and expose actual pending deadlines;
provider/model generation latency is reported separately from engine dispatch.

Zero sessions means no per-seat timers, transcript watches or mail waits. Idle
live sessions park on OS events and coalesced commit watches. No 250 ms mail loop,
1.5 s process poll, minute projection drain, hourly canary or atlas tick returns.
Claude's bounded vendor HTTP renewal is the explicit exception in section 8.2,
counted in idle CPU/wakeup measurements; zero-wakeup marketing would be false.
Busy/debounce/retry timers exist only while that work is outstanding and cancel
when it resolves. Request expiry is checked on use and has no periodic sweeper.

Implementation estimate: 8–11k Rust lines for this host/harness/listener scope,
plus roughly 200–350 provider-native mod JS lines. se-proc/platform and store
implementation are separately owned, not counted again. Module decomposition is
by ownership above, with narrow composition glue; estimates are review signals,
not a reason to sacrifice correctness or pad code. Current se-host base is a
one-line empty crate; this candidate adds declarations in five focused modules
rather than a runtime god file. No existing Node hotspot changes.

## 13. Five journeys and implementation acceptance

The acceptance oracle is the five real scripts on clean Windows, macOS and Linux,
with Claude and Codex where applicable, standalone and actual embedded SE Code.
Reviewers add only targeted black-box checks where a false success is plausible;
this author writes no tests or new gate system. Compiling declarations proves
interface consistency only. No running process is redeployed by this candidate.

| Journey | Host/harness behavior the real script must show | Discriminating failure observation |
| --- | --- | --- |
| J1 Install | Actual signed/downloaded binary; --version/help from fresh terminal without Node/provider requirement | Absent config/provider is clear onboarding, not private runtime access or fake installed version |
| J2 Adopt | Existing files/Git unchanged; init creates/adopts owned integration; safe real Claude/Codex agent writes requested artifact; actual MCP tool call and captured turn | Old/missing CLI refuses before takeover; permission approval remains real; partial readiness retains owned process and no success claim |
| J3 Come back | Close/stop through actual outside witness; new host/generation/process resumes exact saved conversation and recalls prior task; original-key debt/capture recovered | Invalid resume reference refuses; held session stays held; writer/process crash after ACK does not lose ordinary process-crash-committed history |
| J4 Two agents | Authenticated agent/creator handoff commits once, wakes intended route, recipient reads/acks through actual tools and does requested work; user sees separate offer/read/result facts | Held/refused callback preserves debt; lost reply retries original NoticeId; huge body/marker metadata stays within final wire cap; no other agent's mailbox/owner authority |
| J5 Remove | Hold/revoke, exact root/descendant stop witness, matching owned config/secret exposure removed; user work/history preserved | Reused PID, unreadable scope or user-edited config yields named residual/incomplete removal; no broad process kill or recursive home wipe |

Targeted failure actions at these same seams: mismatched G after restart; panic
before/after native/store commit; cold prepare cancellation; crash after launch
reservation/scope checkpoint but before execution; lost native queue ACK; held
zero-mail predecessor takeover; human resume between absence/select; unreadable
point query; wrong Host/Origin/bearer/OS peer; live unjoinable writer; transcript
rotation; concurrent final-envelope read budgeting; revoked creator grant;
provider unavailable/old; disk full/FULL failure; and user-modified removal entry.
These are required truths to exercise during implementation review, not a request
to author sixteen independent harnesses or add test-process ceremony now.

Mirror coverage: CLI/MCP/library share typed operation/auth/receipt semantics;
attended/headless share safe profiles, leases, conversation/capture and stop;
Claude/Codex share Harness but use real provider-specific input evidence;
standalone/embedded share durable intents and generation rules while SE Code
alone uses NativeQueue; sync CLI/direct readers and async host writers preserve
Read/Page/Window/errors; read paths never create write/disposition effects except
the explicitly mutating message.read operation. Each journey result names actual
platform/mode and any exempt unexercised path; one Linux success is not all mirrors.

## 14. Open qualification questions and design defaults

These do not authorize implementation shortcuts. They are visible integration
risks for reviewers/maintainers, with safe behavior already specified above.

1. **Actual SE Code dependency pins/API publication (Alpha + host composition).**
   Replace the proposal with the upstream permissive crate and align Tokio and
   SQLite packages exactly. The constructor function then uses that real trait.
   Compile the combined consumer; declaring a generic pointer is not that witness.
2. **Native peer-proof implementation (process platform owner + host).** The safe
   IpcPlatform seam requires real named-pipe/Unix credential and process proof on
   each OS, including macOS limitations. Unsupported stronger identity refuses;
   do not emulate proof from request fields or add unsafe host code.
3. **Attended stock Codex private attach (harness qualification).** Verify private
   transport/auth/reconnect and terminal behavior on Windows/macOS. Stdio headless
   remains the supported baseline, not evidence of attended support. Optional
   vendor transport cannot be assumed production-stable because it exists.
4. **Claude mod renewal versus idle budget (harness qualification).** The verified
   30-second fetch ceiling invalidates 25-minute waits. Measure 25-second renewal
   under settled real sessions against <0.1% CPU. If it fails, bring the measured
   vendor/API constraint to the lead; do not hide CPU or substitute polling.
5. **CLI and security latency on real disks (store/host qualification).** Existing
   Linux direct/FULL data exceeds 20 ms. Preserve the fixed durability/authority
   contract and report cold/direct/security costs separately; optimize actual
   critical paths before claiming the hard budget.
6. **Crash survival versus resume on every OS (process/harness qualification).**
   Demonstrate native scope persistence, pipe EOF behavior, original conversation
   resume and descendant absence. Recovery may truthfully remain incomplete where
   platform custody is unprovable; alpha cannot call that a passed required path.

Implementation freedom remains in private helper names, bounded collection and
watch implementation, batching/fairness mechanics and focused module layout.
Changing canonical authority, callback ordering, durable witness meaning, closed
public operation/API surface or safe failure direction requires review by its
owner. This candidate changes no runtime, config, listener or deployment; future
implementation must be integrated by Prime, deployed in actual products and
witnessed through these consumers before it becomes operational evidence.
