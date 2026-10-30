# 40 — Host runtime and harnesses

Design candidate, not runtime implementation or qualification. Owner: Vera.
Base: accepted main `a644381871cbae5d8e1eaf56559943443b580f35`.
This revision folds Prime's Opus return `msg-1f35564dbeb211d846bf5f9c` and Sol's
`msg-8e0ac6e98350f404c9abe25f`. Verification tier: kernel boundary design;
compiling declarations here, journey/black-box checks owned by reviewers.

## 1. Outcome, boundaries and source of truth

One StateEngine host runs inside SE Code or as one standalone daemon. It launches
real Claude/Codex agents, captures their work, resumes their original conversations
and delivers mail without confusing an offer with a read or a PID with custody.
The host implements the accepted [operation inventory](../OPS.md),
[types/linked API](10-types-and-host-api.md), [store](20-data-model.md) and
[process ownership](30-process-ownership.md). Shared sections 00, 70 and 80 in
Prime's design bundle govern architecture, security and budgets; Prime's review
decisions settle the conflicts called out below. Drafts 01–05 are background.

* se-core owns identity, permissions and the single closed operation executor;
  se-store owns events, snapshots, the writer, migration and backup; se-proc owns
  native identity, containment, peer credentials, ACLs and native unsafe code.
* se-host owns supervision, process coordination, provider adapters, capture,
  IPC/HTTP and the proprietary implementation of SE Code's linked API. The binary
  owns argv/environment, human rendering and transient entry points.
* The registry has 59 operations and 26 MCP tools. Private handover, hook and
  lifecycle protocols add no user command, tool, generic dispatcher or actor flag.
* Hosted writes use the exclusive runtime lease and one store writer. Direct
  writes use the same transaction path under a shared lease only with no host.
  The accepted fixed security-event set commits FULL; ordinary writes use NORMAL.
  Ordinary startup never migrates: supported older schema requires the explicit
  owner-approved section-20 upgrade/maintenance path with the old host down.
* **Live standalone↔SE Code handover is in alpha.** Its retained coordinator uses
  section 30 and section 10's factory/native transfer seam. Iris owns the small
  linked-API amendment; the earlier API exclusion does not defer this requirement.
* SE Code has one native input queue. The concrete adapter uses HostServices;
  no parallel NativeQueue trait or translated native DTO family. A transfer fence
  is distinct from a human/takeover hold and cannot clear either.
* Windows uses KILL_ON_JOB_CLOSE | BREAKAWAY_OK, never SILENT. Unstaged full host
  loss closes the last job handles and ends ordinary members. Same-process
  generation replacement and staged overlapping-handle handover are different.

No factory tooling, PostgreSQL multiplayer, remote HTTP, provider login manager,
telemetry, Node runtime, dynamic plugins or new permission bypass is introduced.
Atlas is absent embedded; standalone reserves its section-80 share. Agent CLIs
and their tools are separate provider processes, not extra StateEngine processes.

### 1.1 Evidence and limits

The Linux S4 prototype exercised real Claude 2.1.312 command hooks and stock
Codex 0.166 app-server tasks, capture, mail/steer and same-conversation resume.
Hosted NORMAL sequential hook p95 was 8.3–9.5 ms; concurrent p95 10.966 ms, with
8/200 above 20 ms, maximum 65.199 ms. Direct hooks took roughly 90–101 ms; FULL
hosted p95 47.9–56.9 ms. Zero acknowledged ordinary writes were lost in 100 exact
writer-process kills: process-crash evidence, never power-loss durability.
Project-local records `vera-s4-socket-20261030/REPORT.txt` and
`vera-s4-normal-20261030/REPORT.txt` are prototypes, not shipped dependencies.
Attended Claude mod push, Windows/macOS transports, native custody and embedded
RSS are **not** established by those results or this declaration candidate.

## 2. Compile-only surface and implementation shape

Canonical declarations are actual compiling Rust, with no method bodies, defaults,
panic placeholders, test code or executable backend. The exact linked public
HostFactory/Host/HostServices signatures remain solely in
[the section-10 API proposal](secode-stateengine-api.rs), compiled independently
with [its commercial constructor signature](commercial-factory.rs). Alpha owns
that permissive crate; replace the proposal with its published dependency at
integration. No proprietary copy is promoted to a second public API.

| Canonical source | Types / actual polymorphism |
| --- | --- |
| [model.rs](../../crates/se-host/src/model.rs) | HostFuture; HostKind, HostPhase, HostConfig, HostLimits; ListenerConfig; concrete CancellationState; CallContext, OpenContext; SessionIdentity; opaque VerifiedCaller/BoundSession; HostStatus; DrainReport; RestartRequest, RestartReason; FaultReport, FaultStage |
| [runtime.rs](../../crates/se-host/src/runtime.rs) | Concrete HostFactoryAdapter, HostAdapter, SecodeAdapter, HandoverCoordinator, LaunchCoordinator, ExitBridge, ReactorAdapter; ConfigureFactory pointer; PreparedRuntime/Integration; Adoption, AdoptionOutcome; HandoverIntent, HandoverState, HandoverPhase |
| [client.rs](../../crates/se-host/src/client.rs) | Tokio-free ClientOptions, BlockingIpcClient, BlockingConnection; BlockingTransport (Unix/Windows implementations); synchronous RuntimeFilesystem (three OS implementations) |
| [ipc.rs](../../crates/se-host/src/ipc.rs) | IpcEndpoint/EndpointRecord; BorrowedChannel; PeerProof, ServerChallenge; IpcPlatform (three OS implementations); ClientHello, ServerHello, AuthorizedConnection, RawOperation, AdmittedOperation, OperationOutput, IpcRequest, IpcEnvelope; PresentedAuthority; concrete AdmissionAdapter, Dispatcher, HttpListener; HttpRequestHead, HttpChannel |
| [session.rs](../../crates/se-host/src/session.rs) | HarnessKind; SessionPhase/Activity/HoldReason; provider-only ProviderNotice; SessionLease/Coordinator; TakeoverRequest, TakeoverTicket, TakeoverReport; trusted TranscriptPin; CaptureRole/Input |
| [harness.rs](../../crates/se-host/src/harness.rs) | Harness (Claude/Codex implementations); ProviderVersion/ProbeRequest; ConfigPlan/IntegrationEdit/OwnedLaunchFile; HarnessRequest, HarnessAttach, HarnessBinding; ProviderIo/Transport/Invocation/Interrupt; BindingWitness/LaunchOutcome; OfferStage, OfferWitness, BellOutcome; TranscriptSource; ClaudeHookKind/Input/Output/Adapter; CodexTransport, CodexInvocation |

Concrete adapters have opaque layout declarations. They implement the existing
linked/core contracts at implementation time; they do not expose a second set
of public service methods now. The implementation stages named in this chapter
are private module responsibilities unless an existing canonical trait declares
them. Native queue receipt/target/hold types and error variants are section 10's
canonical types, not renamed host replicas. Shared IDs, Read/Page/Window/errors
and process/store types are referenced from their owners.

HostFuture is an object-safe Send future only for genuine provider polymorphism.
CallContext carries required generation, timeout and concrete cancellation state.
OpenContext/ClientOptions alone allow unknown generation. RestartRequest has key
and reason; **the authoritative old G comes from call options**, not another
request field. A Drained report's G is a witness to compare, not another selector.
Opaque handles prevent mistaken reconstruction from JSON, not hostile in-process
code already inside the project trust boundary. Secret-bearing values have no
public serde/Debug path; typed DTO validation bounds every vector/string.

ProviderIoPlatform, ProviderStream, StreamRead and StreamWrite in harness.rs are the genuine
Unix/Windows evented-stream port and its bounded data shapes, not a native queue.

### 2.1 Module tree and line allocation

Future implementation layout, estimates not correctness caps; totals count host
work only, excluding se-core/store/proc and the permissive API. No file is planned
above 500 lines. A directory total below is spread over the listed responsibilities.

```text
se-host/src/
  lib.rs + model.rs                         250  composition/data only
  client/{endpoint,lease,wire,auth,mod}.rs   750  blocking common client, native ports
  runtime/{factory,generation,tasks,
           shutdown,handover,mod}.rs       1550  retained ownership and recovery
  process/{launch,stop,recovery,events,
           reactor,io,mod}.rs              1350  ProcessRuntime consumer
  session/{state,takeover,mail,mod}.rs      1050  binding and indexed notice debt
  capture/{pins,reader,watch,mod}.rs         650  incremental trusted sources
  harness/{mod,config,claude_launch,
           claude_hook,claude_mail,
           codex_rpc,codex_input,
           codex_capture,secode}.rs        1900  provider-specific translation
  http/{server,admission,mcp,mail,mod}.rs    1000  one bounded HTTP server
  integration/{install,remove,mod}.rs        400  owned edit/readback
                                           ----
                                           8900 Rust lines
provider-native Claude mod JS               200–350 lines, no Node process
```

The six current declaration modules are not a mandate to put all eventual
runtime code in six files. Public API changes follow section 10's exact-version
and major-version rule, not an independent adapter-version policy.

## 3. Process coordinator and store ordering

LaunchCoordinator alone consumes ProcessRuntime. A Harness produces configuration
and provider invocation and attaches to an already owned process. HarnessRequest
has identity, profile/policy/mode, executable/cwd, explicit resume, initial input,
protected launch credential and stable key. It contains no native launch authority.
ProviderInvocation is literal argv/environment; ProviderIo splits explicit child
StandardIo Files from a retained host ProviderTransport. HarnessAttach receives
the real process reference/record, transport and trusted transcript pin. Arena
ownership remains with se-proc; the reference is not a second native owner.

### 3.1 Launch order (no transaction spans native work)

| Step / owner | Store boundary | Native/provider call and retained result |
| --- | --- | --- |
| Core/coordinator admission | Verify caller/creator grant/profile/resume, expected revision; reserve session/launch | Probe provider before changing incumbent; bypass only saved named opt-in |
| Coordinator reserve | Commit Reserved LaunchReservation, exact nonce/parent/host/G, before any native effect | ProcessRuntime::prepare_launch inserts arena Starting slot then creates scope, no vendor child |
| Coordinator checkpoint | Commit returned ScopeCheckpoint (`scope-prepared`) and revision | Retain PreparedScope.process and PreparedLaunch; no begin before successful commit |
| Coordinator native start | Recheck reservation/G and exact prepared checkpoint | begin_launch consumes prepared + LaunchSpec, including ExitBridge; Pending retains ticket/process; failures retain remaining custody |
| Coordinator event wait | No held store/native lock | Arm native watch/readiness, immediately poll_launch; await coalesced notice or original deadline, then poll again; no sleep loop |
| Coordinator pre-exec barrier | On AwaitingExecCommit, commit RootCheckpoint: real pre-exec identity/group/intended image | Only then authorize_exec; applies to macOS/terminal attach and any required native barrier |
| Coordinator root publication | Commit actual returned ProcessRecord/root image/state using CAS, never intended executable as observed image | Started includes actual exec observation; keep arena/process/streams even if commit fails |
| Harness attach | Credential/binding uses verified selected conversation and current reserved lifecycle, FULL security commit | attach receives HarnessAttach; validates native conversation and accepts work; actual echo/readiness required for LaunchOutcome |
| Coordinator publish readiness | Commit actual session/binding/readiness facts and cursor as applicable | Return real conversation/lifecycle and complete resume instruction, not PID-only success |
| Coordinator natural/failed exit | Read outside witness, commit Exited plus original exit/scope evidence | Only after commit call release; failed release stays indexed cleanup debt |

Windows begin_launch associates the job **at creation** using
PROC_THREAD_ATTRIBUTE_JOB_LIST and explicit CREATE_BREAKAWAY_FROM_JOB, not a
create-then-assign race. Its job has KILL_ON_JOB_CLOSE | BREAKAWAY_OK, never SILENT.
Required caller breakaway failure refuses without retrying weaker policy. Linux
BestAvailable lazily requests the approved user-manager delegation on first launch;
without it, select the explicit Uncontained group with reason, never refuse default
launch merely because delegation is absent. Explicit KernelScope may still refuse.
macOS uses the accepted tracked-group policy and before-exec root checkpoint.
The se-proc state/checkpoint schema is referenced, not locally redefined.

Cancellation while Starting: coordinator retains the process/ticket, calls
prepare_stop to obtain PreparedStop, commits **Starting -> StopRequested** with
revision CAS, then calls cancel_launch(ticket, prepared). Failed CAS dispatches
nothing; post-CAS native failure becomes StopUnproved with retained cleanup.
Dropping a future never abandons an OS effect already entered. A checkpoint-commit
failure cannot authorize vendor execution; revoke helper authorization, witness
scope/root closure and commit cleanup before release.

### 3.2 Exit notifications, stop and catch-up

ExitBridge implements the accepted ExitSink. It sends only bounded/coalesced
lifecycle/G/sequence nudges, holds no arena/store lock and wraps its entry in
catch_unwind. Stale G and duplicate/older sequence are ignored for routing, never
used as a stop witness. A callback panic records MonitorFailed/TaskFailed and
wakes independent supervision; it cannot unwind through a native callback or
kill the shared Windows collector. Native collector/lease invariant failure is a
host-wide fault; one recipient's callback failure is route-local.

After watch_exit registration, immediately reobserve progress/root/scope to close
the exit-before-subscribe race. On each event or deadline, use observe,
witness_exit or witness_stop; notifications are never emptiness evidence. Provider
EOF, terminal/attach-channel close, harness completion or actual root-handle
signal schedules a targeted native read within 50 ms. LeaderExited with possible
members arms one **coalesced live cleanup timer**, at most one read/second/scope;
stop it on empty scope or completed cleanup deadline. Active stop does a final
read at its original deadline even if no event arrived.

The runtime supervisor owns **one 15-minute live-work catch-up**, armed only while
at least one live session exists, per accepted sections 30/80. It walks bounded
indexed live lifecycles/capture cursors/debt and rereads native state; it never
scans the whole floor or machine process table. Coalesce missed ticks rather than
bursting. A missing final job event without any other trigger can take that long
to discover: this residual is not prompt-exit evidence. This explicit safety
sweep is not the retired per-seat mail/process polling loop. Capture uses harness
signals first and the same bounded catch-up as repair of missed native events.

Activation calls arena_snapshot to include unpublished/Starting/quarantined slots,
then merges that bounded native view with indexed store phases. Cold recovery
passes the actual tagged Reserved/ScopeCheckpoint/RootCheckpoint/Record to
plan_recovery and recover; do not create a fake complete record with PID zero.
Same-process generation recovery re_adopt's verified records/from/to G while
retaining arena resources. Exited-but-unreleased rows are re-witnessed and released.
Unreadable ownership blocks that route; a historical imported PID is never custody.

## 4. Executor, blocking and native thread accounting

All async work uses the supplied Tokio Handle. No ambient spawn/current handle,
nested runtime or block_on. Embedded creates no runtime; standalone has one
current-thread executor. Constructor stores Handle without I/O/spawn. Tokio is
optional behind `runtime`; client-only builds have no Tokio dependency. The
current declaration pin compiles Handle; actual composition must match SE Code's
exact Tokio/SQLite versions. No library installs a global tracing subscriber.

| Work | Execution and owner | Bound / section-80 accounting |
| --- | --- | --- |
| Session state/mail/control, IPC/HTTP, vendor JSON framing | Supplied executor tasks, one coordinator/session | ~50 KB/session, no thread/session; session/mail/listener lines §3.1 |
| SQLite writes | One named se-writer OS thread, se-store owns it | Blocks on bounded receive; store lines, no shared-pool occupation |
| Foreground DB reads, transcript chunks, config filesystem, CreateProcess/native finite steps | Shared blocking pool, at most two admitted jobs | Never run sync file reads/CreateProcess on standalone executor; finite work only |
| Whole-copy backup / close_clean | One background/maintenance blocking slot for its entire synchronous call | At most one; reserve the other slot for foreground work; not a per-step fake async call |
| Unix process and watch events | Existing Tokio AsyncFd/kqueue reactor via ReactorAdapter implementing NativeReactor | se-proc HostConfig.reactor supplied; no Unix collector thread |
| Windows native job/process completion | One existing se-proc IOCP collector thread per host | §80 custody 0.2 MB includes collector; no RegisterWait pool or second collector |
| Windows provider stdin/out/err | Overlapped named-pipe host ends and IOCP readiness, bounded buffers | No tokio::fs::File/blocking read wrapper or thread per pipe; detailed below |
| Transcript watch | Unix native events; Windows uses section 60's shared safe se-proc file-watch service (ReadDirectoryChangesW on the same per-host IOCP) | One shared service for capture/Atlas, no notify-owned helper thread; §80 watcher 0.5 MB includes state, not an omitted stack |
| Optional Atlas | Accepted standalone Atlas worker only after use | §80 standalone 2 MB in-host share; cold-index child has separate approved 64 MB window |

On Unix ReactorAdapter takes the owned File from NativeReactor::register, installs
AsyncFd with requested read/priority interest on the supplied Handle, calls the
safe NativeReadiness callback, and retains NativeRegistration until cancellation
and in-flight callback completion. No native lock is held during callback.

Windows stdio is explicitly evented: provider-side StandardIo Files are the
specified inheritable child endpoints; host endpoints use FILE_FLAG_OVERLAPPED.
The safe native stream bridge uses the **existing per-host IOCP collector** for
completion and wakes the host's Tokio tasks. This avoids an unsafe raw-handle
conversion in se-host and extra per-pipe blocking workers; it is the same counted
collector, not a new pool. Native creation, ACL and overlapped read/write lifetime
code belongs to se-proc's platform owner; host io.rs owns framing/buffer/deadline
coordination. Async operation buffers stay pinned/owned until actual completion
or cancellation completion, never freed merely because a caller future drops.
This is the native-collector implementation of the review's evented-stdio
requirement; no claim that an ordinary File magically becomes async. Safe port
signatures for this bridge are part of the host/provider IO contract, and its
native implementation must be integrated with the section-30 owner before build.

ProviderIoPlatform.open takes the actual prepared OwnedProcess reference and
session identity, so it cannot create unowned stream resources from an ID alone.
The agreed native bridge is ProviderStdioApi: create_stdio against the already
prepared OwnedProcess -> StandardIo + opaque port; begin_read/begin_write return
retained tickets; take_completion returns Pending or exactly-once bytes/EOF/write
count/error; cancel is request-only; begin_close(port, All) cancels/drains asynchronously.
release_operation requires a terminal taken result; release_stdio requires a
closed witness and no unreleased operations. stdio_state retrieves bounded current-
generation port/ticket references after future drop/re-adoption. One operation per
stream, global byte cap, no EOF from cancellation. This is the signature agreement
with 5p, now declared in the section-30 amendment; it is not an implemented backend.

For same-process adoption or staged native import, register the wake then call
attach_stdio with the actual recovered/imported OwnedProcess and successor-local
StdioConfig sink/limits. It creates no pipe and starts no I/O. Read stdio_state
after binding and each BindingChanged nudge; Unbound/Draining cannot admit new
I/O, Ready means old callbacks drained and the local successor binding is usable.
An inactive imported port remains unable to read/write until activate_transfer.
Retained operation IDs, completions and byte charges survive; smaller limits
refuse rather than free old buffers. After activation, recover those same safe
ports through stdio_state. No source Arc/callback is transferred across processes.

After successful launch, drop the host's copies of child StandardIo; retaining
them would suppress real EOF. A Windows read completion with ERROR_BROKEN_PIPE,
ERROR_PIPE_NOT_CONNECTED or ERROR_HANDLE_EOF reports its actual prefix followed
by EOF/Complete; every other failure remains an error and cancellation is never
EOF. The host delivers a prefix once before exposing the retained terminal EOF.
finish_input finishes any accepted stdin write, then requests
begin_close(port, Stdin) and awaits its witness while stdout/stderr reads stay live. All-stream
close is a separate cancel/drain operation; neither future drop nor stdin close
may discard output/completion buffers. These are section 30's reviewed EOF and
half-close requirements, not a synthetic empty-read convention.

For Windows directory events, use the **same shared safe se-proc file-watch
service specified by section 60**, including ReadDirectoryChangesW on the one
per-host IOCP. Capture subscribes independently of Atlas activation; Atlas being
absent embedded cannot remove capture's watch service. There is no separate
transcript-specific native port, collector or unsafe host implementation. Use
that service's loss/overflow observations for bounded pinned-source catch-up,
never full machine/floor scans. Unix sources use the existing native reactors.
Do not quietly select notify's extra thread or poll watcher. If events are unavailable, expose
watcher unavailable and rely on real hook/completion plus the bounded live catch-up.
No extra uncounted watcher thread is reserved. CreateProcess and transcript
256-KiB chunk reads run as bounded blocking jobs. Exec/provider readiness awaits
native events outside the pool. A stuck kernel call retains its slot and custody,
reports pending and cannot be killed by terminating a host thread.

The two blocking slots use a common admission arbiter: one reserved foreground,
one eligible background. Only one backup/maintenance job may run, including
across generations; cancellation does not free its permit until it actually ends.
Drain cancels and joins backup before queueing close_clean on that background
slot. Store worker join is awaited without blocking the executor, after native
coordination; foreground slot remains available for status/recovery reads.

Every public entry is catch_unwind protected, including future construction and
polling. Mutex poison maps to Internal and retains/quarantines its actual owned
resources; it is never cleared into Running. A session task restarts **at most
three times in a rolling 60 seconds**, recovering its original keys/cursors first;
then it is failed by name in status, with its custody/debt retained. Non-writer
listener/capture/session/adapter faults fence only affected routes. **Writer,
runtime-lease and shared-native-collector faults, panics in activate/drain/close,
and migration failures after resources start poison the generation.** A lifecycle
panic retains the partial resources and gates its known G even when the writer
itself has not failed. These ownership/lifecycle faults use independent factory
recovery; ordinary API/session panics return Internal/EnginePanicked and
route-local failure rather than poisoning unrelated sessions. Iris's section-10
amendment mirrors this reconciled policy at the linked boundary; existing restart
generation fences remain. panic=unwind is required;
abort/OOM/OS kill use cold recovery.

## 5. Ownership, generation restart and shutdown

RuntimeFilesystem is synchronous in client.rs. endpoint(deadline) and
acquire_direct(deadline) require **no generation**; acquire_host likewise obtains
native custody before G is known. publish/unpublish require the retained actual
lease and exact owned epoch. Async host wrappers call finite native/filesystem
work through the supplied blocking arbiter; they never make CLI bootstrap async.
The full blocking client (discovery, peer/server proof, framing, owner MAC and
receipt decode) lives in client/, builds with no default features and no Tokio,
and owns no executor. ClientOptions.expected_generation is optional until hello;
post-handshake IpcEnvelope always carries the discovered exact G.

One protected runtime.lock has shared direct-client and exclusive host modes.
A direct writer retains its shared lease until transaction/connection closure;
the writer thread retains an Arc of the exclusive lease until actual join. A
stale endpoint/PID, missing pathname, timeout or caller-supplied report cannot
steal a lock. IPC failure under a live exclusive lease cannot fall through to a
direct write. Read-only snapshots remain available without the host. Hostless
stdio custody requests refuse CustodyUnavailableHostless; legal launch can
bootstrap the standalone host through section-30 NativeProcessApi spawn_runtime,
commit_runtime with authenticated readiness, or abort/witness/release_runtime.
The exact RuntimeChild stays pinned through that outcome.

Factory preparation is read-only, returns absent/unreadable/version error
truthfully, and starts no writer/callback/native effect. SE Code registers the
Prepared Host/G and fresh immutable generation-fenced services before activate.
Missing store does not implicitly init. Ordinary incompatible/older schema
refuses; explicit owner-approved migration is a distinct offline maintenance
path with its accepted approval/backup contract. Same-factory duplicate healthy
open shares the registered owner; an independent live owner refuses.

| From | Trigger | Next / actual effect |
| --- | --- | --- |
| Unopened | Valid read-only prepare | Prepared, possibly held preparation lease; no worker/native mutation |
| Prepared | Registered correct G/epoch/services, activate | Activating; start compatible store writer/resources |
| Prepared | Invalid source/G before resource start | Prepared + error |
| Activating | Initial authenticated first bind/continuity ready | Ready, with route recovery exposed separately |
| Activating/Ready | Indexed routes need reconciliation | Recovering; unaffected routes work |
| Recovering | Required route reconciliation done | Ready |
| Any owned active state | Writer/lease/collector ownership fault, activate/drain/close panic, or migration failure after resource start | Poisoned, gate G and retain exact partial resources; independent factory restart |
| Prepared/Ready/Recovering | Explicit drain, native G fenced first | Draining |
| Draining | All generation tasks joined, unfinished effects durable, writer drained | Drained, still owned until close |
| Draining | Deadline/live work/unreadable closure | Remain Draining with named blockers |
| Drained | Actual matching close | close_clean/checkpoint/resource closure, then Closed |
| Drained/Poisoned | Independent factory restart of exact call G + stable key | Close old resources safely, fresh Prepared G+1 |
| Restart closure | Unjoined worker/unsafe ownership | Old quarantined ownership retained; no new writer |
| Closed | Same-handle close retry | Original result, no reopened resources |

All unlisted transitions refuse. HostStatus reports its own G/epoch/phase and
bounded real blockers/counts; status/negotiated/health are nonblocking snapshots.
Lifecycle wait is event-driven, not a mail stream. Old handles stay fenced. The
factory supervisor independently retains writer/task/native resources; restart
never calls a poisoned Host object's drain/close. Exact restart retry returns the
same successor, not G+2. A truly stuck writer cannot be killed/abandoned in process:
retain lease, name blocker and require controlled application restart. A joined
panicked writer proves termination, not transaction outcome; integrity and
original-key readback precede reuse.

Shutdown order: gate new admissions; fence native G; stop/revoke or hand over
owned sessions according to the selected operation; persist debt/capture offsets;
cancel/join route tasks and backup; flush accepted writer work; consume/await
WriterOwner::drain and its join to regain unique HostStore; run synchronous
**HostStore::close_clean** on the maintenance slot (TRUNCATE checkpoint, backup
result and actual close); close native/listener resources; unpublish our exact
endpoint; release the actual lease. Failure at any step retains named obligations
and cannot emit a successful drained/closed report. Backup errors remain explicit.
Drop does not join, flush, wait, block_on or supply a closure witness.

The standalone **auto-start** supervisor owns one ten-minute exit timer, armed
only after the last live session and client end. Any new session/client cancels
it. On expiry recheck emptiness then use the same shutdown path; explicit se up
never auto-exits. Do not combine this timer with the 15-minute live catch-up:
catch-up exists with live sessions, exit timer only with none. No timer/session.
Deadlines use Instant plus a suspend/resume boundary check: on OS resume recheck
actual identity and the original requested wall/awake bounds; Instant can exclude
suspend, so a resumed stop is not silently granted a fresh full interval.

### 5.1 Exact per-OS close/crash behavior

| Event | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Explicit se down | Graceful stop then exact job stop/witness; final last-handle close enforces KILL_ON_CLOSE for ordinary members; save original conversation for relaunch | Stop exact owned cgroup or explicitly Uncontained group at achieved guarantee, witness and record; preserve resume reference | Stop exact owned group/tracked members at accepted bound; preserve original conversation; incomplete tracking remains incomplete |
| Unstaged host crash/full process loss | Last job handles close and ordinary members end; cold successor proves old closure and resumes saved conversation under a **new lifecycle**, never reopens job name as authority | Cgroup/group may survive, pipes may EOF; reobserve exact old identity/scope and verify transport/conversation before adoption or same-conversation replacement | Group may survive, pipes may EOF; same exact tracked/native proof, no global-descendant guarantee |
| Normal SE Code exit with handover configured | Staged overlapping-handle handover below keeps jobs/PIDs and streams alive; if handover fails, retain source until resolved or explicitly stop, never silently drop last handles | Staged FD/scope transfer preserves actual PIDs/streams where supported; failure is visible | Staged streams/PTY and protected-record transfer, re-register native events; preserve achieved tracked bound |
| Normal exit choosing explicit stop | Same stop policy as se down | Same stop policy as se down | Same stop policy as se down |
| Ordinary SE Code/daemon exit with neither handover nor explicit stop selected | Run graceful stop first: interrupt, save original resume reference and flush capture/debt; then exit. Last job close ends ordinary members; status/resume retain the saved reference and distinguish observed closure from pending readback | Same graceful stop/save/flush; stop and witness exact owned cgroup or explicitly Uncontained group before exit at its achieved bound; saved reference remains available | Same graceful stop/save/flush and exact tracked-group stop/readback at its achieved bound; incomplete closure stays named, saved reference remains available |
| Same-process generation restart | Arena/job/pipe resources stay with supervisor, no last-handle interval | Arena/FDs stay retained | Arena/FDs stay retained |

Explicit Windows breakaway descendants are outside the stated ordinary-job bound;
the receipt retains that limitation. Successful staged handover is the narrowly
proved exception to full-host-loss behavior, not a reversal of KILL_ON_CLOSE.
An unproved live job/foreign retained handle after unplanned loss blocks automatic
replacement. Linux/macOS provider EOF can require original-conversation resume
rather than process preservation; never start a duplicate while old scope closure
or transport ownership is unknown.
The ordinary-exit path is an explicit shutdown policy, not a raw Rust Drop.
An external status/resume reader reobserves exact native closure after host exit;
an unwitnessed final job close cannot forge an already committed Exited fact.
It shows the stopped/exit-pending state and the actual saved conversation resume
command as supported by that observation, never claims live adoption.

## 6. Live handover: standalone ↔ SE Code

Prime's alpha scope is SE Code restart/upgrade without killing its agents.
The daemon takes native custody and continues capture; SE Code-native user-input
and pushed-mail routes become **NativeDormant**, with status saying “waiting for
SE Code to reopen”. Its protected queue, original pending admissions and new
undelivered mail remain intact. No daemon promotes or recreates that native
queue. Reopened SE Code proves the original queue/adoption and reclaims it before
enabling promotion. Agents launched by the daemon itself remain unaffected.
This is custody/capture re-adoption, never a claim that dormant input routes are
fully active. Current-turn quiescence/timing follows the reconciled barrier below.
Before Prepared, request interruption of every participating agent immediately;
cancel an in-progress turn rather than await its natural completion, then prove
exact idle with active_session Present(None). An interruption ACK is insufficient.
Report request-to-quiescence time separately. B8 starts at cutover **after all
participating agents are quiescent**, and ends when actual custody and capture
are re-adopted. A slow quiescence cannot be hidden as an instantaneous request,
nor may its delay justify skipping the idle witness to meet the cutover target.

HandoverCoordinator owns the host half; ProcessTransfer owns native staging. A
trusted source/standby control protocol carries HandoverIntent/State over native
peer-authenticated IPC, not an agent-callable IpcRequest. The factory's retained
handover entry initiates this protocol independently of the Host handle;
open/restart cannot substitute for it and close cannot precede native staging.
It adds no model operation. The source and
successor HostEpoch/full native identity, old/new G, transfer nonce/key, expected
store revision and deadline are bound into one durable intent. The successor is
started detached/pinned by NativeProcessApi and stays Standby without a writer,
lease or delivery/input consumer while source owns runtime.lock.

The linked trigger is HostFactory::handover(request, native, CallOptions), with
source G in CallOptions and actual pinned successor resolved by the retained
factory. It uses Iris's HandoverServices with native epoch/queue accessors
independently of ordinary G callback fencing. The fence is keyed by the exact
transfer and retained queue incarnation, not the lifetime of one SE Code epoch.
freeze_queue installs that fence and returns NativeQueueCheckpoint for the
complete participating native binding set; queue_state resolves the original
durable result after a lost reply. **The factory** reads/verifies durable phase,
ownership and native proof; the permissive adapter checks only its actual epoch,
queue incarnation and exact persisted transfer/checkpoint binding. It has no
StateEngine store reader and cannot turn an opaque EventRef into a phase witness.
The factory requests settle_queue only after verified FULL Finished, pre-claim
Aborted or checked-cold Recovered, removing only that transfer fence. The checkpoint names the actual
protected NativeQueueId, original cut/event, digest/count and target receipts,
never pending input bodies or a substitute host queue. The native control plane
flushes and independently reopens/readbacks that queue image before SE Code exit.
Its full retained manifest includes pending bodies/IDs, admissions, promotion
dedupe, target/adoption mappings and independent holds; hashes alone cannot
restore it. These names remain canonical in section 10's major-2 linked API,
not copied as host service traits/DTOs. Fresh ordinary HostServices registration
still precedes destination callbacks; the transfer adapter gains no successor-G
work authority from surviving its old routing fence. A later SE Code epoch may
settle its predecessor's still-open fence only after proving the same protected
queue/cut and native adoption lineage and after factory-verified terminal outcome.
Different native queue/store identity refuses; epoch replacement alone is neither
authority to clear the fence nor a reason to strand the retained queue.

| Direction | Actual native adapter and freeze semantics |
| --- | --- |
| SE Code → standalone | native.epoch() is plan.source; native.queue() identifies the source's actual protected queue. Freeze the complete participating source target set; retain the image/cut through process exit and show NativeDormant after cutover |
| Standalone → SE Code | native.epoch() is plan.successor; native.queue() opens/proves the original dormant queue and native target adoption. Freeze/retain that receiving queue against promotion while the daemon owns custody; no fresh admissions reconstructed from engine debt |

NativeQueueCheckpoint.owner names the actual native epoch that created that cut,
not necessarily the later recovery adapter. The factory checks the directional
epoch, protected queue incarnation and original cut before its first callback.
A recovery adapter instead proves its fresh epoch through the verified native
adoption lineage and the same retained queue/transfer, never by pretending to be
the dead source or successor.
A second handover plan while a fence is open refuses transfer-in-progress with
the open transfer identity. Resolve the first transfer before starting a reverse
one; timeout, an empty active map or a new epoch cannot replace that resolution.

| Phase | Source / receiver / store / native barrier |
| --- | --- |
| SourceGated | Validate/retain keyed request and owner; gate new custody/delivery, immediately fence native admission/promotion and interrupt participating agents, then finish accepted finite launch/capture/debt operations and prove exact idle; do not await a running turn's natural completion; source still owns lease/resources |
| Standby | Verify exact successor peer/PID/birth/API/home and native ready channel; receiver is read-only, no ordinary HostServices callbacks or queue promotion |
| Staged | After source capture/debt heads and full-frame input/output boundaries freeze, duplicate host-owned/Unix stream/PTY descriptors and call begin_transfer; native arena includes Windows provider ports automatically; transfer_manifest reads actual nonce/digest, receiver accept_transfer stages inactive copies and attaches ready local stdio sinks |
| BarrierCommitted | Seal FULL Prepared with final immutable manifest/nonce/frozen_at after all accepted work is finished; drain/join writer, then record FULL ReadyToClaim on drained maintenance; frozen data cannot change afterward |
| LeaseTransferred | Source closes readers/backup/context and releases exclusive runtime.lock after ReadyToClaim; successor acquires lease and records FULL Claimed on maintenance with exact owner-generation/head CAS before any destination writer/native consumer |
| Activated | Receiver verifies lease/CAS/native manifest, calls activate_transfer once and obtains streams/receipt; record FULL Activated on maintenance before starting writer or input/capture consumers; register/read around event reassociation, fresh G services and original-notice recovery precede new offers |
| Acknowledged | Persist/read back keyed destination activation receipt and original admission/capture heads; source verifies exact receipt plus current ownership barrier, calls commit_transfer and closes its now-gated originals |
| Finished | After source resource closure is verified, destination commits FULL Finished; factory then settles that transfer's native fence, with old-G routing still fenced. Destination remains unique owner; native routes stay dormant while SE Code is absent |
| Aborted | Before Claimed and before native activation: source abort_transfer and receiver discard_transfer staged copies; restore source only after actual lease/owner/G validation; settle only this transfer fence and preserve all human/takeover/revocation holds |
| Recovered | A checked cold owner supersedes Claimed/Activated; one FULL transaction records the new runtime.owner and original transfer's Recovered outcome with fresh activated custody/capture and retained queue-cut proof; only then may the factory settle that original fence |
| RecoveryPending | Lost ACK, peer death, ambiguous CAS/lease/stream state; no guessed rollback or second consumer; reconcile exact transfer/receipt/native state |

The ownership row is a CAS and key in the store, not permission to bypass the
OS lock. Between source release and destination claim neither may write/input.
A racing third owner sees committed transfer state and refuses ordinary activation;
it cannot ignore the pending destination. If destination cannot acquire/claim,
source may reclaim only after native peer/death proof and a new checked owner CAS
under exclusive lease, while native transfer is still pre-activation. If receiver
already activated, rollback is a **new reverse transfer**, never source takeover
on timeout. Uncertainty gates affected work and remains visible.

Before sealing a native route, the transfer-scoped fence -> interrupt -> exact
Present(None) precedes final target selection; target/G/fence/no-execution are
rechecked inside the native atomic transition. Never reuse Takeover/HumanStop
then automatically unhold it. Settle only the matching transfer fence after
verified Finished, pre-claim Aborted or checked-cold Recovered. FULL Activated alone cannot clear it.
Do not clear a human hold to make handover appear live.
A resumed human invalidates the stale absence barrier; re-read/retry legally.
Host-only delivery is frozen before native transfer. SE Code freezes its sole
queue's admission/promotion and retains its complete pending state under its
native handover seam through destination acknowledgment; store message debt is
not a substitute for lost native pending input. Original queue admissions, target adoption mapping,
NoticeId/digest and capture cursor are carried; receiving callbacks use a fresh
G wrapper after its registration/activation, not an old Arc silently rebound.

Only source consumes provider stdout/capture until the freeze head commits. Its
read task then parks at that exact offset/frame boundary before descriptor
transfer. Receiver stages files without reading; activate_transfer returns them
exactly once after the lease/ownership barrier. Receiver resumes from the frozen
cursor and dedupe keys. On Windows, provider endpoints remain in the native
arena: ReceivedTransfer.processes supply the owners for attach_stdio, every port
must have a Ready successor binding before activation, then stdio_state returns
safe activated ports. ActivatedTransfer.streams contains only host-owned/Unix
Files; the host never extracts Windows raw handles or wraps them in AsyncFd.
No EOF interval on transferred stdin, no concurrent
readers, no duplicate prompt/captured turn. A missing required stream means
handover failed, not native-PID-only success. Source originals remain retained
through verified receipt; Windows job handles overlap across the whole transition.

Failure recovery:

* Before accept/staging: original source retains custody and may abort the intent;
  receiver closes its own standby resources, no input was accepted there.
* Staged receiver crash before activation: verify exact peer exit, discard/revoke
  that staged attempt and restore source native association/lease only through
  checked abort. Do not leak a staged Windows handle that keeps jobs alive forever.
* Source crash before committed ownership barrier: receiver may not activate on
  channel EOF alone. Verify durable transfer plus source exit/lease availability;
  otherwise discard staged resources and apply ordinary crash policy.
* Source crash after barrier: receiver uses exact intent/CAS/lease/native manifest
  to complete the same activation. If proof fails, RecoveryPending; no invented
  successor or arbitrary descriptor adoption.
* Activation reply lost: query durable transfer/receipt/current owner and native
  staged state with original key. Successful activation is never repeated to get
  a second stream set. Source never aborts an already activated receiver.
* Receiver crash after activation before ACK: source originals stay gated; prove
  receiver state/exit and recover through cold/reverse ownership protocol, never
  ungate source on elapsed timeout. Windows may retain jobs via source handles
  only while this bounded recovery is owned; unresolved staged copies are closed
  once their committed transfer cannot be proved, applying ordinary crash policy.

After Claimed, receiver loss requires checked cold recovery of the original
transfer into actual activated custody/capture. The same FULL transaction as its
new runtime.owner records the original transfer as **Recovered**, citing that
new owner event plus fresh native custody/capture and retained queue-cut proof.
The original peers, generations, nonce and manifest remain immutable. Do not
invent Finished/Aborted or append an ordinary old-generation phase advance.
HandoverState.recovery_owner names that verified new owner event only for a
Recovered outcome; it never overwrites the original HandoverIntent or fabricates
an old native transfer receipt. Missing/unreadable completion proof keeps recovery
pending. A new reverse plan requires the original fence's terminal settlement
first. Original admission/debt and independent holds survive either route.

Before Prepared, staging has no committed transfer authority. If source dies or
staging times out before that first FULL seal, receiver closes the uncommitted
inactive copies and ordinary OS crash policy applies; actual native holds/debt
remain. No receiver may activate from an uncommitted request or channel EOF.
This is Prime's reconciled drain/freeze-before-Prepared order
(msg-cf8e46cdeebb8fd10816bdc7), not a final-manifest mutation at ReadyToClaim.

The source obtains actual TransferManifest from the safe read-only
ProcessTransfer::transfer_manifest(&TransferOffer) accessor admitted in
msg-0e942ce53c74c86b78080306. Its transfer nonce/digest bind Prepared; native handles
remain private. Do not invent a source nonce or infer the manifest from PID lists.
TransferManifest.transfer is the se-proc-generated native nonce, not the store
transfer RecordId. The host records that exact value. The host proves pre-Claimed
from the current durable head under its actual lease before requesting abort or
discard; se-proc checks its retained native facts, not SQL. Failed restoration
retains the borrowed offer/import for keyed reconciliation and retry.

The accepted native Windows IOCP reassociation/readbacks and Unix SCM_RIGHTS/
kqueue steps are section 30's contract. Handover state never substitutes a
manifest hash for outside process/resource proof. B8 ≤500 ms is a target, still
unmeasured; bounded slow failure reports pending/refusal rather than overlapping
owners to meet the clock.

Before releasing the source lease, gate/close the old public listener and endpoint
after draining their calls; the authenticated private transfer connection remains
owned until settlement. The destination binds the persisted port/socket/pipe and
publishes its checked endpoint only under its new lease/claim. Old long-polls
return retry with no admission/read claim. Bind conflict cannot change the port
silently or revive old G: keep RecoveryPending and use proved forward/cold recovery
or a new reverse transfer. No public listener socket is assumed to transfer when
the section-30 manifest contains only process/stream resources.

Freeze drains outstanding native reads to an actual complete frame boundary;
partial buffers remain with the source parser/vault. If the boundary cannot be
proved within the original deadline, refuse before claim and preserve the source
buffers/consumers for checked abort. Never discard a consumed partial JSON frame
or start a receiver reader while a source native read may still complete.

### 6.1 Store record agreement (Nell owns the amendment)

Reuse existing store/incarnation/actor/request-key envelope and record Revision;
add no config key or JSON side-file authority. Host request fields are transfer RecordId, source/successor HostEpoch (full
process identity), old/new engine Generation, expected owner revision, request
key, deadline_at UnixMicros and bounded requested timeout. HandoverState keeps
optional actual native nonce/manifest digest/frozen revision only during transient
preparation; all three are required before sealing **Prepared**, immutable
thereafter, and never filled with zero/fake identities. Native descriptor roles/process records use the exact
section-30 canonical manifest digest; frozen_at binds store capture/debt heads.
No raw handle, body or credential is in that record.

| Durable phase (all FULL + current-owner-G/record CAS) | Host observations / crash rule |
| --- | --- |
| Prepared | New admission frozen; accepted launches/capture/debt finished, transfer fence/idle proved and inactive copies staged before sealing immutable fields; source still owns G; only proved pre-claim abort restores it |
| ReadyToClaim | Only writer/reader/backup drain and lease release remain after Prepared; record on drained HostStore; destination may acquire released exclusive lease and claim the exact transfer, no third owner |
| Claimed | Destination owns target G under exclusive lease before native activation; recover same transfer after peer/lease/manifest proof, never source timeout rollback |
| Activated | Actual native activation receipt persisted FULL **before destination input/capture consumers run**; lost ACK is keyed readback; a crash cannot justify fresh stream activation/input |
| Finished | Source verified destination receipt/owner and committed native transfer, then closed originals; destination records terminal FULL outcome before native transfer-fence settlement |
| Aborted | Only before Claimed and native activation, after checked source/lease recovery or while source retained it; retain real human holds/debt |
| Recovered | Exceptional checked-cold completion from Claimed/Activated, atomically with the new FULL runtime.owner; cite its event, fresh activated custody/capture and retained queue-cut proof while keeping original peer/generation fields immutable |

The Recovered row consumes section 20's admitted recovery amendment, not a local
side-file, invented Finished or phase-only write under a stale generation.
Acknowledged/LeaseTransferred/RecoveryPending are bounded host observations, not
extra durable owner phases. Exact phase retries use stable per-transition keys
derived from the original request, transfer and phase; changed fingerprints
refuse. Elapsed deadline permits failure reporting, never lease/owner theft.
On native activation success but lost durable Activated reply, resolve the exact
phase/request and native receipt before any consumer starts. If actual native
activation cannot be proved after peer loss, cold recovery remains explicit
rather than inventing an abort or a second set of streams. The record's immutable
peer/generation/nonce/digest binding and legal transition checks belong to Nell's
store amendment; the host supplies real outside facts and holds the OS lease.

### 6.2 Closed recovery attestations

RuntimeOwnerEstablished.recovered uses section 20's RuntimeRecoveredTransfer,
not another recovery event. transfer and handover_event identify the exact current
Claimed/Activated head; capture_at is a real committed revision in the same store,
at least frozen_at and no later than the observed head. The enclosing FULL owner
event is both new-owner and Recovered completion reference. Its projection keeps
the original transfer plus Recovered under the fresh epoch/G. A standalone
RuntimeHandoverRecorded(Recovered) or a bare owner event is illegal.

The two digests bind these private, versioned metadata documents:

| Schema / digest | Closed content and checks before the FULL append |
| --- | --- |
| se.handover.recovered-custody/v1 / activated_custody_sha256 | Original transfer/current handover event/manifest digest; actual fresh owner HostEpoch/G; one entry per required original lifecycle with canonical ProcessRecord, fresh OwnedObservation, achieved containment bound, exact transferred/recovered stream roles and current ready native binding. Include each original capture source's identity, verified conversation/incarnation and committed cursor at capture_at, plus its fresh generation-bound capture registration. Missing required lifecycle/stream/source or stale/unreadable native observation refuses publication; an old receipt/hash alone proves none of these facts |
| se.handover.retained-queue/v1 / queue_cut_sha256 | Original NativeQueueId/incarnation, keyed plan, checkpoint owner/freeze event, native manifest digest/count, original admission/promotion-dedupe/hold cut, and the actual independent native flush/reopen/readback observation verifying that retained cut. Source bodies remain solely in the native queue. A path, new epoch, engine debt, count or old digest without that readback cannot supply the proof |

Use the owners' checked lossless ID/path/record codecs and one versioned compact
JSON encoding with recursively sorted keys, integer numeric values and no unknown fields;
hash UTF-8 bytes prefixed by the schema domain and a zero byte. Sort lifecycle
and capture-source entries by their canonical IDs; duplicate/missing entries
refuse. The factory reads the canonical original facts and actual native reader
results before constructing these documents. They are attestations inside the
trusted host, not authority imported from an agent-supplied hash or JSON body.
Stage/hash them through existing bounded chunk permits under protected host
custody at STATE/recovery/handover/<sha256>.json, retain their digest references
with the completion fact, and exclude bodies,
credentials, nonce formatting and raw handles. A complete document exceeding
4 MiB refuses recovery with custody retained; never truncate it into a complete
attestation or reserve 4 MiB per session. Missing queue readback can leave native
routes pending until an authorized native adapter can prove the original cut.

## 7. Client transport, provenance and HTTP

### 7.1 Synchronous discovery and local framing

BlockingIpcClient uses RuntimeFilesystem.endpoint without G, verifies actual
native owner and server, performs handshake, then sends exact-G calls through
BlockingTransport. Its Unix and Windows implementations are blocking native I/O
with one absolute deadline; Ctrl-C/cancellation cannot reset it or undo COMMIT.
The host's async endpoint/lease wrappers use the same native backend under bounded
blocking admission, not another lock/write implementation. Initial unknown G is
legal; an invented zero/one generation is not.

EndpointRecord schema 1 contains address, HostEpoch/full instance, separate engine
generation, host kind, optional listener port, exact API, package version and
image digest. Protected endpoint.json is ≤16 KiB, atomic,
no credentials, address tagged unix_socket/native path or windows_pipe/name.
NativePath is lossless bytes/UTF-16. It is a routing hint, not custody. Unix socket
is in verified-owner 0700 directory, socket 0600. Windows server requires
**FILE_FLAG_FIRST_PIPE_INSTANCE**, **PIPE_REJECT_REMOTE_CLIENTS** and the accepted
user-only pipe DACL. A preexisting instance refuses, never joins the squatter.
Windows clients set **SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION before
connecting**, then verify GetNamedPipeServerProcessId plus exact start/image/SID;
server checks GetNamedPipeClientProcessId and actual token SID. Linux uses
SO_PEERCRED; macOS LOCAL_PEERCRED + LOCAL_PEERPID. ACL/peer/native unsafe code
belongs to se-proc; IpcPlatform accepts BorrowedFd/BorrowedHandle, not ownership
conversion of an async stream into std::fs::File. The process-platform owner is
5p, the accepted section-30 maintainer; no unsafe code is added in se-host.

Wire v1: four-byte unsigned big-endian length, then that many UTF-8 JSON bytes,
maximum 1 MiB request; reject zero/oversize, malformed UTF-8/JSON, duplicate or
unknown fields, depth >64 and incomplete EOF **before dispatch**. One outstanding
operation/connection; serialize complete response frames. Default local result
cap 262,144 bytes, hard max 1 MiB; MCP default 32,768 including its final wrapper.
Do not slice encoded JSON or append unbudgeted marker/window metadata.

Handshake: native peer/server proof first; server sends ServerChallenge(API,
epoch, image digest, fresh 32-byte nonce); client sends ClientHello(exact API,
optional expected G, reply cap, protected authority); server sends ServerHello
with actual G/epoch and effective cap. OwnerProof MAC is HMAC-SHA256 over
length-prefixed `se.ipc.owner/v1`, API, epoch/image, server nonce, fresh client
nonce and verified peer identity. Challenge is channel-bound/one-use; machine
secret never crosses IPC. Session/Launch bytes travel only after server proof,
never in logs. Exact API equality, not minor-range negotiation.

Call envelope contains API, positive request_id, discovered G, optional per-call
authority and Operation or Hook. Operation has registry name, closed arguments,
optional stable key; decode once to AdmittedOperation then invoke core. Hook is
the fixed Claude operation mapping. **No Nudge request remains**: in-host commits
already wake debt, while direct writes are recovered at activation. Reply echoes
id/API/G and either typed result or ErrorEnvelope. Transport IDs are not durable
idempotency keys. Broken post-COMMIT reply resolves by original operation key.
Five-second hello/write bounds, 30-second ordinary call ceiling; registered
custody deadlines may return truthful pending rather than block forever.

### 7.2 Owner provenance on every path

| Path | Owner possible? | Mandatory authority provenance |
| --- | --- | --- |
| CLI over peer-authenticated IPC | Yes | Correct OS user + machine proof, **outside every managed agent tree**, no present session authority/provider marker; ancestry checked by native process owner |
| Hostless direct CLI | Yes | Same native self/ancestry and machine-credential checks before shared lease/admission; unreadable ancestry refuses Owner |
| HTTP MCP or stdio model tool | **Never** | Verified current session/launch-derived bearer per call; OwnerProof variant explicitly refuses |
| Helper token issuance | Session helper, or legal CLI owner route only | Same session/ancestry/provenance rules; protected IPC, not browser/HTTP issuance |
| Trusted SE Code native UI | Yes | In-process OwnerAuthority from native control plane; human-only operations additionally require its UI-gesture HumanPresence token |

Removing SE_SESSION does not grant owner: job membership, cgroup subtree, managed
session/group/parent chain and present provider markers still withhold it.
Absent markers prove nothing. Invalid/expired/revoked **present** session authority
refuses; no owner/cwd/default fallback. Unreadable ancestry refuses owner for
ordinary owner-only operations too, not only destructive/human-only verbs.
Human-only CLI actions additionally require console/TTY stdin and stdout outside
agent trees and no SE_SESSION. Native UI HumanPresence is separate from CLI TTY;
model tools cannot construct either. This is the accepted mistake/drift boundary,
not an attempt to sandbox a hostile same-UID program.

AdmissionAdapter/Dispatcher are concrete common implementations of these stages,
not polymorphic public service traits. Every call, including multiplexed session
calls, rechecks G, credential revocation/binding revision and scope. A supplied
invalid authority never falls back to connection authority. Creator control is
only the current can-create grant plus immutable same-project direct created_by;
no grandchildren/all-agent privilege or private mailbox read follows from it.

### 7.3 HTTP inventory and concrete parser

Reuse **the HTTP crate SE Code's server already links**, verified against that
server's Cargo.lock at build start, with its existing runtime integration.
The desktop lockfile alone does not establish a shared server dependency; do not
assume hyper is present or add a second stack. If the server links no HTTP crate,
use a minimal **POST-only HTTP/1.1 MCP parser**: fixed routes, bounded headers and
Content-Length body, no chunked/ambiguous framing, pipelining, upgrades or SSE.
The fixed GET mail/livez auxiliary endpoints below remain supported through the
same bounded front end, with no request body and no generic HTTP proxy surface.
Standalone uses the selected common stack/parser. No TLS/client stack or hidden
process/server per agent is introduced. Both parser choices enforce the same
Host/Origin/Sec-Fetch-Site, credential and final-envelope budgets below.

Admission order: bounded parse -> origin-form target -> exact Host/port ->
Origin/Sec-Fetch-Site -> method/media -> credential -> core scope. Host is exactly
127.0.0.1:P or localhost:P; Origin absent or exact local http origin, never null,
suffix matching, alternate IP spellings, wildcard/reflected CORS or forwarded
headers as authority. HttpRequestHead carries **sec_fetch_site**: if present,
only same-origin or none is legal. Missing Origin cannot erase a cross-site
fetch signal. No Access-Control-* header is emitted. OPTIONS always 405.

| Route | Alpha method / authority / result |
| --- | --- |
| `/mcp` | **POST only**, Content-Type application/json; return application/json only, no SSE; GET/OPTIONS 405; bound session per call, never Owner |
| `/stateengine/mail/next_change` | GET, session bearer, one parked ≤25 s Claude wait; bounded IDs/cursor only, no marker or body |
| `/stateengine/livez` | GET, anonymous `{ok,api}` only; no private counts/projects/readiness fiction |
| `/stateengine/local-http-proof` | POST JSON anonymous bounded challenge, server-auth HMAC only; no token issuance/owner grant |

There is **no HTTP mcp-token route**. Installed `se mcp token` issues over the
existing protected IPC operation only. Before returning headers it verifies the
listener's challenge proof so a squatting port gets no bearer. Separate HMAC
domains `se.http.server/v1` and any owner/client request proof; bind nonce,
image/epoch/G/origin and consume challenges once. Server proof cannot be replayed
as client authority. Token/credential bytes never enter query/argv/environment,
model context, telemetry, errors or support bundles; SE_SESSION is only a handle,
with actual secret in the accepted owner-only pin or protected native channel.

Limits from shared 70/80: 16 KiB headers, 1 MiB body, depth 64, ten-second headers,
30-second ordinary request; reject duplicate length/ambiguous framing/coding and
count actual bytes regardless of Content-Length. **64 active connections plus a
separate parked-wait cap equal to session cap**, one wait/session, replacement
cancels its predecessor. Parked waits do not consume the 64 active slots; cap
metadata/buffers within the mail/listener memory allocation and refuse overflow.
The 25-second timeout rearm contributes **0.04/s per attended Claude session**;
section 80 now includes it, plus the separate live catch-up/auto-exit timer.

MCP discovery and schemas come from the closed OPS registry. tools/list/call
scope is bound identity, no project/actor overrides. One typed outcome feeds text
and structured content; budget the final complete JSON-RPC envelope, both copies,
window and marker metadata. Listing, even full-body, is read-only. A first full
item that cannot fit gets a precise budget error/remedy; do not silently truncate
or mark unseen bytes read. Hostless stdio advertises push unavailable, supports
legal reads/direct writes and refuses custody. Domain errors stay typed errors,
not successful empty data. Actual tool discovery/call is required qualification.

## 8. Session, takeover and mail state

SessionIdentity is durable project/agent/session, ProviderSessionId a real vendor
conversation, LifecycleId native custody; native HostSessionTarget also binds
epoch/session/fingerprint. They are not interchangeable labels. Opaque
SessionLease/TakeoverTicket retain actual keyed reservation intent, not caller
claims. SessionCoordinator uses core/store plus the concrete provider/native
adapters; there is no parallel SessionControl public trait.

| Session from | Input / necessary fact | To |
| --- | --- | --- |
| None | Authorized prepared binding/launch at expected absent/CAS | Prepared |
| Prepared | Process/native binding begins | Starting |
| Prepared/Starting | Verified failed/cancelled launch and durable end | Ended, cleanup obligations retained until witnessed |
| Starting | Actual provider/native binding, consent and FULL activation/readiness | Active |
| Starting/live | Readiness deadline, crash or unknown native state | RecoveryPending, not absent/ended |
| Active | Durable human/takeover/revocation hold | Holding |
| Active/Holding/Held | SE Code exits after proved custody/capture handover and retained queue cut | NativeDormant; actual activity and independent holds remain separate |
| NativeDormant | Reopened SE Code proves original queue/adoption and current target | Active or actual Held/Revoked; promotion only after verified native settlement |
| Holding | Same-target point observation proves no execution | Held |
| Held | Genuine human input promotion under valid target | Active; engine cannot synthesize it |
| Active/Holding/Held | Explicit stop/end | Ending, hold first where execution/input exists |
| Ending | Actual native end/outside closure and end commit | Ended |
| Any nonterminal | Actual credential/target revocation | Revoked; process closure remains separate |
| RecoveryPending | Exact custody/binding/native observations | Actual Active/Held/Revoked/Ended; never unconditional Active |

Unlisted transitions refuse. Activity is orthogonal: Idle -> Executing on real
turn start, Executing -> Interrupting on request, -> Idle only on actual completion.
Unknown/unreadable is not idle. Native Eligible/Held/Revoked is section 10's state;
revocation cannot be cleared by a human resume/reconnect. A new legitimate binding
gets fresh revision/capability and preserves applicable human holds.

Takeover: commit replacement reservation; durably hold predecessor even with no
pending mail; interrupt only against that HoldReceipt; require exact
active_session **Present(None)**; perform required se-proc outside client/scope
stop; recheck intent/G/revision; final native Select atomically rechecks all
superseded targets held/nonexecuting, revokes/selects; read back selection; only
then enable/commit successor FULL binding. Paged active_sessions, interrupt ACK,
Absent/Unknown/Unreadable and timeout never prove no execution. Human resume
between point read and Select makes Select refuse. Cross-store effects are keyed
intents, never a transaction spanning callbacks. Aborted takeover records failure
without releasing holds/re-enabling predecessor; actual native state is reported,
not re-held as cleanup. Standalone uses durable host admission hold plus outside
process exclusion; it cannot claim a SE Code Select witness it did not obtain.

### 8.1 Single native queue and durable debt

SecodeAdapter calls canonical HostServices hold/interrupt/active_session/
binding_state/adopt_binding/update_mail_target/deliver_notice/notice_status with
exact target/epoch and generation-fenced ServiceOptions. Its concrete translation
checks every shared/permissive ID/range/fingerprint. No duplicate public native
queue trait or alternative pending-input queue exists. MailNotice/native admission
shapes and canonical digest are the accepted section-10 definitions: ordered
IDs, stable intent and cursor, no bodies; transient generations excluded from
digest, epoch checked separately. Hold/Refused never acknowledges admission.

| Debt state | Observation | Result / retry |
| --- | --- | --- |
| Unoffered | Message COMMIT | Indexed recipient debt and coalesced watch, even with no live session |
| Unoffered | Reserve distinct session/message set | Stable NoticeId/digest/target/cursor intent before callback |
| Pending | Native Admitted/Replayed, matching original target/key/digest/event/sequence | Record original queue admission once; still unread, not presumed promotion |
| Pending | Provider complete transport frame | Offered only; matching actual input acceptance may later establish delivered |
| Pending/Offered | Held/Refused | Keep intent/debt/cause; no admission/read cursor advance |
| Uncertain | Lost reply/panic/deadline | Query original notice_status before retry, never allocate a new key |
| Uncertain | Exact successful Absent + eligible target | Retry original ID/digest; Unknown/Unreadable retain uncertainty |
| Held | Genuine native human eligibility event | Re-read binding/status, retry same debt; restart/mail/reconnect never unholds |
| Offered/admitted | Real correlated native/provider promotion/input | Delivered; still not recipient read |
| Any | Recipient complete message.read or explicit ack | Durable attributable read marker |
| Any | Recipient dismiss | Dismissed, not read/completed |
| Any | Permanent target revocation | Preserve original history/debt; new legitimate target gets a new explicit intent |

Native admission proves durable queue commit, not promotion. Section 10 has no
promotion settlement call; without actual captured input correlation or recipient
read/ack, leave delivered unwitnessed. Validate original committed epoch/event/
sequence through the verified adoption map; never rewrite an old admission as a
fresh generation's event. Native state nudges contain no bodies/ACK and merely
schedule reconciliation. Only SE Code promotes its existing queue at safe
steer/idle boundaries. Each callback checks immutable wrapper G and current native
fence inside the atomic native transition; no lock/transaction spans an await.

Recipient debt is oldest unresolved indexed work, not newest-N floor rows.
Bound batches ≤32 IDs/8 KiB; coalesce watches and schedule fairly. Resident caps
do not cap durable mailboxes; pressure retains debt and reports pending. No idle
retry loop. Activation, real commits, actual eligibility/repair and the bounded
live catch-up trigger work. All full lists are read-only; owner inspection cannot
manufacture recipient read. Explicit recipient read budgets the final response
before marking; incomplete body does not mark omitted content read. ACK is a
separate deliberate recipient acknowledgment, not task completion or reply.

## 9. Provider modes, capture pinning and configuration

### 9.1 Harness API semantics and mode matrix

Harness::kind selects closed Claude/Codex implementations. probe bounds actual
executable/version/feature output to 16 KiB/five seconds and refuses missing/old/
unrecognized protocol **before** disturbing an incumbent. configuration produces
a plan without applying it. invocation produces literal provider argv/environment,
never spawns. attach takes the real owned-process reference/record/transport and
proves conversation/readiness; adopt verifies the same facts after recovery.
bell returns actual Offered/Held/Refused, transcript returns a trusted source,
capture uses core consent/dedupe/store commit, and graceful_stop returns only
ProviderInterrupt request evidence. LaunchCoordinator alone obtains native stop/
exit witnesses. ProviderInterrupt.requested and provider completion are not scope
absence. Stream/native ownership never moves merely on trait-object Drop.

ProviderIoPlatform is genuine Unix/Windows native I/O polymorphism: open creates
explicit child Files and retained host transport; read yields bounded bytes or
actual EOF; read failure retains any partial bytes and structured cause, write
reports actual completed byte count plus failure when present; close awaits native
completion/cancellation. Outer errors occur before an operation is accepted or
when no completion can yet be proved; a completed cancelled/failed native read or
write returns its retained partial-data/count result rather than losing it inside
an unstructured error. Coordinator framing requires all bytes of one frame
before TransportWritten. Native outstanding buffers remain owned on future drop.
ProviderStream selects stdin/stdout/stderr; no unbounded provider log. These safe
contracts keep native unsafe/IOCP work below the host without a Tokio dependency
in se-proc or a thread per pipe. Native bridge implementation is coordinated with
the section-30 maintainer; no backend is implemented in this design.

| Mode | Capture source | Mail path | Interrupt / liveness |
| --- | --- | --- | --- |
| Claude headless | **Pinned transcript + command hooks are authoritative**; stream-json supplies activity/input correlation only, not duplicate captured turns | Serialized persistent stream-json stdin; complete write is offered, correlated real input acceptance is delivered | Provider supported control/stdin graceful request plus coordinator native stop; process/root/scope and stream events, no polling |
| Claude attended | Same pinned transcript/hooks; native directory events and live catch-up recover missed hooks | Small provider-native JS mod, one authenticated GET wait, attributed prompt after safe idle boundary | Genuine human stop/hold plus provider/native control; terminal/process/native binding events |
| Codex stdio headless | Actual app-server completed item/turn IDs, optional **pinned** rollout as catch-up only | turn/start idle, turn/steer exact active turn; real response/input correlation | turn/interrupt request then actual turn completion; process and exact scope remain separate |
| Codex private WebSocket attended | Same canonical app-server item/turn capture, no duplicate hook ingestion | Same RPC through actual WebSocket-over-UDS transport and stock remote UI | Same RPC/native witnesses; private transport/terminal attach separately qualified on each OS |
| SE Code embedded | Direct canonical capture_turn with native event identity; no invented transcript file | Its existing native input queue via concrete SecodeAdapter | Durable hold -> interrupt -> exact point active state; native source fence/epoch and custody where applicable |

**Windows Codex supported stranger path is explicit:** `se launch AGENT --detach`
starts stock app-server over stdio with the normal user's existing login/home,
safe permissions, real tools and saved-thread resume. The same mode is available
on all OSes and is the headless journey baseline. Attended Windows Codex requires
the stock build's qualified private attach capability; until demonstrated, that
mode refuses ProviderProtocolUnsupported/WindowUnavailable with the detached
command. This is an honest supported fallback, **not** a passed attended alpha
requirement; windowed support remains a release qualification obligation.

### 9.2 Trusted transcript pin is the only read authority

TranscriptPin is created by trusted bind from the host-controlled provider launch
configuration/native conversation and known provider source resolver, or an
explicit owner-adopted validated source. It binds exact identity, conversation,
NativePath and file incarnation/identity. The hook's **claimed_transcript is
untrusted**, even with a valid session credential. Resolve it without following
links and require equality with the already pinned source. A different path,
symlink/reparse target, foreign conversation/incarnation or non-regular file
refuses **before any file bytes are read or capture is staged**. If the pin is
missing/unreadable, capture is unavailable; a hook cannot supply a replacement.
Do not read arbitrary files from `payload.transcript_path` or treat capability
possession as filesystem-read authority.

The pin retains an open native source handle in the supervisor. file_identity is
SHA-256 of the canonical stable native file-ID tuple (Unix device/inode or Windows
volume/file ID), not a hash of growing contents or merely the pathname. Compare
the opened handle against that retained pin; ordinary append does not invalidate
identity. File bytes/content digest belong to individual capture records.

Open only the pinned regular file with no-follow/native handle identity checks,
size bounds and chunk reads. A path replaced between check/open is caught by
handle identity comparison; accepted rotation requires a trusted provider/owner
rebinding transition, never hook-path substitution. TranscriptSource reports the
pinned path, actual next committed offset and incarnation. Incremental 256 KiB
chunks, complete-line decoding and accepted storage limits apply; a vendor line
above section 80's 4 MiB ceiling gets an explicit oversize verdict. Captured turn
and cursor advancement commit together. Decode/IO/write failures retain old
cursor; incomplete final line waits for a real signal, not a timer scan.

CaptureInput validates conversation, stable vendor_turn/item ID, role, consent,
canonical Body and digest; natural dedupe retains original event. Changed content
under one identity is an explicit error. Rotation/truncation preserves old turns
and reports actual mismatch, never resets offset and silently replays the file.
Erased content cannot be resurrected by catch-up. No body text enters diagnostics.
Consent missing is visible suppression, not success or private context access.

### 9.3 Claude launch, hooks and mod

Use qualified per-launch --settings/--mcp-config/--plugin-dir inputs, safe profile
flags and explicit --session-id for new selected conversation or verified --resume
for existing. No global settings/login mutation, forked CLI or bearer argv/env.
Bind under the owned pre-exec/native reservation before session-start private
context; session-start only validates actual echoed identity and reads. Mismatch
returns no private context and schedules coordinator revocation. A readiness
result still requires real provider echo/acceptance, not prepared argv alone.
Initial version floor is the established mods-capable Claude 2.1.287, with exact
required features checked; version number alone does not prove a private API.

Fixed native mappings: SessionStart -> session-start, UserPromptSubmit -> prompt,
Stop -> stop, StopFailure -> stop-failure through `se hook claude EVENT`, bounded
1 MiB stdin, no arbitrary event. ClaudeHookInput has kind, real conversation,
untrusted claimed transcript and bounded payload. Authority comes from protected
binding, not payload IDs. Concrete ClaudeHookAdapter uses the pinned-source rule.
Session-start returns matching hookSpecificOutput/additionalContext only; prompt
captures real new input and may add bounded context; stop/stop-failure capture
incrementally and return **empty stdout**, no block/continue/recursive turn.
The [native hook reference](https://code.claude.com/docs/en/hooks) defines vendor
field semantics; implementation checks the installed supported version.

Hook failure exits zero for provider availability with bounded nonsecret stderr,
but HookOutput carries actual captured Read/failure and status exposes failed/
suppressed capture. Zero exit is never capture evidence. If persistence itself
fails, do not claim a durable diagnostic exists. Hosted hook writes go through
existing writer. With no owner, bounded auto-start may be attempted; if unavailable
within hook deadline, same transaction code under shared direct lease is the
legal fallback. No direct write while an exclusive host still exists.

Attended plugin is ~200–350 lines of provider-native JS, no Node process/executor.
Manifest plus hooks module registration uses the installed API types. One
credential-scoped wait returns IDs/cursor only. Submit attributed mod text after
blocking hook returns; never `asUser:true`, body/secret prompt injection or
concurrent ordinary turn. Human stop/session end/revocation cancels its wait;
new mail/reconnect/restart cannot clear hold. The [mods API](https://code.claude.com/docs/en/plugins/mods/reference)
limits an entire HTTP fetch to 30 seconds: use ≤25 s waits, **0.04/s renewal per
attended session**, as updated in 70/80. One wait per session, own cap outside 64.
No 25-minute promise or unproven attended-push/idle measurement. Server never
redirects; plugin verifies private final origin and never sends bearer in URL.

### 9.4 Stock Codex RPC and direct SE Code

Headless baseline: stock `codex app-server --listen stdio://`, newline JSON.
Private unix://PATH is WebSocket HTTP Upgrade, not JSONL over a socket. No
unsecured TCP fallback. The [app-server contract](https://learn.chatgpt.com/docs/app-server)
labels WebSocket experimental; qualify installed-version schemas and actual OS.

Sequence: initialize once -> initialized; thread/start for explicit new or
thread/resume exact saved threadId; persist actual returned thread.id; turn/start
idle with safe model/cwd/approval/sandbox/MCP config; turn/steer busy with exact
expectedTurnId; capture actual completed item/turn IDs and status; interrupt exact
thread/turn then await actual completion, not just request ACK. Reconnect repeats
handshake and exact saved-thread verification, resolving original notice status
before retry. Vendor frames omit JSON-RPC version header; response IDs correlate,
notifications omit id. Bound framing, stderr and item content. Older than the
established 0.163 HTTP-tools floor or lacking required feature refuses before
launch, never runs silently without coordination tools.

Use per-launch MCP/helper configuration and user's existing CODEX_HOME/login;
no managed replacement home, hooks.json injection, fork or automatic approval.
Headless unsupported approval reports pending/refusal rather than inventing a
human decision. Turn completion is separate from process exit/task effect.

Embedded SE Code registers the Prepared Host/G before activate, supplies exact
native epoch/fresh fenced services and calls canonical linked methods directly.
Model tools use BoundSession; native UI alone supplies trusted OwnerAuthority and
HumanPresence where required. No StateEngine child, MCP config hop, mail HTTP
hop or parallel queue. API errors retain opaque engine cause/remedy without
proprietary type dependencies in the permissive crate; the public stub returns
NotIncluded visibly while ordinary SE Code stays usable.

### 9.5 Owned configuration and remove

ConfigPlan is owned edits plus ephemeral files, not a generic writer. IntegrationEdit
has path/key/expected prior digest/replacement **nonsecret** bytes; secrets use
OwnedLaunchFile's protected Secret. Compare actual prior entry, no-follow path,
atomic write and outside digest readback before claiming install. Preserve unrelated
keys/comments, repository files/Git and provider auth. Unknown/unreadable is not
absent. Modified owned entries refuse IntegrationConflict rather than overwrite
from an old full-file backup. Remove holds/revokes/stops exact owned instances,
then removes only matching owned entries/secret exposure with readback; preserve
foreign additions and history. Credential revoke precedes unlink; cleanup failure
is RemoveIncomplete, not a claim every process/file vanished. Erasure is separate.

## 10. Performance allocation: section 80 is authoritative

Numbers are decimal MB and targets, not cargo-check results. All attributed
helpers count; provider/model processes are reported separately. B1 embedded
≤30 MB; B2 ≤100 ms includes the **first complete authenticated session response**;
B3 zero persistent StateEngine processes embedded/one standalone/none per agent;
B4 ≤25 MB standalone **with one live session after real work**; B5 <0.1% of one
core; B6 ≤1 wake/s with none, ≤2/s with one. B7 CLI reads p95 <20 ms across all
30 samples; B9 writes through a running host p95 ≤20 ms; do not falsely extend
that to already-slow cold direct/FULL security writes. Native custody/readiness
and model latency are measured separately with section 80's launch/stop targets.

### 10.1 Memory rows, mapped without a second budget

| Section-80 §3.1 embedded row | MB | Host responsibility |
| --- | ---: | --- |
| Code pages | 4.0 | Host/core/store/proc touched code, shared once |
| SQLite page caches | 6.0 | Writer + two lazy readers ×2; store owns cap |
| SQLite connection/schema/statements | 1.5 | Exactly the accepted allocation; no connection/session |
| Sessions, 16 ×~50 KB | 0.8 | One async coordinator/session including task overhead, not the previous 8 KiB estimate |
| Mail watches/subscriptions | 1.0 | IDs/coalesced watches, parked-wait metadata included |
| Listener/MCP buffers | 2.5 | ≤2 large bodies at once, global byte permits |
| Capture buffers/parsing | 1.0 | Two active 256 KiB chunks plus bounded parsing |
| Transcript watcher | 0.5 | Reactor/native state, **no extra notify thread** |
| Native custody including Windows collector | 0.2 | No invented 2 MiB reservation or second collector |
| Resume assembly | 0.5 | Four bounded assemblies |
| Allocator slack | 2.0 | Account actual allocation/stack RSS, not virtual reservation |
| Spend / reserve / total | 20 / 10 / 30 | Atlas absent embedded |

Standalone follows **§80 §3.2 exactly**: code/libraries 5 MB, current-thread Tokio
and ≤2 blocking threads 1 MB, SQLite page caches 4 MB, connections/statements
1 MB, sessions/mail/listener/capture/watch/custody/resume 6.5 MB, **optional
in-host Atlas 2 MB**, allocator 1 MB: spend 20.5 MB, reserve 4.5 MB, total 25 MB.
Atlas cold-index child has its separately approved 64 MB transient window; not a
hidden persistent helper or a reason to erase its 2 MB steady-state reservation.
Native/worker resident stacks are charged to these rows/reserve; virtual stack
address space is not RSS, and no stack is omitted because it is a thread.

Defaults are **16 sessions**, 64 active connections, **16 separately parked mail
waits**, 1 MiB aggregate resident queued payload, 32 notice IDs/session, 512 IDs
aggregate, 262,144 local reply bytes and two admitted blocking jobs. This replaces
the old unbudgeted 128-session default. Embedded may explicitly negotiate up to
128 only against its reserve: 128×50 KB=6.4 MB, +5.6 MB over the 16-session row,
20+5.6=25.6 MB before the remaining reserve; all other aggregate caps stay fixed.
The separately parked-wait count scales to that negotiated session cap (one per
session), while its aggregate byte allocation stays fixed in the mail/watch row.
Release header/body parsing buffers before parking and retain only bounded
IDs/cursor/auth metadata; no 16 KiB header or 1 MiB body reservation per wait.
Standalone policy stays at 16 until an independently measured within-B4 allocation
is approved. A cap is admission/backpressure, not preallocation; durable debt
retains overflow and no oldest unread item is dropped. Parked connection buffers
are small ID metadata, not 1 MiB per wait. Enforce global body/buffer permits.

### 10.2 Startup rows and deferred adoption

| Section-80 §3.3 step | ms | Host behavior |
| --- | ---: | --- |
| Compatible store open/header/WAL | 4 | No implicit migration |
| Indexed bounded pending-effects discovery | 2 | Schedule, do not drain every route before response |
| Projects/profiles | 2 | Bounded initial selection |
| Runtime lease/endpoint/listener/IPC | 2 | Actual owner/security checks |
| Static tool catalogue | 1 | Generated schemas, no runtime catalogue construction |
| First session FULL binding/credential activation | 8 | Actual fsync, no early ACK |
| First bounded continuity | 8 | Real authenticated response before B2 endpoint |
| Spend / reserve / total | 27 / 73 / 100 | Reserve covers cold/Defender/new-store cost, not waived work |

Nell's runtime.owner amendment adds an explicit FULL owner-publication commit
before start_writer. Charge that real work to §80 §3.3's 73 ms reserve (the
27 ms nominal table predates this amendment), not outside B2 or invisibly inside
first-bind timing. The outside authenticated-response measurement includes both
owner publication and first-session FULL activation; their combined cost remains
unqualified and can fail the unchanged 100 ms ceiling.

Re-adoption, Codex reconnect, backup and Atlas run **after that first ready
response**, with explicit per-route Recovering/status; no 50-route native census
on B2's critical path. Initial readiness is not a claim all old agents are ready.
B8 re-adoption/handover remains ≤500 ms target (§80 §3.4: 165 ms planned spend,
335 reserve), unmeasured. Per Prime's alpha scope, re-adoption means custody plus
capture with no lost/doubled input; SE Code-native input/mail routes may remain
explicitly NativeDormant until SE Code reopens. It does not claim fully active
native routes or change daemon-launched agents. The 500 ms interval starts at
cutover after the complete quiescence barrier and ends at actual custody/capture
re-adoption; request-to-quiescence is measured and reported separately, including
interrupt/idle delays. Do not defer the first FULL bind/continuity outside B2
or fabricate missing adoption success to stop the clock.

CLI read spend is section 80 §3.5 (Linux 7.5 ms, Windows 13 ms plus reserve);
status uses synchronous protected endpoint + exact native identity, not a runtime
or census. Ordinary write/command-hook, MCP and burst targets are §3.6; direct
and FULL prototype tails remain contrary evidence requiring qualification, not
weaker sync/auth. A missed budget blocks release rather than prompting a rerun
until green. Observer definitions stay section 80's per-OS outside measurements.

### 10.3 Idle and work-triggered maintenance

Use §80 §3.7: executor/writer/accept/collector blocked; native watch events only;
**0.04/s per attended Claude wait renewal**; one live 15-minute catch-up about
0.0011/s; one auto-start exit timer after ten empty minutes. Expected baseline
~0.002/s no session, ~0.003/s plus 0.04/s per attended session; >0.05/s plus the
attended contribution is a defect even if under the hard ceiling. No claim of
zero wakeups with the vendor's bounded request API. Shared 70/80 are already
updated by Prime; section 40 supersedes any stale 25-minute text in the bundle.

Backup starts after readiness; use the accepted shared BackupContext, one stable
read transaction, 64-page steps, abort at 64 MiB WAL pressure instead of blocking
writes, release pin and retry only next start-of-day. Its synchronous job keeps
one background permit throughout; the other remains foreground. No per-command
backup, minute retry, database watcher, 250 ms mail loop, 1.5 s process loop,
15 s organ tick, projection timer or hourly canary. Explicit live catch-up and
empty auto-exit are the only stated supervisor timers; active stop/debounce/retry
has a work-bound lifetime and cancels when resolved.

## 11. Error direction and required witnesses

One shared Code/Detail/ErrorBody/ErrorEnvelope catalog, typed remedy and real
cause. No new free-form wire strings. Store/proc domain causes preserve exact
context through the section-50 mapper. Read::Absent requires an authorized actual
lookup; Unknown/Unreadable/Present(None) remain distinct. Page/Window preserve
omissions, unreadables and progressing cursors. A post-COMMIT lost response or
cancelled wait is keyed readback, not proof of rollback. Secret-bearing raw
stderr/argv/native payload never enters errors/bundles.

| Boundary | Existing codes raised / cause / legal remedy |
| --- | --- |
| Input/wire | usage-invalid-value, input-unknown-field, input-too-large: fix closed schema/budget; no dispatch/marker on invalid input |
| API/version | api-version-unsupported, runtime-version-mismatch: upgrade matching side; no negotiation bypass |
| Native peer/owner provenance | os-user-mismatch, listener-admission-refused, owner-required, human-terminal-required: correct user/native owner route; never ambient fallback |
| Credential | machine-credential-missing/unreadable, capability-invalid/revoked/expired, session-binding-unproven: authenticated init/repair/renewal/rebind, no owner conversion |
| Runtime | runtime-not-running, custody-unavailable-hostless, runtime-owned-elsewhere, runtime-start-failed/pending: legal up/actual-owner inspection, not a PID shortcut |
| Generation/shutdown/handover | session-generation-mismatch, runtime-handover-in-progress, runtime-drain-timeout, runtime-stop-unwitnessed: re-read exact key/G/ownership; retain unsafe custody; controlled restart for unjoinable worker |
| CAS/scope | revision-conflict, idempotency-key-reused, launch-in-flight, agent-already-running, grant-required, message-scope-denied, not-recipient: re-read/current authorization, preserve incumbent/original receipt |
| Provider | provider-cli-not-found/too-old/unrecognized, provider-protocol-unsupported, codex-app-server-failed, resume-reference-missing/unverifiable, provider-change-breaks-resume: install/fix/explicit --new where desired, never silent fresh thread |
| Process | process-identity-changed/unreadable, bare-pid-refused, job-breakaway-refused, window-unavailable, launch-failed/readiness-timeout, stop-unwitnessed/partial/deadline-exceeded: exact outside observation and legal supported mode; no weakened containment/name kill |
| Capture/config/remove | transcript-unreadable/truncated, hook-payload-invalid, capture-consent-missing, turn-invalid, integration-conflict/write-failed/readback-mismatch, remove-incomplete: preserve cursor/foreign bytes/history, repair actual pin/config; hook exit zero is not capture proof |
| Failure/cancellation | deadline-exceeded, cancelled, task-failed, internal: original-key outcome readback, named route failure or ownership/lifecycle-domain poison as specified; mutex poison never success |

A bounded se-proc stop is incomplete at the requested guarantee even if root
exited; Complete retains its actual supported OS bound. Windows explicit escape,
Linux Uncontained and macOS tracked-group limitations stay in the receipt. No
ownerless lock reclamation, empty-page absence proof, callback self-witness or
read-after-truncation claim satisfies a required effect. FULL security failure
closes admission with an error, never silently drops revocation.

## 12. Five journeys, mirrors and remaining integration work

Reviewers own the real clean-Windows/macOS/Linux scripts, Claude/Codex and actual
embedded/standalone composition. This author writes no tests or runtime bodies.
Compile checks establish declarations only, not native, provider, resource or
journey qualification. No deployment/config/listener changes occur here.

| Journey | Real consumer witness / closest false success excluded |
| --- | --- |
| J1 Install | Real download/version in fresh terminal, no Node; absent provider/config gives honest onboarding, not fake provenance |
| J2 Adopt | Existing work/Git preserved; safe real agent writes requested artifact and discovers/calls actual tools; PID/port alone is not readiness |
| J3 Come back | Exact stop/crash/handover path for that OS; same saved conversation with demonstrated recall; original-key capture/debt recovery and no duplicate input |
| J4 Two agents | Authorized send, actual target wake, recipient read/ack and performed work visible separately; Held/refused/lost ACK retain debt and huge metadata respects final wire cap |
| J5 Remove | Hold/revoke + achieved exact scope stop + owned config readback; foreign edits, reused PID or unreadable tracking remain named residuals, not broad kill/wipe |

Targeted review cases are the admitted return teeth, not a new test estate:
Starting cancellation before/after CAS; crash at each checkpoint and transfer
phase; lost activation ACK; actual Windows last-handle termination versus staged
handle overlap; native task/sink panic isolation; owner CLI inside an agent tree
with SE_SESSION removed; wrong Host/Origin/Sec-Fetch-Site/pipe instance/SQOS;
forged hook transcript path; wrong-G delayed callback; human resume between
absence/Select; held zero-mail predecessor; stuck writer; disk-full/FULL failure;
transcript rotation; final wire budgeting and user-edited removal entry.

Mirror coverage is explicit: CLI/MCP/library share core semantics but transport
owner authority differs; sync CLI/hooks have no Tokio; async host uses the supplied
runtime; attended/headless and Claude/Codex use the mode matrix; SE Code alone has
native queue callbacks; standalone/embedded share debt/generation and staged
handover barriers; actual read and write/disposition remain separate. Platform
results name their exact exercised mode; Linux prototype cannot qualify Windows.

Integration obligations still requiring owner review/measurement:

1. **Accepted section 20** supplies the typed FULL runtime-owner/transfer CAS,
   private runtime_ownership_fact maintenance read and non-secret runtime_owner
   head. The field/phase mapping in §6.1 consumes those declarations; native
   witness, FULL durability and crash behavior still need implementation proof.
2. **5p, section-30 process maintainer**, owns native peer/ACL and the safe overlapped
   IOCP stream bridge. ProviderIoPlatform consumes its create/attach/read/write,
   scoped close/completion and manifest-accessor declarations described above;
   native qualification and single-collector integration remain unmeasured.
   No host unsafe or second collector.
3. **Alpha + host composition** publish the permissive linked API, unify actual
   Tokio/selected-HTTP/SQLite packages, catch unwinds and apply the reconciled route-local
   versus ownership/lifecycle poison policy at the existing boundary. Iris's
   major-2 handover entry and queue fence are required, with Prime's quiescence,
   cutover timing and explicit native-route dormancy policy. Section 40 adds no
   proprietary copy of that permissive surface.
4. **Provider/platform qualification** proves attended Claude mod prompt/hold
   behavior and idle cost, private Codex attended transport on every OS, native
   scope/EOF/resume, real live handover, B1/B2/B4/B7/B8/B9. Explicit detached
   Windows Codex path is supported design, not a waiver of windowed alpha work.

Private helper/layout/batching choices remain implementation freedom within these
truth/authority/lifecycle/resource bounds. A public API/schema/ownership change
belongs with its owner; no signature compilation substitutes for real outside
witnesses. Prime alone integrates and lands the resulting complete candidate.
