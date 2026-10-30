# 40 — Host runtime and harnesses

Design candidate, not runtime implementation or qualification. Owner: Vera.
Round-2 reconciliation base: assembled rust-se `f25ca90`. Verification tier: kernel boundary design;
compiling declarations here, journey/black-box checks owned by reviewers.

## 1. Outcome, boundaries and source of truth

One StateEngine host runs inside SE Code or as one standalone daemon. It launches
real Claude/Codex agents, captures their work, resumes their original conversations
and delivers mail without confusing an offer with a read or a PID with custody.
The host implements the accepted [operation inventory](../OPS.md),
[types/linked API](10-types-and-host-api.md), [store](20-data-model.md) and
[process ownership](30-process-ownership.md), [security](70-security.md) and
[performance budgets](80-performance-budgets.md). The Node repository remains
the private factory with its existing engine; no fleet cutover, factory-history
import or factory CLI adaptation is part of this product.

* se-core owns identity, permissions and the single closed operation executor;
  se-store owns events, snapshots, the writer, migration and backup; se-proc owns
  native identity, containment, peer credentials, ACLs and native unsafe code.
* se-host owns supervision, process coordination, provider adapters, capture,
  IPC/HTTP and the proprietary implementation of SE Code's linked API. The binary
  owns argv/environment, human rendering and transient entry points.
* Operation and MCP-tool counts are generated from the registry. Private
  handover, hook and
  lifecycle protocols add no user command, tool, generic dispatcher or actor flag.
* Hosted writes use the exclusive runtime lease and one store writer. Direct
  writes use the same transaction path under a shared lease only with no host.
  The fixed security/decision transition set commits FULL; ordinary writes use
  NORMAL, which can lose several recent ordinary commits on power loss or OS
  crash, while preserving acknowledged application-crash commits. The sole owning
  host automatically applies supported additive migrations after a verified
  pre-migration backup; a live older host refuses with “run se down first”.
  Unsupported or too-new schema refuses with the specific upgrade/restore remedy.
* **Live standalone↔SE Code handover is in alpha.** Its retained coordinator uses
  section 30 and section 10's linked factory/native transfer seam.
* SE Code has one native input queue. The concrete adapter uses HostServices;
  no parallel NativeQueue trait or translated native DTO family. A transfer fence
  is distinct from a human/takeover hold and cannot clear either.
* Windows uses KILL_ON_JOB_CLOSE | BREAKAWAY_OK, never SILENT. Unstaged full host
  loss closes the last job handles and ends ordinary members. Same-process
  generation replacement and staged overlapping-handle handover are different.

No factory tooling, PostgreSQL multiplayer, remote HTTP, provider login manager,
telemetry, Node runtime, dynamic plugins or new permission bypass is introduced.
Atlas is compiled only into the standalone `se`; it is disabled by default and enabled by `atlas.enabled = true` in config.toml; in embedded SE Code that setting returns feature-unavailable.
Its build follows all five journeys and live handover; it never holds a milestone.
Its cold-index child has the section-80 transient bound. Agent CLIs
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
The later Linux attended spike (`vera-attended-proofs-20261030/REPORT.txt`)
used real Claude 2.1.312: a 30,008 ms fetch timeout, three 25-second renewals with
one parked wait, and attributed mail queued during a busy human turn until idle.
Stock Codex 0.163 used a private-socket app-server plus a viewable xterm TUI;
three turns and six distinct message IDs were independently read back from the
same saved thread. Stop/revocation and final-origin checks remain unqualified:
Claude's installed fetch API exposes neither caller abort nor a final URL.
The native pipe-transfer spike passed three cases each on Linux and Windows;
real headless Claude 2.1.314/Codex 0.166 two-way transfer passed on Linux and
Windows (two providers each), keeping process and conversation identity. These
are bounded prototype facts, not product store/lease/queue integration, Windows
job re-association under the required loop/failure campaign, all crash phases,
timing, macOS or embedded-memory proof.

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
| [harness.rs](../../crates/se-host/src/harness.rs) | CODEX_MINIMUM_VERSION; Harness (Claude/Codex implementations); ProviderVersion/ProbeRequest; ConfigPlan/IntegrationEdit/OwnedLaunchFile; HarnessRequest, HarnessAttach, HarnessBinding; ProviderIo/Transport/Invocation/Interrupt; BindingWitness/LaunchOutcome; OfferStage, OfferWitness, BellOutcome; TranscriptSource; ClaudeHookKind/Input/Output/Adapter; CodexTransport, CodexInvocation |

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

### 2.1 Implementation responsibilities

The detailed file/task estimates and total are generated from section 95; this
chapter keeps no second size table. Composition/model, blocking client,
runtime lifecycle/handover, native-process coordination, session/mail, trusted
capture, provider harnesses, HTTP admission and owned integrations are separate
cohesive modules. The current declaration files are not a mandate to grow six
runtime god files. Linked API changes use the exact statically linked contract;
JSON families carry their own schema versions. No N-1 encoder or schema-freeze
tooling is built before a consumed older family exists; the frozen SE Code
context adapter remains required.

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

The common launch path has **three commits**; events sharing a row are one
transaction with one request identity, not separate serial acknowledgments.

| Boundary / owner | Store boundary | Native/provider call and retained result |
| --- | --- | --- |
| Admission + C1 / core and coordinator | Validate caller/direct creator grant/profile/resume and expected revision; FULL reservation + prepared session + process-bound credential issuance, before any native effect | Probe required provider features before disturbing incumbent; only a named saved profile may opt into bypass |
| Prepare + C2 / coordinator | Commit actual ScopeCheckpoint (`scope-prepared`) under the reservation/G CAS | prepare_launch first retains its Starting arena slot and creates the exact scope, no vendor child; begin_launch only after C2 |
| Native start / coordinator | No transaction spans native work | Retain ticket/process/streams, arm watch and immediately poll; Pending waits for event/original deadline, no sleep loop |
| Helper exception / coordinator | One additional durable RootCheckpoint **between C2 and C3** for Unix terminal, macOS and uncontained helper paths | Commit real pre-exec start/group/intended image before authorize_exec; no fabricated Running/root image |
| Attach + C3 / coordinator and harness | One FULL actual process/root publication + trusted credential activation + session activation/readiness, consent/cursor where applicable, at expected revisions | Validate actual native identity and selected conversation, not intended image or argv; complete provider echo/readiness is required before success |
| Natural/failed exit / coordinator | Commit outside-witnessed Exited plus original exit/scope evidence | Release only after that commit; failure remains indexed cleanup debt |

The helper path therefore has **four commits**. Removing its separate root
checkpoint would allow vendor execution without recoverable group/start identity,
or falsely publish Running before actual exec. Retain this crash-rule exception
and include its cost in E3. C1/C3 group all compatible session/credential events;
prepared authority cannot admit an ordinary operation before verified first use.
An early trusted session-start handshake can supply the final root/conversation
witness and trigger C3; it exposes no private context or ordinary mutation until
that FULL commit. If readiness cannot be proved, return pending/failure while
retaining native custody, not a partial successful launch. Embedded SE Code has
no process-bound credential events and uses its distinct in-process bind path.

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

The core remains synchronous and never waits on a commit. It returns
`OpStep::Commit { batch, then }`: an owned typed batch and a typed continuation,
not a closure holding a transaction or borrowed connection. The host submits
`batch` through `WriterClient::submit`, awaits its `Completion` on the calling
async task, then invokes `then` with the actual committed receipt to construct
the result or next operation step. The store performs SQL on its one writer
thread; no host thread blocks waiting for that writer, and no core call waits
for IPC or starts a runtime. `wait_blocking` is CLI-only for hostless execution.
Submission refusal leaves no accepted write; a timeout, cancellation or lost
reply after acceptance cannot cancel the batch or invent failure/success.
Return `commit-outcome-unknown` (Unknown/transient) where the outcome cannot be
established: CLI remedy “rerun the same command with --key K”; MCP remedy
“repeat the call with the same idempotency_key”. Retain that original key for
readback/retry; notify mail/capture consumers only from the
actual committed receipt/wakes. Native/provider steps run only after their
required commit continuation, with no SQL transaction or native lock across await.

All async work uses the supplied Tokio Handle. No ambient spawn/current handle,
nested runtime or block_on. Embedded creates no runtime; standalone has one
current-thread executor. Constructor stores Handle without I/O/spawn. Tokio is
optional behind `runtime`; client-only builds have no Tokio dependency. The
library dependency uses a caret range, not an exact Tokio pin. SE Code's
shipping Rust server is `secode-server` in `crates/secode-product` at dev
`58e8a145f` (`E:\rust-secode`); its lock resolves Tokio 1.53.3 and bundled
rusqlite 0.40.1 / libsqlite3-sys 0.38.1. Composition must resolve one compatible
Tokio and one SQLite links=sqlite3 dependency. No library changes process umask
or installs a global tracing subscriber; owner-only file creation/readback is
per file, including SQLite WAL/SHM, under section 70.

| Work | Execution and owner | Bound / section-80 accounting |
| --- | --- | --- |
| Session state/mail/control, IPC/HTTP, vendor JSON framing | Supplied executor tasks, one coordinator/session | Section-80 session/mail rows, no thread/session |
| SQLite writes | One named se-writer OS thread, se-store owns it | Blocks on bounded receive; store lines, no shared-pool occupation |
| Foreground DB reads, transcript chunks, config filesystem, CreateProcess/native finite steps | Shared blocking pool, at most two admitted jobs | Never run sync file reads/CreateProcess on standalone executor; finite work only |
| Whole-copy backup / close_clean | One background/maintenance blocking slot for its entire synchronous call | At most one; reserve the other slot for foreground work; not a per-step fake async call |
| Unix process and watch events | Existing Tokio AsyncFd/kqueue reactor via ReactorAdapter implementing NativeReactor | se-proc HostConfig.reactor supplied; no Unix collector thread |
| Windows native job/process completion | One existing se-proc IOCP collector thread per host | Section-80 custody row includes collector; no RegisterWait pool or second collector |
| Windows provider stdin/out/err | Overlapped named-pipe host ends and IOCP readiness, bounded buffers | No tokio::fs::File/blocking read wrapper or thread per pipe; detailed below |
| Transcript watch | Unix native events; Windows uses section 60's shared safe se-proc file-watch service (ReadDirectoryChangesW on the same per-host IOCP) | One shared service for capture/Atlas, no notify-owned helper thread; Section-80 watcher row includes state and any resident stack |
| Optional Atlas | Standalone only, config opt-in after journeys and handover, disabled by default; unavailable embedded | Section-80 standalone Atlas share and separately bounded transient cold child |

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
On Windows share one recursive handle and 64 KiB buffer per trusted provider
transcript root across sessions; admit at most four such roots within the 0.5 MB
watcher allocation, retaining the remainder for metadata. Extra/unavailable roots
report missing watch coverage and use the stated capture backstops, not extra
per-session buffers or a second collector.
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
stdio custody requests refuse runtime-not-running with the hostless-custody
cause and bootstrap remedy; legal CLI custody can
bootstrap the standalone host through section-30 NativeProcessApi spawn_runtime,
commit_runtime with authenticated readiness, or abort/witness/release_runtime.
The exact RuntimeChild stays pinned through that outcome. This is private
runtime bootstrap, not a public `se daemon` command. Ordinary refusals return on
the error channel without appending a history event.

Factory preparation is read-only, returns absent/unreadable/version error
truthfully, and starts no writer/callback/native effect. SE Code registers the
Prepared Host/G and fresh immutable generation-fenced services before activate.
Missing store does not implicitly init. Preparation reads the version and plans
any supported additive migration; activation, under the exclusive runtime lease,
first verifies a pre-migration backup, applies it and FULL-publishes the version
before starting ordinary resources. There is no MigrationApproval, plan
fingerprint or maintenance-only open mode. A live older owner refuses with
“run se down first”; unsupported/too-new schema refuses with a remedy. A failed
backup never authorizes migration. Same-factory duplicate healthy open shares
the registered owner; an independent live owner refuses.

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
after the last live agent ends; a new live agent cancels it. A detached
`se up` started by default SE Code handback follows the same ten-minute empty
policy even though an ordinary explicit `se up` remains resident. On expiry
recheck emptiness and use the same shutdown path. Do not combine this timer with the 15-minute live catch-up:
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

“Handover configured” is the default SE Code exit policy with live agents:
hand them back to a detached se up through the same checked protocol, per section
00. The ordinary-exit row applies to daemon shutdown or a deliberately selected
no-handover/stop route after handover is unavailable/refused; a failed transfer
must stay visible rather than silently abandoning ownership. No extra setup is
required to enable the default SE Code handback. The detached successor is one
persistent StateEngine process while agents remain live; B3's embedded zero
process observation applies only when no agent is live. Ordinary `se down`
stops owned agents on every OS and prints achieved stop facts and resume argv,
never “agents still running”.

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
The linked TransferId is the checked spelling of the same store transfer
RecordId, never the native transfer nonce or a newly allocated retry identity.
On **every handover entry and recovery**, before allocating that identity or a
replacement successor plan, the factory calls
HandoverServices::queue_state_for_request(original_key) on the verified actual
queue. This bounded indexed lookup returns the original typed Frozen or Settled
plan/checkpoint for (NativeQueueId, request key), including before Prepared.
The initial native fence atomically stores that key index and the complete plan.
Unreadable/Unknown results cannot become absence. A factory crash after native freeze but before Prepared
can leave no transfer identity in the store or caller; queue_state(TransferId)
alone cannot recover it. Discovery must return the original typed plan/checkpoint
without parsing an error message. Verify its original key, immutable source/
destination kind/epoch, source G and queue incarnation: same-key replay retains
that exact plan/TransferId and any settled result returns its original outcome.
Only an actual request-key Absent on that verified queue permits new-plan
preparation; Unreadable/Unknown prevents replacement allocation. A competing
request cannot overwrite the queue's single open fence: freeze_queue atomically
checks that invariant and request-key uniqueness before any new fence commit.
Free-text refusal IDs are informational, never machine recovery inputs.

On process restart or a lost reply before Prepared, discover first, restore the
original plan, then resolve its actual native state and durable phase using the
same recovery/abort rules below. An original plan whose pinned peer is lost may
end in a verified abort; replay does not silently replace its successor or key.
After discovery, queue_state uses that recovered TransferId. The lookup neither
claims ownership nor clears a fence; the factory still proves current lease,
native lineage and terminal FULL outcome before any settlement.
freeze_queue installs that fence and returns NativeQueueCheckpoint for the
complete participating native binding set; queue_state(TransferId) resolves the original
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

Frozen with quiescence_witnessed=false proves only that the initial native fence
committed. It cannot authorize Prepared. Same-transfer retry finishes immediate
cancellation and exact-idle readback, seals quiescence_witnessed=true and returns
the final immutable checkpoint. HandoverReport contains only a verified
NativeQueueSettlement, including actual settled_by epoch; a Frozen checkpoint
is never a successful terminal report. An Aborted committed/replayed report
means the abort completed, not that activation succeeded. NativeDormant maps to
the linked AdoptionState::WaitingForSecode{transfer} typed status and preserves
the original transfer through the next SE Code adoption.

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
A second handover plan while a fence is open refuses runtime-handover-in-progress with
the open transfer identity. Resolve the first transfer before starting a reverse
one; timeout, an empty active map or a new epoch cannot replace that resolution.

| Phase | Source / receiver / store / native barrier |
| --- | --- |
| SourceGated | Validate/retain keyed request and owner; gate new custody/delivery, immediately fence native admission/promotion and interrupt participating agents, then finish accepted finite launch/capture/debt operations and prove exact idle; do not await a running turn's natural completion; source still owns lease/resources |
| Standby | Verify exact successor peer/PID/birth/API/home and native ready channel; receiver is read-only, no ordinary HostServices callbacks or queue promotion |
| Staged | After source capture/debt heads and full-frame input/output boundaries freeze, duplicate host-owned/Unix stream/PTY descriptors and call begin_transfer; native arena includes Windows provider ports automatically; transfer_manifest reads actual nonce/digest, receiver accept_transfer stages inactive copies and attaches ready local stdio sinks |
| BarrierCommitted | Finish accepted work and final capture/queue cut, drain/join writer and release source read/backup pins, then FULL Prepared on the exclusively owned HostStore with immutable manifest/nonce/frozen_at; no ordinary source writer or consumer resumes afterward |
| LeaseTransferred | Source releases exclusive runtime.lock after FULL Prepared; successor acquires lease and records FULL Claimed against that exact Prepared/current owner head before native activation or any destination writer/consumer |
| Activated (transient) | Receiver verifies lease/CAS/native manifest and calls activate_transfer once; retain/read back the actual native receipt, attach generation-fenced bindings and register/read around event reassociation, with **all destination writer/input/capture consumers still disabled** |
| Acknowledged (transient) | Source verifies the exact keyed native activation receipt, FULL Claimed/current owner and frozen admission/capture heads, then commit_transfer and close its gated originals; lost replies use native receipt/readback, not a second activation |
| Finished | After independent source-resource closure proof, destination FULL Finished binds actual native activation plus exact final capture/queue cut and closure; only then start the destination writer/capture and settle the native fence before enabling eligible input/mail. Native routes remain dormant while SE Code is absent |
| Aborted | Before Claimed and before native activation: source abort_transfer and receiver discard_transfer staged copies; restore source only after actual lease/owner/G validation; settle only this transfer fence and preserve all human/takeover/revocation holds |
| Recovered | A checked cold owner supersedes Claimed; one FULL transaction records the new runtime.owner and original transfer's Recovered outcome with fresh activated custody/capture and retained queue-cut proof; only then may the factory settle that original fence |
| RecoveryPending | Lost ACK, peer death, ambiguous CAS/lease/stream state; no guessed rollback or second consumer; reconcile exact transfer/receipt/native state |

Finished verifies closure of the source's transferred native resources, not that
the entire SE Code process has already exited. Retain its native queue adapter
and private control channel through terminal fence settlement, then allow final
process exit. Clearing that fence does not enable an old native route: both human
input and mail promotion still recheck the registered current native target/G.
A standalone destination leaves those routes NativeDormant; only SE Code's
verified return/adoption enables them. Thus a still-closing old UI cannot promote
input in the gap between Finished, settlement and exit.

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
verified FULL Finished, pre-claim Aborted or checked-cold Recovered. A native
activation receipt or FULL Claimed alone cannot clear it.
Do not clear a human hold to make handover appear live.
A resumed human invalidates the stale absence barrier; re-read/retry legally.
Host-only delivery is frozen before native transfer. SE Code freezes its sole
queue's admission/promotion and retains its complete pending state under its
native handover seam through destination acknowledgment; store message debt is
not a substitute for lost native pending input. Original queue admissions, target adoption mapping,
NoticeId/digest and capture cursor are carried; receiving callbacks use a fresh
G wrapper after its registration/activation, not an old Arc silently rebound.

Only source consumes provider stdout/capture before freeze. Its read task parks
at the proved exact offset/frame boundary before native staging and FULL Prepared.
Receiver stages files without reading; activate_transfer returns them exactly once
after FULL Claimed under exclusive lease. Its native receipt is retained, but
receiver consumers remain disabled until FULL Finished proves activation plus
source-resource closure. Then resume from the frozen cursor and original dedupe
keys; no uncommitted capture/input interval is hidden between activation and
finish. On Windows, provider endpoints remain in the native arena: ReceivedTransfer.processes supply the owners for attach_stdio, every port
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
* Staged receiver crash **before Claimed and native activation**: verify exact
  peer exit, discard/revoke that staged attempt and restore source native
  association/lease only through checked abort. Do not leak a staged Windows handle that keeps jobs alive forever.
* Source crash before Prepared: no durable transfer authority exists; receiver
  closes its inactive copies and uses ordinary crash policy, never channel EOF
  as activation authority.
* Source crash after Prepared: receiver verifies that immutable intent, source
  exit and exclusive lease, then commits exact Claimed if not already claimed.
  Only that owner may activate; missing proof leaves RecoveryPending.
* Source crash after Claimed: receiver uses exact intent/CAS/lease/native manifest
  to complete the same activation and source-closure proof for FULL Finished. If proof fails, RecoveryPending; no invented
  successor or arbitrary descriptor adoption.
* Activation reply lost: query durable transfer/receipt/current owner and native
  staged state with original key. Successful activation is never repeated to get
  a second stream set. Source never aborts an already activated receiver.
* Receiver crash after Claimed, including after native activation before ACK: source originals stay gated; prove
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
All accepted work, writer join and source snapshot/backup-pin release precede
FULL Prepared. Its immutable cut is therefore already ready for lease release
and claim; there is no ReadyToClaim append or post-Prepared cut mutation.
If native queue freeze committed but no Prepared fact exists, the factory proves
that absence under the actual source/recovered-source ownership and lease,
verifies staged-copy closure, then settles the original fence as **Aborted**
citing that FULL source-owner fact. There is no store transfer phase to append
or skip in this case. Missing peer/resource/owner proof leaves the fence pending;
timeout alone cannot abort it. Typed request-key discovery above supplies the
original plan/checkpoint even after a lost reply or factory process loss.

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
manifest hash for outside process/resource proof. B8 is the section-80 cutover target, still
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
| Prepared | Admission/input frozen; accepted operations, exact idle, stream framing, final capture/debt/queue cut and source writer/reader/backup drain complete; inactive native copies staged. Seal immutable fields under the retained source lease, then release it; Prepared itself authorizes only exact destination claim |
| Claimed | Destination holds exclusive lease and target G under exact Prepared/head CAS; native activation may occur, but no ordinary writer/input/capture consumer starts. Resolve same native receipt on lost ACK, never source timeout rollback |
| Finished | Actual native activation, exact final capture/queue cut and independently verified source-resource closure are bound in this one FULL completion. Only afterward enable destination capture/ordinary writer, settle the transfer fence and enable eligible input/mail |
| Aborted | Source custody restored only before Claimed/native activation, under actual source/recovered-source lease/owner proof with inactive copies closed; preserve human holds/debt |
| Recovered | Exceptional checked-cold completion of Claimed, atomically in the fresh FULL runtime.owner; cite its event plus actual activated custody/capture and retained queue-cut proof, preserving original peers/generations |

The owner decision retains **five durable values rather than four**. Prepared
already follows writer drain, eliminating ReadyToClaim. Actual native activation
is transient until the combined Finished proof; withholding consumers until that
FULL commit eliminates the separate Activated append without allowing unrecorded
input/capture. Aborted and Recovered remain distinct: the former restores verified
pre-claim source authority, while the latter establishes fresh post-claim owner
custody. Conflating them would either authorize rollback after claim or fabricate
old-generation completion. Normal handover now has three FULL appends
Prepared → Claimed → Finished; failure uses the applicable distinct terminal fact.

The Recovered row consumes section 20's admitted recovery amendment, not a local
side-file, invented Finished or phase-only write under a stale generation.
Activated/Acknowledged/LeaseTransferred/RecoveryPending are bounded host
observations, not extra durable owner phases. Exact phase retries use stable per-transition keys
derived from the original request, transfer and phase; changed fingerprints
refuse. Elapsed deadline permits failure reporting, never lease/owner theft.
A lost native activation reply is resolved from the original native receipt
while the durable head remains Claimed. A lost Finished reply is resolved from
that same transition key and stored completion proof before any consumer starts.
If native activation/source closure cannot be proved after peer loss, use checked
cold recovery; never invent an abort or activate a second set of streams.
The record's immutable peer/generation/nonce/digest binding and legal transition checks belong to Nell's
store amendment; the host supplies real outside facts and holds the OS lease.

### 6.2 Closed recovery attestations

RuntimeOwnerEstablished.recovered uses section 20's RuntimeRecoveredTransfer,
not another recovery event. transfer and handover_event identify the exact current
Claimed head; capture_at is a real committed revision in the same store,
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
never in logs. Exact API equality applies to operations/hooks, not minor-range
negotiation; the stop-only control path below is independent of that API.

Call envelope contains API, positive request_id, discovered G, optional per-call
authority and Operation or Hook. Operation has registry name, closed arguments,
a stable request key required for every public mutation; decode once to
AdmittedOperation then invoke synchronous core validation/planning/store logic.
The host async custody executor alone performs native/provider effects. Reads
need no mutation key; capture/read/ack/dismiss retain only their explicitly
restricted natural-key path. CLI creates/prints its key before the first send
and accepts --key for a later invocation; MCP mutation schemas require
idempotency_key, and linked/IPC mutations carry that same identity. A lost reply
reuses it; same key with a changed admitted body conflicts before any effect. Hook is
the fixed Claude operation mapping. **No Nudge request remains**: in-host commits
already wake debt, while direct writes are recovered at activation. Reply echoes
id/API/G and either typed result or ErrorEnvelope. Transport IDs are not durable
idempotency keys. Broken post-COMMIT reply resolves by original operation key.
Five-second hello/write bounds, 30-second ordinary call ceiling; registered
custody deadlines may return truthful pending rather than block forever.

### 7.1.1 Stop across an API change

`se down` must reach the running host even when its operation API differs from
the installed client. The same owner-only IPC endpoint accepts a small, fixed
`se.runtime.stop/v1` control exchange before operation-API negotiation. It uses
the same native peer/server identity, one-use challenge and owner MAC machinery
with a distinct stop domain; it carries expected HostEpoch/G, the original
request key and deadline, never an operation name, actor or session credential.
Only an outside-agent Owner can use it. This is not a route to execute arbitrary
old/new operation DTOs and is never exposed over HTTP or session MCP.

The running host executes its own ordinary graceful-down coordinator: stop and
witness exact owned agents, save resume references, flush capture/debt, drain
and join, close resources and release the lease in §5 order. The fixed control
reply reports achieved stop facts, retained resume references and named pending
obligations, or a refusal; the client renders it without decoding the host's
operation schema. After a lost reply, reobserve the exact host/lease and original
stop key before reporting the outcome; endpoint disappearance alone is not proof
that agents stopped. All Rust API generations retain this stop control version.
A legacy host lacking it requires its matching `se down` binary and an explicit
remedy; neither API mismatch nor an unreadable peer permits a PID/name kill or
a competing writer. Exercise the mismatch and lost-reply paths on Windows,
Linux and macOS alongside the ordinary shutdown witnesses.

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
agent trees and no SE_SESSION. Docs, help, refusals and decision receipts say
these are mistake/drift guards, not proof against a determined agent on the
user's own account; the existing ratify checks do not change. Native UI HumanPresence is separate from CLI TTY;
model tools cannot construct either. This is the accepted mistake/drift boundary,
not an attempt to sandbox a hostile same-UID program.

AdmissionAdapter/Dispatcher are concrete common implementations of these stages,
not polymorphic public service traits. Every call, including multiplexed session
calls, rechecks G, credential revocation/binding revision and scope. A supplied
invalid authority never falls back to connection authority. Creator control is
only the current can-create grant plus immutable same-project direct created_by;
no grandchildren/all-agent privilege or private mailbox read follows from it.

### 7.3 HTTP inventory and concrete parser

The shipping Rust SE Code server uses axum/Tokio, with axum 0.8.9, hyper 1
(http1, server) and hyper-util 0.1 in its lockfile. se-host uses hyper directly
with those server-only features, or an axum caret range admitting 0.8.9; verify
one compatible resolved stack in the linked server build. No speculative second
fixed-route parser or second HTTP stack is planned. Standalone uses that same
stack. No TLS/client stack, SSE, proxy or process/server per agent is introduced;
MCP is POST JSON, mail/livez are bounded GETs, with no request bodies there.
Reject ambiguous/chunked framing, pipelining and upgrades at this local surface.

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
gets a fresh revision and, only for process-bound clients, a capability; it
preserves applicable human holds. Embedded SE Code uses a generation-fenced
in-process BoundSession, with no credential issuance/activation/hash/pin/bearer
events. Its durable session activation and normal authorization checks remain.

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
mode refuses provider-incompatible/window-unavailable with the detached
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
the existing writer. E8 must measure cold no-host hooks on Windows with Defender
before choosing private host bootstrap versus direct shared-lease fallback;
no cold-start promise is established here. Either selected route uses the same
transaction path and original natural key, and never writes directly while an
exclusive owner exists.

Attended plugin is ~200–350 lines of provider-native JS, no Node process/executor.
Manifest plus hooks module registration uses the installed API types. One
credential-scoped wait returns IDs/cursor only. Submit attributed mod text after
blocking hook returns; never `asUser:true`, body/secret prompt injection or
concurrent ordinary turn. Human stop/session end/revocation must prevent new
offers and preserve hold; the host invalidates and closes its parked wait on
that observed state. Claude's current fetch API has no caller AbortSignal, so
immediate mod-side cancellation is unqualified; do not describe it as a passed
capability. No new mail/reconnect/restart clears hold. The [mods API](https://code.claude.com/docs/en/plugins/mods/reference)
limits an entire HTTP fetch to 30 seconds: use ≤25 s waits, **0.04/s renewal per
attended session**, as updated in 70/80. One wait per session, own cap outside 64.
The Linux spike proves this renewal and idle/busy delivery only, not stop or
revocation. E4 requires 100 real sends with zero missed wakes and the named
fallback if the required hold/security path cannot qualify. The server emits
no redirects, the mod validates the configured private origin before sending,
and no bearer goes in a URL. The installed HttpResponse exposes no final URL;
post-redirect origin verification is therefore unqualified and cannot be
claimed implemented by this API. Retain authenticated local-host proof and
qualify that gap before accepting the attended product path.

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
single se-host CODEX_MINIMUM_VERSION constant, 0.152, or lacking a required
feature refuses before launch. Measurements found helper auth fails at 0.151
and passes at 0.152, the 0.159 fork and stock 0.166; a fork result does not
qualify stock transport behavior. Never launch silently without working tools.

Use per-launch MCP/helper configuration and user's existing CODEX_HOME/login;
no managed replacement home, hooks.json injection, fork or automatic approval.
The Linux stock 0.163 attended spike uses a private unix:// app-server and
`codex resume THREAD --remote unix://PATH`; its real window and socket client
share one saved thread and canonical item/turn capture. Configure safe sandbox
and approval policy on thread/start or thread/resume RPC: remote TUI resume
refuses -s/-a permission overrides. E5 still qualifies headless/windowed auth,
reconnect and every OS, and evaluates --listen as a simplification only if it
removes a whole mechanism; retain the Windows stdio arena. Headless unsupported
approval reports pending/refusal rather than inventing a human decision. Turn completion is separate from process exit/task effect.

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
is RemoveIncomplete, not a claim every process/file vanished. Erasure is separate. Settings resolve flag > environment > user config.toml >
default, with no project-scope configuration layer. Message/working-state
admission uses the shared per-kind DTO byte limits (32 KiB/16 KiB), generated
into every surface/store path; oversized UTF-8 refuses before any effect, never
truncates. For remove, forget, import, migration, restore, credential rotation,
uninstall and diagnosed doctor repair, the host executes the exact typed plan
and printed consequences in section 70; a configuration repair cannot silently
rotate secrets, restore history or migrate.

For file-only effects, the host filesystem adapter owns section 20's protected
`STATE/receipts/` journal outside SQLite and the removed installation. Reserve
a finite versioned record no-replace under exclusive file-effect custody, keyed
by store/home identity, authenticated owner and original request key; retain the
operation, semantic fingerprint and exact plan without secrets or turn bodies.
Sync intent before the effect, then atomically publish/sync achieved outside
readbacks and the final result. Same key/intent resumes or replays; changed intent
conflicts. After a crash, reobserve the original targets before another effect;
unknown/unreadable journal state refuses or reports outcome unknown. Uninstall
preserves the journal with history/backups and prints its location; restore's
journal survives DB replacement. It creates no event, writer stamp, new public
operation, server or timer. Host/se-proc owns no-follow permissions, publication
and agent-path exclusion; a journal entry is never authority or an OS witness.

## 10. Performance and size allocation

Section 80 contains the single budget table and outside observer definitions;
section 95 generates the single size table. This chapter keeps no competing
startup, memory or LOC ledger. All helpers and native/worker resident stacks
count; provider/model processes are reported separately. The first complete
linked session/continuity response is inside B2, actual task memory is inside
B1/B4, and B8 begins after independently reported quiescence. A declaration
compile or arithmetic allocation establishes none of those measurements.

Embedded binds use in-process handles and mint no credentials, removing the two
credential FULL commits; runtime.owner and any required FULL session activation
remain inside the first-bind measurement. E2 re-spends the unchanged B2 ceiling
using the real FULL set on Windows with Defender, both new and existing store,
and memory after a real task. Historical FULL commit tails require actual first-bind measurement, not an
optimistic allocation. Re-adoption, Codex reconnect, backup and optional Atlas run
after the initial real response, with per-route Recovering status; this does not
call every prior agent ready. One SQLite writer and at most two bounded blocking
jobs remain, with one foreground slot available during background work.

B3's embedded zero persistent-process observation applies when no agent is live.
Default SE Code exit with live agents instead creates one detached successor;
that daemon exits ten minutes after its last live agent. Standalone and embedded
must be measured under those actual compositions. B9 measures hosted `msg send`, `working-state set` and `hook claude stop` at
p95 ≤20 ms. The FULL command family has the separate section-80 E3 bound,
p95 ≤75 ms on Windows with Defender; cold direct/FULL tails remain contrary evidence requiring proof,
not weaker authentication or durability. A failed budget blocks release.

Resource defaults in HostLimits are admission/backpressure, not preallocation:
16 sessions, 64 active connections and one separately budgeted parked mail wait
per session; bounded aggregate payload/frame/notice permits retain overflow as
durable debt. Higher negotiated embedded caps must fit section 80's reserve and
keep aggregate byte caps fixed. Release request parsing buffers before parking;
never reserve a full header/body buffer per wait. Atlas is compiled only into the standalone `se`; it is disabled by default and enabled by `atlas.enabled = true` in config.toml; in embedded SE Code that setting returns feature-unavailable.
Build it only after the journeys and handover, with a bounded transient cold
child; it never blocks a milestone. Its embedded absence cannot remove capture's
shared native watch service.

### 10.1 Idle and work-triggered maintenance

Use §80 §3.7: executor/writer/accept/collector blocked; native watch events only;
**0.04/s per attended Claude wait renewal**; one live 15-minute catch-up about
0.0011/s; one auto-start exit timer after ten empty minutes. Expected baseline
~0.002/s no session, ~0.003/s plus 0.04/s per attended session; >0.05/s plus the
attended contribution is a defect even if under the hard ceiling. No claim of
zero wakeups with the vendor's bounded request API. The Linux attended spike
demonstrates renewal and delivery, not the B5 idle-CPU result.

Automatic backup runs at start-of-day after readiness and at clean shutdown;
use the shared BackupContext, one stable
read transaction, 64-page steps, abort at 64 MiB WAL pressure instead of blocking
writes and release its pin; retry a failed scheduled copy only at the next
start-of-day, with the required clean-shutdown copy still explicit. Its
synchronous job keeps one background permit throughout; the other remains foreground. No per-command
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

The public spellings below come from the shared catalogue; retained native or
provider discriminants belong in typed causes, not extra public wire codes.

| Boundary | Public codes / retained cause / legal remedy |
| --- | --- |
| Input/wire | usage-invalid-value, input-unknown-field, input-too-large: fix closed schema/budget; no dispatch/marker on invalid input |
| API/version | api-version-unsupported, runtime-incompatible: upgrade matching side; use §7.1.1's authenticated version-independent control for ordinary down, never arbitrary API negotiation bypass |
| Native peer/owner provenance | os-user-mismatch, listener-admission-refused, owner-required, human-terminal-required: correct user/native owner route; never ambient fallback |
| Credential | setup-required, source-unreadable, capability-invalid: detail distinguishes missing/unreadable credential, invalid/revoked/expired capability and unproved binding; actual init/diagnosed repair/renewal/rebind, no owner conversion |
| Runtime | runtime-not-running, runtime-incompatible, runtime-start-failed, runtime-start-pending: retain hostless/actual-owner/start cause; legal bootstrap/owner inspection, not a PID shortcut |
| Generation/shutdown/handover | state-conflict, runtime-handover-in-progress, stop-unwitnessed: retain exact generation/phase/deadline/closure cause; re-read original key/G/ownership, retain unsafe custody, controlled restart for an unjoinable worker |
| CAS/scope | revision-conflict, idempotency-key-reused, launch-in-flight, agent-already-running, grant-required, message-scope-denied, not-recipient: re-read/current authorization, preserve incumbent/original receipt |
| Provider | provider-cli-not-found, provider-incompatible, launch-failed, resume-reference-missing, resume-reference-unverifiable, provider-change-breaks-resume: retain version/feature/app-server cause; install/fix/explicit --new where desired, never silent fresh thread |
| Process | state-conflict, source-unreadable, usage-invalid-value, job-breakaway-refused, window-unavailable, launch-failed, launch-readiness-timeout, stop-unwitnessed, deadline-exceeded: retain exact identity/bare-PID/partial-stop/native cause and outside observation; no weakened containment/name kill |
| Capture/config/remove | source-unreadable, transcript-truncated, usage-invalid-value, capture-consent-missing, integration-conflict, integration-failed, remove-incomplete: retain exact source/payload/body/write/readback cause; preserve cursor/foreign bytes/history, repair actual pin/config; hook exit zero is not capture proof |
| Failure/cancellation | commit-outcome-unknown (Unknown/transient): rerun the same command with --key K / repeat the call with the same idempotency_key; deadline-exceeded, cancelled, internal retain task/native cause and named route failure or lifecycle-domain poison; mutex poison never success |

A bounded se-proc stop is incomplete at the requested guarantee even if root
exited; Complete retains its actual supported OS bound. Windows explicit escape,
Linux Uncontained and macOS tracked-group limitations stay in the receipt. No
ownerless lock reclamation, empty-page absence proof, callback self-witness or
read-after-truncation claim satisfies a required effect. FULL security or decision-transition failure
closes admission with an error, never silently acknowledges a lost revocation
or ratify/reject/retract/supersede transition. Ordinary refusal itself is not a
history write.

## 12. Five journeys, mirrors and remaining integration work

Done requires all five journeys on clean Windows, Linux and macOS with real
Claude/Codex, standalone and embedded SE Code. Windows/Linux is an intermediate
milestone; the borrowed-Mac campaign qualifies macOS before alpha ships without
holding the broad build. Reviewers own the actual journey composition. This author writes no tests or runtime bodies.
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
   the pipe-transfer primitive has the bounded Linux/Windows spike evidence in
   §1.1; job re-association and full store/provider integration still need proof.
   The same se-proc/section-60 owner supplies the shared file-watch service at
   implementation; capture does not add a separate native watch port.
   No host unsafe or second collector.
3. **Alpha + host composition** publish the permissive linked API into the
   confirmed Rust `secode-server`, unify the known caret-compatible
   Tokio/hyper-or-axum/SQLite packages, catch unwinds and apply the reconciled route-local
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
