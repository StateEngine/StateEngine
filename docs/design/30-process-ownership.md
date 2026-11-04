# 30. Native process ownership (`se-proc`)

Design reconciliation, 2026-10-30. **Declarations only: no product backend or
author tests.** Wave 1 Linux uses an explicitly uncontained process group.
Wave 4 adds preferred delegated cgroups and a fresh scope per new agent
process; absent delegation retains the explicit uncontained path. Optional Landlock/seccomp remains named policy.
Unix windows and live handover are required before alpha. Mac implementation
and native qualification run in the borrowed-Mac campaign after the earlier
Windows/Linux milestone, with all three OSes required before shipment.

## 1. Purpose, scope and ownership

`se-proc` distinguishes a stored process claim, an exact OS instance, a native
custody scope, a stop request and an outside exit witness. It serves the
agent launch/stop/wake and runtime custody operations. Native process readers
and pins serve those adapters; process.start/control/list and their MCP tools
are absent from the public product surface. It adds no public
command, tool, PID killer, process-per-agent owner, Node/PowerShell dependency,
remote compute or generic process census. Observation never grants authority.

The host authorizes, owns durable events/CAS, conversation state, provider
readiness, graceful stop, pipe buffers and the runtime lease. This crate owns
native pins, scope resources, native launch steps, exit-event sources and OS
readbacks. The core remains synchronous; the host owns its async custody executor.
No transaction spans an OS call. Arena resources live above service
generations. `ProcessRecord.state` is the arena's last native phase, **not** a
claim that a store transition committed. The store owns its durable state and
revision; a receipt joins both explicitly.

Dependency direction after shared contracts settle is `se-proc -> se-types`;
libc/windows-sys are target-specific bindings, not workspace-layer dependencies.
The declaration appendix is joined to canonical shared IDs/encodings before
implementation, with native pins staying private. Local proposal declarations
do not establish a second common ID system. Library dependencies use caret
ranges and target-specific bindings; this crate does not link Tokio. Only
se-proc may contain unsafe implementations; each eventual block must justify
resource ownership, pointer lifetime/alignment and thread/fork safety.

Same-user guards defend mistakes, drift and misattribution, not hostile code
already running as the OS user (section 70 / Jimmy's trust-boundary law).
Neither cgroups nor Windows BREAKAWAY_OK are sold as an adversarial sandbox.
Safe provider permissions remain the default; unrestricted permissions require
a saved named opt-in. Cgroup containment does not disable that opt-in.

### 1.1 Achieved guarantee

| OS | Supported alpha scope | Explicit bound |
| --- | --- | --- |
| Windows | host-held job, ordinary descendants inherit, KILL_ON_JOB_CLOSE + BREAKAWAY_OK, never SILENT | an explicit breakaway can leave this scope; a separately owned detached runtime is another lifecycle/owner, not silently killed with the agent |
| Linux | prefer exact delegated cgroup v2 subtree with before-exec entry and cgroup.kill; without delegation, new process group + native tracking labelled **uncontained** | cgroups permit deliberate same-UID migration; uncontained mode also permits setsid/setpgid escape and cannot promise kernel-tree removal or survival of an external parent-cgroup kill |
| macOS | new process group, kqueue root/tracked-child events, exact start/image rechecks, group signals and outside tracked-member exit | deliberate group/session escape or unobserved reparenting is outside the stated bound; no claim of an unescapable kernel tree or atomic PID-check-and-signal |

`ContainmentGuarantee::KernelScope` describes Windows/Linux native membership;
macOS reports `TrackedTree { atomic_signal: false, escape_prevented: false }`
with wire `containment: "process-group"` and `containment_cause: null`. Linux
fallback reports wire `containment: "uncontained"` and a non-null
`containment_cause` from the exact variant mapping in §7. Contained Linux and
Windows report `"cgroup"` and `"job"` respectively, with null cause.
The host selects that **supported macOS policy explicitly**. Linux default
BestAvailable selects a scope before child creation: delegated kernel scope
when available, otherwise Uncontained with a structured reason; status and
launch receipts always name that weaker guarantee. An explicit KernelScope
requirement still refuses if impossible, and a failure after native cgroup
entry is never retried silently in another mode. Under Prime's ruling, an empty macOS
group with all tracked instances exited is `Complete` **at this stated bound**.
`Bounded` remains for a requested guarantee not met, incomplete tracking or a
known escape. Neither means all descendants anywhere on the machine are gone.

## 2. Compile-only public API

All public Rust types/fields and signatures are the normative source appendix:

| Source | Contract |
| --- | --- |
| `identity.rs` | IDs, boot/start/image identity, native process reads, observation, exit evidence and exit status |
| `launch.rs` | explicit environment/streams/policy, headless/window + terminal adapter, capabilities including complete causes, detached runtime bootstrap, stateless native read |
| `ownership.rs` | reservations/checkpoints, records, opaque handles, launch/stop/recovery/transfer outcomes, labelled population/enumeration, arena snapshots and native events |
| `error.rs` | internal cause enum, typed detail, sanitized native cause and result alias |
| `stdio.rs` (Windows) | safe provider-stream creation, bounded operation tickets, partial completions, cancellation, recovery and drained release |
| `lib.rs` | re-exports only |

Opaque runtime/owned/prepared/stop/launch/transfer handles have no public
constructor, Clone, Default or deserialization. `OwnedProcess` is a revocable
**reference to one arena owner**; retrieving another same-generation reference
is legal and does not create another native owner. Serialized records, IDs or
transfer receipt data alone cannot instantiate custody. Private unit fields
express opaque layout only, not resource stubs. Environment/stream/spec types
have no Debug or Clone because their values may hold credentials/handles.

NativeProcessApi declares safe associated functions in a plain trait. There
is no unsafe extern block, unbacked foreign symbol, executable body or linkable
backend. read_process is stateless: no runtime, random HostInstanceId, thread,
lease, arena, watcher or child keeper. Detached bootstrap has bounded per-call
custody through RuntimeChild, not a global agent-owner runtime. Its full
readiness/abort contract is in §5.5.

```rust
pub trait NativeProcessApi: Send + Sync {
    fn read_process(
        machine: MachineId,
        pid: crate::ProcessId,
    ) -> crate::ProcResult<crate::ProcessRead>;
    fn spawn_runtime(spec: RuntimeLaunchSpec) -> Result<RuntimeLaunch, Box<RuntimeSpawnFailure>>;
    fn commit_runtime(
        child: RuntimeChild,
        proof: RuntimeReadyProof,
    ) -> Result<RuntimeReady, Box<RuntimeCommitFailure>>;
    fn abort_runtime(child: &mut RuntimeChild) -> crate::ProcResult<()>;
    fn witness_runtime(child: &RuntimeChild) -> crate::ProcResult<RuntimeExitObservation>;
    fn release_runtime(
        child: &mut RuntimeChild,
        witness: &RuntimeExitWitness,
    ) -> crate::ProcResult<()>;
}
```

The owned backend's complete method declarations follow. No method has an
executable body, placeholder macro or implementation in this revision.

```rust
pub trait ProcessRuntime: Send + Sync {
    fn open(config: HostConfig) -> ProcResult<Self>
    where
        Self: Sized;
    fn capabilities(&self) -> ProcResult<PlatformCapabilities>;
    fn arena_snapshot(&self) -> ProcResult<ArenaSnapshot>;
    fn prepare_launch(
        &self,
        reservation: LaunchReservation,
        spec: LaunchSpec,
    ) -> ProcResult<PreparedScope>;
    fn bind_stdio(&self, prepared: &PreparedLaunch, child: StandardIo) -> ProcResult<()>;
    fn begin_launch(&self, prepared: PreparedLaunch) -> LaunchStart;
    fn poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress>;
    fn authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()>;
    /// Host must commit Starting -> StopRequested before this consumes the token.
    fn cancel_launch(
        &self,
        ticket: LaunchTicket,
        prepared: PreparedStop,
    ) -> ProcResult<StopAttempt>;
    fn describe(&self, process: &OwnedProcess) -> ProcResult<ProcessRecord>;
    fn observe(&self, process: &OwnedProcess) -> ProcResult<OwnedObservation>;
    fn watch_exit(&self, process: &OwnedProcess, sink: Arc<dyn ExitSink>) -> ProcResult<ExitWatch>;
    fn re_adopt(
        &self,
        record: &ProcessRecord,
        from: GenerationId,
        to: GenerationId,
    ) -> ProcResult<OwnedProcess>;
    fn prepare_stop(
        &self,
        process: &OwnedProcess,
        generation: GenerationId,
        deadline: Instant,
    ) -> ProcResult<PreparedStop>;
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt>;
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation>;
    /// Natural exit, failed launch and graceful shutdown need no stop ticket.
    fn witness_exit(&self, process: &OwnedProcess) -> ProcResult<StopObservation>;
    fn release(&self, process: &OwnedProcess, witness: &StopWitness) -> ProcResult<()>;
    /// Ordinary stop first; owner-human release CAS only from StopUnproved.
    /// Tracked groups only, no signal; other origins are IllegalTransition.
    fn release_uncontained(
        &self,
        process: &OwnedProcess,
        release: &UnwitnessedRelease,
    ) -> ProcResult<ReleasedOwnership>;
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan>;
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome>;
}

pub trait ProcessTransfer: ProcessRuntime {
    fn begin_transfer(&self, request: TransferRequest) -> ProcResult<TransferOffer>;
    /// Frozen actual offer metadata/digest, never native handle values.
    fn transfer_manifest(&self, offer: &TransferOffer) -> ProcResult<TransferManifest>;
    fn accept_transfer(
        &self,
        endpoint: TransferEndpoint,
        manifest: TransferManifest,
    ) -> ProcResult<ReceivedTransfer>;
    fn activate_transfer(&self, imported: &mut TransferImport) -> ProcResult<ActivatedTransfer>;
    /// Host proves pre-Claimed/lease from its store head; native refuses activated imports.
    /// A failure keeps this borrowed import and staged custody available for retry.
    fn discard_transfer(&self, imported: &mut TransferImport) -> ProcResult<()>;
    fn commit_transfer(&self, offer: TransferOffer, receipt: TransferReceipt) -> ProcResult<()>;
    /// Host proves pre-Claimed/lease from its store head; native refuses committed offers.
    /// A failure keeps this borrowed offer and native custody available for retry.
    fn abort_transfer(&self, offer: &TransferOffer) -> ProcResult<()>;
}
```

`ProcessRecord.ownership_release` is `Option<UnwitnessedRelease>`. The marker
contains the lifecycle, generation, resulting nonzero per-entity revision,
exact scope, bounded `RemainingScope` diagnostics and release time. The host
proves the committed owner-human CAS originated in StopUnproved after an
ordinary stop could not be proved; native code checks lifecycle/generation/
scope, never treats a caller-supplied revision as independent store evidence.
`ReleasedOwnership` returns that marker without constructing `StopWitness`.
`plan_recovery` selects ReleaseUncontainedOwnership for a marked record;
`recover` returns RecoveryOutcome::ReleasedOwnership, never a live reference.
A release marker mismatching its record's lifecycle/generation/scope refuses.

### 2.1 Input/read semantics

The host supplies persisted machine ID, fresh host-instance ID, expected
service generation, absolute executable/cwd, literal argv and an explicitly
constructed environment. `se-proc` never searches PATH, expands a shell or
reads ambient configuration. A host resolver may deliberately resolve a
provider command; a missing program maps to `provider-cli-not-found` in the
provider resolver or contextual `launch-failed` for a native/helper launch.
Reject NUL, duplicate env keys (case-insensitive on Windows), relative paths,
invalid PID range/native identity variant and bounded input overflow. Secret
values are never logged or put in error detail. Program/cwd and redacted field
names can be shown. A deliberately chosen absolute shell is user input, not
an extra wrapper inserted by this crate.

A stateless `read_process` gives Present, Absent or an existing exited record;
unreadable boot/stat/image/query is a typed error, never empty. Linux zombies
without an executable yield ExitedRecord with boot/start, not an invented
image. Owned readers join that start to their held original instance. Image
changes on the same start require a new authorized observation; they are not
silently ignored. Only a genuine target's native absence status means absent.

`Capability::Unavailable` carries the entire boxed ProcError: internal cause,
typed detail and native API/code/reason, so the host can render the exact
missing capability and mapped remedy. No bare enum code loses the cause.

### 2.2 Explicit stream ownership

`Headless`: supplied standard-stream Files are duplicated into only those
slots; None means the null device. The host harness owns stream protocol and
buffer admission; Windows pipe creation and pending native buffers stay in
se-proc through the safe port below. Streams can be transferred without giving
the agent a host control handle. No unspecified FD/handle inheritance.

`Window`: `WindowSpec` is required. On Windows, allocate a new console and let
its default keyboard/screen handles populate **unspecified** streams; do not
set STARTF_USESTDHANDLES to three NUL handles. If any stream is redirected,
construct all three intended console/file handles explicitly and pass only
that closed handle list. On Unix the registered attach helper owns a fresh
PTY slave as controlling terminal and duplicates it to 0/1/2; the terminal
owns the master. Explicit redirects are intentional exceptions, not default
NUL. Host-held PTY masters use the TerminalMaster transfer role. Terminal
lifetime/readiness and provider readiness remain separate facts.

### 2.3 Windows provider-stdio port (narrow amendment)

`stdio.rs` is the safe native counterpart of section 40's
`ProviderIoPlatform`. `NativeProcessRuntime` implements `ProviderStdioApi`
on Windows through its existing arena and IOCP collector, with no additional
collector or per-stream thread. It is Windows-only; Unix keeps nonblocking descriptors on
the host's existing AsyncFd reactor.

| Native method | Safe host contract |
| --- | --- |
| `create_stdio(owner, config)` | After `prepare_launch` and before `begin_launch`, verify the owned lifecycle/host/generation, allocate one pipe set, and return ordinary child `StandardIo` Files plus an opaque host port |
| `attach_stdio(owner, config)` | Bind the successor's local sink/limits to an existing/recovered/staged port, without creating pipes or starting I/O; old callbacks drain before Ready |
| `stdio_state(owner)` | Return current-generation port/ticket references, stdin/binding facts and retained results; None means no port, while read failure is an error |
| `begin_read(port, stdout-or-stderr, max)` | Reserve bounded owned storage and return an opaque operation ticket; no synchronous pipe wait |
| `begin_write(port, owned Vec)` | Transfer the input buffer into the native arena; rejection returns the untouched Vec and typed admission error |
| `cancel(ticket)` | Request cancellation only; `Requested`, `AlreadyCompleted`, or native failure never substitutes for taking completion |
| `take_completion(ticket)` | `Pending`, or one terminal read/write/close result; preserve read stream, partial bytes, EOF, original write buffer and actual completed count even on cancellation/error |
| `begin_close(port, Stdin)` | Gate new writes, finish the accepted write, then close only the host stdin endpoint; stdout/stderr reads continue |
| `begin_close(port, All)` | Gate all new I/O, cancel/drain accepted operations asynchronously, and close every host endpoint; no blocking destructor |
| `release_operation(ticket)` | Reclaim operation metadata only after kernel completion has been consumed and its terminal result taken |
| `release_stdio(port, closed_witness)` | Reclaim the port only after its exact close witness and every operation's release; an unrelated witness refuses |

A port is created for an already reserved native owner, before a vendor child
exists; identity must exactly match the prepared scope. Move child-side Files
into `LaunchSpec.stdio` and its closed inheritance list. After child inheritance
is installed, se-proc and the host drop every parent-side copy of those child
endpoints (also on failed launch); retaining a child stdout/stderr writer in
the parent would prevent EOF. Only the host's opposite endpoints remain.
Host endpoints are non-inheritable overlapped byte pipes, connected and
associated with the
existing IOCP before use; child endpoints retain ordinary synchronous stdio.
Create the pairs inside se-proc with CSPRNG names, FIRST_PIPE_INSTANCE,
max_instances=1, REJECT_REMOTE_CLIENTS and closed access/handle lists. Host
stdout/stderr use INBOUND access and host stdin uses OUTBOUND access; se-proc
opens the matching synchronous client endpoints itself before publication, so
no external client/connect race is required. Pipe names and raw HANDLE or
OVERLAPPED values never enter se-host. Native partial creation is arena-owned
before publication; creation failure gates vendor exec and schedules
cancellation/drain of partial
endpoints in the arena, without dropping pending native storage or process
custody. `stdio_state` keeps this cleanup reachable. Only one port per owned
lifecycle is admitted; zero limits or a zero-byte read refuse InvalidInput.

At most one unreleased read per stdout/stderr and one unreleased write to
stdin are admitted; a single additional close control ticket is allowed.
This bounds ordering and metadata without a per-stream thread or executor.
`StdioLimits` caps each read/write and total retained bytes per port, and
`ResourceLimits.max_stdio_buffer_bytes` caps the sum across the host, including
completed-but-untaken buffers. Charge actual Vec capacity, not just its length,
and reserve that full allocation before native dispatch; reject oversized
capacity/counts with ResourceLimit and return the untouched write Vec.
Payload buffers use section 80's existing provider-I/O allocation, never an
extra 0.2 MB custody allocation; native ticket/OVERLAPPED metadata fits the
existing per-lifecycle custody share. Returned buffers transfer their charge
to the host's existing provider buffers; no duplicate hidden payload copy.

The arena retains each overlapped structure, port pin and buffer until the
actual native completion, independently of Rust future/port/ticket drop.
Immediate success and pending completion feed the same exactly-once state.
FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is not set and OVERLAPPED.hEvent never
suppresses completion packets. Each successfully accepted overlapped request,
including immediate success, therefore expects one packet; a synchronous
pre-acceptance failure expects none. Reclaim an address only after the due
packet has been consumed or native non-acceptance has been established. A
failed GetQueuedCompletionStatus with a non-null OVERLAPPED is
a real failed completion, including its returned byte count. On a **read**,
ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED or ERROR_HANDLE_EOF means
`Read{bytes: returned_prefix, eof: true, outcome: Complete}`. Deliver any prefix
before EOF; `eof=true` is legal only with Complete and those three native
statuses. Every other native error remains Failed with its partial bytes;
ERROR_OPERATION_ABORTED/cancellation and an empty successful read use eof=false.
The same codes on a write remain write errors, never read EOF. A recognized
read EOF returned synchronously also produces that terminal Read result,
with no completion packet expected for native non-acceptance; argument or
admission rejection remains a submission error. After accepted dispatch,
native failure is retained in a terminal outcome with sanitized
API/code/reason; it does not disappear as a submission error.

CancelIoEx success and ERROR_NOT_FOUND both race completion and prove no
buffer lifetime bound. Keep the operation pinned until the completion path
records Complete, Cancelled or Failed; cancellation may still return bytes
or a completed write prefix. `take_completion` returns the original write
Vec plus `written` (bounded by its length), so the host can retain its exact
unwritten suffix and classify ambiguous provider input. A second take/release
refuses IllegalTransition. Nothing here proves a provider accepted a message.

The collector records completion before posting a coalesced
`StdioNotice{identity,kind,sequence}` through the unwind-contained,
lock-free sink. A notification contains no buffer pointer and is only a
nudge; the host registers its wake before checking native state and rereads
after every wake/deadline. No native lock is held across a sink call, and
CallbackPanicked follows section 4.2 without dropping another port's custody.

`begin_close(port, Stdin)` atomically gates new writes, lets the outstanding
accepted write reach its real terminal outcome without cancelling it, then
closes only the host stdin endpoint. Partial/error/cancelled write results
remain separately retrievable; a half-close never claims that unwritten input
was delivered. It does not wait for the host to take/release the completed
write ticket before closing the endpoint. Stdout and stderr reads continue,
so `codex exec -` can receive prompt EOF while the host drains the response.
A blocked write keeps the close Pending; the host's existing deadline may
explicitly cancel that write or request All, then must still consume its actual
completion. `stdio_state.stdin_closed` reports the native endpoint fact.

`begin_close(port, All)` gates all new reads/writes, cancels outstanding I/O,
and closes every host endpoint after native requests drain. It may upgrade a
pending Stdin close without a second control slot: the original close ticket
remains the recoverable operation and its terminal Close scope is All. With no
pending close, a terminal Stdin close permits a later All close after its
result is taken and its ticket released; terminal results never get overwritten.
`Close{scope, result: Ok(witness)}` proves only that scope's endpoints closed
and its kernel requests drained. The host reads the returned Close.scope;
StdioClosed stays opaque. Failed close retains the port and native cause for
retry; read/write outcomes remain until taken/released across future
drop. `release_stdio` requires an exact **All** witness and every operation
released; a Stdin witness cannot release output readers or the port. Dropping
a reference never closes a live port, waits or frees pending buffers; the
supervisor recovers retained state through `stdio_state`. Failed launch or host
shutdown explicitly requests All close/drain. Process scope release does not
bypass stream cleanup.

`attach_stdio(owner, config)` is the safe binding for both same-process
re-adoption and a staged cross-process import. It verifies the exact current
or authenticated staged lifecycle/host/generation, validates successor limits
against every retained buffer charge and replaces only local notification
metadata. It never recreates pipes, changes resource roles or starts native
I/O. The receiver supplies its **own** Arc<dyn StdioSink>; source callback
pointers/Arcs are never serialized into a native transfer frame. Too-small
limits refuse ResourceLimit without losing old storage, completion records
or their admission charges.

Binding disables the prior sink before admitting successor notifications.
It returns without waiting for old in-flight callback references: while they
drain, `StdioState.binding` is Draining and new I/O refuses. On Ready the new
sink receives BindingChanged; a sink-free imported port reports Unbound.
The host registers its wake before attach and reads state after any nudge,
so no polling/extra thread is required. Existing operation IDs, partial results
and charges survive binding; callbacks carry the new identity only after the
old generation is fenced/drained. An inactive staged port may bind a sink and
report Ready, but cannot read/write until native activation; activate_transfer
refuses until every imported Windows provider port has a ready local binding.

`accept_transfer` reconstructs these Windows ports inside the native arena
from authenticated stream roles and duplicated endpoints, without new pipe
creation. The host uses ReceivedTransfer.processes to call attach_stdio on each
inactive owner before activation; after activation it calls stdio_state on the
same current-owner references to obtain its safe ports and resume framing.
Windows provider endpoints never leave the arena as ActivatedTransfer.streams
Files and never go through Unix AsyncFd. That vector carries only actual
host-owned/Unix stream Files; the native source automatically includes its
Windows provider ports in the manifest/frame instead of asking se-host to
extract or pass raw handles in TransferRequest.streams.

Generation replacement gates old submissions before effects, requests
cancellation and retains every outstanding outcome. The new owner uses
`stdio_state` after the existing ownership CAS/re-adoption to recover the
same operation IDs with current-generation references; old references refuse
HostChanged/GenerationChanged even if an old nudge is delayed. Before live
handover, section 40 freezes input and drains/cancels reads to a proved complete
frame boundary, preserving partial frames in its transfer state. Only then
may section 6 transfer/reassociate the quiescent endpoints to the successor's
single collector. Source notifications are fenced and all in-flight source
callbacks drained before that replacement; no source-process Arc survives
into the receiver. Staged ports stay inactive until activation and require the
successor's ready sink binding before activation. Abort restores
source ownership only before the durable Claimed phase; uncertain ownership
after Claimed remains pending under section 20. No pending OVERLAPPED moves
between collectors.

Pipe handles already associated with an IOCP cannot be moved by calling
CreateIoCompletionPort again, and the IOCP itself cannot be duplicated to
another process. The native handover path therefore uses the documented
NtSetInformationFile / FileReplaceCompletionInformation (Windows 8.1+) inside
se-proc: after freezing and draining all operations, the staged receiver
atomically replaces the shared FILE_OBJECT association with its own IOCP/key
inside accept_transfer, before returning the inactive import. Activation
checks that association but does not replace it again. The replacement uses
the duplicated endpoint. There is no detach-then-bind gap and source
and receiver cannot have different simultaneous associations for that object.
All original endpoints stay pinned and neither host submits I/O during this
replacement. After the host proves pre-Claimed and a still-valid source lease,
abort atomically replaces back to the source's retained IOCP/key **before**
discarding receiver resources; unproved restoration remains pending. After
Claimed only the successor may finish binding; unknown binding stays pending
with both copies retained. Native qualification must
prove this replacement for the actual named-pipe handles and shared object,
including a failed or unproved atomic replacement; failure never falls back to a
second collector, a forwarding host or hidden per-pipe blocking threads.

Windows create/connect/partial read/write, error-after-prefix, cancel-versus-
completion, future drop, generation replacement, EOF/close, blocked provider,
and quiescent handover are reviewer/native qualification obligations. Compile
checks prove signatures only; no native behavior is claimed by this amendment.

## 3. Durable data and native resources

`ProcessRecord` (format version 1, `se.process/v1`) contains lifecycle, host,
exact owner process, generation, root instance, scope, achieved guarantee,
entry method, native phase, optional exit status/ownership-release marker,
native observation timestamp and argv SHA-256. Store envelope supplies
project/session/actor, per-entity revision and commit timestamp. No secrets,
environment values, executable-name filter or live native handle is serialized.
Store import makes process records Historical and grants no native authority.

Wire encoding is shared with sections 10/20/50: fixed IDs use the canonical
foundation encoder; u64 start ticks/FILETIME/inode/device and ns timestamps
are lossless decimal strings; native Unix bytes and Windows UTF-16 use the
shared lossless path codec, never lossy display round trips. Enums are closed
tagged variants; unknown version/fields refuse before allocation. Section 30
does not publish a second wire-ID/error scheme.

`LaunchReservation` is committed **before creating even an empty scope**:
format, lifecycle, original host/owner/generation, 128-bit random scope_nonce,
created time and ReservationParent. An already delegated Linux parent includes its exact pinned
path/device/inode/boot; lazy LinuxUserManager is an explicit unresolved parent
kind with unit name derived from this reservation's host/scope_nonce. It does
not fabricate a path/inode before the manager creates a scope. Windows/macOS
and LinuxTracked have explicit tagged parent kinds. ScopeCheckpoint.parent
records the resolved physical parent (or chosen tracked fallback) while keeping
the original reservation unchanged; recovery validates that phase's actual facts.
Native names are fixed and reconstructible from this durable reservation:

* Linux directory: `se-<host-id-32hex>-<lifecycle-32hex>-<scope-nonce-32hex>`
  directly below the recorded delegated parent, never a searched ancestor.
* Windows job: `Local\\SE-<host-id-32hex>-<lifecycle-32hex>-<scope-nonce-32hex>`.
  A name collision refuses; it never adopts an existing job by name.

### Launch commit grouping

Three causal store barriers cover ordinary agent launch; each groups the facts
already known at that point, never a native call inside the transaction:

| Barrier | Facts committed together | Crash boundary |
| --- | --- | --- |
| C1 FULL | LaunchReservation, prepared session and prepared credential issuance when an external credential is required | Before even an empty scope or helper exists; prepared credentials admit no ordinary operation |
| C2 | Actual ScopeCheckpoint (`scope-prepared`) | Before begin_launch; exact scope cleanup remains possible without a published root |
| C3 FULL | Actual observed ProcessRecord/root, trusted first-use credential activation, session activation/readiness and incumbent revocation when required | After real exec/selected-conversation evidence; before authenticating ordinary work or reporting launch ready |

The host may attach the retained transport and obtain provider identity/readiness
while C3 is pending, but gates ordinary authenticated calls and launch success
until C3 commits. Failed C3 keeps the real child, pending credential/session and
native observations available for reconciliation; it never fabricates rollback
or repeats a launch under a new request identity after a lost reply. The public
mutation identity is created before first send and reused across uncertain retries.

**Four-commit exception:** Unix terminal attach, macOS and Linux uncontained
helper paths add a separate durable RootCheckpoint between C2 and C3, before
`authorize_exec`. Removing it permits vendor execution without recoverable
native start/group identity; moving it into C3 either authorizes before durable
proof or falsely calls an unexecuted child Running. This exception is counted
in E3 and in the launch target, not hidden as provider startup. Cancellation,
failed-start cleanup and stop use their own required crash-safe transitions;
three is the successful ordinary-launch count, not a cap on recovery records.

Embedded in-process binding issues no credential events. Required runtime.owner,
session-activation and new-schema FULL commits remain, with their actual cost
reported in section 80/E2. Standalone credential preparation and activation
are batched into C1/C3 instead of adding serial security transactions.

`prepare_launch` consumes LaunchSpec as well as the committed reservation,
so mode, selected terminal/broker and containment requirement are known before
native preparation. PreparedLaunch retains that spec; begin_launch
cannot substitute a different launch mode or policy after C2. For headless provider I/O,
`bind_stdio(&PreparedLaunch, StandardIo)` installs the child endpoints once after
`create_stdio`/the host's Unix reactor preparation, before `begin_launch`.
It refuses preexisting streams or a second binding and fences execution after a
failed binding; the prepared scope remains available for ordinary cleanup.
The host registers its transport for reads before beginning the launch. It inserts its
Starting arena slot **before** any native effect, creates an exclusive scope (no vendor child) and returns PreparedScope with an opaque
PreparedLaunch, OwnedProcess reference and ScopeCheckpoint. The checkpoint
contains reservation, resolved parent, exact ScopeIdentity and achieved guarantee. The host
commits that checkpoint (`scope-prepared`) **before** consuming PreparedLaunch
with `begin_launch`; no agent exec is legal before that commit succeeds.
A failed checkpoint commit revokes helper authorization, witnesses any
transient bootstrap exit and releases only the outside-witnessed empty scope.

`begin_launch` performs only the native creation step and returns Pending
with ticket/reference, or failure with retained custody. Linux exec-status
pipes are nonblocking and event-driven; `poll_launch` reads progress without
waiting. The host waits for a LaunchChanged nudge or its monotonic deadline,
then calls poll_launch again. Successful native creation/exec is not provider
readiness, provider login, durable publication, capture or task completion.
Short commands can already be exited. Ambiguous pre-exec death is a failure,
not a successfully started provider. On cancellation, the host prepares a stop token on the returned process,
commits Starting → StopRequested with revision CAS, then passes that token
with LaunchTicket to cancel_launch. A failed CAS sends nothing; a post-CAS
refusal is StopUnproved. No post-creation error discards a live scope.

Recovery input is a tagged `RecoverySource`: committed root Record, Reserved
LaunchReservation, scope-prepared ScopeCheckpoint, or pre-exec RootCheckpoint. These are different
facts, not a fake complete ProcessRecord with PID zero:

| Last durable phase | Cold recovery / cleanup |
| --- | --- |
| Reserved, no vendor exec permitted | verify protected parent/name (lazy manager unit derives from host/nonce); absent scope means no scope remains; existing exact-name empty scope may be reclaimed after outside emptiness; a populated/unreadable/replaced scope is Unproved, never guessed child identity |
| scope-prepared, root not published | verify exact scope object; it may contain a child whose identity was not committed; retain it as PendingScope, stop that authorized scope if rolling back, witness its emptiness with RootWitness::UnpublishedScope |
| root Record | validate instance + scope; recover same scope or report concrete Unproved cause |
| Exited committed, release not acknowledged | ReleaseExitedScope: reread exact empty scope then release; missing scope plus prior committed exit witness acknowledges already released; changed object is preserved/refused |
| Historical | no live adoption/control |

Windows's job-list launch associates the first child inside creation; a crash
before root publication closes the host job and invokes KILL_ON_CLOSE. Linux's
exact checkpoint permits scope-only cleanup without inventing root data.
Mac prepare returns the explicit MacOsPrepared nonce variant (Linux
uncontained preparation uses LinuxPrepared with the same staged protocol): no group or
PID is invented before spawn. Its short-lived native attach helper creates/validates the
group, reports its exact pre-exec start/image, and blocks on a parent-owned
exec-authorization channel. poll_launch returns AwaitingExecCommit with a
RootCheckpoint; the host commits that start/group and the intended executable
before authorize_exec releases the child. EOF/cancellation before authorization
exits the helper without executing the vendor. RootPrepared recovery verifies matching
boot/start/group and the committed exec intent, then independently observes
the first post-exec image (scripts may use an interpreter); no final image is
invented from the intended path. Once a ProcessRecord is published, another
image requires a new authorized transition or is IdentityChanged. If the root checkpoint never
committed, vendor exec was not permitted and the helper exits on parent loss.
Linux/Windows kernel scopes do not need this extra child barrier for cleanup,
but Unix terminal attach and uncontained Linux groups use it so no
unregistered vendor starts before the root/group checkpoint commits.

ArenaSnapshot exposes all slots/reservations/checkpoints/phases, including
ones without any store root row or with a poisoned operation. Its optional
root_checkpoint exposes a pending attach/start identity even before a complete
record exists; a callback/operation panic cannot hide that child from cleanup. It is a bounded
**complete arena** view with revision, not a machine census; at configured cap
it refuses a new slot instead of hiding entries. The host merges this with
store rows for agent status/list, pending effects, drain and crash cleanup. The
public operation still supplies Page/Window if it paginates the merged result.

### 3.1 State transitions, including refusal and natural exit

| From | Trigger/evidence | To / retained obligation |
| --- | --- | --- |
| no row | authorized unique reservation committed | Reserved; no child |
| Reserved | Starting arena inserted, vendor-free scope prepared and checkpoint committed | Starting; exact scope known, root may be absent |
| Reserved/Starting | validation or native failure with no live scope | Exited failed launch; no task-complete claim |
| Starting | native exec observed + running record committed | Running |
| Starting | cancellation/rollback intent committed with stop CAS before native dispatch | StopRequested; retained scope/ticket/rollback; failed CAS has no dispatch |
| Running | root exited, scope still populated | LeaderExited; children remain owned |
| Running/LeaderExited | natural/graceful root and required scope exit | Exited via witness_exit, no signal/token required |
| Running/LeaderExited/Starting | authenticated stop CAS | StopRequested |
| StopRequested | token expired/consumed, generation/identity recheck refuses, native dispatch fails or proof pending | StopUnproved with typed cause; CAS is never erased or mislabelled "nothing happened" |
| StopRequested/StopUnproved | outside required-scope exit witness | Exited; preserve dispatch errors/status |
| StopUnproved, ownership retained | explicit retry, fresh observation/CAS/token | StopRequested |
| StopUnproved, uncontained tracked group | owner-human release CAS after an ordinary stop could not be proved; no signal | StopUnproved with ownership_release; no live ownership or recovery re-adoption, not Exited |
| nonterminal | irrecoverable native custody, actual host/boot loss | Lost, never assumed stopped |
| Lost without ownership release | authorized native recovery + store CAS succeeds | actual Running, LeaderExited or StopUnproved |
| Lost | old required scope/instances exit proved | Exited |
| Exited | durable witness committed, native release succeeds, release acknowledgment committed | terminal released; history retained |
| imported | import | Historical; cannot become live custody |

A marked StopUnproved row is retained history, not an owned nonterminal row:
ordinary stop retries, admission, transfer and re-adoption exclude it. Replaying
the release returns its committed marker and finishes only non-signalling
retirement. It never supplies a new ownership generation.

Every other transition is IllegalTransition → shared `internal`, with report
ID/location and retained slot. Repeating a completed action returns its prior
fact; an intentional new instance needs a new lifecycle. Native phase changes
precede store commits only as pending facts and remain inspectable if commit
fails. A rejected stop after its CAS is a durable failed/pending outcome, not
a missing row. Same-generation re_adopt retrieves another reference; a true
generation transfer CASes the single arena owner and revokes older references.

### 3.2 Natural release and empty-scope reaping

`witness_exit(&OwnedProcess)` reads root/scope without sending a signal or
requiring a stop ticket. A Linux manager may remove an empty exact cgroup
before its final population read. For a still-held, previously validated
cgroup2 directory FD, recheck the recorded boot and use fstat to match the
same device/inode. Then openat(fd, "cgroup.events", O_RDONLY|O_NOFOLLOW)
returning ENOENT proves removal of that exact object: a live cgroup2 directory
always has that control file. The recorded path plus " (deleted)" from
/proc/self/fd/N can corroborate it. Do not require st_nlink == 0: E7 retained
st_nlink=2 on removed cgroupfs objects. EACCES/EIO, failed identity reads,
a changed object or a control file that still opens does not prove removal;
a readable file may instead supply the separate ObservedEmpty witness. This native
removed-object test, joined to the original root's independent
exit witness (or the explicit unpublished/no-child witness), is a successful
scope-exit witness, not ScopeUnreadable. Retain the removed-object fact and
pinned boot/device/inode separately from a population-zero read. The safe
ScopeObservation carries exit_basis = RemovedPinnedLinuxCgroup for that
path, or ObservedEmpty for an actual empty-scope read; populated/unknown
observations have no exit_basis. StopWitness retains this with ScopeIdentity
and RootWitness, and the host persists the same basis with Exited before
release acknowledgment. Section 50 renders a cgroup-removed witness method
instead of calling it a population-file read. An absent pathname alone, unreadable FD or replacement object proves no such closure.
It covers natural completion, provider-graceful exit,
failed launch rollback and prepared-but-never-created scopes. RootWitness
separates NoChildCreated, PinnedUnpublished, UnpublishedScope and Identified;
only the last carries a complete expected root identity. It never fills one
from guesses. Complete carries the achieved platform bound; Pending/Bounded
never becomes a successful strict removal by formatting alone.

Normal order is witness → commit Exited with evidence/status → release exact
empty native scope → commit scope-released acknowledgment. If the exact pinned
scope was already proved removed, release is an idempotent already-released
readback against that retained object witness, not an attempted removal of a
new object at the old path. Commit Exited and scope-released in the same order;
manager collection does not require an earlier committed Exited record to
recognize the first outside removal/root witness. Crash in either
gap is handled by ReleaseExitedScope from the protected store record and
arena snapshot. Startup, generation recovery and project Remove trigger this
bounded reaper; no idle directory sweep/timer is added. Reaper checks original
parent, boot, physical path and inode/device; never recursively deletes a
foreign/replaced directory. Persisted released rows prevent endless retries.
A native release failure is retained explicitly; natural agent exits cannot
leak scopes merely because request_stop never ran. After committed required-scope
exit, a failed empty-directory removal becomes durable cleanup debt (§8),
not a permanently charged live-agent slot. A fresh live/unreadable scope never
qualifies for that retirement.

## 4. Stop, reused roots, notifications and concurrency

Harness-graceful stop is host policy (default 5 s); native forced stop and
outside confirmation get the remainder of the **same** deadline (target
500 ms), never a fresh 30-second blocking wait. prepare_stop performs no signal.
The host commits stop_requested with revision CAS, then request_stop rechecks
token, generation, deadline and exact native custody before one native dispatch.
A failed CAS drops the token without action. A post-CAS refusal records
StopUnproved with its cause. Token consumption/expiry/illegal state is explicit.

A process-instance mismatch and a scope stop are different operations:

* If the caller's record/token does not match the arena's original lifecycle,
  expected birth or scope, refuse IdentityChanged before any signal (T14).
* If the **original tracked root has actually exited** and its PID was later
  reused, record ExitEvidence::Replaced and stop **only the already-pinned
  authorized scope**. Linux cgroup.kill cannot signal a replacement outside
  that cgroup. Its exact scope identity, not the reused PID, supplies custody.
  Whole-job Windows stop similarly targets its pinned job, not a PID lookup.
* This LeaderExited scope-only path is legal after same-host or cold recovery
  with matching protected scope custody; it never attaches the replacement as
  our root. No global PID/name signal, no refusal that makes an old scope
  permanently unstoppable. If replacement is itself a legitimate member of
  that owned scope, its termination is by scope membership, never because it
  reused the root's number.
* macOS and uncontained Linux verify the recorded group and tracked member starts immediately
  before group signalling. Reused individual PIDs are excluded; if the group
  cannot be tied to a live original tracked member, refuse rather than signal
  a numerically reused group. The native check/signal interval is a stated
  platform limit, not an atomic-handle claim.

After an ordinary stop could not be proved and committed StopUnproved, the
owner may use human-only `se stop AGENT --release` (no MCP/agent equivalent).
Running, LeaderExited and Lost must first go through that ordinary stop attempt;
release from those states is IllegalTransition. Print the best-effort
remaining members and their unknown/partial reason before reporting
"ownership released without an exit witness". No group signal, synthetic
empty population, exit status or `StopWitness` is created.

The host CAS-commits `UnwitnessedRelease` for the exact lifecycle/generation/
revision, preserving StopUnproved and the last diagnostic facts. Host lifecycle
serialization drains any admitted native dispatch before this CAS and prevents
new dispatch after it. Then `release_uncontained` revokes all arena references and closes only tracking
registrations/identity pins; it does not stop a provider or close its separate
stdio/PTY port. Only LinuxTracked/MacOsTracked may use this path, never a
Windows job or delegated cgroup. Native close failures remain explicit cleanup
debt and cannot restore signal authority.

Once committed, the marker excludes that ownership from live admission and
Remove blockers. Recovery retries non-signalling native retirement after a
crash but never re-adopts the released process/group. Remove also reports that
processes may remain; release never implies exit or a new lifecycle. Ordinary
unproved stop still blocks Remove without this explicit owner action.

The native attempt returns StopTicket **plus** dispatch Result; a failed
controller cannot suppress an independent complete witness. witness_stop and
witness_exit never signal. Complete requires the appropriate scope emptiness
and original tracked-root exit at the platform's stated bound. Preserve exit
status and any dispatch error separately. Original root executing outside a
required scope is ContainmentEscape / unproved, not an empty-scope success.
Prepared scopes with no child or unpublished roots have their own RootWitness
variants, not a fabricated absent PID.

### 4.1 Notification-driven waits

There is no wait_stopped method or deadline-long blocking launch. The host:
registers watch_exit (or supplies the LaunchSpec sink), immediately rereads
native progress, and awaits a nudge **or its existing tokio deadline**. It
rereads on each event and once at deadline. Registration plus post-arm read
closes the exit-before-subscribe race. No sleep loop, thread per stop, timeout
renewal, or two occupied shared blocking-pool workers while children run.
Native creation/query/dispatch steps use bounded host blocking work where
necessary; unavoidable OS-call latency is reported, not disguised as an
async wait. Long child setup/provider readiness never holds that worker.
The shipped host default is two finite-work jobs, shared across sessions;
`runtime.blocking_jobs` may explicitly raise the cap within 2–8, bounded by
native core availability. One/unknown-core hosts retain the existing independent
foreground and maintenance slots. The host reader and idle read-connection pool
use the same effective capacity; no native wait occupies either read slot.

ExitNotice carries lifecycle, **generation**, per-slot monotone sequence and
kind. It is a hint only. A late/duplicate notice cannot grant authority or
complete a stop; the receiving session rereads and ignores stale generation.
Coalescing uses the host's bounded/watch channel; errors and deadline reads
prevent a lost nudge from becoming silent success. No timer when idle.

Windows uses **one IOCP per host and the one existing native wait/collector
thread from sections 00/80**, GetQueuedCompletionStatus(INFINITE), associated
with every owned job. JOB_OBJECT_MSG_EXIT_PROCESS and ACTIVE_PROCESS_ZERO are
nudges; fresh process-handle/accounting reads establish truth. All scopes,
control wakes, provider-stdio completions (section 2.3), cancellation and staged handover transport use that IOCP. No
RegisterWaitForSingleObject, OS registered-wait pool, per-process waiter or
second collector is added. Native creation registers job completion before
any child can execute; the initial empty job is not a completed launch. Job
messages are not guaranteed delivery, so provider EOF/terminal close, explicit
queries and the existing host live-work catch-up also reread native state;
provider pipe EOF, terminal-close/attach-channel EOF, harness completion and
any observed root-handle signal each enqueue an immediate targeted read of
that lifecycle (dispatch budget <=50 ms). If that read finds the root exited
but members remain, arm a **single coalesced live-cleanup timer**, not one timer
per child: at most one root/accounting read per second per orphaned scope until
empty or the orphan-observation deadline: **5 s from the first observed root
exit with remaining members**. Nudges do not renew it. At expiry do one final
read, retain LeaderExited/StopUnproved and its remaining/unknown facts, then
remove that lifecycle from this timer; only a later explicit operation or the
existing live-work catch-up rereads it. This window never authorizes a signal
or establishes an exit witness. While this window is active, a missed final
child-exit message is observed within 1 s plus scheduling/read latency. This timer exists only for
LeaderExited/unproved cleanup work and stops on emptiness; idle hosts do not
poll. With neither a nudge nor a provider/terminal/explicit-read trigger, the
existing 15-minute live-work catch-up remains the worst-case discovery bound;
this residual is explicit, not prompt-exit evidence. Active stop deadlines
always force a final read even with no notification.

Linux pidfds, exec/error pipes and cgroup.events integrate with the **host's
existing AsyncFd reactor** (read/priority readiness), retaining owned
FD lifetimes through the safe NativeReactor registration port in HostConfig. macOS kqueue exit/group tracking likewise feeds
that reactor. No Linux/macOS extra collector thread is reserved. Where a safe
reactor adapter needs native registration, it is implemented inside se-proc;
the public NativeReactor/NativeReadiness/NativeRegistration and ExitSink
boundaries prevent unsafe code leaking into se-host. NativeReactor wraps the
provided owned File in the existing host AsyncFd/kqueue driver with Readable
or Priority interest; its task calls NativeReadiness::ready, and se-proc assigns
the lifecycle/generation/sequence nudge. NativeRegistration::rearm is called
after native state consumes readiness; until then a terminal pidfd or EOF
produces only one callback, preventing an idle readiness spin. PreparedScope
also returns the native-validated argv_sha256 so the pre-exec root index and
the eventual vendor record use exactly the same digest. NativeRegistration cancellation
disables callbacks without blocking an async thread; in-flight callbacks hold
Arc state until drained. There is no hidden tokio runtime or collector inside
the Unix backend.

### 4.2 Locks, panic and cancellation

The arena map lock covers allocation/removal/snapshot only. Per-slot locks
serialize launch phase, re-adoption, native dispatch and release. No store
transaction, provider call, callback, blocking read or deadline wait holds the
map lock. A stop token releases its slot lock before the host's CAS, and
request_stop reacquires/rechecks it through the native effect. Generation
handover cannot race an already authorized effect.

**panic=unwind is required**, matching Alpha's SE Code setting. Slots are
inserted before any effect; fallible native resources are RAII-owned inside
that slot immediately, never only in stack locals across publication. Wrap
native operation boundaries and every ExitSink callback in catch_unwind.
Windows extern "system" thunks catch every unwind before crossing the ABI;
with IOCP the event dispatcher is Rust, but the same rule applies to any
future OS callback. A sink panic marks MonitorFailed/CallbackPanicked and
posts the shared internal report; it does not kill unrelated sessions.

A poisoned lock is not silently cleared into Running. Recover its inner slot
only to mark it quarantined, retain handles and expose it in arena_snapshot;
return LockPoisoned/internal. A quarantined scope may be independently
observed and stopped through its validated native scope; it cannot launch or
transfer until reconciliation commits its actual phase. No poisoned slot is
forgotten because its store row is missing. Panic outside an effect has a
recorded internal report; panic after creation preserves cleanup
custody, including natural-exit release. No process-wide abort profile is
introduced to make these paths disappear.

An expired token cannot dispatch; wait deadlines are solely host-owned and
cannot be extended by a callee parameter. Cancellation before child creation
releases an empty prepared scope after its committed rollback intent; after
creation it uses prepare_stop → host stop_requested CAS → cancel_launch with
the same prepared token/deadline and a retained stop ticket. cancel_launch
consumes both tickets only after matching lifecycle/generation; failed CAS
keeps the launch inspectable and dispatches nothing. Dropping a Rust future does not detach the OS effect.
A native call already in the kernel cannot safely be killed by terminating a
host thread: the host retains the operation/slot and reports pending until it
settles. Instant measures monotone awake time and may exclude suspend on some
platforms; resume triggers a fresh host deadline/identity check and reports
elapsed wall/awake distinction, never quietly extending a requested stop.

## 5. Per-OS launch and stop

### 5.1 Windows jobs, consoles and detached runtime

Read exact identity through OpenProcess(QUERY_LIMITED_INFORMATION|SYNCHRONIZE),
GetProcessTimes creation FILETIME and QueryFullProcessImageNameW. Hold the
process handle; only a genuine ERROR_INVALID_PARAMETER absence counts as
absent, not access denied/partial image/failed wait. Query handles are not job
custody and need not carry terminate rights. Filetime remains a lossless u64.

prepare_launch creates a unique job with KILL_ON_JOB_CLOSE | BREAKAWAY_OK,
never SILENT, reads limits back, and checkpoints its original policy. At
begin_launch use STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_JOB_LIST so association
is part of creation, not suspended create/assign/resume. Always request
CREATE_BREAKAWAY_FROM_JOB for an independently owned agent launched outside
the caller job, **in addition to** JOB_LIST; these flags solve different
problems. The caller (including SE Code) must allow explicit breakaway. A
strict caller job produces BreakawayDenied/job-breakaway-refused; no retry
without the flag, elevated scheduler, shell or weaker job. Ordinary descendants
inherit our job; explicit independent detach is the ratified scope limit.

Use an absolute non-null application name, correctly quoted mutable Windows
command line (empty args/quotes/trailing backslashes included), explicit sorted
double-NUL UTF-16 environment, cwd, UNICODE_ENVIRONMENT and
EXTENDED_STARTUPINFO_PRESENT. Headless uses CREATE_NO_WINDOW; Window uses
CREATE_NEW_CONSOLE and the console stream rules in §2.2. HANDLE_LIST and
JOB_LIST share one aligned attribute list with backing storage alive through
CreateProcess; delete it on every return path. Only designated stream copies
are inherited; no job/host/credential/other-agent handles. Close the initial
thread handle, retain exact root and job in arena. Failed readback/publish
terminates only this job and returns retained cleanup until witnessed empty.

Stop calls TerminateJobObject. Complete requires pinned original root exit
(or unpublished-child scope proof), fresh ActiveProcesses == 0 and the exact
scope identity. Query job PID lists only for labelled diagnostics, growing on
MORE_DATA/full buffers within caps; they are not an emptiness oracle. Root
status comes from GetExitCodeProcess after its handle is signalled; STILL_ACTIVE
is not confused with an actual code 259 until signalled. No synthetic count.

`spawn_runtime` is a **stateless host-private bootstrap**, not unowned
arbitrary process launcher. Windows se up from SE Code uses CREATE_BREAKAWAY_FROM_JOB |
DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
explicit null/ready streams and no agent job-list attribute. The new process
becomes the one standalone runtime and acquires runtime.lock; the initiating
CLI holds only an exact RuntimeChild pin until authenticated endpoint/readiness.
No KILL_ON_CLOSE job owned by SE Code holds it. If its inherited job prohibits
breakaway it refuses truthfully; do not fall back to a child that dies when
SE Code closes. The runtime-up adapter owns its fixed arguments, credentials,
10 s deadline and unique-owner race; this primitive is not a generic agent
escape hatch. A Windows Terminal single-instance `wt` handoff must be tested
as a brokered path: window appearance is not proof of child membership.

### 5.2 Linux automatic delegation, native floor and entry

**Wave 1 uses the uncontained tracked process-group path on Linux.** Delegated
cgroups and their fresh-scope transport join in wave 4 before alpha; the E7
mechanism proofs remain valid. The remainder of this subsection specifies that
wave-4 path, not a wave-1 dependency.

Preferred contained-mode floor: unified cgroup v2 with cgroup.kill (Linux >=5.14), pidfd_open /
pidfd_send_signal, and close_range(CLOEXEC) support (>=5.11). clone3
CLONE_INTO_CGROUP is preferred; runtime probes check actual capabilities,
including seccomp restrictions/backports, rather than trusting version text.
Only ENOENT/ESRCH of the target proc file is absence. Parse proc stat numeric
suffix as bytes after the final `) `; comm may contain spaces/parentheses or
invalid UTF-8. Bracket executable symlink read with start/state rereads and
combine field 22 with boot UUID. A zombie is an exited record, not absence.

**A stranger needs no manual manager command.** Prime adopted Alpha's
option (b): neither SE Code nor its existing process must move. HostConfig
AutoUserManager probes current delegation, and the embedded
host **and se up's host** request a fresh delegated user scope and temporary
creator for every LinuxUserManager process launch, warm launches included.
Each creator exits after handoff; no resident creator or reused empty scope is
assumed for the next launch. se up calls spawn_runtime only to create the runtime; delegation
for agents is lazy prepare_launch plumbing shared by both hosts. Prime's
2026-10-30 native-timing decision replaces the systemd-run process on this
agent-scope path with direct user-manager D-Bus StartTransientUnit. Reuse is
rejected: it would require resident creation authority, contrary to B3.

Start the installed native se private bootstrap with fixed literal argv and
an owner-only rendezvous descriptor; no provider command, credential or
host-controlled bus address goes in argv. The short-lived bootstrap opens
the current user's authenticated local manager bus and requests only its own
fresh reservation-derived .scope: mode=fail, Delegate=yes and its own live
PID. Validate the expected same-user manager/bus endpoint through the native
adapter; no system-bus privilege or permission change is requested. Install
the authenticated manager's JobRemoved match and call Subscribe before
StartTransientUnit. Filter signals to the exact reservation-derived unit and retain at most its
one completion if it arrives before the method reply; correlate its job object path with the returned job and its unit with
the exact reservation-derived unit. Drive the bus FD on readable events up
to the launch deadline, not a sleep loop or repeated /proc read. Only a
correlated result=done permits one /proc/self/cgroup read proving actual
placement in the requested scope; a wrong scope, other result, timeout or
transport error remains a concrete preparation failure with retained custody.
Then create/enter its private leaf. The host's cgroup is unchanged.
The wave-4 Linux-native D-Bus transport is private to the short-lived bootstrap.
Try pure-Rust/MIT zbus first; measure marginal release-binary size and actual
scope readiness against the retained libdbus path before selecting it. Charge
any executor/thread and its startup to this transient helper, never a resident
host runtime or per-agent service. Section 80 owns the comparison and target.
If zbus misses the agreed budget, libdbus is the fallback: dbus 0.9.10 with
only vendored enabled, default features off, through blocking::Connection
and libdbus-sys 0.2.7. Retain its AFL-2.1 notices/election.

Declare the selected transport only under Linux target dependencies during
wave 4; no dependency is added by this contract correction. Both paths open
only the validated local user-bus endpoint and await correlated completion,
with no sleep-placement polling or systemd-run process in the agent path.
An absent manager or unavailable delegation
still selects the existing explicit uncontained default, with its actual
cause; a transport/malformed-reply/native error cannot fabricate delegation.
The agent path launches no systemd-run process. The separately specified
standalone runtime service-detachment path in §5.5 is unchanged.
The transient helper reports its manager-assigned cgroup and transfers a pinned
directory FD over authenticated same-user IPC; validate cgroup2, boot, exact
path/device/inode and create permission. The host first commits a LinuxUserManager
reservation, with unit se-agents-<host>-<scope_nonce> derived exactly from it.
prepare_launch obtains the unit, creates the private owned child cgroup and
moves its temporary helper **inside that same child cgroup** before returning
ScopeCheckpoint. The checkpoint records the resolved parent's physical identity.
The helper retains only the authenticated authorization/control channel and
reserved native resources; it creates no vendor child during preparation.

**The unchanged host does not clone a child across a delegation boundary.**
An SSH host can be in `user-1000.slice/session-*.scope` while the prepared
scope is below `user@1000.service`. The common ancestor's cgroup.procs may be
root-owned: possessing the target directory FD does not grant permission to
move or clone a child across it. Native EACCES remains a real refusal, never
an ENOSYS fallback, permission change or silent uncontained retry.

For LinuxUserManager headless launch, begin_launch dispatches a one-use native
creation request to the temporary helper **already inside the prepared scope**.
Only after C2 commits may the host send that request, binding the reserved
lifecycle, host generation, scope nonce and physical scope identity to the
validated helper peer's UID/PID/birth. Literal vendor argv/env and allowlisted
child stream descriptors travel only over this protected channel, not in the
bootstrap command line, bus request or diagnostics. The helper performs the native
creation/exec step there; it decides no store transition, provider policy,
credential activation or readiness. begin_launch/poll_launch remain nonblocking
host operations using the existing reactor and launch deadline.

The helper observes the exec-error channel and the child's native status/image
while it is still that child's parent, and reports the actual exec outcome.
EOF alone is insufficient (§5.2's native exec rule). It keeps custody until
that outcome and the host's complete handoff are resolved. It captures the
exact child's pidfd when available, brackets its boot/start/image and transfers
the native pin, exec-error channel and required
stream/control resources by authenticated SCM_RIGHTS. Host-owned stream ends
already prepared in the arena stay there; only missing roles are transferred.
The receiver validates the complete role set, exact instance and scope membership,
registers native exit/I/O sources and retains the child in the existing Starting
slot before acknowledging custody. The helper retains its copies until that
acknowledgment, then closes them and exits; its exact exit is witnessed before
preparation custody retires. Once the host has validated and registered the
complete resource set and retained the root plus reported exec outcome,
helper exit is normal closure,
even if the final ACK was lost. That host-local custody fact, not mere ACK
transmission, separates normal closure from an incomplete handoff. No permanent owner/reaper or resident per-agent helper is
introduced. A duplicate request cannot create a second child: it returns the
same retained result while the handoff is pending. A lost reply, bad bundle,
helper death before complete host registration or expired authorization retains
the checkpoint/ticket and native failure for reconciliation; it never starts a replacement child or fabricates
Running. EOF before authorization exits without vendor creation; after creation,
a failed handoff retains the C2 scope-only cleanup obligation under §3's stop
CAS/recovery rules, without an unregistered PID kill.

The helper's presence keeps the scope alive until the vendor child has entered;
agents keep it alive thereafter. If empty and collected, the next launch requests
a fresh scope; an open directory FD alone is not a keepalive. The embedded and
standalone hosts stay in their original cgroups. The helper is inside reserved
native custody and visible in the arena, never an unrecorded child outside the
cleanup scope. Pre-checkpoint rollback revokes authorization and witnesses helper
exit. Recovery resolves only the deterministic manager unit, forbids vendor exec
and retains a populated/unreadable result as Unproved until that exit is confirmed.
No scope is adopted just because its unit name matches. Supplied/current roots
must independently permit the selected native actor's entry; a received FD does
not bypass the common-ancestor check. No shell interpolation, ambient PATH search
or root escalation is permitted. The manager-assisted cold path, native creation
handoff and helper closure are charged to the existing launch budget (§8).

No user manager/helper/delegation is normal in minimal containers, WSL without
systemd, non-systemd distributions, or SSH sessions without an available user
bus/manager (including absent linger after logout). In default BestAvailable,
select LinuxPrepared/LinuxTracked process-group custody with
ContainmentGuarantee::Uncontained { reason } **before vendor creation**. Report
`containment: "uncontained"` and its mapped `containment_cause` (§7) in status
and launch receipts. The `custody.linux-cgroup` doctor warning carries the
capability finding, not an emitted refusal code. The fixed reason is retained
in the guarantee;
PlatformCapabilities.kernel_scope retains the full probe ProcError/native cause
for the host to render alongside that status fact. This is **not a default launch refusal** and does
not change provider permission defaults. No cgroup.kill is claimed; use
native identity-bracketed group signalling, tracked member/root witnesses and
the same deliberate-escape/race bound as macOS. Native pidfds remain preferred
where available; an older kernel lacking them uses start/image rechecks and
is explicitly non-atomic. Strict KernelScope is an explicit requested contract;
it may fail with launch-failed and cause ContainmentUnavailable, never a bogus
cgroup status refusal. Requested optional hardening is separately enforced.

Open physical cgroup directories with DIRECTORY|NOFOLLOW|CLOEXEC, verify
cgroup2 magic and fstat device/inode/boot, use openat+NOFOLLOW on kernel files.
Never search a writable ancestor, move the host as a side effect of launching
an agent, or delete another delegated subtree. The prepared checkpoint pins
the exact private child scope before vendor creation/exec.

Preferred raw clone3 uses INTO_CGROUP|PIDFD and SIGCHLD (no shared VM). For
LinuxUserManager this call and the permitted fallback run in the temporary
scoped helper; direct supplied/current-root launches must satisfy the same
entry permissions from their actual caller. Prepare all argv/env/FDs/error-pipe
state in that native parent. Child executes only async-signal-safe
native calls: setsid, intended signal reset, streams, CLOEXEC on other FDs,
chdir and execve; no allocation/locking/log formatting/unwind. Parent monitors
the CLOEXEC exec-error pipe asynchronously. EOF alone is not proof of exec:
combine fresh image/known child status; ambiguous pre-exec signal death fails.

Fallback is **only ENOSYS** (syscall unavailable), with raw fork and writing
0 to the pinned cgroup.procs before agent exec, from that same authorized
native parent. EACCES/EINVAL/EPERM retain the real configuration/security
error and stage in the launch result; they are not silently reclassified as missing
clone3. A host may add a reviewed explicit capability probe for a future
feature-specific fallback, not guess from errno. The creating native parent
captures a pidfd while this is still its unreaped child and brackets its
identity before transfer. Record EntryMethod::LinuxClone3 or
LinuxPreExecMigration { clone3_errno }; helper origin invents no new entry method.
No process-group retry after a failed cgroup launch; the uncontained
mode above is a pre-creation capability choice. Reap only exact
owned children (waitid for our pidfd/child), never waitpid(-1), a library-wide
SIGCHLD takeover, or process-global subreaper setting inside SE Code.
After helper exit the host is not the root's parent: pidfd readability proves
exit, not a wait status. Preserve a status actually observed by the helper
before handoff; otherwise report ExitStatus::Unavailable with reason
ExitStatusUnavailable::NotOurChild when no authoritative status is available.
Missing pidfds keep the documented identity-recheck bound, without a fabricated pin, exit code or resident reaper.

No mandatory Landlock/seccomp guard gates alpha launch. ReadOnly/Workspace/
NamedUnrestricted profiles are passed with the provider's safe/default or
saved named opt-in policy. OptionalHardening::Required is explicit: section 70
owns its complete restrictions and compatibility; an unsupported requested
hardening returns HardeningUnavailable with its cause. No implicit network
or AF_UNIX denial breaks stock Claude/Codex or forces a new provider transport.
The original S2 offline filter is reference only. Report same-UID cgroup
migration as a stated residual; the genuine kernel scope still contains
ordinary forks/double-forks/setsid until an explicit migration.

cgroup.events populated is a boolean; populated does **not** imply an exact
member count. Stop writes 1 to the exact cgroup.kill, then independently reads
population and root evidence. No inference from successful write or leader
exit. Diagnostic pre/post enumeration is best effort and labelled (§7).
Same-host re-adoption retains pidfd/cgroup FDs; cold recovery validates protected
checkpoint/record machine/boot/parent/device/inode. A reused root with proved
original exit uses the authorized scope-only path, never signals its new PID.
A malformed/unreadable control field is ScopeUnreadable, not population zero.
The distinct proved-removed exact-object path in §3.2 succeeds with the joined
root witness: retain that basis and never present it as a read of populated=0.
A changed object or merely missing pathname remains unproved.

### 5.3 macOS supported group/tracked-member policy

Identity is proc_pidinfo(PROC_PIDTBSDINFO) start timeval + proc_pidpath image +
kern.boottime, bracketed by a second start read. Validate exact sizes/timeval
ranges. ESRCH alone is absence; EPERM/partial/boot/image failure is unreadable.
Register kqueue EVFILT_PROC NOTE_EXIT for the root and each tracked member,
with identity reads before/after registration; EV_ERROR remains an error.
Use NOTE_FORK events where available plus explicit group enumeration when
observing/stopping; grow/retry full native PID buffers without silently
truncating. They support tracking, not an adversarial containment claim.

Mac prepare records MacOsPrepared, then native posix_spawn launches the installed
se attach image with POSIX_SPAWN_SETPGROUP (new group) and
POSIX_SPAWN_CLOEXEC_DEFAULT plus an explicit file-action allowlist. This helper
exec closes unrelated host descriptors before waiting, reports its pre-exec
identity and waits on only its intended authorization channel. Host stores
the RootCheckpoint before authorize_exec; the same PID then execs the vendor.
EOF before authorization exits the child. This avoids a permanent wrapper and
never manufactures a group ID before its PID exists. See §3 for recovery of
this phase and the single allowed image transition. kqueue is armed before
releasing exec so quick exit is not lost.

Stop enumerates the group, reads each tracked member's boot/start/image, reads
again immediately before group SIGTERM, and rechecks before SIGKILL escalation.
The host first uses harness-graceful shutdown; escalation stays within the
same deadline. Never use a PID/name-pattern kill. A reused member is not
signalled individually; a reused group without any live original tracked
member is refused. Root exit does not imply children exit. The outside reader
requires the group empty and every tracked original instance exited/absent/
replaced, preserving unknown status as unknown. A still-live tracked member
outside the group is explicitly reported as an escaped remaining obligation;
no false success and no unowned-PID rescue kill.

This is Prime's supported alpha policy: deliberate setsid/setpgid escape or
unobserved reparenting is a stated limit under the same-user boundary, not a
reason to refuse default J2/J5. Native PID rechecks are not atomic signal
handles; no Mach task entitlement or impossible task_for_pid guarantee is
required. Full host loss reopens protected tracked records by boot/start/image,
reestablishes kqueue/group tracking and commits re-adoption without changing
agent PID/birth. Handover preserves the same instances and transfers/reopens
tracking before old registrations close. G6 never permits stopping a known
replacement just because its PID equals a saved number.

Section 90's ordinary orphan/group-child checks apply; its deliberately
setsid-escaped macOS case must report the ratified bound rather than require
unescapable-tree behavior. This is a runner-contract reconciliation, not a
claim that refusal satisfies the real normal-provider journey.

### 5.4 Unix interactive windows (Linux and macOS, in alpha)

WindowSpec selects a **closed terminal adapter**, not arbitrary shell text.
Linux adapters cover xterm literal -e argv, konsole's separate-instance exec
argv, and gnome-terminal's brokered exec. macOS Terminal uses native application
launch/Apple Events with escaped arguments only at its documented boundary;
no interpolation of task/environment/secrets. Adapter selection/availability
belongs to host configuration; missing display/terminal is window-unavailable
with attempted adapters and the explicit headless alternative.

The terminal launches only the installed native se attach image entry with
a protected, owner-only one-use bootstrap descriptor, not the vendor yet.
This is runtime launch plumbing, not a new public OPS verb/MCP tool. Its
control connection proves OS peer uid/PID/birth and matches the reserved
lifecycle/nonce; no claimed agent ID in argv grants authority. The helper has
an actual controlling PTY/slave (or establishes one), reports its native
start/group and waits for the host's authorization. In Linux it enters the
exact prepared cgroup **before vendor exec**, by self-writing 0 through the
validated target or receiving its FD on the authenticated channel. Before
creating a terminal/attach peer, prepare_launch uses the selected adapter's
actual spawning origin (the pinned broker when it brokers launch) to probe
common-ancestor and target entry permission. An FD is not migration authority.
If the origin or permission cannot be proved usable, default BestAvailable
chooses LinuxPrepared/uncontained with the existing cause no-delegation, before
any vendor or terminal child exists. The native cause explains the denied or
unproved selected origin; a usable headless manager scope does not imply that
this different actor can enter it. Clean up/witness any vendor-free manager
helper/scope before returning that fallback checkpoint. C1's original parent
remains unchanged; C2 records the actual selected tracked fallback per §3.
Do not create a terminal child to discover denial and then launch a second one.
An explicit strict KernelScope requirement retains its existing failure policy.
After a contained plan is selected, a later native EACCES/permission race is a
real failed launch with retained custody, never a weaker retry. This window
path keeps its RootCheckpoint and same-PID exec contract; the headless SSH
proof does not qualify terminal/broker integration. The preselected uncontained
plan establishes its recorded process group instead. On macOS
it creates its group. Record EntryMethod::TerminalAttach, not a fabricated
clone3 errno: the terminal/broker, not clone3, created this attach process. The host commits RootCheckpoint, arms tracking, then
authorize_exec releases execve into the literal vendor argv/env. The same PID
becomes the agent, so the helper is transient, not a process per seat. The
helper image comes from HostConfig.helper_executable, an installed path supplied
by the package/host, never current_exe of an embedded SE Code server. It preserves
a terminal-provided controlling PTY and creates a new process group; it does
not blindly setsid a process already leading a terminal session. A host-supplied
PTY slave is attached only when a new session actually needs one. All unrelated
descriptors, especially authorization write ends, are closed before waiting;
CLOEXEC alone on a pre-exec waiting helper is insufficient to ensure parent-loss
EOF. The helper exits on closed authorization without starting the vendor.

A terminal broker's root PID, window title or successful client exit is not
agent identity. Only the attach peer/root handshake publishes the process.
Timeout/cancellation revokes the nonce, closes exec authorization and rolls
back the exact prepared scope. Close only an owned terminal client/frame or
its native window handle; never kill the shared terminal server or another
tab by process name. A registered helper that exits before exec produces a
failed native launch, not provider success. Capture/vendor readiness are
host-harness concerns after this native handshake. Test terminal broker
handoff, quoting, actual keyboard/screen streams and window close on each OS.

### 5.5 Detached runtime startup, readiness and failed-start custody

NativeProcessApi::spawn_runtime takes the persisted MachineId, a fresh
startup_nonce, installed native executable, literal arguments/explicit env and
one deadline. It reads actual boot/start/image and returns RuntimeLaunch with
an exact RuntimeChild pin, ProcessIdentity and RuntimeDetachment. Machine ID
is loaded by the host from protected state, never generated inside this call.
The host allocates a bounded pending-start slot before invoking spawn_runtime;
errors after native creation return RuntimeSpawnFailure with remaining
RuntimeChild for that slot, rather than discard cleanup custody. Only a
proved no-child effect may return remaining=None; unreadable identity does
not make a created child vanish. The private helper closes unrelated FDs, obtains
a native start pin and reports the actual runtime PID, never a manager/launcher
PID. A helper crash/EOF before ownership commit makes the runtime exit without
admitting agents. No generic public unowned process launch is introduced.

On Linux with a user manager, invoke its transient **service** mode (no --wait,
--pipe or --pty keeper) for the native bootstrap, using fixed argv and a
protected rendezvous. The manager creates it outside SE Code's cgroup and
parents it independently; RuntimeDetachment::UserManagerUnit records this.
Agent Delegate=yes scope acquisition still happens lazily for each agent process,
not by moving SE Code or recursively calling se up. HostConfig.linux_delegation
owns that agent-scope policy; the obsolete RuntimeLaunchSpec delegation field
is removed so runtime detachment cannot be confused with lazy agent delegation. If manager startup is
unavailable, the installed native bootstrap creates a new session, closes the
controlling terminal/standard streams and forks once to release its transient
launcher; obtain the final child's PID/start through authenticated rendezvous.
setsid alone **does not escape an inherited cgroup**: report SessionOnly with
inherited_cgroup=true where applicable, and uncontained status. Such a runtime
can outlive terminal/session close but is not promised to survive an external
caller-cgroup kill. Do not claim otherwise from a changed parent PID.

On macOS, posix_spawn the installed bootstrap with explicit descriptor actions;
the bootstrap calls setsid while it is not already a group leader, closes its
terminal/streams and forks the final runtime, then exits. No fork/allocator
path runs inside the multithreaded embedding host. Pin and authenticate the
final child's boot/start/image, not the short-lived helper, and report
SessionOnly { inherited_cgroup: false }. Windows uses §5.1's explicit breakaway
and reports WindowsBreakaway. A restrictive parent job remains an honest
job-breakaway-refused; running se up **inside that same restrictive job is
not a remedy**. Launch from an independent terminal/permitted caller or change
the containing caller's BREAKAWAY_OK policy; do not elevate or weaken it.

The child initially accepts only authenticated startup/transfer IPC, no agent
admission. Unique-owner acquisition is in the runtime-up host adapter: same
machine runtime.lock + owner PID/start + nonce. A concurrent existing ready
owner wins; the losing child stays uncommitted and exits, while the caller
connects to the independently verified existing endpoint. Neither kills the
winner. Handover children may remain standby without acquiring the old owner's
lease; they use the §6 store/lease barrier before activation.

* Successful new startup: host verifies the child holds the expected lease and
  endpoint, then passes RuntimeReadyProof (nonce, exact owner, host instance,
  authenticated File) to commit_runtime. Native checks bind the peer/nonce to
  the pinned child. Child acknowledges readiness/ownership commit before its
  parent-loss escape is enabled; after that acknowledgment it is an independent
  owner. commit_runtime consumes the pin and returns RuntimeReady. A failed or
  ambiguous commit returns RuntimeCommitFailure **with the child pin**, so the
  host reconciles its authenticated lease/commit status rather than blindly
  killing a runtime that may already have admitted work. The pending-start
  slot persists through this ambiguity; a retry of commit_runtime with fresh
  authenticated proof is idempotent for the same nonce/owner. abort_runtime
  refuses if ownership has committed, retaining the pin until the ready owner
  is reconciled.
* Failed startup/timeout/losing race: abort_runtime(&mut child) revokes the nonce,
  requests private pre-admission shutdown, and if needed terminates only the
  exact pinned instance after native recheck. It is dispatch, not proof. Unix
  rechecks have the explicit non-atomic bound; Windows signals the held handle.
  Never terminate an existing owner, helper PID substitute or reused PID.
* Outside confirmation: witness_runtime rereads the pinned child's native state
  and yields Pending or RuntimeExitWitness with identity, exit evidence/status
  and timestamp. No failed dispatch is discarded. Only Exited permits
  release_runtime to close the pending pin and the host to retire the failed
  startup slot. Deadline expiry with Pending reports stop-unwitnessed
  and retains custody; dropping a future is not a detach/cleanup mechanism.

Commit/abort checks serialize on the per-child startup slot. EOF before ready
commit cleans up an uncommitted child; EOF after a proved commit does not kill
an owner. A lost final acknowledgment is reconciled using lease, nonce and
native peer proof, never guessed absent. Native crash checks must exercise
both sides of this handoff, unique-owner races and all three platform starts.

## 6. Service generations, live handover and actual host loss

Same-process service reopen keeps the native arena above generations. Gate
admissions, drain native work, flush writer, then re_adopt(record,from,to)
CASes the arena generation. Old handles/tokens refuse GenerationChanged;
from==to retrieves another reference to the same owner. Native callbacks carry
generation and sequence; a failed provider reconnect retains native custody.

**Live SE Code↔daemon handover is in alpha** (00/50/80), distinct from a crash.
The new runtime starts detached through spawn_runtime, proves exact PID/start
and same-user IPC, and remains standby while the old owner holds runtime.lock.
Host section 40 controls hold/interrupt/active-map, store flush/CAS and one-time
input/delivery settlement; native handle transfer does not replace that barrier.
No input is offered by both generations during transfer. B8 is defined in
section 80 and timed from cutover start after participating agents are
interrupted to exact idle; quiescence time is reported separately. The source
writer is drained and joined before exclusive maintenance commits FULL Prepared.
The durable phases are Prepared, Claimed, Finished, Aborted and Recovered.
ReadyToClaim and Activated are not additional durable commits; native activation
is retained in memory until Finished binds its actual receipt, final capture/
queue cut and independently verified source-resource closure. Destination
consumers remain disabled until that FULL Finished commit. Aborted preserves
proved pre-claim source restoration; Recovered establishes a checked fresh
owner for a claimed transfer. Combining those outcomes would erase who owns
the native resources after a crash.

The native two-phase protocol is:

1. Source gates custody/admissions and creates an offer ID, target host/generation,
   bounded manifest and deadline. Pin the exact peer process. begin_transfer
   retains every original resource; no last handle is closed yet. The source
   calls the safe read-only `transfer_manifest(&offer)` to obtain the actual
   immutable TransferManifest, including `transfer` and `resources_sha256`,
   before committing section 20's FULL Prepared record. se-proc generates
   `transfer` with a CSPRNG inside begin_transfer: it is the native nonce,
   **not** the host's independent UUIDv7 transfer RecordId. The host records
   exactly this returned nonce/digest in Prepared and every later phase; it
   does not generate or substitute a second native nonce.
   This accessor performs no transfer effect and returns no native handle.
   The digest is produced from the exact canonical authenticated native
   resource frame, excluding its digest field, and binds the offer/peers,
   generation and actual resource roles/bindings. It is the same digest that
   accept_transfer validates and TransferReceipt echoes; the host never
   substitutes a hash of a guessed/Debug/JSON reconstruction. Any changed
   resource set requires a new offer/nonce; repeated reads of the same offer
   return the same metadata. Native nonce/frame data remains private host
   custody, excluded from public CLI/MCP/history/export surfaces.
2. TransferEndpoint is an authenticated same-user pipe/socket already bound to
   that peer by native identity. TransferManifest lists exact records/resource
   roles; it is data, not authority by itself. Windows uses DuplicateHandle
   into the pinned target for jobs, root handles, native provider endpoints and
   host-supplied stream handles. Linux sends pidfd/cgroup/control/stream FDs
   by SCM_RIGHTS over the
   verified socket. macOS passes streams/PTYs and protected records, and the
   receiver reopens kqueue registrations with before/after native checks.
3. accept_transfer verifies every expected resource/record/peer, installs it in
   the successor's **inactive staged arena**, and returns ReceivedTransfer.
   Windows jobs keep KILL_ON_CLOSE and explicit BREAKAWAY_OK. The native bundle
   is indexed by TransferResource(slot,lifecycle,kind); raw remote handle values
   or SCM_RIGHTS payloads stay in the authenticated native frame, never public
   records/logs. TransferManifest and TransferReceipt deliberately implement
   no Debug: their native nonce cannot enter ordinary formatting. Receiver
   verifies the complete manifest and descriptor types,
   rejects extra/missing roles and closes an invalid received bundle.
   No request client or agent gets a job handle; the only allowed second copy is this authenticated
   staged successor arena. Receiver observes the same live agent PIDs/births.
   Returned OwnedProcess references remain inactive: native readback and
   attach_stdio's local sink/limit binding are allowed, but I/O/launch/stop/
   re-adopt effects refuse HostChanged until activation. Local binding does
   not bypass the host ownership/lease barrier.
4. Host section 40 performs its durable ownership/generation CAS and unique
   runtime.lock transfer. It calls activate_transfer only after that barrier;
   the receiver returns ActivatedTransfer with exactly-once host-owned/Unix
   stream Files and activates its ready-bound Windows native stdio ports, plus
   TransferReceipt identifying offer, hosts, generation, peer identity and
   native resource-manifest digest over the authenticated
   channel. Before activation, Windows removes each old job completion-port
   association through the job-specific API under the supported Windows floor,
   binds it to the successor's one IOCP and rereads root/accounting before and
   after. The reads cover messages lost during reassociation; queued keys are
   immutable slot IDs checked against
   generation, never freed pointers. A pre-Claimed abort restores the source
   association and rereads; after Claimed, ownership cannot return to the source.
   Source commit_transfer verifies the receipt and closes its copies
   only after receiver ownership is established. The source host also drops
   its gated harness originals; its transfer duplicate alone never stood in
   for those originals. The host retains the receipt, independently proves
   closure of both sets of source resources, and commits FULL Finished before
   enabling any destination consumer. Job handles **overlap**, so
   KILL_ON_CLOSE never sees an unintended zero-handle interval.
5. **Only before Claimed** (section 20's durable ownership CAS), the **host**
   proves the pre-Claimed phase and still-valid source lease from the protected
   store head and keeps the existing ownership barrier serialized through its
   abort/discard calls. se-proc does not read the store or claim to prove its
   phase; it checks only native facts it owns (offer committed/import activated,
   generation, pins and association restoration). The host calls
   `abort_transfer(&offer)` first; after proved restoration it may call
   `discard_transfer(&mut imported)` and resume source admission. Both objects
   remain borrowed and inspectable/retryable on failure. Unproved restoration
   stays pending. begin_transfer receives duplicated harness Files, not the
   only originals, so this abort cannot consume source I/O.
   Claimed is irrevocable even before Activated: source admission stays fenced,
   and neither abort nor discard may undo that committed ownership or close
   the successor's only custody merely because an activation ACK is missing.
   accept_transfer keeps Windows provider endpoints inside inactive native
   ports and other stream Files private. activate_transfer enables the bound
   ports and moves host-owned/Unix Files out exactly once after the host CAS/
   lease barrier. Failed activation
   leaves the mutable TransferImport pinned, inspectable and retryable; a
   second successful activation refuses IllegalTransition. After Claimed,
   uncertainty about nonce, committed head, native transfer or peer identity
   remains pending with staged/source resources retained for authenticated
   reconciliation; an unproved transfer is never ordinary crash-policy proof.
   Source death or a broken channel wakes that reconciliation. Only separately
   proved full owner loss permits section 20's cold recovery policy. After
   activation, returned Files remain gated until FULL Finished and then belong
   to the successor harness; any later
   authorized reversal is a new transfer, not resurrection of the old source.

Provider stdin/stdout/stderr and host-owned PTY masters transfer with exact
stream roles before the old harness drops its ends, preventing accidental
stdin EOF and duplicate output reads. Windows provider endpoints remain in
native ports; host-owned/Unix Files use TransferStreams. Capture
offsets/delivery IDs are flushed
and ownership acknowledged by section 40 before the successor resumes consumers.
Untransferred provider streams mean handover failed, not same-conversation
success. No polling/extra permanent helper carries these handles.

Actual unplanned **Windows full host loss outside a staged handover** closes
the last job handles and terminates ordinary members. A cold successor verifies
the old exact owner/root exited, checks old scope disappearance/emptiness with
protected policy provenance, then resumes the saved conversation in a new
lifecycle. It does not reopen a job name as live authority. An unexpected live
job/foreign retained handle/unknown original exit is RecoveryUnproved with
remaining obligations, not automatic replacement signalling. Native tests must
cover last-handle timing and staged-transfer crashes; the old failed S2 named
job reopen did not qualify this new path.

Linux cgroups and macOS groups may outlive an actual host crash. Recover from
Record/Prepared/RootPrepared/Reservation phases, native checks and store CAS;
keep original PIDs/births where supported, or report typed Unproved. Unknown
provider pipe/conversation state is independent of native adoption. Different
machine/boot never becomes current PID kill authority. Exited-but-unreleased
rows use the bounded exact-scope reaper, not another running lifecycle.

## 7. Structured internal causes and section 50 wire mapping

ProcErrorCode contains **internal causes**, not new wire strings. ProcError
carries boxed discriminated ProcErrorDetail and optional NativeFailure(api,
code, sanitized reason). Identity detail has pid, expected_start/found_start
and expected/found complete identity when available. Stop detail has lifecycle,
deadline_ms and RemainingScope. State/token/generation/host/capacity/internal
failures have explicit fields, never a parseable prose convention. A code/detail
mismatch is shared internal with a report ID, not an unwrap or guessed map.

The section 50 mapper is exhaustive over these internal causes. Existing
section 50 wire code/class/remedy owns the output, including surrounding
operation context (agent/lifecycle/session); se-proc does not invent public
observation-ID selectors or a second process-control surface.

| Internal cause(s) | Section 50 wire code | Structured context / remedy |
| --- | --- | --- |
| InvalidInput | usage-invalid-value | field/value rule; supply valid literal input |
| ExecutableMissing | provider-cli-not-found in the provider resolver; launch-failed for a native/helper launch | program; correct executable path |
| CwdOutsideWorkspace | usage-invalid-value | cwd/workspace; use allowed workspace |
| EnvironmentDenied | usage-invalid-value | key only; drop denied key |
| IdentityChanged | launch-failed for launch; state-conflict for rebind; stop-unwitnessed for stop | pid, expected_start, found_start; original-instance mismatch, with scope-only exited-root cleanup kept separate (§4) |
| IdentityUnreadable | launch-failed for launch; source-unreadable for recovery/read; stop-unwitnessed for stop | pid + native reason; retry/doctor, never absent |
| UnsupportedPlatform | window-unavailable for window; launch-failed for unsupported native capability | tried adapters or program/native capability; choose supported mode/system |
| ContainmentUnavailable | launch-failed only when a requested strict scope cannot be provided | path/probes/native cause; default Linux BestAvailable launches uncontained instead and emits the status fact below |
| ContainmentChanged, ContainmentEscape, ScopeUnreadable, RecoveryUnproved | stop-unwitnessed for stop; launch-failed for launch; source-unreadable or state-conflict for the observed recovery cause | preserve scope/remaining/native cause; no empty claim |
| HardeningUnavailable | launch-failed with optional hardening cause | choose a supported requested hardening profile; default alpha launch does not require it |
| BreakawayDenied | job-breakaway-refused | exact parent/caller job; use a terminal outside that job or grant explicit BREAKAWAY_OK; se up inside the same strict job cannot cure it |
| LaunchFailed | launch-failed | program/native cause or provider exit/status/stderr context; retain failed-launch cleanup |
| LaunchTimedOut | deadline-exceeded for native launch; launch-readiness-timeout only when provider readiness timed out | phase/waited/last-observed; distinguish native setup from provider handshake |
| DuplicateLifecycle | launch-in-flight / agent-already-running as observed | existing lifecycle/result; do not duplicate |
| HostChanged | runtime-handover-in-progress during transfer; runtime-not-running after actual loss | current owner/plan; wait for ready or start runtime/recovery |
| GenerationChanged | state-conflict | expected/current; reread and retry |
| StopDispatchFailed | stop-unwitnessed with the original deadline and cause | retain native error even if independent witness completes later |
| StopIncomplete | stop-unwitnessed for agents | observation/deadline_ms/labelled remaining; retain state/custody |
| ResourceLimit | input-too-large for input bounds; launch-failed for native admission/capacity | resource/limit; release witnessed terminal scopes or retry, never truncate |
| IllegalTransition, StopTokenConsumed, LockPoisoned, OperationPanicked, CallbackPanicked | internal | state/action or report_id/location, retained quarantined slot; doctor bundle |
| StopTokenExpired | state-conflict if stale generation, otherwise deadline-exceeded | token generation/deadline; prepare a fresh authorized request, no signal |

Creator/session/lifecycle authority is checked by host admission before the
native API. Retired process verbs, observation selectors and their public error
codes are not retained by this internal mapping. Measured native absence stays
a ProcessRead/ProcessObservation fact, never an ambiguous native error.
The former `cgroup-delegation-missing` refusal/status fact is retired.
Section 50 A.3 exposes `session.containment` and
`session.containment_cause`; its A.10 `custody.linux-cgroup` doctor warning
carries the full probe text with `code: null`. UncontainedReason exactly matches
that wire-cause set, without deriving wire strings from Rust variant names:

| UncontainedReason variant | Section 50 containment_cause | Probe classification |
| --- | --- | --- |
| NoUserManager | `no-user-manager` | no reachable systemd user manager/bus |
| NoDelegation | `no-delegation` | manager/root exists but delegation cannot be obtained, including an unavailable trusted helper or denied delegation |
| CgroupV2Absent | `cgroup-v2-absent` | unified cgroup v2 hierarchy is absent |
| CgroupUnreadable | `cgroup-unreadable` | hierarchy/parent identity or control files cannot be read/validated |
| ScopeCreateFailed | `scope-create-failed` | a readable delegated parent cannot create/prepare the required owned scope, including missing required kernel capability |

After the supported alternatives are exhausted, classify the decisive failed
stage: hierarchy presence, readability, user-manager availability, delegation
grant or child-scope preparation. A usable supplied/current root needs no
manager, so a failed manager probe cannot downgrade that successful root.
Keep the exact native reason in the doctor finding; never collapse unreadable
into absent. Every uncontained launch has one of these non-null causes; all
other containment values have null cause. No extra wire spelling is introduced.
T14 exercises the agent adapter's contextual identity refusal; it does not
restore a retired process-control wire code.

### 7.1 Remaining counts and human output

RemainingScope carries population Empty/Populated/Unknown, best-effort
known_live identities, EnumerationExtent Complete/Partial(reason,omitted?) or
NotRequested, and observation time. Enumerate immediately before stop and on
explicit diagnostic reads up to the small bounded buffer, label races, and
never use that list as native scope authority. A scope can become empty
independently while diagnostic PID reads are partial; the fresh kernel empty
state plus root witness decides Complete. A proved removal of the original
pinned Linux cgroup plus that root witness also decides Complete (§3.2).
Population::Empty then states no live owned scope remains, not a fabricated
kernel population read or an exact count; retain the removed-object basis.

Human defaults coordinated with section 50:

* Complete: "Owned scope stopped; original agent exited (code 0)" or signal /
  unknown-status wording. Do not say "3 processes gone" from a boolean.
* Known complete list: "3 tracked processes still alive" is allowed only when
  the fresh tracked enumeration is complete at the stated platform bound.
* Populated partial list: "Owned scope still populated; 3 live processes
  identified, enumeration incomplete". Empty known_live is not zero remaining.
* Unknown scope: "Cannot confirm scope exit: <native cause>".

Section 50's agent-stop detail includes population/enumeration metadata beside
remaining[], and renders counts using these rules. The delegation status is
uncontained after automatic probing, with optional doctor advice; manual
configuration is not a prerequisite to normal launch. A new authorized stop
retry may choose a fresh deadline, but one token/request never extends its
original deadline mid-flight. Runtime down renders the achieved stop facts and
saved resume command, never a claim that its stopped agents are still running.

### 7.2 Exit status and crash wording

ExitStatus separates native Code(u32), Signal(number,core_dumped), and
Unavailable(NotOurChild/ReapedBeforeRecovery/NativeAccessDenied/NotRecorded).
ProcessObservation::Exited, owned root witnesses and terminal ProcessRecord
carry it. Linux/macOS retain owned child's waitid/waitpid status before reaping
that exact child; Windows reads GetExitCodeProcess on a signalled held handle.
No global child reaper consumes someone else's status. The temporary Linux
creator observes and reports the exec-error channel while the new root is
still its child; failed exec is a concrete failed launch, not unknown success.
If the root exits before that helper leaves, retain its exact wait status.
A root that outlives the helper ordinarily has Unavailable(NotOurChild) when
it later exits: pidfd readability is still an exact exit witness, not status.
Report "exited, status unavailable"; neither infer a crash nor call it exit 0.
A requested stop records requested termination with witnessed exit and status
unavailable; without a request it is an observed exit of unknown cause. Do not
invent crash-versus-normal classification, auto-relaunch policy or a permanent
reaper to conceal that limit. A non-child/post-crash
identity may prove exit without recovering its status: say "exited, status
unavailable", not "crashed" or exit zero. The host combines confirmed nonzero
code/signal with whether it requested termination to distinguish an agent
crash from an intentional stop. Negative statuses never become success.

### 7.3 Runtime bootstrap mapping

The host selects the existing runtime-operation catalogue for §5.5: a native
start/identity failure maps runtime-start-failed with its sanitized native
cause and startup log; an uncommitted startup still pending at the deadline
maps runtime-start-pending; a failed abort with no outside exit proof maps
stop-unwitnessed. A restrictive Windows job keeps the more specific
job-breakaway-refused cause/remedy. Commit ambiguity preserves the pending
startup record/nonce until authenticated reconciliation; it is never rendered
as "ready" merely because a child exists. This is operation-context mapping
of the same typed internal causes, not a new error enum or wire catalogue.

## 8. Budget share, bounds and resources

Section 80 owns the totals. Process custody uses its **0.2 MB (200,000 bytes)
allocation for the 16-live-session embedded profile**, not the previous extra
0.5–1.5 MB proposal. Planned userspace spend: <=16 KiB base arena/index,
<=6 KiB per live lifecycle (16 =96 KiB), <=8 KiB native notification keys and
<=64 KiB one shared bounded diagnostic/transfer scratch: <=184 KiB. Do not
retain argv/env or clone full membership lists in every slot. Kernel jobs,
pidfds and cgroups are reported separately, not hidden as user RSS.

Code pages use section 80's shared code allocation. Windows's one IOCP wait
thread is the **existing fixed native wait thread**, its stack charged once
to the section 00/80 thread allocation, not a second se-proc stack. Linux/macOS
reuse AsyncFd/kqueue in the existing reactor, no extra wait threads. Callback
queues are bounded nudges. The shared blocking pool remains capped at two;
no child setup/readiness, graceful deadline or stop wait occupies it.

Default active lifecycle cap is the embedded 16-session spend plan; an explicit
larger deployment must negotiate/measure its extra per-slot memory within the
global budget, rather than quietly allocating 256 entries eagerly. Standalone
and embedded hosts both default to 16 native custody slots; the separate
256-entry session/transcript binding limit does not enlarge this active budget.
The cap counts Reserved/Starting/Running/LeaderExited/StopRequested/
StopUnproved and Lost entries whose required scope is not proved empty,
including quarantined unpublished children. Reservation admission is charged
before any native effect; concurrent reservations cannot oversubscribe 16.
Historical, witnessed empty Exited and owner-human released rows are not live
admissions. An ownership_release marker retires only that tracked-group
ownership; StopUnproved and remaining-process warnings stay in history.
After exit evidence is committed, release closes registrations/process/job/FD
pins and removes the full native slot even if deleting an **empty** cgroup
directory fails. Persist cleanup-debt identity/path/last-error in the existing
store, retain no full arena slot or descriptor just to retry rmdir, and let the
bounded exact-scope reaper reopen/revalidate it on startup, generation recovery,
Remove or the next admission. Its scratch/page memory is the existing 64 KiB,
not an unbounded second map. A replaced/unreadable directory is preserved and
reported as debt; it cannot retroactively grant signal authority. Without an
explicit owner-human release marker, if closing native ownership is itself
unproved, the slot still counts and admission
refuses with the concrete remaining obligation: a genuinely live/unproved
resource cannot be evicted merely to make space. Thus failed empty-directory
cleanup cannot wedge all 16 live slots, while uncertain live children remain
accounted for. Arena
snapshot and best-effort membership buffers are bounded; oversize input maps
to input-too-large, native capacity pressure maps to launch-failed with typed
Capacity cause and a release/retry remedy. It never maps to a nonexistent
wire `retry` code or a success with omitted custody.

Section 80 owns the launch, stop, identity, runtime-open and handover targets;
this chapter does not publish a second budget table. The ordinary launch chain
includes C1 FULL, C2 and C3 FULL. Only the §3 four-commit paths (Unix terminal
attach, macOS and Linux uncontained helpers) add RootCheckpoint; the contained
manager helper still uses C2's exact scope for unpublished-root cleanup and
adds no store barrier. E3 measures each serial commit, native setup/readback,
host dispatch, provider handshake separately. Every LinuxUserManager launch pays for a fresh
manager scope/temporary creator and handoff, not just the first launch. The
section-80 scope-acquisition target therefore applies to warm launches
too; no per-launch work is amortized behind an absent resident helper.
Section 80 retains the actual scope-only measurements, their environmental
bounds and the wave-4 zbus/libdbus comparison. They do not qualify C1/C2/C3 or
complete launch. Wave-1 E3 includes Linux's four-commit uncontained path;
Windows and later headless delegated Linux retain the three-barrier path.
No 5 ms-per-commit arithmetic or presumed batching proves those targets; the
measured FULL path may exceed them. E2/E3 must report that miss before build
qualification. Never weaken durability, drop a crash barrier, hold a transaction
across native work or relabel setup as provider time to make a target pass.

## 9. Journeys, mirror paths and reviewer-owned checks

Authors add no test code. The pinned independent five-journey runner exercises
real installed native paths and both Claude/Codex. Type-checking an empty
backend is never native behavior or performance evidence.

| Journey | Required native consumer |
| --- | --- |
| J1 Install | packaged se version works with no Node/PowerShell; automatic delegation where supported; unavailable delegation visibly launches uncontained |
| J2 Adopt | safe literal provider launch in headless **and interactive window** modes on all three OSes; real PTY/console keyboard/screen; native creation and provider readiness distinct |
| J3 Come back | natural exit releases its scope; service reopen retains native arena; live SE Code↔daemon handover preserves PID/birth/streams; actual Windows crash resumes conversation in a new lifecycle, Linux/macOS re-adopt at their declared bound |
| J4 Two agents | independent scope/lease/native references; stop, callback panic, handover or read of one cannot consume another's children/input; no owner sidecar per agent |
| J5 Remove | natural/graceful/forced and reused-root cleanup witnessed; unproved ownership blocks removal unless human-only release records its explicit warning/marker; terminal reaper closes crash gaps; user work/provider accounts stay untouched |

CLI/MCP custody uses the same host operation/backend; stateless CLI reads use
the stateless NativeProcessApi reader without starting an owner. Window/headless share
scope/instance checking, with explicit stream differences. Claude/Codex supply
harness argv/streams/readiness but identical native ownership. Embedded and
standalone share transfer/arena contracts and do not reap unrelated SE Code
children. J2 requires a working viewable window for both providers on all three
systems. An attended Windows Codex refusal is honest failure behaviour, not a
supported substitute: an E5 Windows window failure blocks alpha.
Windows live transfer is not confused with its crash relaunch;
Linux and macOS limits are reported separately, not smuggled in as no-op modes.

Reviewers own native checks for: (a) fake/reused-root instance refusal with
replacement surviving (T14), **and separately** legitimate scope-only stop
with original root exited/reused; (b) root exits but children remain; (c)
Linux double-fork/setsid, clone3 ENOSYS fallback before exec, real provider
launch without mandatory hardening, automatic delegation from a normal
terminal/SSH scope; (d) macOS ordinary group/tracked-member stop, crash adoption
and labelled deliberate escape (T15/T16 at Prime's stated bound); (e) Windows
job-list atomic association, strict caller breakaway refusal, explicit detached
se up, console streams and `wt` single-instance broker handoff; (f) natural
exit/failed launch and crashes around each reservation/checkpoint/Exited/
release boundary; (g) two concurrent long stops plus other store work without
blocking-pool starvation; (h) sink panic/poison/quarantined-slot reconciliation;
(i) exact exit-code/signal and unknown-status rendering; (j) live bidirectional
handle/stream handover, receiver/source crashes and no zero-job-handle gap.
All targets are native-qualified later; this candidate claims only compilation.

## 10. Integration and qualification

The native crate is internal to agent/runtime adapters. Section 50 generates
public errors/status and truthful containment/exit bounds; section 70 owns
optional hardening and same-user policy. Section 40 owns async execution,
provider framing, holds/input/capture/debt, runtime lease and store barriers.
Its real-provider transport consumes section 2.3's safe Windows port and the
host's Unix reactor; no Tokio runtime or second native owner is inserted here.
Section 90 qualifies the generated public agent paths rather than retired
process commands. Without pidfds, a native start/identity exit readback reports
its actual witness method and group/tracking bound instead of pidfd-exit.

The throwaway continuous-writer experiment passes Linux 3/3 and native Windows
11 3/3: two-way transfer, staged source loss and pre-claim destination loss,
2,097,152 ordered stdout bytes per case with no loss or duplication. Real stock
Codex 0.166 and Claude 2.1.314 each also pass A→B→A mid-turn transfer on both
systems, retaining PID/start and conversation and recalling the first prompt's
marker in a second answer. These observations support the native stdio arena;
they do not replace product implementation or qualification. The observer owns
framing/phase choices, and the fixture job uses suspended create/assign rather
than the product JOB_LIST path. Raw proof directories are listed in section 80.

E1 still qualifies job completion-port reassociation and abort, 100 traffic
loops, exact resource closure and every product crash phase; E2/E3 qualify
startup/launch/write timing and memory with actual FULL barriers. E7's throwaway
native helper proof passes 4/4 each in a desktop session, a real noninteractive
SSH login and rootless Podman. Desktop/SSH verify two contained launches,
including native ENOSYS-only fallback, live stdio/optional pidfd handoff, helper
exit and unchanged host cgroup; the two uncontained cases preserve the escaped
setsid/double-fork survivor until exact fixture cleanup. Podman has no manager
and honestly reports all four cases uncontained; zombies remain labelled exited.
Raw failures, source and outside readback are retained under
`/mnt/nvme/stateengine/5p-e7-containment-20261030`, including the original SSH
cross-boundary EACCES and final `FINAL-AUDIT.json`. This is headless native
mechanism evidence, not durable host integration, terminal qualification or
launch-budget acceptance. The measured manager collected the exact pinned
scope before a population-zero read; the audit retains deleted-object and
native exit evidence, never a fabricated zero. The prototype still used a
placement polling loop and libsystemd; it does not qualify the selected
dbus-rs/JobRemoved implementation. This E7 observation establishes
the collected-scope witness mechanism adopted in §3.2; durable host integration
and reviewer crash/replacement cases still require qualification. Docker and WSL2 remain unqualified pending
installation approval; Podman is not substituted for Docker. Default Linux launch remains
uncontained when delegation is unavailable; its group-empty witness cannot
assert every descendant gone.
E5 stock Codex 0.163 headless stdio and private Unix --listen pass on Linux and
Windows (native Windows 16/16 and 26/26), with saved-thread resume, real work,
a separate CLI write-boundary denial and exact captured process exit. The
actual app-server write-boundary follow-up also passes on Linux and native
Windows stdio (40 §9.4). The private listener still requires a stock proxy and
WebSocket framing, so it removes no whole
mechanism: retain the Windows stdio arena and Claude's required native port.
Section 40 §9.4 defines the saved-profile policy, shell and private-path contract;
these provider proofs do not qualify native descendant containment or the Rust
implementation.
Mac's native identity/group/window/exit/transfer paths are qualified in the
borrowed-Mac campaign before alpha, with both providers and embedded/standalone
journeys. An earlier Windows/Linux pass is an intermediate milestone.

No product backend or author test is introduced by this reconciliation.

## 11. Primary native references

These sources support OS facts, not claims that the proposed backend or
native journeys are implemented:

* [Windows job-list and handle-list creation attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
  [CreateProcessW flags and environment](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
  [STARTUPINFOW console/standard handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow),
  [job limits and breakaway](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
  [job completion ports](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port).
* [Linux clone3](https://man7.org/linux/man-pages/man2/clone3.2.html),
  [pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
  [cgroup v2 delegation/events/kill](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
  [systemd transient scopes](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html),
  [systemd-run scope startup](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html),
  [dbus-rs blocking/vendored features](https://github.com/diwic/dbus-rs#features)
  and [dbus 0.9.10 message-driven processing](https://docs.rs/dbus/0.9.10/dbus/blocking/struct.Connection.html#method.process).
* [Apple kqueue process exit notifications](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html),
  [Apple spawn implementation and descriptor inheritance](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).

Windows provider-stdio amendment references: [overlapped pipe I/O](https://learn.microsoft.com/en-us/windows/desktop/ipc/synchronous-and-overlapped-input-and-output), [CancelIoEx lifetime and races](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex), and [GetQueuedCompletionStatus failed completions](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus). These specify OS contracts, not implemented qualification.
The handover binding also follows [CreateIoCompletionPort's fixed file association](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-createiocompletionport), [FileReplaceCompletionInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_completion_information), and its [user-mode NtSetInformationFile port replacement](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile); no completion-port handle is transferred between processes.
