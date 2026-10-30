# 30. Native process ownership (`se-proc`)

Architecture review revision, 2026-10-30. **Compile-only: no backend, runtime
behavior, native performance qualification or author tests.** This supersedes
the earlier section 30 where it differs. It incorporates the 22 Opus returns,
Sol R1–R6, Opus N1–N10 and Prime's latest Linux decision: prefer delegated
cgroups and automatically request them on first agent launch; absent delegation
uses an explicitly **uncontained** process group. Optional Landlock/seccomp is
section 70 hardening; Unix windows and live host handover are in alpha; macOS
uses process groups, native identity rechecks and tracked-member witnesses.

## 1. Purpose, scope and ownership

`se-proc` distinguishes a stored process claim, an exact OS instance, a native
custody scope, a stop request and an outside exit witness. It serves the
existing OPS process/agent/runtime custody operations. It adds no public
command, tool, PID killer, process-per-agent owner, Node/PowerShell dependency,
remote compute or generic process census. Observation never grants authority.

The host authorizes, owns durable events/CAS, conversation state, provider
readiness, graceful stop, pipe buffers and the runtime lease. This crate owns
native pins, scope resources, native launch steps, exit-event sources and OS
readbacks. No transaction spans an OS call. Arena resources live above service
generations. `ProcessRecord.state` is the arena's last native phase, **not** a
claim that a store transition committed. The store owns its durable state and
revision; a receipt joins both explicitly.

Dependency direction after shared contracts settle is `se-proc -> se-types`;
libc/windows-sys are target-specific bindings, not workspace-layer dependencies.
This compile-only crate has no dependency yet because supplied se-types has
no definitions. Local ID declarations are proposed common IDs to replace with
canonical re-exports before implementation, never a parallel ID system. Only
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
macOS reports `TrackedTree { atomic_signal: false, escape_prevented: false }`.
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
    fn prepare_launch(&self, reservation: LaunchReservation) -> ProcResult<PreparedScope>;
    fn begin_launch(&self, prepared: PreparedLaunch, spec: LaunchSpec) -> LaunchStart;
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
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan>;
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome>;
}

pub trait ProcessTransfer: ProcessRuntime {
    fn begin_transfer(&self, request: TransferRequest) -> ProcResult<TransferOffer>;
    fn accept_transfer(
        &self,
        endpoint: TransferEndpoint,
        manifest: TransferManifest,
    ) -> ProcResult<ReceivedTransfer>;
    fn activate_transfer(&self, imported: &mut TransferImport) -> ProcResult<ActivatedTransfer>;
    /// Pre-activation only: close staged copies; source retains original streams.
    fn discard_transfer(&self, imported: &mut TransferImport) -> ProcResult<()>;
    fn commit_transfer(&self, offer: TransferOffer, receipt: TransferReceipt) -> ProcResult<()>;
    fn abort_transfer(&self, offer: TransferOffer) -> ProcResult<()>;
}
```

### 2.1 Input/read semantics

The host supplies persisted machine ID, fresh host-instance ID, expected
service generation, absolute executable/cwd, literal argv and an explicitly
constructed environment. `se-proc` never searches PATH, expands a shell or
reads ambient configuration. A host resolver may deliberately resolve a
provider command; missing program maps to `command-not-found` before launch.
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
slots; None means the null device. Provider pipes are created/retained by the
host harness and can be transferred without giving the agent a host control
handle. No unspecified FD/handle inheritance.

`Window`: `WindowSpec` is required. On Windows, allocate a new console and let
its default keyboard/screen handles populate **unspecified** streams; do not
set STARTF_USESTDHANDLES to three NUL handles. If any stream is redirected,
construct all three intended console/file handles explicitly and pass only
that closed handle list. On Unix the registered attach helper owns a fresh
PTY slave as controlling terminal and duplicates it to 0/1/2; the terminal
owns the master. Explicit redirects are intentional exceptions, not default
NUL. Host-held PTY masters use the TerminalMaster transfer role. Terminal
lifetime/readiness and provider readiness remain separate facts.

## 3. Durable data and native resources

`ProcessRecord` (format version 1, `se.process/v1`) contains lifecycle, host,
exact owner process, generation, root instance, scope, achieved guarantee,
entry method, native phase, optional exit status, native observation timestamp
and argv SHA-256. Store envelope supplies
project/session/actor, event revision and commit timestamp. No secrets,
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

`prepare_launch` inserts its Starting arena slot **before** any native effect,
creates an exclusive scope (no vendor child) and returns PreparedScope with an opaque
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
store rows for process.list, pending effects, drain and crash cleanup. The
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
| StopUnproved | explicit retry, fresh observation/CAS/token | StopRequested |
| nonterminal | irrecoverable native custody, actual host/boot loss | Lost, never assumed stopped |
| Lost | authorized native recovery + store CAS succeeds | actual Running, LeaderExited or StopUnproved |
| Lost | old required scope/instances exit proved | Exited |
| Exited | durable witness committed, native release succeeds, release acknowledgment committed | terminal released; history retained |
| imported | import | Historical; cannot become live custody |

Every other transition is IllegalTransition → shared `internal`, with report
ID/location and retained slot. Repeating a completed action returns its prior
fact; an intentional new instance needs a new lifecycle. Native phase changes
precede store commits only as pending facts and remain inspectable if commit
fails. A rejected stop after its CAS is a durable failed/pending outcome, not
a missing row. Same-generation re_adopt retrieves another reference; a true
generation transfer CASes the single arena owner and revokes older references.

### 3.2 Natural release and empty-scope reaping

`witness_exit(&OwnedProcess)` reads root/scope without sending a signal or
requiring a stop ticket. It covers natural completion, provider-graceful exit,
failed launch rollback and prepared-but-never-created scopes. RootWitness
separates NoChildCreated, PinnedUnpublished, UnpublishedScope and Identified;
only the last carries a complete expected root identity. It never fills one
from guesses. Complete carries the achieved platform bound; Pending/Bounded
never becomes a successful strict removal by formatting alone.

Normal order is witness → commit Exited with evidence/status → release exact
empty native scope → commit scope-released acknowledgment. Crash in either
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

ExitNotice carries lifecycle, **generation**, per-slot monotone sequence and
kind. It is a hint only. A late/duplicate notice cannot grant authority or
complete a stop; the receiving session rereads and ignores stale generation.
Coalescing uses the host's bounded/watch channel; errors and deadline reads
prevent a lost nudge from becoming silent success. No timer when idle.

Windows uses **one IOCP per host and the one existing native wait/collector
thread from sections 00/80**, GetQueuedCompletionStatus(INFINITE), associated
with every owned job. JOB_OBJECT_MSG_EXIT_PROCESS and ACTIVE_PROCESS_ZERO are
nudges; fresh process-handle/accounting reads establish truth. All scopes,
control wakes, cancellation and staged handover transport use that IOCP. No
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
empty or a host cleanup deadline. A missed final child-exit message is then
observed within 1 s plus scheduling/read latency. This timer exists only for
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
the lifecycle/generation/sequence nudge. NativeRegistration cancellation
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
recorded task-failed/internal report; panic after creation preserves cleanup
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
process.start. Windows se up from SE Code uses CREATE_BREAKAWAY_FROM_JOB |
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

Preferred contained-mode floor: unified cgroup v2 with cgroup.kill (Linux >=5.14), pidfd_open /
pidfd_send_signal, and close_range(CLOEXEC) support (>=5.11). clone3
CLONE_INTO_CGROUP is preferred; runtime probes check actual capabilities,
including seccomp restrictions/backports, rather than trusting version text.
Only ENOENT/ESRCH of the target proc file is absence. Parse proc stat numeric
suffix as bytes after the final `) `; comm may contain spaces/parentheses or
invalid UTF-8. Bracket executable symlink read with start/state rereads and
combine field 22 with boot UUID. A zombie is an exited record, not absence.

**A stranger does not run systemd-run manually.** Prime adopted Alpha's
option (b): neither SE Code nor its existing process must move. HostConfig
AutoUserManager probes current delegation, and the embedded
host **and se up's host** request a delegated user scope on first agent launch
if needed. se up calls spawn_runtime only to create the runtime; delegation
for agents is lazy prepare_launch plumbing shared by both hosts. There is no
launcher prerequisite and **no in-binary D-Bus client**.

Use the installed trusted systemd-run helper, literal fixed argv and an
owner-only bootstrap descriptor: --user --scope --quiet --property=Delegate=yes
--unit=se-agents-<host>-<scope_nonce> -- <installed-se> <private-bootstrap-entry>. It runs only
the native bootstrap, not a provider command or credential-bearing arguments.
The transient helper reports its manager-assigned cgroup and transfers a pinned
directory FD over authenticated same-user IPC; validate cgroup2, boot, exact
path/device/inode and create permission. Its temporary presence keeps the scope
alive until the first vendor child has entered; then it exits. Agents keep
the scope alive thereafter. If it becomes empty and the manager collects it,
the next launch requests a fresh scope; FD presence alone is not a keepalive.
This is transient scope acquisition, **not** a permanent per-agent owner.
The embedded host stays in its original cgroup; children enter the independent
delegated scope before vendor exec. The host first commits a LinuxUserManager
reservation, with unit se-agents-<host>-<scope_nonce> derived exactly from it.
prepare_launch obtains the unit, creates the private owned child cgroup and
moves its temporary helper **inside that same child cgroup** before returning
ScopeCheckpoint. The helper keeps only the authenticated authorization/control
channel, no provider work. The checkpoint records the resolved parent's physical
identity. begin_launch creates the actual vendor root in that scope, then the
helper exits; window attach can enter the scope instead. The helper is inside
reserved native custody and is visible as pending work in the arena; it is
never an unrecorded child outside the cleanup scope. Parent loss/rollback
revokes authorization and the helper exits; post-checkpoint cleanup can also
use the exact cgroup. Pre-checkpoint recovery resolves only the deterministic
manager unit, forbids vendor exec and retains any populated/unreadable result
as Unproved until the helper's independent exit is confirmed. No scope is
adopted just because its unit name matches. Check a supplied root just
as strictly; no shell interpolation, ambient PATH search or root escalation.
The manager-assisted cold path is charged to the launch budget (§8).

No user manager/helper/delegation is normal in minimal containers, WSL without
systemd, non-systemd distributions, or SSH sessions without an available user
bus/manager (including absent linger after logout). In default BestAvailable,
select LinuxPrepared/LinuxTracked process-group custody with
ContainmentGuarantee::Uncontained { reason } **before vendor creation**. Report
status fact `cgroup-delegation-missing` with the probe cause and `uncontained`
in status/launch receipts. The fixed reason is retained in the guarantee;
PlatformCapabilities.kernel_scope retains the full probe ProcError/native cause
for the host to render alongside that status fact. This is **not a default launch refusal** and does
not change provider permission defaults. No cgroup.kill is claimed; use
native identity-bracketed group signalling, tracked member/root witnesses and
the same deliberate-escape/race bound as macOS. Native pidfds remain preferred
where available; an older kernel lacking them uses start/image rechecks and
is explicitly non-atomic. Strict KernelScope is an explicit requested contract;
it may fail with spawn-failed and cause ContainmentUnavailable, never a bogus
cgroup status refusal. Requested optional hardening is separately enforced.

Open physical cgroup directories with DIRECTORY|NOFOLLOW|CLOEXEC, verify
cgroup2 magic and fstat device/inode/boot, use openat+NOFOLLOW on kernel files.
Never search a writable ancestor, move the host as a side effect of launching
an agent, or delete another delegated subtree. The prepared checkpoint pins
the exact private child scope before vendor creation/exec.

Preferred raw clone3 uses INTO_CGROUP|PIDFD and SIGCHLD (no shared VM). Prepare
all argv/env/FDs/error-pipe state in parent. Child executes only async-signal-safe
native calls: setsid, intended signal reset, streams, CLOEXEC on other FDs,
chdir and execve; no allocation/locking/log formatting/unwind. Parent monitors
the CLOEXEC exec-error pipe asynchronously. EOF alone is not proof of exec:
combine fresh image/known child status; ambiguous pre-exec signal death fails.

Fallback is **only ENOSYS** (syscall unavailable), with raw fork and writing
0 to the pinned cgroup.procs before agent exec. EINVAL/EPERM retain the real
configuration/security error; they are not silently reclassified as missing
clone3. A host may add a reviewed explicit capability probe for a future
feature-specific fallback, not guess from errno. Capture a pidfd while this
is still our unreaped child and bracket its identity. Record entry method and
errno. No process-group retry after a failed cgroup launch; the uncontained
mode above is a pre-creation capability choice. Reap only exact
owned children (waitid for our pidfd/child), never waitpid(-1), a library-wide
SIGCHLD takeover, or process-global subreaper setting inside SE Code.

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
validated target or receiving its FD on the authenticated channel; without
delegation it establishes the recorded uncontained group instead. On macOS
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
admitting agents. No generic public unowned process.start is introduced.

On Linux with a user manager, invoke its transient **service** mode (no --wait,
--pipe or --pty keeper) for the native bootstrap, using fixed argv and a
protected rendezvous. The manager creates it outside SE Code's cgroup and
parents it independently; RuntimeDetachment::UserManagerUnit records this.
Agent Delegate=yes scope acquisition still happens later on first launch,
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
  startup slot. Deadline expiry with Pending reports runtime-stop-unwitnessed
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
No input is offered by both generations during transfer. B8 is <=500 ms.

The native two-phase protocol is:

1. Source gates custody/admissions and creates an offer ID, target host/generation,
   bounded manifest and deadline. Pin the exact peer process. begin_transfer
   retains every original resource; no last handle is closed yet.
2. TransferEndpoint is an authenticated same-user pipe/socket already bound to
   that peer by native identity. TransferManifest lists exact records/resource
   roles; it is data, not authority by itself. Windows uses DuplicateHandle
   into the pinned target for jobs, root handles and harness-supplied stream
   handles. Linux sends pidfd/cgroup/control/stream FDs by SCM_RIGHTS over the
   verified socket. macOS passes streams/PTYs and protected records, and the
   receiver reopens kqueue registrations with before/after native checks.
3. accept_transfer verifies every expected resource/record/peer, installs it in
   the successor's **inactive staged arena**, and returns ReceivedTransfer.
   Windows jobs keep KILL_ON_CLOSE and explicit BREAKAWAY_OK. The native bundle
   is indexed by TransferResource(slot,lifecycle,kind); raw remote handle values
   or SCM_RIGHTS payloads stay in the authenticated native frame, never public
   records/logs. Receiver verifies the complete manifest and descriptor types,
   rejects extra/missing roles and closes an invalid received bundle.
   No request client or agent gets a job handle; the only allowed second copy is this authenticated
   staged successor arena. Receiver observes the same live agent PIDs/births.
   Returned OwnedProcess references remain inactive: native readback is allowed,
   but launch/stop/re-adopt mutations refuse HostChanged until activation; they
   do not bypass the host ownership/lease barrier.
4. Host section 40 performs its durable ownership/generation CAS and unique
   runtime.lock transfer. It calls activate_transfer only after that barrier;
   the receiver returns ActivatedTransfer with exactly-once owned stream Files
   for the successor harness plus TransferReceipt identifying offer, hosts,
   generation,
   peer identity and native resource-manifest digest over the authenticated
   channel. Before activation, Windows removes each old job completion-port
   association (supported since Windows 8), binds it to the successor's one IOCP
   and rereads root/accounting before and after. The reads cover messages lost
   during reassociation; queued keys are immutable slot IDs checked against
   generation, never freed pointers. Abort restores the source association and
   rereads. Source commit_transfer verifies the receipt and closes its copies
   only after receiver ownership is established. The source host then drops
   its gated harness originals; its transfer duplicate alone never stood in
   for those originals. Job handles **overlap**, so
   KILL_ON_CLOSE never sees an unintended zero-handle interval.
5. Before activation failure/timeout, abort_transfer retains the old owner;
   receiver calls discard_transfer(&mut imported), closing staged native and
   stream copies; source abort_transfer retains its originals and resumes its
   generation if still valid. begin_transfer receives duplicated harness Files,
   not its only originals, so pre-activation failure cannot consume source I/O.
   accept_transfer stages stream Files privately; it never hands them to an
   active harness. activate_transfer moves those Files out exactly once after
   the host CAS/lease barrier. It borrows TransferImport mutably: a failed call
   leaves staged custody inspectable/retryable; a second successful activation
   refuses IllegalTransition, never yields duplicate readers. After activation,
   discard/abort cannot revoke returned Files; the successor harness owns and
   closes them, and any rollback needs a new authorized reverse transfer.
   After activation, source never reclaims control on an ambiguous lost ACK:
   it rereads the ownership barrier/receipt; successor keeps resources. Source
   death/broken transfer channel wakes staged recovery; if the committed transfer
   cannot be proved, staged handles close and the ordinary crash policy applies.
   No leaked staged copy silently keeps Windows agents alive forever.

Provider stdin/stdout/stderr and host-owned PTY masters transfer as labelled
TransferStreams before the old harness drops its ends, preventing accidental
stdin EOF and duplicate output reads. Capture offsets/delivery IDs are flushed
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
operation context (agent/observation IDs); se-proc does not invent those IDs.

| Internal cause(s) | Section 50 wire code | Structured context / remedy |
| --- | --- | --- |
| InvalidInput | usage-invalid-value | field/value rule; supply valid literal input |
| ExecutableMissing | command-not-found (or provider-cli-not-found in resolver) | program; correct executable path |
| CwdOutsideWorkspace | cwd-outside-workspace | cwd/workspace; use allowed workspace |
| EnvironmentDenied | env-key-not-allowed | key only; drop denied key |
| IdentityChanged | process-identity-changed | pid, expected_start, found_start; original instance mismatch refusal, not the old `pid-reused` spelling; scope-only exited-root cleanup is separate §4 |
| IdentityUnreadable | process-identity-unreadable | pid + native reason; retry/doctor, never absent |
| UnsupportedPlatform | window-unavailable for window; spawn-failed for unsupported native capability | tried adapters or program/native capability; choose supported mode/system |
| ContainmentUnavailable | spawn-failed only when a requested strict scope cannot be provided | path/probes/native cause; default Linux BestAvailable launches uncontained instead and emits the status fact below |
| ContainmentChanged, ContainmentEscape, ScopeUnreadable, RecoveryUnproved | stop-unwitnessed for agent; stop-deadline-exceeded for expired process stop; process-identity-unreadable for inspect | preserve scope/remaining/native cause; no empty claim |
| HardeningUnavailable | spawn-failed with optional hardening cause | choose a supported requested hardening profile; default alpha launch does not require it |
| BreakawayDenied | job-breakaway-refused | exact parent/caller job; use a terminal outside that job or grant explicit BREAKAWAY_OK; se up inside the same strict job cannot cure it |
| LaunchFailed | spawn-failed (or launch-failed after provider startup) | program/native cause or provider exit/status/stderr context; retain failed-launch cleanup |
| LaunchTimedOut | deadline-exceeded for native launch; launch-readiness-timeout only when provider readiness timed out | phase/waited/last-observed; distinguish native setup from provider handshake |
| DuplicateLifecycle | launch-in-flight / agent-already-running as observed | existing lifecycle/result; do not duplicate |
| HostChanged | runtime-handover-in-progress during transfer; runtime-not-running after actual loss | current owner/plan; wait for ready or start runtime/recovery |
| GenerationChanged | session-generation-mismatch | expected/current; reread and retry |
| StopDispatchFailed | stop-unwitnessed or stop-deadline-exceeded if still unproved at deadline | retain native error even if independent witness completes later |
| StopIncomplete | stop-deadline-exceeded for process, stop-unwitnessed/stop-partial for agents | observation/deadline_ms/labelled remaining; retain state/custody |
| ResourceLimit | input-too-large for input bounds; spawn-failed for native admission/capacity | resource/limit; release witnessed terminal scopes or retry, never truncate |
| IllegalTransition, StopTokenConsumed, LockPoisoned, OperationPanicked, CallbackPanicked | internal (task-failed when reported by host task) | state/action or report_id/location, retained quarantined slot; doctor bundle |
| StopTokenExpired | session-generation-mismatch if stale generation, otherwise deadline-exceeded | token generation/deadline; prepare a fresh authorized request, no signal |

`observation-not-yours`, `bare-pid-refused` and authority/validation errors from
50 §6.11 remain host admission checks **before** this native API. They are not
missing native error variants. ProcessAbsent was removed: measured absence
is a ProcessRead/ProcessObservation fact, never an ambiguous native error.
`cgroup-delegation-missing` is a Linux capability/status fact accompanying
Uncontained (with structured reason/probe cause), **not a default launch
error**. Section 50 must move it out of refusal semantics; no new wire spelling
is introduced here.
T14's wire spelling is process-identity-changed; section 90 now uses it.

### 7.1 Remaining counts and human output

RemainingScope carries population Empty/Populated/Unknown, best-effort
known_live identities, EnumerationExtent Complete/Partial(reason,omitted?) or
NotRequested, and observation time. Enumerate immediately before stop and on
explicit diagnostic reads up to the small bounded buffer, label races, and
never use that list as native scope authority. A scope can become empty
independently while diagnostic PID reads are partial; the fresh kernel empty
state plus root witness decides Complete.

Human defaults coordinated with section 50:

* Complete: "Owned scope stopped; original agent exited (code 0)" or signal /
  unknown-status wording. Do not say "3 processes gone" from a boolean.
* Known complete list: "3 tracked processes still alive" is allowed only when
  the fresh tracked enumeration is complete at the stated platform bound.
* Populated partial list: "Owned scope still populated; 3 live processes
  identified, enumeration incomplete". Empty known_live is not zero remaining.
* Unknown scope: "Cannot confirm scope exit: <native cause>".

`stop-deadline-exceeded` retains its existing wire code; section 50's detail
schema must add population/enumeration metadata alongside remaining[], and
its count renderer must use these rules. Its delegation entry must report
uncontained status after automatic probing, with optional doctor advice;
manual delegation is not a prerequisite to the normal launch.
These are explicit sibling contract edits requested from Prime, not silently
new wire codes. A later --deadline retry may choose a new deadline, but a
single token/request cannot extend its deadline mid-flight.

### 7.2 Exit status and crash wording

ExitStatus separates native Code(u32), Signal(number,core_dumped), and
Unavailable(NotOurChild/ReapedBeforeRecovery/NativeAccessDenied/NotRecorded).
ProcessObservation::Exited, owned root witnesses and terminal ProcessRecord
carry it. Linux/macOS retain owned child's waitid/waitpid status before reaping
that exact child; Windows reads GetExitCodeProcess on a signalled held handle.
No global child reaper consumes someone else's status. A non-child/post-crash
identity may prove exit without recovering its status: say "exited, status
unavailable", not "crashed" or exit zero. The host combines confirmed nonzero
code/signal with whether it requested termination to distinguish an agent
crash from an intentional stop. Negative statuses never become success.

### 7.3 Runtime bootstrap mapping

The host selects the existing runtime-operation catalogue for §5.5: a native
start/identity failure maps runtime-start-failed with its sanitized native
cause and startup log; an uncommitted startup still pending at the deadline
maps runtime-start-pending; a failed abort with no outside exit proof maps
runtime-stop-unwitnessed. A restrictive Windows job keeps the more specific
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
global budget, rather than quietly allocating 256 entries eagerly. The cap counts Reserved/Starting/Running/LeaderExited/StopRequested/
StopUnproved and Lost entries whose required scope is not proved empty,
including quarantined unpublished children. Reservation admission is charged
before any native effect; concurrent reservations cannot oversubscribe 16.
Historical, witnessed empty Exited and released rows are not live admissions.
After exit evidence is committed, release closes registrations/process/job/FD
pins and removes the full native slot even if deleting an **empty** cgroup
directory fails. Persist cleanup-debt identity/path/last-error in the existing
store, retain no full arena slot or descriptor just to retry rmdir, and let the
bounded exact-scope reaper reopen/revalidate it on startup, generation recovery,
Remove or the next admission. Its scratch/page memory is the existing 64 KiB,
not an unbounded second map. A replaced/unreadable directory is preserved and
reported as debt; it cannot retroactively grant signal authority. If closing
native ownership is itself unproved, the slot still counts and admission
refuses with the concrete remaining obligation: a genuinely live/unproved
resource cannot be evicted merely to make space. Thus failed empty-directory
cleanup cannot wedge all 16 live slots, while uncertain live children remain
accounted for. Arena
snapshot and best-effort membership buffers are bounded; oversize input maps
to input-too-large, native capacity pressure maps to spawn-failed with typed
Capacity cause and a release/retry remedy. It never maps to a nonexistent
wire `retry` code or a success with omitted custody.

Targets remain section 80's: <=50 ms StateEngine launch work excluding provider
startup, <=50 ms stop CPU/CLI work plus 5 s graceful and <=500 ms forced wait,
<=500 ms handover without changed agent identity/input duplication, native
identity p95 <1 ms, idle event waits with no polling. Runtime open contributes
<=2 ms synchronous native setup; re-adoption after ready is bounded and
reported. Instant deadline does not invent wall-clock guarantees across sleep.
The launch latency allocation explicitly includes **serial writer commits**;
causally separated barriers are never collapsed into one transaction around OS
calls. Ordinary kernel launch: reserve <=5 ms + scope-prepared <=5 ms + Running
<=5 ms =15 ms writer time; native setup/readback <=15 ms; host dispatch/IPC
<=8 ms; notification/record processing <=5 ms; contingency <=7 ms: **50 ms**.
Mac/terminal/uncontained helper paths add a RootCheckpoint commit (5 ms), using
5 ms of that contingency: **50 ms** with 2 ms spare. Writer batching with other
requests may reduce cost but cannot delay these commits beyond their allocation.
Cold user-manager/helper scope acquisition is charged inside native setup,
not relabelled provider startup; if it exceeds 15 ms or commits exceed budget,
the <=50 ms target is unmet and must be measured/reported before qualification.
No NORMAL/commit durability semantics are weakened to satisfy this arithmetic.
These are design allocations/targets, not measurements of these declarations.

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
| J5 Remove | natural/graceful/forced and reused-root scope cleanup witnessed; unknown live scope blocks removal; terminal scope reaper closes crash gaps; state/credentials survive an unproved stop; user work/provider accounts stay untouched |

CLI/MCP custody uses the same host operation/backend; stateless CLI reads use
the stateless NativeProcessApi reader without starting an owner. Window/headless share
scope/instance checking, with explicit stream differences. Claude/Codex supply
harness argv/streams/readiness but identical native ownership. Embedded and
standalone share transfer/arena contracts and do not reap unrelated SE Code
children. Windows live transfer is not confused with its crash relaunch;
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

## 10. Cross-section contract changes and open integration work

Prime has been asked to route these **concrete sibling-owner edits** while
this section/API is corrected; no other crate or owner's doc is edited here:

* Section 50: same wire catalogue, labelled population/enumeration metadata
  alongside remaining[], count-safe human wording, cgroup-delegation-missing as
  an uncontained status fact rather than refusal, correct job-breakaway-refused
  remedy (outside the strict caller job), structured identity/recovery causes.
  No new wire spelling.
* Section 70: optional Landlock/seccomp policy belongs there, not a mandatory
  alpha launch guard. Same-user deliberate migration/escape is stated honestly.
* Sections 00/40/80: one Windows IOCP collector replacing registered wait-pool
  wording; Linux/macOS AsyncFd integration; 0.2 MB custody share; native
  transfer plus provider-stream/hold/interrupt/active-map/lease barriers align.
* Section 90: T14 now uses process-identity-changed; macOS's deliberate escape
  test must reflect the ratified group/tracked bound, rather than assert an
  unescapable-tree promise. Normal J2/J5 and ordinary descendant stop remain
  supported outcomes, not successful refusals.
* Section 10: canonical ID/error/path types replace this compile-only proposal's
  local declarations before implementation. No serializable record becomes
  a custody constructor. Native peer/ACL primitives from section 70 belong to
  the integrated se-proc unsafe seam; they do not silently gain implementations
  in this signature-only process revision.

No additional product decision is requested for Linux hardening/delegation,
macOS scope, Unix windows or live handover: Prime has settled them. Native
qualification and integrated shared type signatures remain review/implementation
work. The design-first stop remains binding until architecture approval.

## 11. Return coverage

| Review item | Concrete correction |
| --- | --- |
| Opus 1 | §7 exhaustive internal-to-section-50 map; no invented wire codes, T14 spelling aligned |
| 2 | ProcErrorDetail Identity/Stop/Scope/State/Token/Generation/Host/Capacity/Internal plus NativeFailure |
| 3 | RemainingScope and labelled best-effort enumeration; §7.1 count-safe renderers and sibling schema request |
| 4 | witness_exit plus release for natural, graceful, prepared and rollback paths |
| 5 | commit Exited → release → acknowledgment; exact bounded ReleaseExitedScope reaper |
| 6 / Sol R1 | durable LaunchReservation + ScopeCheckpoint + RootCheckpoint; no-root RecoverySource/RootWitness; before-exec durable barrier |
| 7 | §4 scope-only stop after proved original-root exit/reuse; no signal to replacement by PID |
| 8 | wait_stopped removed; one host-owned immutable request deadline |
| 9 | begin_launch/poll_launch/authorize_exec and watch_exit+witness_stop, no deadline-long blocking waits |
| 10 | one IOCP for all Windows job exit/active-zero/control events; no registered wait pool |
| 11 | §8 200,000-byte custody share and existing fixed thread/reactor budget |
| 12 | stateless safe NativeProcessApi::read_process declaration, no Runtime/HostInstance dependency |
| 13 | complete bounded arena_snapshot includes Starting/quarantined/unpublished slots |
| 14 | §4.2 panic=unwind, pre-effect arena insertion, catch_unwind and poisoned-slot quarantine |
| 15 | cgroup alpha guarantee; named unrestricted opt-in remains launchable; hardening optional/section 70 |
| 16 | spawn_runtime + Windows explicit detached flags, distinct from JOB_LIST agent launch |
| 17 / Sol R2 | explicit console/PTY WindowSpec and mode-dependent standard streams, no NUL TUI |
| 18 | internal IllegalTransition, StopTokenExpired/Consumed, LockPoisoned/OperationPanicked/CallbackPanicked, RecoveryUnproved |
| 19 | arena vs durable state separated; StopUnproved after post-CAS refusal; repeated handle references are not duplicate native owners |
| 20 | Capability unavailable retains complete ProcError/native cause |
| 21 | native Linux floor and automatic helper delegation on first launch, explicit uncontained fallback when unavailable |
| 22 | ExitStatus code/signal/unavailable carried to observations/terminal records; crash vs intentional stop is host-classified |
| Sol R3 | Unix windows §5.4 and live bidirectional native/stream handover §6 are in alpha |
| Sol R4 | supported macOS group/kqueue/recheck/tracked-witness design with deliberate-escape/native-race bound, no Mach entitlement requirement |
| suggestions | callback generation/sequence; Instant suspend bound; ENOSYS-only clone3 fallback; explicit wt broker check; macOS types support the ratified path |

### 11.1 Final confirmation items

| Item | Folded correction |
| --- | --- |
| N1 | safe plain NativeProcessApi, no extern block or unresolved foreign symbols |
| N2 | §8 serial 3/4-commit allocation, cold manager time charged, no OS call inside a transaction |
| N3 | PreparedStop + Starting stop CAS before cancel_launch dispatch; post-CAS refusal retained |
| N4 | immediate lifecycle reread on provider/terminal completion; orphan cleanup <=1 s timer; explicit otherwise-15-minute discovery bound |
| N5/N6 + Alpha | §5.2 lazy helper-only delegated scope without moving embedded host; §5.5 all-OS runtime detachment/races; default uncontained fallback and sibling status change |
| N7 | TerminalAttach entry distinct from clone3 errno; LinuxProcessGroup for uncontained native entry |
| N8 | §8 precise active admissions, empty cleanup debt in store, no retained full slot for failed rmdir |
| N9 | remove ProcessAbsent; native absence remains a successful measured fact |
| N10 | separate ProcessTransfer trait from ProcessRuntime |
| Sol R5 | ActivatedTransfer owns streams after host barrier; discard_transfer closes only staged duplicates before activation, source originals remain |
| Sol R6 | persisted machine/startup nonce; RuntimeChild readiness commit, retained-pin failure, abort, outside witness and release |

Final confirmation still checks design/declarations only. Native BREAKAWAY +
JOB_LIST behavior under a strict parent, IOCP rebinding, last-job-handle timing,
bootstrap acknowledgment races, Linux fallback and latency/RSS remain unqualified.

## 12. Primary native references

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
  [systemd-run scope startup](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
* [Apple kqueue process exit notifications](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html),
  [Apple spawn implementation and descriptor inheritance](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).
