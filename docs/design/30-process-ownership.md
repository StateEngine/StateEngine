# 30. Process ownership (`se-proc`)

Design proposal for the architecture review, 2026-10-30. This revision is
**compile-only**, not an implemented backend or a claim that any journey passes.
Prime's design-first assignment supersedes the earlier implementation assignment.
The partial backend written before that instruction is preserved outside this
repository as reference; it is not in this candidate.

## Purpose and boundaries

`se-proc` makes a host's authorized launch and stop affect the intended process
instance and its owned containment scope. It distinguishes a recorded claim,
a live native observation, a termination request and a witnessed exit. It never
turns an unreadable OS query into absence or a successful signal into success.

The crate supplies the native part of OPS `process.start`, `process.control`
(inspect/stop), `process.list`, managed `agent.launch`/`agent.stop`, and runtime
shutdown/removal. Those operations remain in the one operation registry. The
crate adds no command, MCP tool, arbitrary PID killer, remote compute, census,
process supervisor daemon, shell wrapper, permissions bypass or background poll.
`read_process(pid)` is a host-private diagnostic selector, not custody.

Dependency direction is `se-proc -> se-types`; it does not import store, core,
host, harness, HTTP or tokio crates. During implementation, target-specific libc
and windows-sys are native bindings, not other workspace-layer dependencies.
This is the only crate permitted to contain unsafe Rust. Every unsafe block
must state ownership, lifetime, alignment and thread/fork-safety requirements.
The compile-only revision needs no OS bindings and contains no unsafe code.

The host authorizes every operation, resolves project/session/lifecycle IDs,
constructs the environment and safe profile, commits state transitions, and
owns provider readiness and conversation resumption. `se-proc` owns native
handles, literal native launch, containment, exit notification and outside
observations. It never opens the store or holds a transaction. In-process
callers are inside the project's trust boundary; private handles prevent
accidental reconstruction, not hostile code already able to alter the host.

## Precedence and measured input

The direct assignment, `docs/OPS.md` and synthesized plan control where the old
numbered drafts disagree. In particular, use a host-held Windows job with
`KILL_ON_JOB_CLOSE`, job-list launch attributes and explicit caller breakaway;
do not copy the runtime draft's suspended-create/assign/resume sequence or its
claim that agents survive arbitrary full host-process loss. Window launch on
Linux/macOS and live daemon/SE Code handover are after alpha in the synthesis.
Their unsupported branches are explicit below, not silent headless fallbacks.

S2 measurements support design choices, not product qualification:

* A Windows native run disproved name-only job reopen after its owner released
  the last handle. The precise destruction timing was not established. A
  revised one-host/KILL_ON_CLOSE package was delivered; its native result was
  not available to this author when writing this design.
* Linux delegated-cgroup runs contained an ordinary tree, a reaped leader with
  living descendants and a `setsid` escape: 28/28 outside stopped-scope witnesses.
  The measured offline Landlock/seccomp guard denied migration and external
  socket creation. It was not a real Claude/Codex compatibility measurement.
* Linux clone3 birth into a cgroup removed a measured ~16 ms migration write;
  final launch/CLI samples were 15.050–17.974 ms. The injected ENOSYS path used
  pre-exec migration and retained containment, with a slower entry method.
* Native macOS was not measured. PID+start rechecks alone do not make a later
  signal atomic or establish an unescapable process tree.

Raw S2 measurements remain under
`/mnt/nvme/stateengine/5p-rust-process-ownership-20261030/`; product code has no
runtime dependency on that directory or the Node repository.

## Public Rust contract

The complete declarations are the crate's checked-in source, with no executable
bodies, implementations, `todo!`, `unimplemented!`, backend stubs or author tests:

| File | Public definitions |
| --- | --- |
| `identity.rs` | Process/machine/lifecycle/host/generation IDs, native boot/start identity, process observation/read/exit evidence |
| `launch.rs` | Host/delegation/limit configuration, exact launch specification, stream ownership, policy, modes, capabilities and native entry method |
| `ownership.rs` | Scope/record/state types, opaque owned resources, launch/recovery/stop outcomes, notifications and `ProcessRuntime` |
| `error.rs` | Process-domain codes, cause/native-code envelope and result alias |
| `lib.rs` | Public re-exports only |

All functions are declared as methods of the following real Rust trait. This is
also the intended interface of `NativeProcessRuntime`; there is intentionally
no `impl` until architecture approval. All named types and field layouts are
in the source files above; no public item is hidden in an illustrative sketch.

```rust
pub trait ProcessRuntime: Send + Sync {
    fn open(config: HostConfig) -> ProcResult<Self> where Self: Sized;
    fn capabilities(&self) -> ProcResult<PlatformCapabilities>;
    fn read_process(&self, pid: ProcessId) -> ProcResult<ProcessRead>;
    fn launch(&self, spec: LaunchSpec) -> LaunchOutcome;
    fn describe(&self, process: &OwnedProcess) -> ProcResult<ProcessRecord>;
    fn observe(&self, process: &OwnedProcess) -> ProcResult<OwnedObservation>;
    fn watch_exit(&self, process: &OwnedProcess,
                  sink: Arc<dyn ExitSink>) -> ProcResult<ExitWatch>;
    fn re_adopt(&self, record: &ProcessRecord, from: GenerationId,
                to: GenerationId) -> ProcResult<OwnedProcess>;
    fn prepare_stop(&self, process: &OwnedProcess,
                    generation: GenerationId, deadline: Instant) -> ProcResult<PreparedStop>;
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt>;
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation>;
    fn wait_stopped(&self, ticket: &StopTicket,
                    deadline: Instant) -> ProcResult<StopObservation>;
    fn release(&self, process: &OwnedProcess,
               witness: &StopWitness) -> ProcResult<()>;
    fn plan_recovery(&self, record: &ProcessRecord) -> ProcResult<RecoveryPlan>;
    fn recover(&self, plan: RecoveryPlan,
               generation: GenerationId) -> ProcResult<RecoveryOutcome>;
}
```

The quoted trait compiles in `ownership.rs` using its explicit imports; the
crate is the canonical signature source. `OwnedProcess`, `PreparedStop`,
`StopTicket`, `ExitWatch` and `NativeProcessRuntime` have private opaque layouts,
no public constructor, no `Clone`, no `Default` and no deserialization. Their
current private unit fields express opacity only, not a resource implementation.
A process record is cloneable data; it does not contain a handle or authorize
`stop`. Environment and stream specifications are neither `Clone` nor `Debug`.

ID newtypes currently live in `se-proc` because the supplied `se-types` is empty.
These are a design proposal for the common contract, not permission to create
parallel ID systems: before implementation the foundation owner must nominate
canonical IDs/shared errors and replace/re-export the overlapping declarations.
`ProcErrorCode` remains the process-domain exhaustive enum; the common error
renderer maps it exhaustively without parsing refusal strings. `ProcResult`
keeps an unreadable read distinct from `ProcessRead::Absent`; shared `Read<T>`
can wrap this result at the operation boundary without losing its native cause.

### Contract semantics

`open` validates current native host identity and reserves no child. It does
not change process-global signal disposition, `SIGCHLD`, subreaper policy,
`umask`, cwd, environment or privileges. The host configuration supplies a
persisted machine ID and freshly random host-instance ID; neither comes from
a process name or agent environment. Configured caps must be nonzero and fit
platform integer limits. Default caps proposed: 256 active lifecycles, 4096
members per scope, 1 MiB of native observation data; reaching one is an explicit
`ResourceLimit`, never a complete truncated list. Idle capabilities can be
probed lazily; no timers or child helpers are started at open.

`launch` takes an absolute executable and cwd, literal arguments, an explicit
closed environment, streams and profile. It never searches PATH, executes a
shell, inherits unspecified descriptors or retries a refused policy with a
weaker policy. The host may deliberately choose an absolute shell as the
executable; the crate itself adds none. NUL, malformed environment keys,
duplicate keys (Windows case-insensitive), empty executable, oversized command
line/environment, relative paths and mismatched native identity variants
refuse before process creation. Native mode/containment/profile checks happen
before any externally executable agent. Provider secrets are not stored in
argv, records or error text; native errors identify action/errno, not raw env.

`Started` means native creation, setup/exec and custody were observed. It does
not mean provider ready, authenticated, productive, captured or durable. A
very short successful command can already be exited at the observation;
`exec_observed` retains that fact. The host separately awaits provider handshake
and records its readiness. A failure after creation returns `remaining` custody
unless outside cleanup proved the scope empty, with its rollback observation.
No post-create error can discard a live scope in an ordinary error return.

`observe` checks host-instance identity, the arena slot, generation and native
scope identity. It reads the root and scope freshly. A root PID naming a new
birth is `IdentityChanged`, with no signal. A missing root can be a witnessed
exit while descendants remain; it does not remove their scope. A failed image
read for a live instance is `IdentityUnreadable`. A genuine exited procfs record
without an image joins to the original image only using the held native pin
and matching boot/start; the diagnostic cold-PID reader instead returns
`ExitedRecord`. An executable change at the same PID/start invalidates the
recorded image until an authorized host transition observes and records it;
there is no automatic image-wildcard adoption.

`watch_exit` installs native notifications and returns an RAII subscription.
A callback is only a nudge to reread native state. It runs without arena locks,
may neither reenter nor block, and receives only lifecycle/notice. The host
queues it onto its existing runtime. Subscription Drop unregisters and waits
for any in-flight callback before releasing its state; generation shutdown
must not free callback data early. The monitor uses at most one blocked native
collector thread per host if an existing host reactor cannot integrate it,
never one thread/process per seat. Its event wait is indefinite when idle;
registration/unregistration wake the collector with a native event. A failed
monitor produces `MonitorFailed` and an explicit unavailable notification state,
not synthetic exit. `wait_stopped` is an explicit deadline-bound caller wait,
not a persistent polling service.

## Data formats and resource custody

Native handles stay solely in an in-memory arena owned by the host process,
above replaceable service generations. Each slot is keyed by lifecycle and
holds host instance, owning generation, native root pin, scope, exit-source
registration, launch phase and stop nonce. Session tasks hold opaque references.
Dropping one reference does not close the arena's job or delete a cgroup.
There is exactly one authoritative native scope owner in the process.

`ProcessRecord` is durable `se.process/v1` body data stored by the host/store,
not a sidecar file. Its fields correspond exactly to the Rust declaration:
format version 1, lifecycle, host, exact owner process identity, generation,
root, scope, achieved guarantee,
entry method, lifecycle state and SHA-256 of the canonical literal argv.
Project/actor/session authority, event revision and commit timestamp are in the
store envelope and are not duplicated as ambient inputs to the native backend.
A command hash is descriptive, not a substitute for start/image custody.

Wire rules for the host codec: IDs are lower-case 32-digit hex for the 16-byte
IDs; generation/start ticks/FILETIME/u64 device/inode are decimal strings (no
JavaScript 53-bit loss); timestamps are decimal nanoseconds since Unix epoch;
enums have explicit lower-kebab-case tags and closed per-tag fields. Linux and
macOS paths/arguments are lossless native bytes encoded as base64 with
`encoding=unix-bytes`; Windows is lossless UTF-16LE bytes with
`encoding=windows-utf16le`. Human display is separately escaped text; never
round-trip a lossy display path into a native open. Public operation codecs
reject unknown fields/versions and cap record sizes before allocation. Store
imported process records are `Historical`, never passed to `recover` as live
custody. Shared codec ownership belongs to the common type/store design; no
serde implementation is introduced by this compile-only candidate.

Scope tags:

* Windows: `windows-job`, host instance and random job name. The name supports
  diagnostics only. No request client, agent, exported record or callback owns
  a job handle. Process query handles may be duplicated without defeating job
  close semantics; job handles may not leave the arena.
* Linux: `linux-cgroup`, lossless absolute path, fstat device/inode and boot UUID.
  Open a physical directory with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, verify the
  cgroup2 filesystem magic and fstat identity, then use `openat` with NOFOLLOW
  for kernel control files. Path alone is never sufficient.
* macOS: `mac-os-tracked`, process group plus complete root identity and explicit
  weaker guarantee. No encoding calls it a kernel tree.

No credentials, inherited host handles, task text, environment values or raw
provider input are in these records. An outside witness is another native
read performed by the host after the effect, never child-reported success.

## State machines and store handshake

The arena and durable record use the following lifecycle states. Every other
transition is refused; duplicate retries reread the existing state and produce
that result instead of creating a second scope.

| From | Trigger / required evidence | To / action |
| --- | --- | --- |
| no row | host authorizes and commits unique lifecycle reservation | `Reserved`; no child exists |
| `Reserved` | arena creates empty scope, validates policy | `Starting`; scope retained |
| `Reserved` | validation/capability refusal | `Lost` with failure; no child exists |
| `Starting` | native child setup/exec observed and host commits record | `Running` |
| `Starting` | child created but publish/exec fails | `StopRequested`; rollback uses retained scope |
| `Starting` | no child created and empty scope read back | `Exited` (failed launch, not completed task) |
| `Running` | root exits but scope still populated | `LeaderExited`; descendants still owned |
| `Running` / `LeaderExited` | authenticated stop CAS committed | `StopRequested` |
| `Running` / `LeaderExited` | root exited and entire required scope empty by outside read | `Exited` |
| `StopRequested` | native dispatch attempted, exit proof missing or failed | `StopUnproved`; custody retained |
| `StopRequested` / `StopUnproved` | independently witnessed root exit and required scope empty | `Exited`; preserve any dispatch error |
| `StopUnproved` | explicit retry with fresh generation/CAS/identity | `StopRequested` |
| any nonterminal | identity/scope custody irrecoverable, boot changed or full host lost | `Lost`; never assert stopped |
| `Lost` | explicit recovery verifies same scope and host/store CAS | `Running`, `LeaderExited` or `StopUnproved`, according to actual native state |
| `Lost` | old instance and scope independently proved exited | `Exited` |
| imported Node process | import | `Historical`; no control/adoption transition |
| `Exited` / `Historical` | any retry | retained terminal fact; new launch needs a new lifecycle |

A reused PID is a refusal on the original lifecycle, not evidence that the
replacement was launched by us. The host records the refusal/lost fact according
to its event policy; `se-proc` changes no durable row itself.

Launch handshake: reserve lifecycle transaction; outside transaction validate
and create scope/child; return custody; host commits `running` plus observed
identity; only then advertise a successful process receipt. If commit fails,
the host must call rollback stop and witness. If the host crashes between child
creation and commit: Windows last-handle closure contains the loss; Linux uses
a host-nonce/lifecycle-named cgroup beneath its delegated subtree, so startup
can identify an incomplete reservation and inspect/stop it. No unknown path
outside that owned subtree is swept. A cgroup without a committed child identity
can be stopped only using its protected reservation plus exact cgroup custody;
it is not promoted to a running agent. If either is missing, report an orphan
obligation and block removal rather than deleting evidence.

Stop handshake: first the harness may gracefully end a turn, send Codex RPC
shutdown or close an owned stdin. That is host policy, not a native success
claim. `prepare_stop` reads exact instance/scope and yields a one-use token;
the host commits `stop_requested` with its store revision CAS outside the OS
read; `request_stop` checks the token, arena generation, identity and scope
again immediately before the native effect. It consumes the token even on
failure. A failed CAS means discard the token without any signal. The native
attempt returns a stop ticket **and** its dispatch error. Subsequent witness
can establish exit even if the OS controller reported an error; the error is
retained in the receipt. A timed-out/pending witness blocks Remove and leaves
all credentials/state needed to retry. No success on a deadline.

`witness_stop` never signals. Complete requires original root exit evidence
and an empty scope satisfying the achieved guarantee. An empty cgroup/job is
not enough while the original pinned root still executes elsewhere; that is
`ContainmentEscape`. Root absence/replacement is valid outside evidence of
that original root's exit during witness, but a reused root refuses a new stop
request. `release` checks the supplied witness belongs to this host/lifecycle/
scope and rereads emptiness; a forged/stale/foreign witness refuses. It deletes
only the exact empty cgroup or closes the arena job. No recursive directory
removal and no PID/name-pattern kill are legal cleanup paths.

## Concurrency and cancellation

The arena map lock protects slot allocation/removal only. Per-lifecycle locks
serialize launch completion, generation transfer, stop dispatch and release;
no store transaction, provider RPC, callback or blocking exit wait runs under
the map lock. `prepare_stop` releases its lifecycle lock before returning; the
host can perform its store CAS without holding native locks. `request_stop`
reacquires it, validates the one-use nonce/generation/deadline and current
identity/scope, and holds it through the single native dispatch. Re-adoption
cannot race that effect. A subscriber can observe a nudge after a newer
observation; nudges carry no authority and the subsequent read is canonical.

The prepared token carries the absolute host stop deadline. Retries, EINTR and
`wait_stopped` cannot extend it. Native syscalls already in the kernel cannot
be safely cancelled by killing an unrelated host thread: if a blocking native
call outlives the host's await deadline, the host reports Pending and retains
the operation/arena resources until that call settles. It must not delete
credentials/state or launch a replacement based on an abandoned future.
Cancellation before process creation releases an empty reservation; after
creation it requests retained rollback, never detaches by dropping a handle.
Generation drain accounts for every in-flight launch/native operation before
publishing the successor. A failed durable publication is still owned work.

## Windows native design

1. Query with `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE)`,
   `GetProcessTimes` creation FILETIME and `QueryFullProcessImageNameW`. A held
   handle pins the kernel process object. Only `ERROR_INVALID_PARAMETER` from
   a correctly issued PID query is absence; access denied, truncated image,
   failed wait or other API failures stay unreadable. Returned FILETIME is
   an exact u64, not milliseconds or a floating-point date. Query handles do
   not carry termination rights unless needed for a validated owned effect.
2. Create a random `Local\\SE-<host-nonce>-<lifecycle>` job. Reject name collision
   (`ERROR_ALREADY_EXISTS`), never reuse it as custody. Set
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK`, with
   **no SILENT_BREAKAWAY**. Read limits back before creation. This follows
   Prime/Alpha's explicit-breakaway contract: ordinary children stay in the
   attended job; an explicitly detached independently owned process can leave.
3. Use `STARTUPINFOEXW` and `PROC_THREAD_ATTRIBUTE_JOB_LIST` to associate the new
   process with its job as part of creation. Do not use suspended start,
   AssignProcessToJobObject or ResumeThread. The job handle remains alive from
   before creation through readback and the entire host lifetime. Allocate the
   attribute-list storage with the documented alignment; every pointer and
   backing handle array remains live through CreateProcess. Delete the list
   on every return path. A job-list API failure creates no permitted fallback.
4. Supply non-null absolute application name and a correctly Windows-quoted
   mutable command line (argv0 plus literal args, including empty strings,
   quotes and trailing backslashes). Supply an explicit double-NUL-terminated
   UTF-16 environment sorted case-insensitively, cwd and
   `CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT`.
5. Request `CREATE_BREAKAWAY_FROM_JOB` for the independently owned launch. A
   caller job that forbids explicit breakaway yields `BreakawayDenied`, with
   the native cause and alternative to start from a normal terminal or fix
   the caller's explicit breakaway policy. No retry without the flag, no task
   scheduler, elevated broker, hidden PowerShell or unknown nested-job retry.
   SE Code's containing jobs must grant explicit BREAKAWAY_OK, never SILENT.
   Recheck membership in our exact job before reporting launch success.
6. Window mode uses `CREATE_NEW_CONSOLE`; headless uses `CREATE_NO_WINDOW`.
   Console appearance or successful window creation is not provider readiness.
   Explicit standard streams are duplicated into a restricted
   `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, with appropriate STARTF_USESTDHANDLES
   and bInheritHandles. Only those duplicated stream handles are inheritable;
   the job, host listeners, credentials and other agents' handles are not.
   Both attributes must coexist in one list. Windowed terminal handoff must
   be witnessed against the actual vendor CLI on the supported Windows build.
7. Retain the exact process handle and job in the arena; close the initial
   thread handle after creation. If readback/publish fails, terminate this job,
   then outside-wait on the process and job emptiness. Keep custody on timeout.
8. Force stop uses `TerminateJobObject`, not PID pattern enumeration. Completion
   requires pinned root signalled **and** fresh
   `JobObjectBasicAccountingInformation.ActiveProcesses == 0`. Accounting is
   authoritative for emptiness; PID-list enumeration is diagnostic and must
   grow/retry on MORE_DATA/full buffers, bounded by configured limits. A member
   disappearing during a list is not a proof that the entire job is empty.
9. Native exit events use registered process waits and job completion-port
   notifications; callbacks queue a nudge. Notifications can be coalesced/lost
   without losing truth because each consumer reads accounting/state. Wait
   registrations keep callback storage alive until unregistered/drained.

**Scope of the guarantee:** `KernelScope { explicit_breakaway: true }` proves
that the exact root and all remaining job members stopped. It deliberately
does not claim an explicitly detached child outside the job stopped. Such a
child has independent custody and must be handled as another registered
lifecycle for project Remove. A deliberately detached third-party program is
outside this managed scope; the renderer must never say "all descendants on
the machine are gone". There is no implicit/silent detachment. Linux strict
cgroups report `explicit_breakaway: false`. This distinction preserves the
ratified ability to start a detached engine from an attended agent without
mislabeling a job-membership witness as universal descendant containment.

When the full host process exits, its last job handles close and the kernel
terminates job members. Only the host owns those handles; request tasks never
open a job by name, so a stale client cannot accidentally prolong it. A killed
host may not have committed an exit event. Its successor first verifies the
old instances exited from outside, reports pending/unreadable where necessary,
then resumes the saved provider conversations in **new** lifecycles. Cold
recovery verifies the recorded owner process exited (not merely a new service
generation), the original root exited, and the old unpredictable job name is
absent or its original proved scope is empty. Name absence alone while the
owner lives is never a witness. This inference additionally relies on the
protected original job policy/readback and exclusive host handle custody: the
kernel KILL_ON_JOB_CLOSE contract supplies the descendant termination fact.
If a job still exists, owner death is unproved, an exported handle is suspected,
or the policy provenance cannot be established, recover returns Unproved and
keeps the removal obligation. Architecture reviewers must validate this
cross-host witness against native last-handle timing; it is not established by
the original failed name-reopen spike. The successor does
not claim same-process reattachment, or kill a replacement PID. An external
administrator/debugger retaining a job handle is outside this ownership
boundary; failed exit witness stays incomplete rather than assuming closure.

Primary references: [job-list/handle-list attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[job objects and breakaway](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).

## Linux native design

Identity uses the kernel boot UUID and `/proc/<pid>/stat` field 22, with the
native executable symlink. Parse stat as bytes after its final `) ` delimiter;
comm can contain spaces, parentheses and invalid UTF-8. Verify PID and required
numeric fields, then re-read start/state after the optional image read. A
changed generation during reading is an unreadable/changed observation, never
a guessed row. Zombies are existing exited records. Only ENOENT/ESRCH for the
specific target proc entry means absence; a missing helper/probe, invalid
procfs mount or permission denial does not. Do not scan by executable name.

`pidfd_open` brackets a repeat birth/image check when reopening an observation.
It selects a kernel object, but it is not a substitute for checking that it
selected the expected birth. Launch obtains an atomic pidfd using clone3.
Held pidfds provide exit notification and exact-instance signals, never a
later `kill(pid)` fallback. An older kernel without the required pidfd support
refuses managed launch before it can run an unowned agent.

### Scope creation and entry

Choose the host's current unified cgroup from `/proc/self/cgroup`, or the
explicit delegated root in HostConfig. Verify that root is a physical cgroup2
directory; never walk up looking for a writable ancestor or move the fleet
host. Create an exclusive child named by unpredictable host nonce/lifecycle,
open and pin its device/inode/boot identity, and require writable `cgroup.procs`
and `cgroup.kill`. Absence of delegation is `ContainmentUnavailable` with the
exact missing capability and `systemd-run --user --scope -p Delegate=yes` or
explicit delegated-root remedy. The crate never invokes systemd automatically.
The host's containing cgroup remains unchanged.

Preferred entry: raw `clone3(CLONE_INTO_CGROUP|CLONE_PIDFD, SIGCHLD)` without
CLONE_VM/CLONE_THREAD. Prebuild argv, env, stdio, guard state and an exec-error
pipe in the parent. The child runs only async-signal-safe syscall sequences:
reset intended signal mask/dispositions, set session, configure standard
streams, make all other descriptors close-on-exec, apply the prepared guard,
chdir and execve. No allocator, logging formatter, lock, Rust unwinding or
host callback is allowed in that child path. The CLOEXEC error pipe closes on
successful exec; a fixed-size errno/phase message reports pre-exec failure.
An EOF alone does not prove exec: a child killed before exec also closes the
pipe. Success additionally requires an outside image observation, or a child
completion status possible only after this fixed child path has execed. A
signal/exit status ambiguous with pre-exec failure remains LaunchFailed with
retained evidence; it is not advertised as a successfully started provider. Parent timeout
kills the owned scope and returns retained cleanup if not yet empty.

Fallback only for clone3 ENOSYS/EINVAL/EPERM indicating syscall/feature policy:
a raw fork with the same error pipe and precomputed child path, writing `0`
to the pinned scope's cgroup.procs **before any agent exec**. It then applies
the identical guards and execs. Capture a pidfd while the child is still our
unreaped child, bracket identity reads, and retain wait ownership. Do not use
a generic Command::spawn whose fork policy/pre_exec socket protocol could
silently change the ordering. Other clone3 errors retain their actual cause;
no process-group fallback. Record fallback errno and `LinuxPreExecMigration`.
The syscall and argument construction must be reviewed for both x86_64 and
AArch64; this design does not infer a new architecture's clone3 ABI.

All inherited host control descriptors are CLOEXEC and never part of stdio.
Native child-reaping tracks **only the exact children the arena created**;
no `waitpid(-1)`, global SIGCHLD takeover or process-wide subreaper opt-in in
an embedded library. The host's other children belong to their own owners.
After a direct child exits, `waitid` for that exact owned pidfd/child reaps it;
a descendant reparented elsewhere can remain a nonexecuting zombie, which is
not a live-scope stop failure. The outside record distinguishes those facts.

### Migration guard and realistic profile boundary

A writable same-UID delegated cgroup is not by itself an unescapable sandbox.
`setsid` does not escape it, but writing another cgroup.procs or asking an
external broker to move a process can. The S2 offline guard is not silently
applied to networked Claude/Codex: its blanket socket restriction would break
real consumers. `LaunchPolicy` therefore expresses both write/network policy
and the required achieved scope guarantee.

Proposed strict profile: Landlock ABI >=6 with scoped signals/abstract sockets,
write access only to the explicit workspace/provider-cache/scratch roots and
null device, no write rule covering `/sys`, `/proc`, the registry or an
ancestor of them. A seccomp filter blocks external AF_UNIX socket creation,
keeps private stream/seqpacket socketpairs, rejects cross-ABI/x32 bypass and
io_uring socket bypass, and blocks operations that steal other processes'
descriptors or attach to their execution. For Network Allow, IPv4/IPv6 socket
creation remains permitted; this is not the offline S2 filter. Standard streams
must not be supplied as arbitrary broker/control sockets. Existing inherited
FDs are excluded by the strict stream/handle contract.

Provider and host control must therefore use stdin/stdout or a preauthorized
safe transport for that profile; Codex app-server over stdio is the proposed
consumer path. The old runtime draft's arbitrary pathname Unix endpoint is
not assumed compatible with this guard. This is a **design proposal needing
review and real-provider qualification**, not a verified guard. If a required
native guard or provider-compatible profile is unavailable, strict launch
returns `SandboxUnavailable` before agent exec. It never claims KernelScope
while merely hoping a same-UID broker cannot move the child.

ReadOnly and Workspace policies are explicit; provider-account/cache write
locations are narrowly supplied by the host, not a blanket writable HOME.
`NamedUnrestricted` is a saved, named permission opt-in, not permission to
silently abandon containment. It cannot satisfy this unprivileged strict
cgroup guard; KernelScope plus that profile refuses pending an approved
alternative isolation mechanism. An explicitly requested TrackedTree mode
must advertise its lower guarantee. No alpha default chooses it for a failed
strict launch. This Linux guard/real-provider compatibility is an architecture
review question before implementation, listed below.

### Observe, stop, notifications and recovery

Read scope state via pinned cgroup.events; `populated=0` means this subtree
contains no executing processes, including nested child cgroups. `populated=1`
is a boolean, not a member count: `observed_members=None` unless a separate
bounded complete enumeration supplied a count. Parse every required field;
missing/malformed/unreadable control data is `ScopeUnreadable`, never zero.
Force stop writes `1` to the pinned cgroup.kill, which handles fork/migration
races within the scope. Then independently reread cgroup.events plus the root
pidfd/record. Never infer tree exit from the leader's death, a process-group
scan or a successful write. Keep the original cgroup fd until the witness and
exact empty-directory release; do not recursively remove foreign directories.

The native monitor integrates pidfd readiness and cgroup.events priority
notifications into one epoll collector, with an eventfd for changes/shutdown.
No per-session 1-second timer. A notification rechecks the reader; missed or
coalesced events do not become missing work. Explicit waits use one monotonic
deadline and retry EINTR without extending it.

Service-generation re-adoption retains arena handles. After full host loss,
Linux cgroups may still contain agents. Protected committed records can be
recovered only with matching machine, boot, cgroup2 device/inode and fresh
root start/image evidence (or proof the original root exited while the exact
scope remains). New host/store CAS transfers this lifecycle to the new host
and generation; mismatched root PID refuses before any signal. Missing or
unreadable custody leaves an explicit `Unproved` obligation. Different boot
means old records are lost/exited historically, never current kill authority.
Provider pipe loss/reconnect or conversation relaunch is separately decided
by its harness; recovering a cgroup does not manufacture a provider session.

Primary references: [clone3 including CLONE_INTO_CGROUP](https://man7.org/linux/man-pages/man2/clone3.2.html),
[pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[cgroup v2 delegation, events and kill](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[Landlock ABI and IPC scoping](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html).

## macOS design and explicit capability limits

Read native identity using `proc_pidinfo(PROC_PIDTBSDINFO)` start seconds and
microseconds, `proc_pidpath` image and `kern.boottime`. Validate exact return
sizes and timeval ranges. A zero PID-info return is absence only for ESRCH;
EPERM, partial data and an unreadable boot/image remain errors. A second
PID-info read brackets the image query. kqueue EVFILT_PROC/NOTE_EXIT supplies
notification for the observed root: register between two identity reads,
inspect EV_ERROR, retain the registration, and recheck on every notification.
A NOTE_EXIT registration is observation, **not** a stable termination handle.

Proposed tracked launch uses posix_spawn with an absolute executable, explicit
argv/env and file actions, a new process group/session as supported by the
native spawn flags, and no extra persistent wrapper. Revalidate the created
child's start/image and attach kqueue before publication. An exec-status/error
channel or a native spawn failure must distinguish native startup from provider
readiness. Window mode would require an owner-approved Terminal application
handoff with authenticated one-use child registration; it is **after alpha**
and returns UnsupportedPlatform without starting a terminal in this revision.
No hidden AppleScript launching a detached, unregistered agent.

A process group is not an unescapable tree: a child can setpgid/setsid or be
reparented before a lineage snapshot. proc_listpids enumeration must grow/retry
full buffers and reread native identity, but it cannot prove absence of an
unobserved escaped descendant. NOTE_FORK can assist diagnostics; it does not
turn a bounded snapshot into a kernel-enforced group. Therefore capabilities
report `kernel_scope=Unavailable` for this design, while explicit TrackedTree
can report `TrackedTree { atomic_signal, escape_prevented: false }`.

Forced control must not use `kill(pid)` or `kill(-pgid)` after a userspace birth
check and call that atomic. The proposed strong-instance option is an actual
Mach task send right, acquired and birth-checked before and after acquisition,
with task_terminate applied only to that right. Entitlement/hardened-runtime
restrictions can deny obtaining the right even for a child; that is
`safe_forced_stop=Unavailable`, never a PID fallback or elevated helper. Each
tracked child needs its own rights/identity; no task right proves complete tree
containment. The feasibility and required entitlements must be reviewed and
measured against the shipped vendor binaries on real macOS before implementation.
No type-check is a witness of Mach permissions or a working provider.

Without strong rights, the host may request harness-graceful shutdown and
observe root/known children exiting; a still-live instance remains pending and
Remove refuses. Even with strong rights for the known set, `StopObservation::Bounded`
labels the observed tracked set's exit. `Complete` is reserved for an empty
kernel-owned scope satisfying the requested policy. The default strict alpha
policy cannot be declared supported on macOS by the current group design.
The architecture review must choose a supported stronger mechanism or an
explicitly ratified weaker product guarantee; this candidate does not silently
weaken G6 or call its macOS journey complete.

Full host loss on macOS loses kqueue/task rights. A new host can inspect
protected tracked records by boot/start/image and return a bounded recovery,
but it cannot infer unseen descendants or regain denied Mach rights. Process
and provider conversation recovery remain separate. Changed boot, reused PID,
missing permissions or unknown membership produce `Unproved`, not adoption.

Primary reference: [Apple kqueue/EVFILT_PROC/NOTE_EXIT](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html).
Mach task-right availability for the real provider binaries remains an explicit
unverified design question; no source is cited as proving that availability.

## Re-adoption and full-host-loss states

`HostInstanceId` names a **process lifetime**, and GenerationId names a
replaceable service generation inside it. They are not interchangeable.

| Event | Native resources | Required transition |
| --- | --- | --- |
| generation n drains | arena remains above generation, callback producers quiesced | gate admission; stop/transfer in-flight launches; flush durable state |
| generation n+1 opens in same process | same process/job/pidfd/cgroup/kqueue objects | `re_adopt(record,n,n+1)` CASes the arena generation; old session references refuse |
| stale n request arrives | slot now belongs to n+1 | GenerationChanged; no native action |
| explicit stop racing generation swap | prepared token belongs to old generation | token invalidated, new generation must reobserve and prepare |
| Windows host killed/crashes | last arena job handles close | members killed; successor verifies exit then resumes provider conversation in new lifecycle |
| Linux host killed/crashes | cgroup can outlive host, direct child may exit on pipe loss | exact protected scope/root recovery and store CAS, or Unproved |
| macOS host killed/crashes | task/kqueue rights lost, tracked processes may survive | reinspection only; bounded/unknown scope, never invented kernel custody |
| OS reboot / machine changes | original native identities cannot be current | old record Lost/Historical; new lifecycle for resume |

Same-host re-adoption uses the original arena entry, not a named-object reopen.
The record must match machine/host/lifecycle/root/scope; a changed native
identity refuses. `from == to` is an idempotent retrieval of the same slot;
it cannot create another owner or alter its native resources. `from != to`
requires the exact current arena generation and host admission gate. A failed
provider reconnect does not roll back a valid native re-adoption to the old
generation; it records provider failure and retains process custody.

Full-loss recovery does not use a serializable token as proof by itself.
`plan_recovery` selects a platform-specific plan from the protected record;
`recover` verifies current native facts and only then lets the host commit the
new host/generation CAS. A failed commit rolls back the attempted transfer and
retains the scope obligation; it must not report an owned running session.
No live SE Code↔daemon transfer is built for alpha. A later design would need
explicit native handle transfer and ownership acknowledgment, not last-handle
closure followed by optimistic name reopen.

## Error catalogue (cause and legal remedy)

These codes are exhaustive in `ProcErrorCode`. Native code is retained as a
number; causes name the failed operation and target identity without printing
secret env/arguments. The shared error mapper supplies class, stable wire code
and remedy. A permission error is never a missing-process success.

| Rust code / proposed wire code | Cause | Remedy / state consequence |
| --- | --- | --- |
| InvalidInput / `process-input-invalid` | invalid PID/path/env/variant, size or deadline | supply absolute literal launch input or reread the issued observation; no child created |
| ProcessAbsent / `process-absent` | required live instance absent before pin/action | read lifecycle and resume as a new instance; no PID signal |
| IdentityUnreadable / `process-identity-unreadable` | native query/boot/image inaccessible, malformed or partial | restore query permission/native support and reread; preserve unknown state |
| IdentityChanged / `process-identity-changed` | boot, PID start or executable differs | reread lifecycle; never stop replacement; retain original scope obligation |
| UnsupportedPlatform / `process-capability-unsupported` | unavailable native mode/guarantee, including Unix window mode | choose a supported explicit mode or supported platform; do not silently substitute |
| ContainmentUnavailable / `process-containment-unavailable` | missing delegated cgroup/pidfd/job-list capability | provide delegated v2 root/user scope or supported Windows capability; refuse before agent exec |
| ContainmentChanged / `process-containment-changed` | inode/device/boot/job/host membership or limits changed | inspect original scope; do not use a path/name as substitute custody |
| ContainmentEscape / `process-containment-escape` | original pinned root still executes outside an allegedly empty required scope | retain custody/removal block; inspect the escaped exact instance with safe native rights |
| SandboxUnavailable / `process-sandbox-unavailable` | strict migration guard/profile cannot be enforced or is incompatible | use a reviewed compatible safe profile/native support; never drop sandbox automatically |
| BreakawayDenied / `process-breakaway-denied` | containing Windows job rejects explicit breakaway | fix caller BREAKAWAY_OK or start outside that job; no silent/elevated retry |
| LaunchFailed / `process-launch-failed` | native create/setup/exec or publication rollback error | fix named native cause, retry with new lifecycle; remaining custody is returned |
| LaunchTimedOut / `process-launch-timeout` | native setup/exec not proved by deadline | inspect retained scope, stop/witness rollback before retry; not provider timeout |
| DuplicateLifecycle / `process-lifecycle-exists` | same lifecycle already reserved/owned | retrieve its prior result; use new lifecycle only for an intentional new instance |
| HostChanged / `process-host-changed` | record/handle belongs to another full host lifetime | run platform recovery; on Windows verify exit then resume new lifecycle |
| GenerationChanged / `process-generation-changed` | stale session/token after generation transfer | reread current service generation and reprepare, no signal |
| ScopeUnreadable / `process-scope-unreadable` | incomplete accounting/member/control read | repair native access and reread; no empty-scope claim |
| StopDispatchFailed / `process-stop-dispatch-failed` | native termination call failed | retain ticket/error, attempt independent witness, retry only with fresh preparation |
| StopIncomplete / `process-stop-incomplete` | deadline, live scope/root, or insufficient guarantee | retain credentials/state/custody; inspect survivors; block Remove |
| ResourceLimit / `process-resource-limit` | lifecycle/member/byte cap reached | release witnessed terminal scopes or choose reviewed larger cap; never truncate to complete |

A read method returns ProcResult with unreadable failures; `ProcessRead` keeps
absence and an existing exited record distinct. `StopObservation::Pending`
is a measured state, not automatically a dispatch error. The public operation
maps Pending/Bounded at its deadline to an incomplete refusal with remaining
obligations. No negative acknowledgment is discarded because another part of
the scope exited. An outside Complete can coexist with a preserved dispatch
error; it does not retroactively make the dispatch successful.

## Performance allocation and resource lifetime

These are proposed **shares of** the global <=30 MB added RSS, <=100 ms startup,
<0.1% idle CPU and <20 ms CLI budgets, not new product-wide thresholds or
measured product facts. Kernel/process costs are reported separately from
host RSS; retained records must not hide leaked native resources.

| Resource/path | Proposed allocation / measurement |
| --- | --- |
| empty process runtime | <=0.5 MB added resident memory, <=2 ms of synchronous open; no eager child census |
| live arena entry | <=8 KiB userspace per lifecycle excluding host-owned provider stream buffers; 32 agents <=256 KiB |
| native exit integration | <=1 MB resident total including the optional one shared native monitor stack; 0 timer wakeups when idle |
| process observation | p95 <1 ms, no PowerShell, no helper process, no executable-name scan |
| generation re-adoption | native exact checks only; <=1 ms/instance target, schedule bulk adoption after host-ready |
| native launch plumbing | target p95 <5 ms excluding provider exec/ready and externally imposed fallback cgroup migration delay |
| clone3 fallback | record slower method/errno; measure within end-to-end journey budget rather than conceal migration latency |
| user-issued stop | single explicit monotonic deadline shared with harness drain/native effect/witness; no deadline extension on EINTR |

The CLI has no process owner sidecar or OS monitor. It asks the existing host
for custody operations; its reads use stored last-witnessed state or explicit
native inspection as specified by the operation. "Recorded running" is never
rendered as freshly observed running. The one monitor, if used, is part of the
same host process; no seat creates its own keeper/door. Native wait callbacks
and descriptors are unregistered/closed on release. Empty scopes do not remain
forever merely to make re-adoption easy; only committed history persists.

No periodic /proc scan or all-process Windows snapshot runs during idle.
A stop or explicit list may enumerate its scope within limits. Cold recovery
is bounded and reports pending/unknown entries while the host is already
ready; it does not block startup on every possible orphan. Backpressure is
explicit when the arena is full. Native guards never allocate in a forked
child; all preparation cost is included in launch measurements.

## Five journeys and review-owned verification

No author test code is in this candidate. The independent journey oracle and
reviewers own executable assertions. This table binds their real consumers to
the contract, rather than adding a new test/gate framework.

| Journey | Native behavior that the real provider exercises |
| --- | --- |
| J1 Install | packaged architecture loads native bindings with no Node/PowerShell/runtime helper; capability errors name required OS support |
| J2 Adopt | launch real Claude/Codex from existing repo with safe explicit profile/env; observe correct image/start and provider-ready separately; an argv containing spaces/quotes stays literal |
| J3 Come back | same-host service restart re-adopts arena without killing agents; full Windows host close kills old members, outside witness precedes new lifecycle/conversation resume; Linux recovery proves exact scope or reports unknown |
| J4 Two agents | independent lifecycles/jobs/cgroups; stopping/re-adopting one cannot affect the other; host notifications cause fresh reads without a mail/process sidecar |
| J5 Remove | graceful provider stop, forced owned-scope termination if needed, outside root+scope exit; stop errors survive; pending/weak/unreadable scope blocks deleting state and credentials; user/Git/provider-account files survive |

Mirror paths share this backend: CLI/MCP call the same custody methods;
Claude/Codex supply different literal launch/stream/readiness adapters but the
same native ownership; Windows window/headless differ in console flags, not
identity/job/witness; service-generation/cold-host recovery are distinct typed
paths. Linux/macOS window mode is an explicit after-alpha capability, not a
missing test silently treated as passing. Embedded/standalone share the arena
contract; the library does not consume unrelated children/signals in SE Code.

Reviewers should exercise the hazards journeys do not naturally reach:
replacement start identity refusal with no replacement signal; inaccessible
identity versus absence; leader exits while child lives; Linux setsid and
attempted migration; missing delegation before launch; clone3 fallback before
exec; Windows strict caller job refusal, explicit breakaway, job-list native
creation, last-owner death and no leaked job handle; generation/token races;
post-create commit failure with retained rollback custody; false controller
error with an independently complete witness; active scope at deadline;
notification removal concurrent with callback; full/truncated native lists;
and preserving another SE Code child when reaping ours. macOS strong-task-right
and escaped-descendant feasibility requires a native machine. Type-checks alone
cannot accept these behaviors, and no passing count is invented here.

## Decisions for the architecture review

These are explicit freeze questions, not permissions requests to resume coding.
Implementation stays stopped until the integrated architecture is approved.

1. **Shared DTO ownership:** nominate canonical IDs, Read and shared error
   signatures in se-types; migrate/re-export this design's overlapping ID
   declarations without parallel formats. The compile-only crate therefore
   has no dependency yet; implementation will depend on that canonical
   foundation, not local copies.
2. **Windows explicit detachment scope:** this proposal follows the ratified
   BREAKAWAY_OK, never SILENT contract and labels the resulting kernel-scope
   witness. Confirm the common Stop/Remove renderer and project registry account
   for separately owned detached lifecycles; a universal-descendant claim is
   incompatible with that permission and is not proposed.
3. **Linux provider-compatible guard:** approve/adjust the Network Allow plus
   blocked external Unix-broker guard and Codex stdio transport, then qualify
   real Claude/Codex cache/account behavior. The measured offline S2 guard is
   insufficient evidence; until resolved strict launch is unavailable rather
   than unsafe. Confirm support for kernels without Landlock ABI 6: the
   proposed answer is an actionable refusal, not weakened containment.
4. **macOS kernel-scope gap:** process groups/kqueue are insufficient for the
   strict scope and atomic signal promises. Decide a stronger supported native
   mechanism/entitlement strategy or explicitly ratify a bounded guarantee.
   This proposal refuses unsupported strict launch/forced stop, and does not
   call the macOS alpha journey cured by that refusal.
5. **Common cross-host recovery order:** host/store owners must align the
   protected reservation/record CAS and failure rollback with this native
   two-phase transfer. Live daemon↔SE Code ownership handover remains deferred.

## Implementation sequence after approval

1. Adopt the reviewed shared types; native read/pin and exact-instance events,
   with reviewer-owned OS cases. No temporary implementation of a public verb.
2. Windows host arena, job-list window/headless launch, breakaway/accounting,
   same-host re-adoption and host-loss recovery, with Alpha's native review.
3. Linux validated delegation, clone3/error channel/fallback, reviewed guard,
   cgroup events/kill and cold recovery; real provider journeys, not fixture-only
   containment.
4. macOS native implementation according to the resolved guarantee, then native
   journeys. Type-check all three targets throughout; never use cross-compile
   success as platform behavior evidence.

Each increment is reviewable product code against this contract, touches only
se-proc and required workspace dependency lines, and is landed only by Prime.
This compile-only design revision contains no backend implementation or test.
