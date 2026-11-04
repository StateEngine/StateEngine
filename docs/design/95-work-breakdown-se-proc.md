# 95. Work breakdown — se-proc

Round-4 planning correction, base `500da05`. Jimmy approves wave 1 once C1–C9
land and pass one cross-section check; J1 plus hosted E3 completes that wave.
Later waves wait for its results. This candidate changes contracts only, not
native backend implementations or author tests.

Section 30, including its accepted stdio port, transfer_manifest and handover
rules, is the contract; sections 10/20/40 supply the host/store barrier. The
outcome is real native custody through those consumers, not passing declarations.
Mac implementation and native qualification run in the **borrowed-Mac campaign
before alpha ships**; they do not delay the Windows/Linux intermediate milestone.
P03-M/P07-M include the Mac-specific joins of shared tasks; retaining portable
builds does not claim a native Mac journey pass. All five journeys require both
real providers, standalone and embedded, on all three operating systems.

Dependencies: **F** = accepted se-types and its owner's shared IDs/encodings;
**S** = section 20 durable checkpoints, CAS, pending effects and recovery reads;
**H** = section 40 authority, async custody executor, reactor, provider framing
and streams; **U** = packaged native image/private-entry and runtime-up owner;
**X** = sections 10/20/40 handover, exact-idle/input/queue and lease barrier;
**E** = section 70 native peer/security and surface error contracts; **Q** =
independent section 90 reviewers, journey scripts and release artifacts.
Missing consumers block their behavior witness, not agreed independent work.

Owner slots below are assigned by the project maintainer, not permission to spawn seats. **PROC**
alone owns shared se-proc sources, Cargo.toml, module registration and target
dependencies; Cargo.lock changes serialize with the workspace owner. **WIN**,
**LINUX** and later-campaign **MAC** own their disjoint `src/platform/<os>/` trees.
Paths below are relative to `crates/se-proc/`. External host/store/binary files
and reviewer tests remain with their owners. Retired generic process commands/
tools have no dispatch or implementation unit here; native instance reads remain
internal to agent/runtime consumers. se-proc links se-types/native
bindings; the private Linux bootstrap transport joins in wave 4. No se-host/
se-store dependency, public bus API or resident helper is added; unsafe stays
here. The wave 4 zbus-first/libdbus-fallback decision and measurements are owned
once in 30 §5.2 and 80 §1.

Estimates are rough final production Rust lines, including se-proc-specific retained
declarations once under P00, excluding canonical se-types definitions, docs, tests, generated/vendor bindings and external
implementations. Each task's allocation is counted once; these are sizing
signals with broad uncertainty, not gates or grounds to cut behavior. Atlas A02/
A08 separately count the physical-file/file-watch adapters under se-proc; PROC
coordinates their registration, but those native lines are not counted again here.

## Tasks, in build order

**P00 — Shared contracts and backend ports (~1,000 lines).** Owner PROC.
Files: `Cargo.toml`, `src/lib.rs`, `src/{identity,launch,ownership,error,stdio}.rs`,
`src/platform/mod.rs`, `src/runtime/mod.rs`. Depends F and agreed S/H/U/X/E ports.

Implement 30 §§1–2/7: shared IDs, opaque custody, phase-specific inputs, native
causes and safe reactor/security/private-entry/stdio/transfer ports. Include
the distinct human-release outcome from StopUnproved only, after an ordinary
stop could not be proved; no StopWitness is fabricated. PROC alone
wires modules; leaf work follows this agreement.

Witness: actual host adapter compiles; T14/T23/T28 and J2/J3/J5 exercise the
consumer. No fake backend or duplicate common ID system.

**P01 — Arena, generations and retained obligations (~750).** Owner PROC; file `src/runtime/arena.rs`. Depends P00; can overlap OS leaf work. Satisfies §30 §§3–4/8: reserve before effects, revocable references/one-use tokens, complete bounded snapshots, slot serialization, deadline/generation checks, unwind containment and poison quarantine; no map lock across callbacks/store/waits. Account for 16 active admissions and separately persisted witnessed-empty cleanup debt. Witness: T14/T16, J3–J5 plus reviewer public-host checks for unpublished work, stale references, callback panic and admission 17; compiler success is not custody proof.

**P02 — Unix attach/control and terminals (~900).** Owner PROC; files `src/unix/control.rs`, `attach.rs`, `terminal.rs`. Depends P00/P01 and E/U rendezvous/private-image contracts; overlaps WIN/LINUX leaves, with Linux spawn joining this seam. Satisfies §30 §§2.2/5.2/5.4: exact helper peer/PID/birth, one-use nonce, closed FD inheritance, parent-loss EOF, real controlling PTY, literal argv/env, durable RootCheckpoint before exec and truthful TerminalAttach identity. Helpers are transient; rollback never kills a shared terminal server. Witness: T15/T21/T23 and J2/J3/J5, both providers/window/headless; reviewers cover broker races, authorization EOF and publication crashes. Mac-specific terminal integration joins P03-M before alpha.

**P03-W — Windows identity, jobs, launch and events (~1,500).** Owner WIN; files `src/platform/windows/{mod,identity,security,job,spawn,notify}.rs`. Depends P00, P01 retention and U/E. Can overlap LINUX; WIN serializes its own stdio work. Satisfies §30 §§4.1/5.1: held FILETIME/image identity, absent versus unreadable, native peer/ACL/membership, explicit BREAKAWAY plus atomic JOB_LIST creation, KILL_ON_CLOSE|BREAKAWAY_OK without SILENT, exact inheritance/quoting/console defaults and pinned-job stop with independent root-exit/active-zero witness. One existing host IOCP serves jobs and streams, with the stated missed-nudge bounds. Witness: native T14–T16/T21–T23 and J1–J5; reviewers cover strict caller jobs, unrelated children, console behavior and last-handle timing. Cross-compilation alone is insufficient.

**P03-L — Linux identity, tracked groups and later delegation (~2,050 lines).**
Owner LINUX; files `src/platform/linux/{mod,identity,security,scope,spawn,notify}.rs`.
Depends P00/P01 and U/E; attach joins P02. Native identity/probes can precede terminals.

Wave 1 implements boot/start/image reads, pidfds, native peers/modes and the
honest uncontained tracked-group path, including the fourth pre-exec root
checkpoint, exact cause, stop witness and human release from 30 §4. No scope
transport or delegated-cgroup acquisition blocks wave 1.

Wave 4 adds fresh per-launch LinuxUserManager scopes, exact completion/placement,
scoped creator after C2 and authenticated stdio/pidfd custody. Follow 30 §5.2
and 80's zbus-first comparison; include ~200 native launch/handoff and ~250
transport adapter lines in this estimate. The old libdbus footprint is a
measured reference, not an estimate of zbus. No dependency/backend is selected
by a compiling declaration, and no permanent reaper or extra store barrier is added.

Witness: native T14–T16/T21–T23/T28 and J1–J5 with/without manager/pidfds, actual
SSH origin, transferred streams and exact cleanup. No weaker retry after
failed entry, invented population or non-parent exit status. Window-origin
preflight remains separate; headless proof never qualifies a terminal peer.

**P03-M — macOS backend and shared-task joins (~1,000; MAC CAMPAIGN BEFORE ALPHA).** Owner MAC, with PROC coordinating shared-file edits; files `src/platform/macos/{mod,identity,security,group,spawn,notify}.rs` plus Mac-specific joins in PROC-owned Unix/recovery/bootstrap files. Depends P00/P01/P02 and U/E; assigned only in the Mac campaign. Satisfies §30 §§1.1/5.3–5.5: boot/start/path checks, existing-reactor kqueue, native peers/modes, literal helper/PTY/session setup, exact tracked-group stop/recovery and its explicit non-atomic/deliberate-escape bound. No Mach task entitlement or unescapable-tree claim. Witness: actual Mac J1–J5, T15/T16/T21–T23 and reviewer Mac mismatch/escape/terminal cases; T14's current Linux/Windows listing is not a Mac pass. Cross-compilation remains intermediate only.

**P03-S — Windows provider-stdio arena (~1,100).** Owner WIN; file `src/platform/windows/stdio.rs`, using P00's PROC-owned public facade and P03-W's collector. Depends P01/P03-W and H's ProviderIoPlatform consumer. Satisfies §30 §2.3: private overlapped host pipes/ordinary child Files, parent child-end closure, bounded capacity charges, one read per output/one write, stable tickets, exact partial/EOF/error results, cancellation/drain custody and scoped Stdin/All close with release witnesses. attach_stdio binds successor-local sink/limits and drains old callbacks through Unbound/Draining/Ready; no per-pipe thread, polling or second collector. Witness: real Claude/Codex prompt-to-EOF/output, generation replacement and reviewer native partial/error/cancel/future-drop/close races; J2/J3/J5. Framing, delivery and payload budget stay with H, not another native transport implementation.

**P04 — Launch, stop and outside witnesses (~850).** Owner PROC;
`src/runtime/launch_stop.rs`. Depends P01, one ready backend, H/S commits and
P02 for Unix helper paths; integrate Windows/Linux independently.

Implement 30 §§3–5's causal launch barriers and stop/CAS/witness sequence.
Core returns OpStep::Commit with a typed continuation; host awaits completion,
with no native work inside a store transaction or long blocking-pool wait.
An unproved stop retains its facts. Owner-human release instead uses 30 §4's
committed marker and non-signalling retirement, never successful-stop evidence.

Witness: T14/T15/T28 and CLI/MCP J2/J4/J5; reviewers cover CAS/creation races,
simultaneous stop and natural exit. Dispatch alone never means stopped.

**P05 — Recovery and natural cleanup (~650).** Owner PROC;
`src/runtime/recovery.rs`. Depends P04 and S/H phase/CAS/read ports; overlaps
native transfer leaves. Mac joins P03-M before alpha.

Implement 30 §§3.2/6: recover every durable launch phase, preserve unknown exit
status and refuse reused/foreign identities. Witness/Exited/release/ack precede
normal retirement; empty-scope cleanup debt does not retain a live slot.
Human-released markers reconcile only non-signalling cleanup, never re-adoption.
Windows owner loss requires outside proof before a new lifecycle.

Witness: T14/T16 and J3–J5, checkpoint/release crashes, original-root reuse with
surviving children and graceful exit without a stop ticket.

**P06 — Detached runtime bootstrap (~650).** Owner PROC; file `src/runtime/bootstrap.rs`; OS creation stays in its P03 spawn.rs and U owns binary dispatch. Depends P00/P01, native spawn/identity and U/E startup-slot/lease/endpoint contracts. Satisfies §30 §5.5: persisted machine/startup nonce, exact final runtime pin, retained spawn/commit failures, readiness/abort/witness/release and lost-ACK reconciliation; losing startup cannot kill the winner. Standby admits no agents; committed owner survives parent loss. Windows job refusal and Linux manager-unit versus SessionOnly/inherited-cgroup bounds remain truthful, with no permanent helper or public arbitrary-process launcher. Witness: T16/T21/T23, J1–J3/J5 and reviewer readiness/crash/startup races with outside helper inventory. Mac native detach joins P03-M before alpha.

**P07-W — Windows native resource transfer (~700).** Owner WIN; file `src/platform/windows/transfer.rs`, with WIN retaining its job/notify/stdio files. Depends P03-W/P03-S and X's frozen native frame. Can overlap LINUX transfer/P05/P06. Satisfies §30 §§2.3/6: exact pinned-peer DuplicateHandle, overlapping job custody, drained callbacks/operations, job-port readback and atomic shared FILE_OBJECT pipe association replacement inside accept_transfer; activation verifies it. Retain original IOCP/key for proved pre-Claimed abort replacement; no pending OVERLAPPED crosses collectors. Witness: T16/T21 plus reviewer invalid-bundle, source/receiver-crash, zero-handle-gap and provider stream/PTY continuity checks through the public host consumer; real two-way handover is required.

**P07-L — Linux native resource transfer (~500).** Owner LINUX; file `src/platform/linux/transfer.rs`, with notification edits remaining LINUX-owned. Depends P03-L and X's peer/frame contract; can overlap WIN transfer/P05/P06. Satisfies §30 §6: authenticated SCM_RIGHTS for exact pinned cgroup/pidfd/control/provider/PTY descriptors, complete resource-role validation, inactive staging, retained source originals and restored notifications on authorized abort. Witness: T16/T21, J3/J4 and reviewer source/receiver crash, invalid/missing/extra descriptors and unchanged-instance stream continuity. Missing pidfds must preserve the reported alternate witness bound, not invent a native pin.
Wave 3's round trip covers tracked-group/stdio custody; delegated-cgroup transfer
joins with scopes in wave 4 before the full provider/crash campaign.

**P07-M — macOS native resource transfer (~350; MAC CAMPAIGN BEFORE ALPHA).** Owner MAC; file `src/platform/macos/transfer.rs`, with PROC-owned transfer joins coordinated by PROC. Depends P03-M, P08's agreed transfer protocol and X; assigned in the Mac campaign. Satisfies §30 §6: authenticated stream/PTY transfer and reopening exact kqueue/tracked-group sources, retained originals and readback/abort at the stated platform bound. Witness: actual Mac two-way live handover with both providers, unchanged PID/birth, reviewer wrong-bundle/crash/stream cases and measured B8. T16/T21 or a successful cross-build alone does not prove live transfer.

**P08 — Native manifest and host-barrier activation (~650).** Owner PROC; file `src/runtime/transfer.rs`. Depends P01/P06 and P07 for the integrated OS plus X/H/S's phase/lease barrier. Integrate ready Windows/Linux independently. Satisfies §30 §6 and §§20/40: CSPRNG native nonce, safe immutable transfer_manifest/digest, separate store RecordId, private non-Debug nonce/frame, inactive accept and ready local Windows stdio binding before activation. Host proves pre-Claimed/lease and serializes abort; borrowed offer/import retain retry custody, native checks its own facts, Claimed never restores source, and unproved work stays pending. Move host-owned/Unix Files once; Windows endpoints stay native. Witness: T16/T21/T27, J3/J4 and reviewer phase/crash/lost-ACK tests, with no doubled input or reused owner. The host drains/joins its writer before exclusive FULL Prepared; Prepared/Claimed/Finished/Aborted/Recovered remain distinct durable outcomes. Native readiness/activation are in-memory facts; FULL Finished binds activation receipt, final capture/queue cuts and independently proved closure of all source originals before any destination writer/consumer release. Q measures B8 at section 80's boundary, with quiescence separately reported.

**P09 — Consumer and budget integration (~100).** Owner PROC for final wiring;
fixes stay with each source owner, tests/runner maps with Q. Full integration
joins P04–P08 and H/S/U/X/E/Q; Mac joins its borrowed-Mac campaign before alpha.

Integrate incrementally: wave 1 proves stop and hosted E3 launch-barrier costs;
wave 2 measures combined SE Code+StateEngine memory after a real provider task
(80 §2.2); wave 3 proves a handover round trip; wave 4 joins scopes and the
full provider/crash matrix. Later transfer dependencies never block earlier
consumer measurements. Section 80 owns every budget/target; the overview owns
early-proof status, not duplicated native counts here.

Witness: J1–J5, both providers, CLI/MCP, embedded/standalone and window/headless;
applicable T14–T16/T21–T23/T27/T28. Include serial durable barriers, idle costs
and exact custody inventory. Unmeasured/native-Mac work is not green; no new
gate family or author tests.

**P10 - Native IPC peer/ACL surface (2,411 lines at f00ea79f; retained code).** Owner 5p. Files: `src/native_ipc/**` (11 files). Consumed by the se-host IPC listener/lease (NativeUnixEndpoint/NativePipeReservation/NativeUnixStream). Qualifies the existing peer/ACL unsafe code as a named plan unit: SO_PEERCRED on Linux, LOCAL_PEERCRED/LOCAL_PEERPID on macOS, Windows pipe DACL plus GetNamedPipe{Server,Client}ProcessId and token-SID checks, image and image-cache proof, and the IpcPlatform BorrowedFd/BorrowedHandle boundary. No new implementation scope; corrections are sized as separate candidates. Review record: Prime's Opus security review ACCEPT (msg-41f95b08); 5p's E1/D3 a449bc93 and D1 6953ac37 landed in batch 15 (3108f870).

**P11 - State-file native security (6,998 lines at f00ea79f; retained code).** Owner: maintainer to assign. Files: `src/state_files/**` (33 files). Qualifies the existing state-file security code as a named plan unit: Windows ACLs and install claims, Unix ownership/permission checks, atomic replace and PATH edits; the count includes the batch 16b macOS ACL work (8340be56). No new implementation scope; corrections are sized as separate candidates. Review record: dedicated GPT security review by Otto (commissioned in msg-72a325f3), treating state_files as a process boundary with a hostile local process.

## Joins and total

After P00, PROC serializes P01/P02 then ready-platform P04/P05/P06/P08/P09;
WIN and LINUX may progress on disjoint leaves, with their transfer tasks joining
agreed host barriers. P03-S shares WIN's collector; it does not create a second
runtime. Other workstreams retain authority, store, framing, public transport,
binary dispatch, schemas, packaging and reviewer ownership. The project maintainer alone assigns
and lands; a declaration stub never completes a behavioral task.

Production estimate: **~20,800 Windows/Linux + shared lines** (11,400 build-order
units plus the retained-code units P10 2,411 and P11 6,998 measured at f00ea79f),
plus **~1,350 Mac-specific lines in the pre-alpha Mac campaign** (P03-M ~1,000;
P07-M ~350), for **~22,150 total**. P10/P11 record existing code under plan
ownership; they add no new build order, and their lines are counted once.
The active subtotal includes ~1,000 retained/shared contracts, ~10,400 further
native/common lines and ~9,400 retained native security lines under P10/P11; it
excludes the separate core/CLI, host, store, foundation, Atlas, release and
reviewer implementations. These are rough planning amounts,
not measured finished code or an implementation authorization. Removing generic
process operations reduces the core/CLI surface, not the native arena, stop,
identity or transfer mechanisms needed by agent consumers; this part therefore
keeps the per-unit native estimates rather than claiming the overview's earlier
unallocated reduction.
