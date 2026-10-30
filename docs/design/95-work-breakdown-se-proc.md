# 95. Work breakdown — se-proc

Reconciled planning input for Prime, 2026-10-30; base `f25ca90`. **No code, tests or
build permission. Jimmy approves the full design before implementation.**

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

Owner slots below are assigned by Prime, not permission to spawn seats. **PROC**
alone owns shared se-proc sources, Cargo.toml, module registration and target
dependencies; Cargo.lock changes serialize with the workspace owner. **WIN**,
**LINUX** and later-campaign **MAC** own their disjoint `src/platform/<os>/` trees.
Paths below are relative to `crates/se-proc/`. External host/store/binary files
and reviewer tests remain with their owners. Retired generic process commands/
tools have no dispatch or implementation unit here; native instance reads remain
internal to agent/runtime consumers. se-proc links se-types/native
bindings, never se-host, se-store, Tokio or a D-Bus client; unsafe remains here.

Estimates are rough final production Rust lines, including se-proc-specific retained
declarations once under P00, excluding canonical se-types definitions, docs, tests, generated/vendor bindings and external
implementations. Each task's allocation is counted once; these are sizing
signals with broad uncertainty, not gates or grounds to cut behavior. Atlas A02/
A08 separately count the physical-file/file-watch adapters under se-proc; PROC
coordinates their registration, but those native lines are not counted again here.

## Tasks, in build order

**P00 — Shared contracts and backend ports (~1,000 lines).** Owner PROC; files `Cargo.toml`, `src/lib.rs`, `identity.rs`, `launch.rs`, `ownership.rs`, `error.rs`, `stdio.rs`, `platform/mod.rs`, `runtime/mod.rs` (source paths after lib.rs are under src). Depends F and agreed S/H/U/X/E interfaces. Satisfies §30 §§1–2/7: canonical shared IDs, opaque custody, phase-specific inputs, internal causes mapped to the merged public catalogue, lossless paths/start values, safe reactor/security/private-entry ports and the accepted ProviderStdioApi/ProcessTransfer declarations. All later leaf work follows this port agreement; PROC alone wires modules. Witness: actual host adapter compiles; T14/T23/T28 and J2/J3/J5 exercise identity, environment, causes and consumer contracts. No fake backend or duplicate common ID system.

**P01 — Arena, generations and retained obligations (~750).** Owner PROC; file `src/runtime/arena.rs`. Depends P00; can overlap OS leaf work. Satisfies §30 §§3–4/8: reserve before effects, revocable references/one-use tokens, complete bounded snapshots, slot serialization, deadline/generation checks, unwind containment and poison quarantine; no map lock across callbacks/store/waits. Account for 16 active admissions and separately persisted witnessed-empty cleanup debt. Witness: T14/T16, J3–J5 plus reviewer public-host checks for unpublished work, stale references, callback panic and admission 17; compiler success is not custody proof.

**P02 — Unix attach/control and terminals (~900).** Owner PROC; files `src/unix/control.rs`, `attach.rs`, `terminal.rs`. Depends P00/P01 and E/U rendezvous/private-image contracts; overlaps WIN/LINUX leaves, with Linux spawn joining this seam. Satisfies §30 §§2.2/5.2/5.4: exact helper peer/PID/birth, one-use nonce, closed FD inheritance, parent-loss EOF, real controlling PTY, literal argv/env, durable RootCheckpoint before exec and truthful TerminalAttach identity. Helpers are transient; rollback never kills a shared terminal server. Witness: T15/T21/T23 and J2/J3/J5, both providers/window/headless; reviewers cover broker races, authorization EOF and publication crashes. Mac-specific terminal integration joins P03-M before alpha.

**P03-W — Windows identity, jobs, launch and events (~1,500).** Owner WIN; files `src/platform/windows/{mod,identity,security,job,spawn,notify}.rs`. Depends P00, P01 retention and U/E. Can overlap LINUX; WIN serializes its own stdio work. Satisfies §30 §§4.1/5.1: held FILETIME/image identity, absent versus unreadable, native peer/ACL/membership, explicit BREAKAWAY plus atomic JOB_LIST creation, KILL_ON_CLOSE|BREAKAWAY_OK without SILENT, exact inheritance/quoting/console defaults and pinned-job stop with independent root-exit/active-zero witness. One existing host IOCP serves jobs and streams, with the stated missed-nudge bounds. Witness: native T14–T16/T21–T23 and J1–J5; reviewers cover strict caller jobs, unrelated children, console behavior and last-handle timing. Cross-compilation alone is insufficient.

**P03-L — Linux delegation and honest fallback (~1,600).** Owner LINUX; files `src/platform/linux/{mod,identity,security,scope,spawn,notify}.rs`. Depends P00/P01, P02 for attach and U/E; identity/probes can start before terminals. Satisfies §30 §§4.1/5.2/7: bracketed boot/start/image reads, zombie/status facts, pidfds when supported, native peer/mode/membership, lazy trusted delegation without moving the embedded host, pinned cgroup checkpoint, clone3 entry/accepted ENOSYS fallback and tracked uncontained group with exact cause. No weaker retry after failed cgroup entry, fabricated member count or unrelated-child reap; optional hardening remains opt-in. Witness: native T14–T16/T21–T23/T28 and J1–J5 with/without manager and genuinely unavailable pidfds; witness labels must match capability. Reviewer crash/entry failures supplement journeys.

**P03-M — macOS backend and shared-task joins (~1,000; MAC CAMPAIGN BEFORE ALPHA).** Owner MAC, with PROC coordinating shared-file edits; files `src/platform/macos/{mod,identity,security,group,spawn,notify}.rs` plus Mac-specific joins in PROC-owned Unix/recovery/bootstrap files. Depends P00/P01/P02 and U/E; assigned only in the Mac campaign. Satisfies §30 §§1.1/5.3–5.5: boot/start/path checks, existing-reactor kqueue, native peers/modes, literal helper/PTY/session setup, exact tracked-group stop/recovery and its explicit non-atomic/deliberate-escape bound. No Mach task entitlement or unescapable-tree claim. Witness: actual Mac J1–J5, T15/T16/T21–T23 and reviewer Mac mismatch/escape/terminal cases; T14's current Linux/Windows listing is not a Mac pass. Cross-compilation remains intermediate only.

**P03-S — Windows provider-stdio arena (~1,100).** Owner WIN; file `src/platform/windows/stdio.rs`, using P00's PROC-owned public facade and P03-W's collector. Depends P01/P03-W and H's ProviderIoPlatform consumer. Satisfies §30 §2.3: private overlapped host pipes/ordinary child Files, parent child-end closure, bounded capacity charges, one read per output/one write, stable tickets, exact partial/EOF/error results, cancellation/drain custody and scoped Stdin/All close with release witnesses. attach_stdio binds successor-local sink/limits and drains old callbacks through Unbound/Draining/Ready; no per-pipe thread, polling or second collector. Witness: real Claude/Codex prompt-to-EOF/output, generation replacement and reviewer native partial/error/cancel/future-drop/close races; J2/J3/J5. Framing, delivery and payload budget stay with H, not another native transport implementation.

**P04 — Launch, stop and outside witnesses (~850).** Owner PROC; file `src/runtime/launch_stop.rs`. Depends P01 plus a ready backend, H/S commit ports and P02 for Unix helper paths; integrate one OS while another finishes. Satisfies §30 §§3–5: prepare/begin/poll/authorize/cancel, describe/observe and stop/watch/witness bind actual native effects to C1 FULL reservation + prepared session/credential, C2 actual scope checkpoint and C3 FULL root/activation/readiness; embedded binding issues no credential events. Unix terminal, macOS and uncontained helper paths retain the fourth RootCheckpoint before exec. The synchronous core returns `OpStep::Commit { batch, then }` with a typed continuation, the host awaits writer completion asynchronously without `wait_blocking`, and no store transaction spans a native call. Failed stop CAS dispatches nothing; post-CAS refusal retains StopUnproved, status and independent exit proof. One host deadline spans graceful/forced work without long-held blocking workers. Witness: T14/T15/T28, CLI/MCP J2/J4/J5 and reviewer pre/post-CAS, unpublished-exec, simultaneous-stop and natural-exit cases. Successful dispatch never means stopped.

**P05 — Recovery and natural cleanup (~650).** Owner PROC; file `src/runtime/recovery.rs`. Depends P04 and S/H durable phase/CAS/read ports; overlaps native transfer leaves. Satisfies §30 §§3.2/6: recover Reservation/Prepared/RootPrepared/Record/Exited/Historical, re-adopt above generations, preserve unknown status and reject reused PID/foreign boot/path/job-name authority. Witness/commit Exited/release/ack precede retirement; failed empty-scope cleanup persists as debt without charging a live slot. Unstaged Windows owner loss resumes a new lifecycle only after outside proof; Linux re-adopts exact instances. Witness: T14/T16 and J3–J5 plus reviewer checkpoint/release crashes, original-root reuse with surviving children and graceful exit without a stop ticket. Mac joins are in P03-M before alpha.

**P06 — Detached runtime bootstrap (~650).** Owner PROC; file `src/runtime/bootstrap.rs`; OS creation stays in its P03 spawn.rs and U owns binary dispatch. Depends P00/P01, native spawn/identity and U/E startup-slot/lease/endpoint contracts. Satisfies §30 §5.5: persisted machine/startup nonce, exact final runtime pin, retained spawn/commit failures, readiness/abort/witness/release and lost-ACK reconciliation; losing startup cannot kill the winner. Standby admits no agents; committed owner survives parent loss. Windows job refusal and Linux manager-unit versus SessionOnly/inherited-cgroup bounds remain truthful, with no permanent helper or public arbitrary-process launcher. Witness: T16/T21/T23, J1–J3/J5 and reviewer readiness/crash/startup races with outside helper inventory. Mac native detach joins P03-M before alpha.

**P07-W — Windows native resource transfer (~700).** Owner WIN; file `src/platform/windows/transfer.rs`, with WIN retaining its job/notify/stdio files. Depends P03-W/P03-S and X's frozen native frame. Can overlap LINUX transfer/P05/P06. Satisfies §30 §§2.3/6: exact pinned-peer DuplicateHandle, overlapping job custody, drained callbacks/operations, job-port readback and atomic shared FILE_OBJECT pipe association replacement inside accept_transfer; activation verifies it. Retain original IOCP/key for proved pre-Claimed abort replacement; no pending OVERLAPPED crosses collectors. Witness: T16/T21 plus reviewer invalid-bundle, source/receiver-crash, zero-handle-gap and provider stream/PTY continuity checks through the public host consumer; real two-way handover is required.

**P07-L — Linux native resource transfer (~500).** Owner LINUX; file `src/platform/linux/transfer.rs`, with notification edits remaining LINUX-owned. Depends P03-L and X's peer/frame contract; can overlap WIN transfer/P05/P06. Satisfies §30 §6: authenticated SCM_RIGHTS for exact pinned cgroup/pidfd/control/provider/PTY descriptors, complete resource-role validation, inactive staging, retained source originals and restored notifications on authorized abort. Witness: T16/T21, J3/J4 and reviewer source/receiver crash, invalid/missing/extra descriptors and unchanged-instance stream continuity. Missing pidfds must preserve the reported alternate witness bound, not invent a native pin.

**P07-M — macOS native resource transfer (~350; MAC CAMPAIGN BEFORE ALPHA).** Owner MAC; file `src/platform/macos/transfer.rs`, with PROC-owned transfer joins coordinated by PROC. Depends P03-M, P08's agreed transfer protocol and X; assigned in the Mac campaign. Satisfies §30 §6: authenticated stream/PTY transfer and reopening exact kqueue/tracked-group sources, retained originals and readback/abort at the stated platform bound. Witness: actual Mac two-way live handover with both providers, unchanged PID/birth, reviewer wrong-bundle/crash/stream cases and measured B8. T16/T21 or a successful cross-build alone does not prove live transfer.

**P08 — Native manifest and host-barrier activation (~650).** Owner PROC; file `src/runtime/transfer.rs`. Depends P01/P06 and P07 for the integrated OS plus X/H/S's phase/lease barrier. Integrate ready Windows/Linux independently. Satisfies §30 §6 and §§20/40: CSPRNG native nonce, safe immutable transfer_manifest/digest, separate store RecordId, private non-Debug nonce/frame, inactive accept and ready local Windows stdio binding before activation. Host proves pre-Claimed/lease and serializes abort; borrowed offer/import retain retry custody, native checks its own facts, Claimed never restores source, and unproved work stays pending. Move host-owned/Unix Files once; Windows endpoints stay native. Witness: T16/T21/T27, J3/J4 and reviewer phase/crash/lost-ACK tests, with no doubled input or reused owner. The host drains/joins its writer before exclusive FULL Prepared; Prepared/Claimed/Finished/Aborted/Recovered remain distinct durable outcomes. Native readiness/activation are in-memory facts; FULL Finished binds activation receipt, final capture/queue cuts and independently proved closure of all source originals before any destination writer/consumer release. Q measures B8 at section 80's boundary, with quiescence separately reported.

**P09 — Consumer and budget integration (~100).** Owner PROC for final module wiring; fixes remain with each file's owner and Q owns all tests/runner maps. Depends P04–P08 and H/S/U/X/E/Q for Windows/Linux; P03-M/P07-M and the borrowed-Mac campaign complete release acceptance before alpha. Witness: real J1–J5, both providers, CLI/MCP, embedded/standalone and window/headless; applicable T14–T16/T21–T23/T27/T28 plus the native boundary cases above. Measure section 30's 16-live-lifecycle custody share and section 80's single canonical budget/target set: collector/helper inventory, native identity/runtime setup, three/four serial launch barriers including first Linux delegation, stop bounds, B8, ordinary B9 and the separate FULL-command sampling boundary. The native continuous-writer spike is E1 PARTIAL, real-provider E1b passes 2/2 per Windows/Linux; neither establishes job-port reassociation/abort/100-loop coverage, product crash integration or B8. Include serial durable barriers and idle measurement; unmeasured/unreached/native-Mac work is not green. No new gate family or author tests.

## Joins and total

After P00, PROC serializes P01/P02 then ready-platform P04/P05/P06/P08/P09;
WIN and LINUX may progress on disjoint leaves, with their transfer tasks joining
agreed host barriers. P03-S shares WIN's collector; it does not create a second
runtime. Other workstreams retain authority, store, framing, public transport,
binary dispatch, schemas, packaging and reviewer ownership. Prime alone assigns
and lands; a declaration stub never completes a behavioral task.

Production estimate: **~10,950 Windows/Linux + shared lines**, plus **~1,350
Mac-specific lines in the pre-alpha Mac campaign** (P03-M ~1,000; P07-M ~350), for **~12,300 total**.
The active subtotal includes ~1,000 retained/shared contracts and ~9,950 further
native/common lines; it excludes the separate core/CLI, host, store, foundation,
Atlas, release and reviewer implementations. These are rough planning amounts,
not measured finished code or an implementation authorization. Removing generic
process operations reduces the core/CLI surface, not the native arena, stop,
identity or transfer mechanisms needed by agent consumers; this part therefore
keeps the per-unit native estimates rather than claiming the overview's earlier
unallocated reduction.
