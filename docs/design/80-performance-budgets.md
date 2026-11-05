# 80 — Performance budgets

Design reconciliation, 2026-10-30. This is the canonical budget table for the
Rust product. Section 90 names the independent Rust runner and its actual
probe coverage; missing probes are unqualified, never passing measurements.
The Node engine remains the factory's private implementation and has no
runner-parity or fleet-cutover obligation in this product plan.

Windows/Linux are intermediate milestones. Release requires the five journeys
with real Claude and Codex on Windows, Linux and the borrowed-Mac campaign,
including standalone and embedded SE Code. Mac implementation does not delay
the earlier build, but native Mac qualification precedes alpha shipment.

The embedding target is the Rust `secode-server` in the SE Code repository,
`crates/secode-product`, branch dev at `58e8a145f`; the CLI/install owner is
`crates/secode-cli`, and the TUI is `crates/secode-tui-r`. S3 linked a private
copy of that server; its existing measurements are not an unrelated TypeScript
host or a complete first-bound/after-task qualification.

All budgets cover everything StateEngine adds, helpers included, and exclude the agent CLIs. Bytes are
decimal, as in the runner (`30 MB` = 30,000,000 bytes).

## 1. Hard budgets

| # | Budget | Threshold | Boundary | Runner probe |
| --- | --- | --- | --- | --- |
| B1 | Memory added inside SE Code | ≤ 30,000,000 bytes | A/B against a baseline SE Code server | `embedded A/B` |
| B2 | Delay StateEngine adds to SE Code | In-window first bind: one combined check, p95 ≤ 100 ms including the first bound session; late path: two checks, each p95 ≤ 100 ms | Late check 1: added startup at server start; late check 2: from late first-session open (bind request) through the first visible assistant response to the user's first message, including activation and any fallback-owner-COMMIT race, against the paired unbound run; each has its own n and over-count, never derived from a summed percentile | `embedded A/B`, actual first-request consumer |
| B3 | Persistent processes added | 0 while embedded with no live agent; exactly 1 standalone or detached handback daemon; 0 persistent helpers per agent | Outside inventory by exact pid + birth; include the daemon after SE Code exits | `standalone persistent processes`, `persistent processes after 1/2 seat(s)` |
| B4 | Standalone memory | ≤ 64,000,000 bytes with one live session, after one real agent task | Sum over every attributed StateEngine process | `standalone RSS one session` |
| B5 | Idle CPU | < 0.1% of one core (< 60 ms CPU per 60 s) | All StateEngine processes, 60 s with no product queries | `idle no session`, `idle one session` |
| B6 | Idle wakeups | ≤ 1/s with no session; ≤ 2/s with one | Same | Same |
| B7 | CLI reads | p95 strictly < 20 ms, 30 runs each of `--version`, `status`, `agent list`, `msg inbox`, `msg list`, `decision list` | Spawn to process exit | `CLI --version`, `CLI contextual read verbs` |
| B8 | Re-adoption after handover or restart | ≤ 500 ms, no lost or doubled input | Cutover start (after participating agents are interrupted to exact idle) to every live session re-adopted; quiescence time reported separately | **Not yet probed** (§2.6) |
| B9 | Ordinary CLI writes: `msg send`, `working-state set`, `hook claude stop` | Serial p95 ≤20 ms; eight-agent target initially ≤20 ms, with the operator’s ≤50 ms fallback if the quiet hosted rerun misses | Each command separately, spawn to exit through a running host; one in-flight write per agent, including FULL queue delay | Wave-1 hosted E3; component observations are not acceptance (§3.6) |
| FULL | `se decision ratify`, `se decision reject`, `se decision retract`, `se decision supersede`, `se agent add`, `se config set agent.<A>.profile`, `se config set agent.<A>.model`, `se config set agent.<A>.can-create`, `se init` | p95 ≤ 75 ms on Windows with Defender | Spawn to exit; fresh-state init includes hostless schema/publication/setup, other commands use the running host; each sampled separately | E3; not yet qualified |

B1 and B2 are SE Code's requirements. The rest are plan decisions. Budget failures make the Rust run exit
nonzero even when every behavior row passes. Measurements include embedded
first binding and a sample after one real task, context, mail and tool use.

Long operations have their own targets, measured on StateEngine's share only:
- **Launch:** request to child spawned, identity pinned and recorded ≤ 50 ms
  for paths other than contained LinuxUserManager (Linux prototype: 15 ms,
  24 of 24 under 20 ms). Provider startup is excluded and reported separately.
  **Contained LinuxUserManager has a separate scope-acquisition target:
  p95 ≤ 200 ms**, inside the agent's multi-second launch. Every such new
  process, warm included, requests its own delegated scope through direct
  user-manager D-Bus StartTransientUnit and a short-lived native creator;
  no systemd-run process, reused scope or resident creation authority is
  assumed. Measure from beginning native creator/manager preparation through
  actual scope placement and validated prepared-leaf custody, not just the
  method reply. Report C1/C2/C3, native child creation/custody, provider
  startup and total launch separately; the 200 ms is a scope-stage target,
  not a complete contained-launch claim or an extra serial-store allowance.
  Window preparation checks the selected terminal/broker origin first; an
  unusable origin selects uncontained with no-delegation before child creation.
  Acquisition/probe work already performed is still charged to that actual
  launch and reported; default fallback never hides its cost. Other paths
  retain ≤ 50 ms, and manager-unavailable default launch stays explicitly
  uncontained with its actual cause. A short capability probe may cache
  measured manager absence, never cache new-child authority. Its cost is
  reported separately, never silently omitted to claim the other-path target.
  Uncontained stop retains the stated setsid/double-fork escape bound.
  The throwaway native acquisition probes passed 60/60 per environment:
  desktop load 25.18→26.03, direct p95 148.459 ms versus systemd-run 193.889 ms;
  real SSH load 23.70→24.54, direct p95 145.384 ms versus systemd-run 203.221 ms.
  Each path has 30 samples and outside exact-scope/helper-exit readback.
  Direct SSH RPC p95 91.323 ms and post-reply placement p95 59.225 ms explain
  distinct stages; quantiles are not additive. No store/provider/full-launch
  integration was measured. Re-measure acquisition on a quiet box before
  qualification; the selected-transport quiet run below completes that step.
  The loaded runs overlapped a full preflight and system-wide syscall tracing;
  they remain raw diagnostics, not reliable latency conclusions or proof of
  the 200 ms target. The old first-launch-only 20–60 ms estimate is withdrawn.
- **Stop:** identity recheck, stop and outside confirmation ≤ 50 ms of CLI time (prototype: ~4 ms each),
  plus the graceful deadline (5 s) and at most 500 ms of forced stop.
- **Native custody setup:** identity-read p95 < 1 ms and synchronous runtime-open
  setup ≤ 2 ms. These retained design targets exclude the separately reported
  async readiness/re-adoption wait; native qualification is still required.
- **Atlas** (standalone only, enabled by default and off the milestone path): cold index peak ≤ 64 MB in its own process (§3.2); save-to-searchable
  ≤ 200 ms (prototype 67 ms); query p95 ≤ 50 ms (prototype 7–16 ms); zero idle wakeups once settled.

Linux cgroups are wave-4 work; wave 1 uses the uncontained process-group path.
The corrected quiet selected-libdbus helper passed 30/30 on the local box at
load1 5.79–5.81: scope readiness p95 156.922 ms, maximum 158.153 ms; all helpers
exited and pinned scopes were empty/removed. Its earlier watch-initialization
failure is retained. These are scope-only results, not SSH-origin selected-
transport timing, host/CLI launch or store-barrier qualification.

Wave 4 tries pure-Rust/MIT zbus first. Compare release/LTO/strip artifact delta,
resident memory and fresh-scope readiness against the same libdbus consumer;
include bus setup, subscription, exact job completion, placement and FD custody.
Any helper executor/thread is counted. Use the libdbus fallback if zbus misses
the agreed scope budget; no transport is installed or selected by declaration
success. No resident helper, reused scope or untrusted bus address is allowed.

The retained build-only libdbus probe added 303,824 bytes over std-only
(611,472 versus 307,648), with roughly 384 KiB planned, not a hard size gate or
RSS claim. The fallback is `dbus` 0.9.10/default-features=false/vendored through
`libdbus-sys` 0.2.7 with AFL-2.1 notices/election. Final combined marginal size and
RSS, and all zbus costs, remain unmeasured. Only Linux target dependencies are
admitted in wave 4; this amendment adds none.

## 2. How the runner measures

### 2.1 CLI latency (B7, B9 and FULL)
`performance.now()` before `spawn` to the child's `exit` event. No census, logging or helper inside the
interval; output is validated after timing, so a fast refusal is not a sample. All 30 samples count,
including the cold first call. Nearest-rank p95 of 30 is the 29th sorted sample.
For B7's strict threshold, **at most one run in 30 may reach 20 ms.** On Windows the first run of a new binary under Defender is the likely outlier, so a
second slow run is a real failure.

For B9 sample each named ordinary-write command through an already running
host at serial and eight independent agents, one in-flight CLI write each.
Report each command/client cohort unpooled; delay behind FULL traffic counts.
The separate twenty-agent burst requires worst case ≤ 100 ms and no lost writes.
If the quiet hosted rerun misses the initial eight-agent ≤ 20 ms target, the operator
permits eight-agent p95 ≤ 50 ms while serial stays ≤ 20 ms; build continues without
a write-path redesign. A component rerun never substitutes for that host/CLI
check or silently applies its fallback. Sample every FULL-command family separately under the
FULL row on Windows with Defender; retain actual durability and batch promotion,
not just the command label. Sample each listed decision action and agent
setting separately; general settings writes are not FULL store mutations.
Use valid changing fixtures so the sample performs the requested mutation,
including a new project for init, rather than timing an already-matching readback.
Measure fresh-state init separately as well: protected DB/schema publication,
required FULL commits and owner/project/agent setup are inside its complete CLI
clock, even with no host. Moving that work out of B2 cannot hide or waive it.
Include request framing, queue wait, required COMMIT/sync, receipt
delivery and process exit; a timeout, lost acknowledgment or refused operation
cannot become a fast successful sample. Report queue, SQL, sync/checkpoint,
receipt and client startup/round-trip components alongside the complete sample.
Use the same 30-run/all-samples and p95 convention; never pool ordinary and
FULL-command samples to conceal a failing command. E3 also retains the mixed
workload to expose ordinary requests promoted into FULL batches and their delay.

### 2.2 Memory (B1, B4)
| OS | Source | Note |
| --- | --- | --- |
| Linux | `/proc/<pid>/smaps_rollup` `Rss` | Includes shared, file-backed pages (our binary's code, libc), hence the code-pages line in §3 |
| Windows | `WorkingSet64` | The OS can trim a working set; runs should also record private bytes, as a diagnostic only |
| macOS | `proc_pid_rusage` `ri_phys_footprint` | Footprint, not RSS: excludes clean file-backed pages. Comparable within a platform only |

Wave 2 measures **combined resident memory after a real provider task** in the
thin linked SE Code slice, as well as startup/first bind. Record the complete
SE Code+StateEngine resident total and the matched SE Code-only total, then
apply B1 to their added-memory difference. Include every attributed helper and
committed stack; exclude provider CLI memory consistently on both sides.

The task must do independently read-back work and exercise capture/mail or
continuity before sampling the still-open session. Retain the task peak and
the post-task settled sample with caches/queues intact; no artificial reopen,
cache flush or forced allocator trim. Report native process/birth inventory,
per-process resident values and baseline alongside the result. Wave 2 cannot
claim memory qualification from a startup-only sample; B4 also keeps its
one-session after-task boundary.

### 2.3 Idle on Linux (B5, B6): reaped-child accounting
Endpoint sampling of `/proc/<pid>/task/*/status` misses threads and helpers that exit inside the
window. So the runner runs two fresh, identical public setups as foreground hosts (`se up --foreground`)
under a small C supervisor, one idle 10 s and one 70 s:
- The supervisor sets `PR_SET_CHILD_SUBREAPER`, so orphaned or double-forked helpers re-parent to it
  instead of `init` and their usage is not lost.
- It reaps the whole subtree, then reads `getrusage(RUSAGE_CHILDREN)`. That total includes every exited
  thread and every waited-for descendant, which per-thread endpoint counters cannot see.
- Wakeups = `((nvcsw + nivcsw)₇₀ − (nvcsw + nivcsw)₁₀) / 60`. CPU = `|CPU₇₀ − CPU₁₀| / 60`. Startup and
  shutdown cancel out because both runs pay them.
- Voluntary switches approximate "blocked, then woken"; non-voluntary ones are preemptions. Summing
  both is conservative. The estimate is signed and its magnitude is judged, so a negative value neither
  clamps to zero nor passes automatically.
- A StateEngine process outside the supervised subtree makes the measurement unavailable, never zero.

**Product obligations:** `se up --foreground` must stay in the foreground (no double-fork), and
StateEngine must not hand work to processes outside its own tree.

**Noise risk:** 60 extra switches between runs fail B6 with no session; thread-pool growth that races
differently per run can cause that. The product keeps startup deterministic (fixed thread count, §4).
If false failures persist, judging the median of retained repeated pairs is the runner owner's call,
under independent review.

### 2.4 Idle on Windows
Raw `Win32_PerfRawData_PerfProc_Thread.ContextSwitchesPersec` (a cumulative count despite the name) per
thread at both endpoints, plus process CPU. A changed thread inventory fails. The blind spot, a thread
born and gone inside the window, is a named bound until an ETW path exists; the product closes it by
rule (no thread churn at idle, §4). Proposed: run the host in a test-owned job and take CPU from
`JOBOBJECT_BASIC_ACCOUNTING_INFORMATION`, which includes exited threads and processes.

### 2.5 Idle on macOS
The observer runs `proc_pid_rusage(RUSAGE_INFO_V0)` and reads `ri_pkg_idle_wkups + ri_interrupt_wkups`.
These are task-level counts that include exited threads.

The native runner records each field's units and applies any required native
time conversion before reporting seconds. Unit correctness is checked against
the actual observer; no unverified existing-runner defect is assumed.

### 2.6 Early proofs and coverage
- **E2 / B1/B2:** newly initialized and existing stores on Windows with Defender,
  inside the actual Rust SE Code server. Run real se init before the newly
  initialized-store sample and report its cost separately; never call lazy
  creation or setup-required a successful first bind. Include first bind, the
  atomic FULL owner/first-session commit and complete continuity response in
  the one in-window combined check. Separately measure both late checks, each
  p95 ≤100 ms: added startup, and late first-session bind request through the
  first visible assistant response to the user's first message against the
  paired unbound run. The latter includes activation and any race with fallback
  owner COMMIT; idle expiry fallback is recorded off both clocks deliberately.
  Each check has its own n/over-count, never inferred from a summed percentile.
  Retain supported startup migration/backup when applicable and after-task memory.
  Existing eight-pair readiness-only A/B measurements do not prove this boundary.
- **E1 / B8:** both handover directions, source and destination loss around every
  durable phase, job-port reassociation/abort and 100 traffic loops. Interrupt
  participating agents to exact idle and report quiescence separately; include
  every subsequent serial FULL/lease/capture/queue barrier in the timed cutover.
  Outside PID/birth, post-transfer work and exact-once input/debt settlement
  are required. A cold restart replacing a Windows agent is a separate case,
  not unchanged-instance live handover.
- **E3 / B9:** measure the complete native CLI/IPC host writer on ext4 and NTFS,
  retaining ordinary/FULL mix and separate command-class samples, queue, batch,
  SQL, COMMIT, sync/checkpoint and
  receipt timings. Apply the B9 and FULL rows to their named command classes;
  neither a fast refusal nor an
  in-process producer substitutes for the CLI sample. The launch slice also
  measures section 30's three barriers and four-commit helper exception.
- **E4–E9:** attended mail, Codex modes, non-fleet user-history import, Linux
  containment from SSH/Docker/WSL2, cold Windows hook startup and the actual
  SE Code composition precede the broad build. E8 settled cold-hook routing:
  private host bootstrap, then the host writer (40 §9.3); its warm-cache Windows
  fixture establishes no production cold-hook latency guarantee.

Native writer transfer passed Linux 3/3 and Windows 11 3/3, each with 2,097,152
ordered bytes and no loss/duplication at the named cuts. Real Codex 0.166 and
Claude 2.1.314 each also pass two-way mid-turn process/conversation transfer
on Linux and Windows, then recall the first prompt's marker in a second answer.
Those throwaway observers retain protocol framing/phase decisions. They do not
qualify product store/lease/queue/capture integration, job-message reassociation,
all crash phases, cancellation, RSS or B8. Raw results: `native-handover-spike-20261030/{linux-r2,windows-pc-run-a}` and `provider-handover-spike-20261030/{linux-r1,windows-pc-run-a}` under the private evidence root.

## 3. Allocation per component

Baselines are prototype measurements from the plan. Allocations are this design's spend plan. A
component that outgrows its line has to fix that or negotiate within the total (§5).

### 3.1 Embedded memory (B1: 30 MB)
| Component | Allocation | Baseline / basis |
| --- | ---: | --- |
| Code pages touched (se-host, se-core, se-store, se-proc in secode-server) | 4.0 MB | Minimal core added 114 KB of binary; full product estimated at 3–5 MB of text |
| SQLite page-cache targets: writer + active/idle foreground readers × 512 KiB | About 2.6 MB at the two-job default; 8.9 MB at eight jobs | `cache_size=-512` on writer and reader connections; cache target, not a hard allocation cap |
| SQLite connections, schema, statement caches | 1.5 MB | Up to 5 foreground connections at the two-job default, 32 statements each; overhead beyond the original 3-connection allocation remains unmeasured |
| Session tasks, 16 live × ~50 KB | 0.8 MB | 00 §2.2 |
| Mail watches and bounded subscriptions | 1.0 MB | Bounded channels |
| Listener and MCP buffers (1 MiB body cap, ≤ 2 large bodies at once) | 2.5 MB | §4 |
| Capture: 256 KiB read buffer × 2 active + parsing | 1.0 MB | Bounded transcript reads |
| Transcript watcher | 0.5 MB | Live sessions' directories only |
| Process custody state | 0.2 MB | Handles, job/cgroup records and one Windows IOCP collector's state per host; stack charged once below, no registered-wait pool |
| Resume assembly: up to four packets; one may exceed 32 KiB, max 1 MiB | 1.5 MB | One shared above-default permit, bounded metadata and no duplicate encoded packet |
| Fixed native/writer thread stack pages and allocator slack | 2.0 MB | Count every added committed stack page in E2; SE Code's existing reactor is not a second runtime |
| **Estimated spend at two jobs** | **17.6 MB** | Eight jobs with idle cache targets increase this estimate to 23.9 MB; additional connection overhead is unmeasured |
| Estimated reserve at two jobs | 12.4 MB | About 6.1 MB at eight jobs with idle cache targets, before additional overhead; Atlas is off in embedded |
| **Hard total budget** | **30.0 MB** | Unchanged |

### 3.2 Standalone memory (B4: 64 MB)
| Component | Allocation | Baseline / basis |
| --- | ---: | --- |
| `se` code pages and system libraries, excluding Atlas grammars | 30.0 MB | Provisional allocation: the native public-consumer host showed 29.2 MB file-backed immediately after up, with preceding SSD noise 0.47 MB/s at 0.44% busy and NVMe 40.66 MB/s at 24.00%; attribution and quiet joined qualification remain outstanding |
| tokio `current_thread`, blocking pool (two threads by default; explicit caps 2–8), writer and native collector stack pages | 1.0 MB | One fixed set, all committed stack pages included |
| SQLite page-cache targets: writer + active/idle host readers × 512 KiB | About 2.6 MB at the two-job default; 8.9 MB at eight jobs | `cache_size=-512`; hosted planning and continuations use readers even though independent CLI reads also access the file directly |
| SQLite connections, schema, statements | 1.0 MB | Up to 5 foreground connections at the two-job default; additional connection overhead unmeasured |
| Sessions, mail, listener/MCP, capture + watcher, custody, resume | 7.5 MB | Includes the same single-large-packet resume allowance as 3.1 |
| Optional Atlas anonymous: queries and single-file updates when enabled | 13.0 MB | One closed-when-idle connection plus one parser; measured Linux ordinary-file profiles in 60 §9 |
| Shared Atlas grammar/parser file pages | 5.5 MB | One 5,473,485-byte reservation across all roots/grammars; separately reported from anonymous memory |
| Allocator slack | 1.0 MB | |
| **Estimated spend at two jobs** | **61.6 MB** | Eight jobs with idle cache targets increase this estimate to 67.9 MB before additional connection overhead |
| Estimated reserve at two jobs | 2.4 MB | Eight jobs exceed the estimate by 3.9 MB before additional connection overhead; configuration does not relax B4 |
| **Hard total budget** | **64.0 MB** | Larger standalone host budget adopted 2026-11-05; quiet joined qualification remains outstanding |

The shipped finite-work default is two jobs for standalone and embedded hosts;
more cores do not raise it. An explicit `runtime.blocking_jobs` in 2–8 is capped
by native availability; one/unknown-core hosts keep the existing foreground and
maintenance split. Reader slots and idle admission connections follow the same
effective capacity, with a minimum reader capacity of two.

The store configures `cache_size=-512` for writer and reader connections.
Two shared active readers can coexist with two idle admission connections:
including the writer, their five cache targets total 2.5 MiB (about 2.6 MB).
At eight jobs, sixteen foreground readers plus the writer target 8.5 MiB
(about 8.9 MB). These are source-derived foreground connection bounds, not
observed pooled-host RSS or a cap on separate maintenance allocations.
The tables use decimal MB rounded to one decimal place. Cache targets are
not hard allocation caps; schema, statements, stacks and allocator retention
still require measurement. E2 must establish actual pooled-host and post-task
memory within unchanged B1/B4 limits; larger configured caps remain subject
to those same budgets.

Atlas is compiled only into the standalone `se`; it is enabled by default and can be disabled with `atlas.enabled = false` in config.toml; a host without an installed Atlas controller reports it unavailable.
It is built after the journeys and live handover pass and never holds a
milestone. After readiness, an enabled standalone host admits its cold index as
a transient background child; it is not triggered by an ordinary first query.
The child has a separate cold-window cap and exits after indexing; resident
queries/incremental updates stay in the allocation above. The runner reports
that window separately and measures B4 outside it. The prototype's large-file
peak makes the per-file admission/deadline mandatory, not already qualified.

The cold child's resident ceiling remains 64,000,000 bytes. On Linux its
virtual-address limit is separately 96,000,000 bytes: the Rust54 release maps
about 50.9 MB of ELF segments, and ordinary JavaScript needed about 64.03 MB
including the unchanged 8 MB cancellation/SQL margin. The larger address
envelope leaves about 32 MB above that admission requirement for image growth;
it does not raise the resident ceiling. Windows committed-memory and macOS
footprint limits remain unchanged. Per-file failures remain visible in the
published partial status even if later maintenance cannot acquire its writer
lease; successful reparsing clears the diagnostic.

### Shared input limits and packet sizing

CLI, MCP and linked calls consume one closed input DTO per operation. Lists
accept 1–100 rows, default 20; search accepts 1–50; message previews are 400
characters; resume defaults to 4 KiB and accepts at most 1 MiB. A row limit
does not override the page/body or final encoded reply cap. A full message is
never cut to fit a page; retain whole rows and explicit omissions/cursor.
Preview text is a labelled view, not a truncated stored body. The DTO byte
limits remain message 32 KiB and working state 16 KiB before effects.

A maximum preview page can carry 100 × 400 Unicode characters: at most
160,000 UTF-8 bytes of preview text, before metadata/JSON escaping. Full-body
pages retain the separate 256 KiB body budget and final transport cap; append
only whole rows that fit the encoded result. Build one bounded result buffer,
move it into the transport and do not keep a second encoded copy or all source
bodies. Resume's requested byte budget covers its final encoded wrapper,
markers and cursor. There is one host-wide permit for a requested budget above
32 KiB, shared by CLI/MCP/linked calls. Acquire it before allocation/assembly
and retain it until the final packet buffer is sent or released, including
cancellation/error paths. Waiting requests retain only bounded request metadata;
they do not allocate a second large packet. Default-budget packets can continue
under the existing four-packet concurrency bound.

At most one 1 MiB packet plus three 32 KiB packets require 1,146,880 encoded
bytes. The 1.5 MB allowance covers that output plus bounded assembly metadata;
default packets do not eagerly reserve maximum capacity. This restores 3 MB
to each composition's reserve compared with four simultaneous maximum packets,
leaving hard memory ceilings unchanged. E2 exercises a maximum-budget request,
concurrent default packets and a second above-default request that must wait
without retaining a second large allocation, plus after-task retained capacity;
no packet/stack allowance is a measured RSS result.

### 3.3 Embedded startup (B2)

An embedded session uses an in-process bound handle and emits no credential
issuance/activation events. Explicit `se init` creates and FULL-publishes the
schema/header and completes project/principal setup first, with its cost measured
as init above. Absent state refuses with setup-required and the same-home init
remedy; embedded open never creates it inside or outside a hidden startup clock.
Newly initialized and existing compatible stores use the same normal B2 first-bind path:
one FULL maintenance transaction for runtime.owner and the witnessed first
session, then writer startup and the complete continuity/binding response. At
first workspace open, the pre-TUI repository trust hook invokes bundled managed
se init --repo DIR on the UI owner path only after workspace trust acceptance
and before this interval; declined workspaces are never registered. Profile onboarding
is separate and the public GitHub stub silently skips init. This managed setup
writes nothing in the repository and needs no repository-write consent;
init --adopt still installs the integrations in 70 §3.2. A new-store sample means
newly initialized state.
Neither ordinary work nor a bound handle is published before that commit.

A late first bind is an ordinary path: sign-in can exceed FIRST_BIND_WINDOW.
B2 retains one combined check for an in-window first bind. For the late path,
judge two checks separately, each p95 ≤100 ms against the paired run without
StateEngine bound: check 1 measures added startup at server start; check 2
starts at late first-session open (the bind request), then includes binding and
the user's first message through the first visible assistant tool/text response.
Session activation and any race with the fallback owner COMMIT are inside check 2.
The fallback owner commit at window expiry is deliberately off both clocks
because the user is idle then; record its actual barriers and duration separately.
Use SE Code's deterministic local-script provider for this pre-build consumer
probe. Neither bind RPC alone nor a clock starting only at the message request
closes check 2; preserve HTTP prompt acknowledgement, first assistant response
and first assistant text as distinct facts. Take the bind-to-response span
from its own start/end timestamps before computing each bound/unbound paired
difference, with its own n and over-count; never subtract summed percentiles.
User sign-in idle time and full elapsed-to-first-response time are also retained,
while a sum of the separate costs is diagnostic, not a third B2 check.

In the stable late-path sample, the host has its standalone-style runtime.owner
FULL-committed and writer running before late binding. Independently witness
that owner and zero sessions before binding and the distinct FULL activation
after it. A binding that races expiry must wait for the known owner-commit
outcome inside check 2, retaining every engine barrier where it occurs.
Both late checks on Linux use the coordinated quiet-box criterion: load1 ≤10
at each case start, the measurement as the only heavy job, no system-wide
tracing, and actual load recorded. Use that same criterion for in-window comparisons.
Retain loaded and quiet cohorts separately; never swap one for the other or
discard loaded failures. A successful refusal or prompt-path joint-commit sample
cannot stand in for the late bind-to-first-response check.

| Critical-path work | Current spend status |
| --- | --- |
| Native setup, existing store/header checks and supported upgrade path | Pending quiet-window E2; upgrade includes verified pre-migration backup and refuses an active old host with the se down remedy |
| Runtime.owner plus first embedded session preparation/activation | One joint FULL maintenance commit; up to two SQLite file fsyncs for its journal protocol, with actual file/directory/checkpoint counts reported; no credential barriers |
| Fresh schema/header and project/principal setup | Owned by explicit owner/UI se init --repo DIR before the timed embedded interval; report its complete FULL initialization cost separately, including publication readback |
| Bounded effects/profile load, static catalogue, writer start and first continuity | Pending the same exact-build E2 first-bound response; count every serial step |
| **Measured B2 spend / reserve** | **Pending quiet-window qualification; no measured headroom or qualification claimed** |

The syscall count is not a latency estimate: one FULL transaction can require
multiple file/directory sync calls, and checkpoint/migration work must retain
its actual count and time inside the applicable interval. The closed FULL set,
checkpoint policy and B2 ceiling are unchanged; no directory flush is suppressed.
Historical readiness-only, separate-barrier and loaded-box timings do not
qualify this candidate. The loaded Linux runs overlapped a full preflight and a
system-wide syscall trace; their raw samples remain archived but are excluded
from qualification and from causal latency conclusions.

Qualification requires the actual Rust SE Code in-window combined first-bound
response and both late checks against the unchanged baseline, with newly
initialized and existing stores and the same durability/inputs/build. Record
load beside every result. Both late checks and the in-window comparison use the
coordinated Linux quiet window: the exclusive heavy slot with the measurement
as the only heavy job, no system-wide tracing, and load1 ≤10 at each case start.
This criterion records the parked-runner/desktop idle floor of load1 6–8 on the 48-core box; it does not
qualify the earlier contended measurements. Retain every paired sample, including
signed negative differences and failures; file/directory/count traces are
separate from latency samples. No loaded result or transaction-count arithmetic
establishes latency headroom. Windows with Defender, after-task memory and full
native integration remain independently required; both reviews and accepted
quiet-window numbers gate this candidate's merge.

Section 40's FIRST_BIND_WINDOW = 10 s starts when activate returns Prepared,
uses an absolute Instant deadline and is rechecked on resume. Window expiry
with no bind or a definite first-bind refusal within it falls back to owner-only
FULL admission before writer start; status becomes ready and a later first bind
uses the ordinary session FULL transaction, like a second bind, without an
expiry failure to SE Code. Record the actual
fallback wait/extra barriers rather than pooling it with the normal atomic
first-bind case. Explicit drain must fence/join a racing commit and retain both
keys/known outcomes; it cannot force a duplicate owner or a synthetic successful
binding. Reviewer witnesses include failed managed workspace setup, no side effect
on missing-state open, bare se/status not-set-up exit 0, whole-pair rollback and
same-key replay, concurrent first binds, deadline fallback, and close before a
bind/after refusal/racing COMMIT. Live-handover/recovery barriers stay unchanged.

Startup migration is automatic only in the sole owning host after a verified
pre-migration backup; too-new/unsupported formats refuse, and an active older
host requires se down first. Migration cost is visible, never relabelled as
provider startup. Routine start-of-day and clean-shutdown backups use the one
section-20 rule; the pre-migration copy is an additional required safety step.

### 3.4 Re-adoption (B8)

Quiescence is measured separately; the cutover interval starts after exact
idle. Source drain/flush and FULL Prepared, exclusive lease transfer and FULL
Claimed, native activation/source closure/capture/queue proof and FULL Finished
are serial costs wherever they fall inside that interval. Destination consumers
remain disabled until Finished; activated handles alone are not a finished
handover. Aborted restores proved pre-claim custody, while Recovered is the
fresh-owner outcome of a claimed transfer: these distinct crash facts remain.
There are five durable outcomes, with three on a successful path, not a
seven-FULL-commit plan or a relabelled four-value crash rule.

The prior 165 ms spend/335 ms reserve was not measured with those FULL barriers
and is withdrawn. E1/E2/E3 supply native, storage and queue timings before
reserve is allocated. Exact input/debt IDs and outside ownership readback,
not a duration, establish no loss or duplication.

### 3.5 CLI read (B7)
| Step | Linux | Windows |
| --- | ---: | ---: |
| Process create, loader, static init | 1.5 ms | 5.0 ms (bare start measured at 3 ms) |
| Config and project resolution (exact lookup on a canonical-path index) | 0.5 ms | 1.0 ms |
| Read-only store open and checks | 1.0 ms | 2.0 ms |
| Query (inbox at 1M events: 3.5 ms) | 4.0 ms | 4.0 ms |
| Render and exit | 0.5 ms | 1.0 ms |
| **Spend** | **7.5 ms** | **13.0 ms** |
| Reserve | 12.5 ms | 7.0 ms |

Windows has the thinner margin, which is one more reason to sign the binary (lighter Defender scanning).

Installed Linux diagnostic, 2026-11-04: a temporary instrumented distribution
build (`b94c55c`, following the runtime follow-ups) measured one contextual
`se status --json` at 21.54 ms with load1 14.18. Elapsed phases were startup and
dynamic loading 3.58 ms, read-only store open/schema-header checks 3.47 ms, native
home pinning 3.46 ms, owner admission/selection 2.64 ms, endpoint/process
observation 2.56 ms, clap 1.23 ms, status queries 0.86 ms, lease check 0.45 ms,
config/bootstrap 0.30 ms, session preparation/native observation 0.23 ms,
render 0.16 ms, other Rust work 1.42 ms and exit/parent drain 1.17 ms.
These elapsed clocks include instrumentation and scheduling; one loaded sample
is neither a p95 nor production acceptance, and the allocation table above is
still a design estimate. The cost is distributed across protective phases with
no identified safe structural removal. The coordinator accepted this status investigation
as complete under the operator's rule that an approximately 1 ms overrun does not block
landing; the B7 target remains unchanged. Raw clocks and installed-image binding
are retained in the status-profile evidence directory (private evidence root); its deliberately
aborted pre-provider journey and profiling-stderr cleanup parse failure remain
failures, with private-home/process/account-claim closure verified separately.

### 3.6 Per-operation timing and the open E3 result

B9 and FULL-command thresholds are defined only in §1. Server-side MCP reads
retain p95 ≤ 5 ms and ordinary writes ≤ 15 ms with eight agents; a 20-agent
burst retains worst-case ≤ 100 ms with no lost writes. Hosted Claude stop-hook
processing uses B9's complete boundary, including bounded transcript work.
FULL command samples use their own row; server-only timings never establish
CLI acceptance. The writer drains queued work without a gather timer; a mixed
batch takes FULL when any closed-FULL member is present.

The initial Python mixed-workload spike remains contrary evidence: 4,944
writes/run, producer p95 37.47 ms serial and 66.92 ms with 20 clients. Serial
COMMIT-plus-restore p95 was 35.942 ms; actual FULL execution grew from 1.133%
of requests to 8.879% under mixed grouping. Its clock excluded acknowledgment
delivery and CLI/socket costs. All samples and the independent decomposition
remain retained; these numbers did not establish a language or device cause.

The native prepared-SQL follow-up retains 29 runs/143,376 requests on Linux
ext4/NVMe and Windows NTFS with Defender/realtime protection enabled. All
168 manifest hashes, raw group/request quantiles and 29 separate count/
integrity/FK witnesses were independently checked. The original, reduced and
one-INSERT control preserve identical 1,464,144 payload bytes, kind order and
56 policy-FULL ratifications/run. Builtin 256-page baseline ACK p95 in ms:

| Frozen SQL shape | Linux serial / 20 outstanding | Windows serial / 20 outstanding |
| --- | --- | --- |
| Original schema | 17.38 / 47.86 (repeat 56.62) | 4.35 / 88.86 (repeat 27.42) |
| Chain/non-mail-temporal subtraction | 35.86 / 69.89 | 3.93 / 10.52 (repeat 11.97) |
| Same-payload one-INSERT control | 0.21 / 9.17 | 0.06 / 0.85 |

These are storage-worker observations, not acceptance budgets. In reduced
20-window baselines, queue p95 is 50.139 ms Linux and 6.941 ms Windows;
actual FULL execution is 5.704%/5.643% of requests after promotion. Restoration
and in-process ACK delivery are small here. The Windows original run includes
a 2,056-ms COMMIT; its repeat is retained. Sequential runs, different SQLite
versions and scheduling do not establish a schema-only speedup or the exact
historical slowdown factor.

Checkpoint diagnostics replace the builtin hook with a timed passive callback
at the same threshold; they are separate runs, not an unmodified observer.
[SQLite documents that hook replacement](https://sqlite.org/c3ref/wal_autocheckpoint.html).
In final untraced reduced Linux serial/20 runs, checkpoints consume 59.5%/62.2%
of summed COMMIT wall time; every 25/25 and 37/37 COMMITs over 20 ms includes
one. Serial callback WAL-frame counts sum to 121,530 versus control 5,122
(23.7×); these are reported frames at callbacks, not measured copied frames
or physical bytes. Linux traced WAL fsync p95 is 30.575/29.559 ms, main-DB
17.877/17.851 ms, with tracing overhead retained. Windows physical sync-call
timing is unavailable; callback time cannot stand in for FlushFileBuffers.
Raising the diagnostic threshold to 1,024 pages leaves Linux 20-window ACK
p95 57.45/82.33 ms (original/reduced), supporting no policy change.

The richer WAL/checkpoint work, measured Linux sync cost and ensuing queueing
are demonstrated tail contributors in these runs. Restoration or client RTT
does not explain them; real CLI/IPC RTT was not exercised. Prepared SQL omits
codec/auth/ID/hash construction, preloads the fixture, uses a 128-statement
cache instead of the planned 32 and retains historical capture labels. It
qualifies neither the later session.turn/config-subtracted DDL nor a native
running host, the three B9 commands or the named FULL commands. Windows worker
p95 below a target does not establish product PASS. No B1/B2/B8 or first-bind/
handover spend is inferred from these mixed-workload quantiles.

The section-20 baseline is **4 KiB pages with commit-driven autocheckpoint at
256 pages (1 MiB)**, selected by the maintainer on 2026-10-31 after W2. The
checkpoint policy remains synchronous with the committing path; no worker hides
its latency, and NORMAL/FULL durability is unchanged.
Wave 1 now includes installed CLI→authenticated IPC→host→production writer,
representative schema and mixed NORMAL/FULL traffic. J1 plus this hosted E3
result is the wave exit. Split queue, transaction, sync/checkpoint and receipt;
no codec/auth/startup/IPC cost may remain outside the complete command clock.
Apply the serial/eight/twenty targets in §1 and retain the actual failure.

The R4 prerequisite rerun compares 4 KiB/16 KiB pages with/without list_versions
using the existing native workload, one case at a time in heavy.py's exclusive
slot with load1 ≤ 10 at every start and no concurrent heavy job or system tracing.
Record load, exact schema/plan/binary, durability and all samples. A fixed 256-page
autocheckpoint changes byte cadence from 1 MiB to 4 MiB with page size; report it,
not a pure page-granularity attribution. Removing list_versions is a labelled
experiment that loses historical windows, not an approved product schema.
Report one msg-send's logical row/index touches, payload bytes, appended WAL
frames/bytes, observed SQLite syscall writes and DB/WAL size separately.
Trace only the separate single-message diagnostics, never the latency cases;
retain setup/shutdown writes and distinguish OS writes from physical device I/O.

The coordinated W2 component rerun completed **16/16 behavior witnesses** on
2026-10-31: twelve untraced mixed cases and four separate traced single-message
cases. Every case started at load1 ≤10 (7.76–9.43). Each mixed case retained
4,944 operations and 56 policy-FULL decisions, original order/payload, the same
native binary and builtin 256-page checkpoint policy. Exact table contents, counts,
integrity/FKs and FULL promotion decisions passed outside readback. Independent
recalculation confirmed each NORMAL/FULL and per-kind p95/p99/max; no cohorts
are pooled. ACK milliseconds below are **p95 / p99 / max**; promotion counts
are NORMAL requests executed in a mixed FULL group.

| Page | list_versions | Clients | NORMAL ACK ms | FULL ACK ms | Promoted |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 KiB | yes | 1 | 12.469/15.806/33.214 | 13.901/14.405/14.405 | 0 |
| 4 KiB | no | 1 | 11.500/13.197/23.431 | 11.104/13.546/13.546 | 0 |
| 16 KiB | yes | 1 | 50.140/59.294/69.213 | 44.032/51.319/51.319 | 0 |
| 16 KiB | no | 1 | 28.231/53.443/77.251 | 34.412/53.092/53.092 | 0 |
| 4 KiB | yes | 8 | 54.858/60.521/72.141 | 70.101/72.140/72.140 | 119 |
| 4 KiB | no | 8 | 33.696/38.727/51.796 | 41.960/43.032/43.032 | 117 |
| 16 KiB | yes | 8 | 65.920/70.913/75.950 | 72.287/76.471/76.471 | 151 |
| 16 KiB | no | 8 | 38.488/46.119/67.324 | 55.634/55.650/55.650 | 124 |
| 4 KiB | yes | 20 | 50.116/55.419/63.538 | 55.767/55.769/55.769 | 277 |
| 4 KiB | no | 20 | 45.104/52.751/62.451 | 52.737/54.094/54.094 | 238 |
| 16 KiB | yes | 20 | 62.941/77.242/90.778 | 66.947/79.710/79.710 | 287 |
| 16 KiB | no | 20 | 64.279/73.745/91.704 | 83.543/91.690/91.690 | 247 |

A seeded `msg send` contains 1,161 prepared input bytes and adds 262 payload
content bytes. It writes one statement each to operations, events,
operation_events, aux_data, identities, legacy_ids, payloads, message_data,
messages, marks, resume_heads and, when retained, list_versions. Exact affected
index definitions and row deltas are in the audit; these are logical SQL/index
touches, not a claim that every index rewrites one physical page. External
single-transaction WAL extent and whole-run DB/journal/WAL syscall write bytes:

| Page | list_versions | WAL frames | WAL bytes including header | DB/journal/WAL write bytes including setup/shutdown |
| --- | --- | ---: | ---: | ---: |
| 4 KiB | yes | 39 | 160,712 | 329,180 |
| 4 KiB | no | 32 | 131,872 | 271,668 |
| 16 KiB | yes | 34 | 557,904 | 1,148,260 |
| 16 KiB | no | 27 | 443,048 | 918,716 |

Each trace observes six sync calls, including setup journal and clean shutdown;
main-DB checkpoint/setup writes remain separate from WAL in the raw audit.
The totals exclude sixteen bytes of .db-shm setup writes in each raw trace.
These are the named-file syscall bytes, never total OS or device/NAND writes.
Fixed 256 pages still
confounds page size with 1 MiB/4 MiB checkpoint cadence. Removing list_versions
also loses historical mail windows; no compatibility or product-policy change
is inferred. The archived harness has 43 tables (42 without list_versions),
not the final R4 DDL. The maintainer subsequently selected the 4 KiB/256-page
baseline above; list_versions remains pending its consumer inventory and a
separate decision. These component results do not invoke the eight-agent
fallback or qualify CLI/IPC/auth/launch barriers; final-schema hosted E3 binds
acceptance.

The first attempt is retained: all sixteen cases failed before samples because
the immutable inputs were read-only and native fs::copy preserved that mode;
a separate SQLite open reproduced SQLITE_READONLY. The corrected runner stages
private writable, byte-identical baseline copies before measured work, retaining
all input hashes and the original native binary. No successful timing was rerun.

Launch qualification uses the actual causal sequence: C1 FULL, C2, C3 FULL,
and RootCheckpoint before exec on the four-commit Unix paths. Wave 1 Linux uses
that four-commit uncontained path. The ≤ 50 ms non-scope launch target includes
both FULL commits, the other required barriers and native creation/identity;
provider startup alone is excluded. Measure the whole sequence and every
barrier in hosted E3; neither summed marginal percentiles nor batching across
native effects establishes it. A miss remains a launch-budget miss for the
maintainer’s decision, not permission to omit a commit or borrow the wave 4
scope-stage allowance. Keep one target; do not add another local budget table.

Raw writer data remains under the import-rehearsal evidence directory (private evidence root)
and `nell-e3-write-latency-20261030/`; independent analysis is
`e3-write-decomposition-20261030/NATIVE-REPORT.txt` under the same root.
The selected-transport quiet receipt is
`e7-containment-20261030/SCOPE-DIRECT-QUIET-RESULT.txt` there. W2 artifacts are
`r4-w2-20261031/quiet-run-2/{binding.json,summary.json,INDEPENDENT-AUDIT.txt}`;
raw samples, traces, per-case witnesses and load admission are alongside them.
The unchanged native binary SHA-256 is `1c270fef4969f7ca9ede674f5050d3c044d7735bdd8e40d9db718d3e53b24b77`;
summary SHA-256 is `d57b5900cca15670b5b0d7d5e26e5fe0c33925bd87b5dab6a4fff48ada16f775`.
The failed setup attempt is retained separately in `quiet-run-1`.

### 3.7 Idle wakeups (B6)
| Source | No session | One session |
| --- | ---: | ---: |
| tokio park; `se-writer`, accept loops and the Windows IOCP collector (one per host, all jobs) all blocked | 0 | 0 |
| Transcript watcher (live sessions only, events on writes only) | — | 0 |
| Attended Claude long-poll re-armed every 25 s (Claude's HTTP fetch ends at 30 s), per attended Claude session | — | 0.04/s |
| Safety catch-up sweep every 15 min, only with ≥ 1 live session | — | 0.0011/s |
| Auto-started/handback daemon exit timer (10 min after last live agent) | one wake | — |
| Blocking-pool threads exiting after keep-alive | ≤ thread cap (2–8), once | ≤ thread cap (2–8), once |
| **Expected** | **≈ 0.002/s** | **≈ 0.003/s, plus 0.04/s per attended Claude session** |
| Ceiling | 1/s | 2/s |

The ceiling is far above the expected value. A measured rate above 0.05/s plus 0.04/s per attended Claude session passes the budget but
means a timer or poll got in, and the reviewer treats it as a defect during
settled idle. Section 30's single coalesced live-cleanup timer is active work:
at most one root/accounting read per second per orphaned scope, cancelled on
emptiness or cleanup deadline. Report its wakeups/read cost while it runs;
do not label that interval settled idle or hide it in the baseline expectation.

## 4. Design rules that protect the budgets

| Rule | Protects |
| --- | --- |
| **No idle polling.** Every replaced loop stays gone: 250 ms mail door, 1.5 s watcher, 15 s supervisor tick, 60 s projection drain, 10 min Atlas renew, 1 h capture canary. Process exits arrive as OS events, mail as `watch` bumps after commit, files as OS file events. The live-session safety catch-up and attended renewal in §3.7 remain explicit measured costs. `notify`'s poll watcher is never used: on a filesystem without events, capture relies on the harness signal and reports the watcher as unavailable. | B5, B6 |
| **No timer without a live session,** except the auto-start/handback exit timer. Log rotation happens on write, never on a clock. | B6 |
| **Fixed thread set at idle.** The writer is a named `std::thread`, not a pool thread. Standalone blocking pool defaults to two jobs, with explicit 2–8 caps bounded by native available cores, with the original single foreground plus single maintenance slot on two blocking threads when cores are one or unknown; finite threads remain shared across sessions. No per-session threads. Windows process exits for all jobs arrive on one shared IOCP collector per host; no registered-wait thread pool. | B6, Windows bound |
| **Bounded SQLite:** `cache_size=-512` per connection (512 KiB cache target, not an RSS cap), `mmap_size=0` (mapped pages would inflate RSS without a ceiling), statement cache 32, `temp_store=FILE`, `journal_size_limit` 4 MiB, `TRUNCATE` checkpoint at clean shutdown. | B1, B4 |
| **Batched writer, explicit durability:** block on receive, drain whatever is queued (up to 256), one `BEGIN IMMEDIATE … COMMIT`. No gather window, so no latency or timer is added. Autocheckpoint is commit-driven. Ordinary batches use NORMAL; credential/session/runtime/security transitions and decision ratify/reject/retract/supersede require FULL. NORMAL can lose several recent commits on power/OS loss, not an application crash. | B9, burst, B2 |
| **Bounded everything else:** channels bounded with `Lagged{resume_from}` on overflow; one closed DTO per operation for CLI/MCP; lists default 20 and max 100 rows, search max 50, message preview 400 characters, resume default 4 KiB/max 1 MiB; message body 32 KiB and working state 16 KiB; page/encoded budgets expose incompleteness and never truncate a full body. | B1, B4 |
| **Bounded transcript reads:** read from the stored byte offset in 256 KiB chunks and parse line by line. A line over 4 MiB gets an `oversized-line` verdict (G4/G5). Never load a whole transcript. | B1, B4, hooks |
| **After-readiness work:** Codex reconnect, re-adoption and the start-of-day backup run after ready. The backup uses SQLite's online backup API in 64-page steps on a background read connection, never holding the writer. It holds one read transaction for the whole copy, so it reads one stable WAL snapshot and never restarts when the writer commits. While that snapshot pins the WAL, the 16 MiB high-water rule defers checkpointing instead of raising `store-backpressure`; if the WAL reaches 64 MiB the backup aborts, releases its snapshot and retries at the next start-of-day. A backup never stalls the writer. Tool schemas are built at compile time. | B2 |
| **A lean CLI:** no async runtime, no TLS, no network, no subprocess (no `git`, no PowerShell), no process census. `status` reads `endpoint.json` and checks the host pid's identity natively instead of making an IPC round trip. | B7 |
| **Atlas budgets:** standalone-only compilation and config activation are fixed in §3.2; cold index in a transient child; files over 512 KiB skipped with a recorded `skipped: size` fact; per-file parse deadline 200 ms (tree-sitter progress callback); one parse at a time; the search index holds names and paths, not bodies; its own `atlas.db`. | B4, B6 |
| **Smaller events:** trim the prototype's ~2 KB per event toward ≤ 600 B median for non-turn events (00 open item 3); a review signal. | Disk, cache hit rate |

## 5. When a budget is missed

1. **Keep everything.** `budgets.json` retains every sample; a rerun counts only alongside the failed
   run it follows. No rerun-until-green.
2. **Reproduce at the same commit on the same OS** before blaming anything else; bisect within the
   (small) landing batch.
3. **Classify:** a *product regression* goes to the author whose §3 line overran; an *environment*
   cause (first-run Defender, another process) must show in the retained diagnostics, and the next run
   must pass; a *measurement defect* goes to the runner owner with
   independent review, and the independent Rust runner records the correction; Node parity is outside this product plan.
4. **Fix in this order:** remove the cause (a poll, an unbounded buffer, a sync on the critical path);
   then move the work off the critical path (lazy or after ready); only then move allocation between
   components inside the total, as a doc change with one sentence of reason.
5. **A missed budget blocks the landing batch,** exactly like a failed behavior row.
6. **Totals don't move without their owner** (B1, B2 SE Code; the rest the product owner). A structural miss reopens
   the fallbacks: reconsider composition with SE Code if embedding misses B1/B2; optional Atlas remains off and its cold child is separately bounded.
7. **Self-reports are not evidence.** `status` and `doctor --bundle` may show the host's own memory and
   session counts for support; budgets are judged only from outside (G8).


## 6. Composition and release boundary

While SE Code hosts StateEngine, the library adds no permanent helper or
per-agent owner. B3's embedded-zero inventory is measured with no live agent;
ordinary provider CLIs are excluded and transient StateEngine helpers are
reported. Default SE Code exit with live agents performs live handback to one
detached se up daemon; that process is now standalone and counts in B3/B4.
It exits ten minutes after its last live agent. Explicit se down still stops
agents on Windows, Linux and macOS; no handover exception changes that verb.

Only se-host owns Tokio/async runtime composition; se-proc supplies safe native
reactor ports without linking Tokio. Library dependencies use caret ranges;
SE Code's Tokio 1 / rusqlite 0.40 bundled graph must share one SQLite links
version. Listener dependencies use Hyper directly or an Axum range admitting
SE Code API's 0.8.9. Memory/startup are measured in that actual linked graph.
The embedded library never changes process umask: owner-only file and WAL/SHM
modes are set and read back on each created file.

The release sequence is the assembled section 95: early proofs and runner;
unsigned install/uninstall; Claude vertical journeys; both providers and
Windows/Linux standalone; embedded/handover/forget/signing; optional Atlas and
native Mac qualification. Size comes from section 95's generated total, not a
second allocation or a promised calendar. The alpha release is not complete at the earlier
Windows/Linux milestone.
