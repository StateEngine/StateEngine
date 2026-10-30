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

The embedding target is the Rust `secode-server` in `E:\rust-secode`,
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
| B2 | Startup added to SE Code | ≤ 100 ms, including the first bound session | Spawn to complete authenticated `/api/session` response | `embedded A/B` |
| B3 | Persistent processes added | 0 while embedded with no live agent; exactly 1 standalone or detached handback daemon; 0 persistent helpers per agent | Outside inventory by exact pid + birth; include the daemon after SE Code exits | `standalone persistent processes`, `persistent processes after 1/2 seat(s)` |
| B4 | Standalone memory | ≤ 25,000,000 bytes with one live session, after one real agent task | Sum over every attributed StateEngine process | `standalone RSS one session` |
| B5 | Idle CPU | < 0.1% of one core (< 60 ms CPU per 60 s) | All StateEngine processes, 60 s with no product queries | `idle no session`, `idle one session` |
| B6 | Idle wakeups | ≤ 1/s with no session; ≤ 2/s with one | Same | Same |
| B7 | CLI reads | p95 strictly < 20 ms, 30 runs each of `--version`, `status`, `agent list`, `msg inbox`, `msg list`, `decision list` | Spawn to process exit | `CLI --version`, `CLI contextual read verbs` |
| B8 | Re-adoption after handover or restart | ≤ 500 ms, no lost or doubled input | Cutover start (after participating agents are interrupted to exact idle) to every live session re-adopted; quiescence time reported separately | **Not yet probed** (§2.6) |
| B9 | Ordinary CLI writes: `msg send`, `working-state set`, `hook claude stop` | p95 ≤ 20 ms through a running host | Spawn to exit, including IPC/queue/commit/receipt | E3 native CLI probe required; retained mixed writer spike fails (§3.6) |
| FULL | `se decision ratify`, `se decision reject`, `se decision retract`, `se decision supersede`, `se agent add`, `se config set agent.<A>.profile`, `se config set agent.<A>.model`, `se config set agent.<A>.can-create`, `se init` | p95 ≤ 75 ms on Windows with Defender | Same complete CLI boundary, each concrete command sampled separately through the running host | E3; not yet qualified |

B1 and B2 are Alpha's requirements. The rest are plan decisions. Budget failures make the Rust run exit
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
  qualification, in Prime's designated window with starting load below 4.
  The loaded runs overlapped a full preflight and system-wide syscall tracing;
  they remain raw diagnostics, not reliable latency conclusions or proof of
  the 200 ms target. The old first-launch-only 20–60 ms estimate is withdrawn.
- **Stop:** identity recheck, stop and outside confirmation ≤ 50 ms of CLI time (prototype: ~4 ms each),
  plus the graceful deadline (5 s) and at most 500 ms of forced stop.
- **Native custody setup:** identity-read p95 < 1 ms and synchronous runtime-open
  setup ≤ 2 ms. These retained design targets exclude the separately reported
  async readiness/re-adoption wait; native qualification is still required.
- **Atlas** (standalone only, opt-in and off the milestone path): cold index peak ≤ 64 MB in its own process (§3.2); save-to-searchable
  ≤ 200 ms (prototype 67 ms); query p95 ≤ 50 ms (prototype 7–16 ms); zero idle wakeups once settled.

The private Linux manager transport uses dbus 0.9.10, default features off,
vendored only (libdbus-sys 0.2.7), with no Tokio/futures dependency. A build-only
Linux x86-64 linker probe with release/LTO/strip/panic-abort was 611,472 bytes
versus 307,648 bytes for the matching std-only executable: **303,824 additional
bytes (~297 KiB)** for this exercised transport surface. Allow roughly 384 KiB
in planning, not zero dependency cost; final combined StateEngine/SE Code
marginal artifact size still must be measured. This is artifact size, not
B1's resident-memory increase; B1 retains its separate RSS measurement. The probe only links
a private client branch; it never executes a bus request or measures latency.
It confirms no dynamic libdbus/libsystemd dependency. Existing scope timings
used libsystemd plus placement polling, so they do not qualify the selected
dbus-rs event-driven path. Its first qualification waits for the designated
quiet window and the actual selected bytes.

## 2. How the runner measures

### 2.1 CLI latency (B7, B9 and FULL)
`performance.now()` before `spawn` to the child's `exit` event. No census, logging or helper inside the
interval; output is validated after timing, so a fast refusal is not a sample. All 30 samples count,
including the cold first call. Nearest-rank p95 of 30 is the 29th sorted sample.
For B7's strict threshold, **at most one run in 30 may reach 20 ms.** On Windows the first run of a new binary under Defender is the likely outlier, so a
second slow run is a real failure.

For B9 sample each of its three named ordinary-write commands through an
already running host. Sample every FULL-command family separately under the
FULL row on Windows with Defender; retain actual durability and batch promotion,
not just the command label. Sample each listed decision action and agent
setting separately; general settings writes are not FULL store mutations.
Use valid changing fixtures so the sample performs the requested mutation,
including a new project for init, rather than timing an already-matching readback.
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
- **E2 / B1/B2:** new and existing stores on Windows with Defender, inside the
  actual Rust SE Code server. Include first bind, required FULL commits,
  supported startup migration/backup when applicable, and after-task memory.
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
all crash phases, cancellation, RSS or B8. Raw results: `5p-native-handover-spike-
20261030/{linux-r2,windows-pc-run-a}` and `5p-provider-handover-spike-20261030/
{linux-r1,windows-pc-run-a}` under `/mnt/nvme/stateengine`.

## 3. Allocation per component

Baselines are prototype measurements from the plan. Allocations are this design's spend plan. A
component that outgrows its line has to fix that or negotiate within the total (§5).

### 3.1 Embedded memory (B1: 30 MB)
| Component | Allocation | Baseline / basis |
| --- | ---: | --- |
| Code pages touched (se-host, se-core, se-store, se-proc in secode-server) | 4.0 MB | Minimal core added 114 KB of binary; full product estimated at 3–5 MB of text |
| SQLite page cache: writer + 2 readers × 2 MB cap | 6.0 MB | `cache_size=-2000` per connection |
| SQLite connections, schema, statement caches | 1.5 MB | 3 connections, 32 statements each |
| Session tasks, 16 live × ~50 KB | 0.8 MB | 00 §2.2 |
| Mail watches and bounded subscriptions | 1.0 MB | Bounded channels |
| Listener and MCP buffers (1 MiB body cap, ≤ 2 large bodies at once) | 2.5 MB | §4 |
| Capture: 256 KiB read buffer × 2 active + parsing | 1.0 MB | Bounded transcript reads |
| Transcript watcher | 0.5 MB | Live sessions' directories only |
| Process custody state | 0.2 MB | Handles, job/cgroup records and one Windows IOCP collector's state per host; stack charged once below, no registered-wait pool |
| Resume assembly: up to four packets; one may exceed 32 KiB, max 1 MiB | 1.5 MB | One shared above-default permit, bounded metadata and no duplicate encoded packet |
| Fixed native/writer thread stack pages and allocator slack | 2.0 MB | Count every added committed stack page in E2; SE Code's existing reactor is not a second runtime |
| **Spend** | **21.0 MB** | Measured minimal core: 1.4 MB; revised packet allowance is unmeasured |
| Reserve | 9.0 MB | Atlas is off in embedded |
| **Total** | **30.0 MB** | |

### 3.2 Standalone memory (B4: 25 MB)
| Component | Allocation | Baseline / basis |
| --- | ---: | --- |
| `se` code pages and system libraries | 5.0 MB | Prototype owners 2.7–3.8 MB in total; Rust MCP server 5 MB |
| tokio `current_thread`, blocking pool (max 2), writer and native collector stack pages | 1.0 MB | One fixed set, all committed stack pages included |
| SQLite page cache: writer + 1 reader × 2 MB | 4.0 MB | CLI reads go straight to the file and don't need host readers |
| SQLite connections, schema, statements | 1.0 MB | |
| Sessions, mail, listener/MCP, capture + watcher, custody, resume | 7.5 MB | Includes the same single-large-packet resume allowance as 3.1 |
| Optional Atlas in-host: queries and single-file updates after config opt-in | 2.0 MB | One closed-when-idle connection plus one parser |
| Allocator slack | 1.0 MB | |
| **Spend** | **21.5 MB** | Prototypes measured 4–12 MB; revised packet allowance is unmeasured |
| Reserve | 3.5 MB | |
| **Total** | **25.0 MB** | |

Atlas is compiled only into the standalone `se`; it is disabled by default and enabled by `atlas.enabled = true` in config.toml; in embedded SE Code that setting returns feature-unavailable.
It is built after the journeys and live handover pass and never holds a
milestone. Explicit config opt-in admits its cold index as
a transient background child; it is not triggered by an ordinary first query.
The child has a separate cold-window cap and exits after indexing; resident
queries/incremental updates stay in the allocation above. The runner reports
that window separately and measures B4 outside it. The prototype's large-file
peak makes the per-file admission/deadline mandatory, not already qualified.

### Shared input limits and packet sizing

CLI, MCP and linked calls consume one closed input DTO per operation. Lists
accept 1–100 rows, default 20; search accepts 1–50; message previews are 400
characters; resume defaults to 32 KiB and accepts at most 1 MiB. A row limit
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
issuance/activation events. It still pays required FULL runtime.owner, actual
session activation and new-schema publication. Runtime ownership must commit
before the writer admits work; first-session activation is not acknowledged
before its own commit. There is no independent token-minting service or
credential work hidden outside the first-bind interval.

| Critical-path work | Current spend status |
| --- | --- |
| Native setup, store/header checks and supported upgrade path | Measure in E2; upgrade includes verified pre-migration backup and refuses an active old host with the se down remedy |
| Initial runtime.owner | One required FULL barrier; no 8 ms fsync assumption |
| First embedded session activation | One required FULL barrier; no credential.issued/credential.activated barriers |
| New store/schema publication | Additional required FULL on a fresh store; report its actual ordering/count |
| Bounded effects/profile load, IPC/native setup, static catalogue and first continuity | Measure with the same build and store; count every serial step |
| **Spend / reserve** | **Unallocated until E2; no claimed headroom** |

Historical S4 FULL transaction p95 was 41–49 ms; NORMAL hosted hooks were
7.5–11 ms end-to-end in a different workload. Neither is a current Windows
FULL cost or permission to subtract syncs from the required contract. Two
serial FULL barriers already consume most of B2 at the historical cost,
before other setup; a fresh store adds another. E2 must report the real
critical path and any miss. The old 75/96 ms readiness-only prototype and
an 8 ms assumed first-bind commit do not establish this revised boundary.

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

Keep **commit-driven autocheckpoint**, 16 KiB pages and 256 pages, as the
section-20 baseline. The measured contribution does not justify moving
checkpoints to a worker, hiding their latency, or weakening NORMAL/FULL.
Nell owns writer/schema reruns; any supported policy change is reviewed once
and applied consistently across 20/40/80/95 with queue/WAL/memory costs. Complete
E3 still requires the approved real host/command consumer and both sampling
classes; it remains unqualified, with the Linux ordinary component over target.

Raw data: `/mnt/nvme/stateengine/nell-import-rehearsal-20261030/` (initial),
`/mnt/nvme/stateengine/nell-e3-write-latency-20261030/` (native).
Independent analysis: `/mnt/nvme/stateengine/5p-e3-write-decomposition-20261030/
NATIVE-REPORT.txt`, `native-decomposition.json` and `analyze-native.py`.

### 3.7 Idle wakeups (B6)
| Source | No session | One session |
| --- | ---: | ---: |
| tokio park; `se-writer`, accept loops and the Windows IOCP collector (one per host, all jobs) all blocked | 0 | 0 |
| Transcript watcher (live sessions only, events on writes only) | — | 0 |
| Attended Claude long-poll re-armed every 25 s (Claude's HTTP fetch ends at 30 s), per attended Claude session | — | 0.04/s |
| Safety catch-up sweep every 15 min, only with ≥ 1 live session | — | 0.0011/s |
| Auto-started/handback daemon exit timer (10 min after last live agent) | one wake | — |
| Blocking-pool threads exiting after keep-alive | ≤ 2, once | ≤ 2, once |
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
| **Fixed thread set at idle.** The writer is a named `std::thread`, not a pool thread. Standalone blocking pool capped at 2. No per-session threads. Windows process exits for all jobs arrive on one shared IOCP collector per host; no registered-wait thread pool. | B6, Windows bound |
| **Bounded SQLite:** `cache_size=-2000` per connection, `mmap_size=0` (mapped pages would inflate RSS without a ceiling), statement cache 32, `temp_store=FILE`, `journal_size_limit` 4 MiB, `TRUNCATE` checkpoint at clean shutdown. | B1, B4 |
| **Batched writer, explicit durability:** block on receive, drain whatever is queued (up to 256), one `BEGIN IMMEDIATE … COMMIT`. No gather window, so no latency or timer is added. Autocheckpoint is commit-driven. Ordinary batches use NORMAL; credential/session/runtime/security transitions and decision ratify/reject/retract/supersede require FULL. NORMAL can lose several recent commits on power/OS loss, not an application crash. | B9, burst, B2 |
| **Bounded everything else:** channels bounded with `Lagged{resume_from}` on overflow; one closed DTO per operation for CLI/MCP; lists default 20 and max 100 rows, search max 50, message preview 400 characters, resume default 32 KiB/max 1 MiB; message body 32 KiB and working state 16 KiB; page/encoded budgets expose incompleteness and never truncate a full body. | B1, B4 |
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
6. **Totals don't move without their owner** (B1, B2 Alpha; the rest Jimmy). A structural miss reopens
   the fallbacks: reconsider composition with Alpha if embedding misses B1/B2; optional Atlas remains off and its cold child is separately bounded.
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
second allocation or a promised calendar. Alpha is not complete at the earlier
Windows/Linux milestone.
