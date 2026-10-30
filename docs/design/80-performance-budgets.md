# 80 — Performance budgets

Status: deep design, 2026-10-30. Precedence as in 00. The journey runner's budget probes
(`journeys/budgets.mjs`, `metrics.mjs`, `reaped.mjs`, `embedded.mjs` on `seat-5d/journey-runtime-budgets`,
head `32bbabfcde6`) are the measuring instrument; this section says what they measure, how each
component spends the budget, and which design rules keep it spent that way.

All budgets cover everything StateEngine adds, helpers included, and exclude the agent CLIs. Bytes are
decimal, as in the runner (`30 MB` = 30,000,000 bytes).

## 1. Hard budgets

| # | Budget | Threshold | Boundary | Runner probe |
| --- | --- | --- | --- | --- |
| B1 | Memory added inside SE Code | ≤ 30,000,000 bytes | A/B against a baseline SE Code server | `embedded A/B` |
| B2 | Startup added to SE Code | ≤ 100 ms, including the first bound session | Spawn to complete authenticated `/api/session` response | `embedded A/B` |
| B3 | Processes added | 0 embedded; exactly 1 standalone; 0 added per agent | Outside inventory by exact pid + birth | `standalone persistent processes`, `persistent processes after 1/2 seat(s)` |
| B4 | Standalone memory | ≤ 25,000,000 bytes with one live session, after one real agent task | Sum over every attributed StateEngine process | `standalone RSS one session` |
| B5 | Idle CPU | < 0.1% of one core (< 60 ms CPU per 60 s) | All StateEngine processes, 60 s with no product queries | `idle no session`, `idle one session` |
| B6 | Idle wakeups | ≤ 1/s with no session; ≤ 2/s with one | Same | Same |
| B7 | CLI reads | p95 strictly < 20 ms, 30 runs each of `--version`, `status`, `agent list`, `msg inbox`, `msg list`, `decision list` | Spawn to process exit | `CLI --version`, `CLI contextual read verbs` |
| B8 | Re-adoption after handover or restart | ≤ 500 ms, no lost or doubled input | Cutover start (after participating agents are interrupted to exact idle) to every live session re-adopted; quiescence time reported separately | **Not yet probed** (§2.6) |
| B9 | CLI writes | p95 ≤ 20 ms through a running host (Prime decision, measured 7.5–11 ms) | Spawn to exit | **Not yet probed** |

B1 and B2 are Alpha's requirements. The rest are plan decisions. Budget failures make the Rust run exit
nonzero even when every behavior row passes; the Node profile reports the same probes without
enforcement.

Long operations have their own targets, measured on StateEngine's share only:
- **Launch:** request to child spawned, identity pinned and recorded ≤ 50 ms (Linux prototype: 15 ms,
  24 of 24 under 20 ms). Provider start-up time is excluded and reported separately. On Linux the
  **first launch a host serves** also pays for BestAvailable delegation: one `systemd-run --user`
  transient scope creation, estimated at ~20–60 ms (not yet measured; the runner records it as its own
  line), so the first launch's target is ≤ 110 ms and every later launch stays ≤ 50 ms. When the probe
  finds no user manager or delegation, the probe's cost is paid once, and the `uncontained` fallback
  adds no cgroup cost to any launch: the agent only gets its own process group.
- **Stop:** identity recheck, stop and outside confirmation ≤ 50 ms of CLI time (prototype: ~4 ms each),
  plus the graceful deadline (5 s) and at most 500 ms of forced stop.
- **Atlas** (standalone only): cold index peak ≤ 64 MB in its own process (§3.2); save-to-searchable
  ≤ 200 ms (prototype 67 ms); query p95 ≤ 50 ms (prototype 7–16 ms); zero idle wakeups once settled.

## 2. How the runner measures

### 2.1 CLI latency (B7)
`performance.now()` before `spawn` to the child's `exit` event. No census, logging or helper inside the
interval; output is validated after timing, so a fast refusal is not a sample. All 30 samples count,
including the cold first call. Nearest-rank p95 of 30 is the 29th sorted sample: **at most one run in
30 may reach 20 ms.** On Windows the first run of a new binary under Defender is the likely outlier, so a
second slow run is a real failure.

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

**Defect to fix before the Mac campaign:** the observer divides `ri_user_time + ri_system_time` by 1e9.
Those fields are in Mach absolute-time units. On Apple Silicon one unit is 125/3 ns, so CPU is
understated about 41.7 times. Scale by `mach_timebase_info` first. The fix belongs to the runner owner.

### 2.6 Embedded A/B, and probes still missing
- **Embedded today:** 8 alternating A/B pairs, fresh profiles, every pair must pass. Gap: memory is
  sampled at readiness, but the budget means after real resume, mail and tool use; add a sample after
  one J2-style task inside SE Code.
- **B8 (proposed):** three live agents, one mid-turn, a message sent during the switch; trigger SE Code
  starting under a running daemon, then a host kill and restart. The mid-turn agent is interrupted to
  exact idle first; record that quiescence time separately. Time from cutover start to `status` showing
  every session adopted, with pid and birth unchanged from outside; then exactly one delivery and reply
  per message.
- **B9:** add `msg send`, `decide` and `hook claude stop` once Jimmy sets the number.

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
| Process custody state | 0.2 MB | Handles plus job/cgroup records; on Windows this includes the one shared IOCP collector per host, with no registered-wait pool and no other custody stack |
| Resume assembly: 64 KiB budget × 4 concurrent | 0.5 MB | Byte-budgeted packet |
| Allocator slack | 2.0 MB | |
| **Spend** | **20.0 MB** | Measured minimal core: 1.4 MB |
| Reserve | 10.0 MB | Atlas is off in embedded |
| **Total** | **30.0 MB** | |

### 3.2 Standalone memory (B4: 25 MB)
| Component | Allocation | Baseline / basis |
| --- | ---: | --- |
| `se` code pages and system libraries | 5.0 MB | Prototype owners 2.7–3.8 MB in total; Rust MCP server 5 MB |
| tokio `current_thread` + blocking pool (max 2 threads) | 1.0 MB | |
| SQLite page cache: writer + 1 reader × 2 MB | 4.0 MB | CLI reads go straight to the file and don't need host readers |
| SQLite connections, schema, statements | 1.0 MB | |
| Sessions, mail, listener/MCP, capture + watcher, custody, resume | 6.5 MB | Same per-item figures as 3.1 |
| Atlas in-host: queries and single-file updates after first use | 2.0 MB | One closed-when-idle connection plus one parser |
| Allocator slack | 1.0 MB | |
| **Spend** | **20.5 MB** | Prototypes measured 4–12 MB |
| Reserve | 4.5 MB | |
| **Total** | **25.0 MB** | |

**Atlas conflict, with a proposal for section 60.** The prototype indexer peaked at 20 MB and settled at
11 MB in-process. If an agent touches Atlas during J2, that alone breaks B4. Proposal: the **cold
index** runs as a transient `se atlas index` child inside the host's job or cgroup, at background
priority, and exits when done. Its peak never lands in the daemon, and B3 holds because the child is
not persistent. The host keeps only queries and single-file re-parses, under the 2 MB line. The per-file
parse budget (§4) keeps one huge file from spiking memory: the prototype's 958 KB file reached 59 MB.

### 3.3 Embedded startup (B2: 100 ms)
| Step | Allocation |
| --- | ---: |
| Store open: WAL, `application_id`/`user_version` check, no migration | 4 ms |
| Pending-effects scan (indexed, bounded) | 2 ms |
| Projects and profiles load | 2 ms |
| `runtime.lock`, `endpoint.json`, listener and IPC bind | 2 ms |
| Tool catalogue (schemas generated at build time, served as static JSON) | 1 ms |
| First session bind: one write transaction; credential and session activation are security events, so it commits with `synchronous=FULL` (one fsync; measure on Windows with Defender) | 8 ms |
| First session continuity: bounded resume read | 8 ms |
| **Spend** | **27 ms** |
| Reserve: Defender, cold page cache, brand-new store (schema in one transaction + WAL switch) | 73 ms |

Baseline: 75 ms p95 on an existing store and 96 ms on a new store, both under `FULL` sync with 3 and 7
disk syncs. `NORMAL` removes most of those syncs. Re-adoption, Codex reconnect, the start-of-day backup
and Atlas all run **after** ready.

### 3.4 Re-adoption (B8: 500 ms, 50 sessions)
Timed from cutover start, after participating agents are interrupted to exact idle (quiescence is
reported separately and is not in this budget). Drain the predecessor and flush the writer: 50 ms. Lock transfer and store open: 15 ms. Identity
recheck and pin (~10 µs each) plus parallel harness reconnects: 50 ms. Delivery debt from durable marks,
1 ms per session: 50 ms. **Spend 165 ms; reserve 335 ms.** "No doubled input" comes from durable marks
and message ids on every offer, not from timing (section 40).

### 3.5 CLI read (B7: < 20 ms)
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

### 3.6 Per-operation latency
| Operation | Target | Baseline |
| --- | --- | --- |
| CLI write through the host (B9) | p95 ≤ 20 ms | Hook through host: 7.5 ms typical, 9 ms worst |
| MCP tool, server side, 8 agents at once | reads p95 ≤ 5 ms, writes ≤ 15 ms | Writes 11 ms worst with 8 agents |
| `se hook claude stop` | p95 ≤ 20 ms plus bounded transcript bytes | 7.5/9 ms through host; 52–76 ms direct, which is why hooks go through the host |
| 20-agent write burst | worst ≤ 100 ms, no lost writes | 22 ms typical, 77 ms worst |

### 3.7 Idle wakeups (B6)
| Source | No session | One session |
| --- | ---: | ---: |
| tokio park; `se-writer`, accept loops and the Windows IOCP collector (one per host, all jobs) all blocked | 0 | 0 |
| Transcript watcher (live sessions only, events on writes only) | — | 0 |
| Attended Claude long-poll re-armed every 25 s (Claude's HTTP fetch ends at 30 s), per attended Claude session | — | 0.04/s |
| Safety catch-up sweep every 15 min, only with ≥ 1 live session | — | 0.0011/s |
| Auto-started daemon exit timer (10 min after last session and client) | one wake | — |
| Blocking-pool threads exiting after keep-alive | ≤ 2, once | ≤ 2, once |
| **Expected** | **≈ 0.002/s** | **≈ 0.003/s, plus 0.04/s per attended Claude session** |
| Ceiling | 1/s | 2/s |

The ceiling is far above the expected value. A measured rate above 0.05/s plus 0.04/s per attended Claude session passes the budget but
means a timer or poll got in, and the reviewer treats it as a defect.

## 4. Design rules that protect the budgets

| Rule | Protects |
| --- | --- |
| **No polling.** Every replaced loop stays gone: 250 ms mail door, 1.5 s watcher, 15 s supervisor tick, 60 s projection drain, 10 min Atlas renew, 1 h capture canary. Process exits arrive as OS events, mail as `watch` bumps after commit, files as OS file events. `notify`'s poll watcher is never used: on a filesystem without events, capture relies on the harness signal and reports the watcher as unavailable. | B5, B6 |
| **No timer without a live session,** except the auto-start exit timer (00 open item 6). Log rotation happens on write, never on a clock. | B6 |
| **Fixed thread set at idle.** The writer is a named `std::thread`, not a pool thread. Standalone blocking pool capped at 2. No per-session threads. Windows process exits for all jobs arrive on one shared IOCP collector per host; no registered-wait thread pool. | B6, Windows bound |
| **Bounded SQLite:** `cache_size=-2000` per connection, `mmap_size=0` (mapped pages would inflate RSS without a ceiling), statement cache 32, `temp_store=FILE`, `journal_size_limit` 4 MiB, `TRUNCATE` checkpoint at clean shutdown. | B1, B4 |
| **Batched writer, WAL `NORMAL`:** block on receive, drain whatever is queued (up to 256), one `BEGIN IMMEDIATE … COMMIT`. No gather window, so no latency or timer is added. Autocheckpoint is commit-driven. | B9, burst, B2 |
| **Bounded everything else:** channels bounded with `Lagged{resume_from}` on overflow; pages default 100 and max 1,000 rows; message bodies in lists budgeted at 64 KiB with an explicit incomplete flag; 1 MiB frames and bodies. | B1, B4 |
| **Bounded transcript reads:** read from the stored byte offset in 256 KiB chunks and parse line by line. A line over 4 MiB gets an `oversized-line` verdict (G4/G5). Never load a whole transcript. | B1, B4, hooks |
| **Lazy startup:** Atlas, Codex reconnect, re-adoption and the start-of-day backup run after ready. The backup uses SQLite's online backup API in 64-page steps on a background read connection, never holding the writer. It holds one read transaction for the whole copy, so it reads one stable WAL snapshot and never restarts when the writer commits. While that snapshot pins the WAL, the 16 MiB high-water rule defers checkpointing instead of raising `store-backpressure`; if the WAL reaches 64 MiB the backup aborts, releases its snapshot and retries at the next start-of-day. A backup never stalls the writer. Tool schemas are built at compile time. | B2 |
| **A lean CLI:** no async runtime, no TLS, no network, no subprocess (no `git`, no PowerShell), no process census. `status` reads `endpoint.json` and checks the host pid's identity natively instead of making an IPC round trip. | B7 |
| **Atlas budgets:** start on first use; cold index in a transient child (§3.2); files over 512 KiB skipped with a recorded `skipped: size` fact; per-file parse deadline 200 ms (tree-sitter progress callback); one parse at a time; the search index holds names and paths, not bodies; its own `atlas.db`. | B4, B6 |
| **Smaller events:** trim the prototype's ~2 KB per event toward ≤ 600 B median for non-turn events (00 open item 3); a review signal. | Disk, cache hit rate |

## 5. When a budget is missed

1. **Keep everything.** `budgets.json` retains every sample; a rerun counts only alongside the failed
   run it follows. No rerun-until-green.
2. **Reproduce at the same commit on the same OS** before blaming anything else; bisect within the
   (small) landing batch.
3. **Classify:** a *product regression* goes to the author whose §3 line overran; an *environment*
   cause (first-run Defender, another process) must show in the retained diagnostics, and the next run
   must pass; a *measurement defect* (like the macOS CPU units) goes to the runner owner with
   independent review, and Node must pass the same runner commit.
4. **Fix in this order:** remove the cause (a poll, an unbounded buffer, a sync on the critical path);
   then move the work off the critical path (lazy or after ready); only then move allocation between
   components inside the total, as a doc change with one sentence of reason.
5. **A missed budget blocks the landing batch,** exactly like a failed behavior row.
6. **Totals don't move without their owner** (B1, B2 Alpha; the rest Jimmy). A structural miss reopens
   the fallbacks: a sidecar if embedding can't meet B1/B2; the transient Atlas indexer for B4.
7. **Self-reports are not evidence.** `status` and `doctor --bundle` may show the host's own memory and
   session counts for support; budgets are judged only from outside (G8).


## Decision: Atlas cold-index window (Prime, 2026-10-30)

The 25 MB standalone ceiling (B4) is the steady-state budget for the daemon and its resident helpers. Atlas's first full index is an explicit exempt window: it runs in a separate short-lived child process at background OS priority, with its own hard cap of 64 MB peak, and exits when the index completes. The journey runner reports that window separately and measures B4 outside it. Incremental Atlas updates run in the host and stay inside B4. The host defers a cold index only under machine memory pressure, and Atlas status says so. Atlas is not part of any journey, so the journeys measure B4 with no cold index running.
