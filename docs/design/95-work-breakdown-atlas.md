# 95 — Work breakdown: se-atlas

Planning revision, 2026-10-30, reconciled through round 3.
This is the Atlas contribution to section 95, not authorization to
implement. It changes no source, tests, public operations or budget thresholds.

The contracts are [section 60](60-atlas.md), `docs/OPS.md`, and section 80
(`80-performance-budgets.md` in the approved design handoff). References below use
those section numbers. Section 80 defines cold-window accounting; section 60
supplies the explicit config-enable activation and private child entry.
Atlas is compiled only into the standalone `se`; it is enabled by default and can be disabled with `atlas.enabled = false` in config.toml; a host without an installed Atlas controller reports it unavailable.

## Dependencies and estimate convention

Build in the numbered order below; a later unit can prepare against an earlier
port, but is not complete until its stated dependency and witness exist. These
are build units within one Atlas outcome, not mandatory separate landings. Planned
filenames locate ownership and keep responsibilities small; existing public
`model.rs`/`queries.rs` reexport the shared values; lifecycle, policy and execution
traits stay local. A01 qualifies this existing ownership boundary.

- **se-types:** shared IDs, `Source::Atlas`, `Read`, `Page`, `Window`, typed `Detail`,
  `ErrorBody` and `SeError` already exist; code DTOs and pure validation live in
  `se-types::code`, without an Atlas dependency.
- **se-store:** se-atlas never depends on it or opens `state.db`. Only core's private
  resume-cursor CAS uses se-store, through its existing owner (A11). Atlas is enabled by
  the single `config.toml` setting (section 60), not by a store record (A12).
- **Host/native:** se-host supplies verified project/viewer authority, lifecycle,
  background scheduling and OS adapters. All eventual unsafe native code stays in
  se-proc behind safe APIs; se-host and se-atlas remain forbid-unsafe. Native APIs
  do not import se-atlas, and se-atlas does not acquire a se-proc dependency.
- **LOC:** ranges estimate handwritten production Rust in the listed files,
  including moved/expanded declarations and cross-crate glue, not net additions.
  Count a shared helper only in its owning unit. Generated grammars, vendored
  SQLite/Tree-sitter, tests and witness tooling are excluded. A04 estimates
  handwritten Tree-sitter query files separately. Estimates are review signals,
  not file quotas or permission to weaken a contract.
- **Witness:** each item describes future evidence, not an observation made by this
  draft. Component witnesses precede final public-consumer qualification in A14.
  Reviewers/runner owners supply their checks; this contribution creates none.

## Ordered build units

### A01 — Shared code contracts and validated query values

**Files:** `crates/se-types/src/code.rs`; module declaration in
`crates/se-types/src/lib.rs` and shared reexports in
`crates/se-atlas/src/{model,queries,errors}.rs`.

**Depends on:** accepted se-types; section 10 owner agreement on shared ports;
se-store: none; host: consume the same verified-scope port without optional-crate
imports in core. Reuse the landed Atlas error catalog, not another error type.

**Satisfies:** 60 §§1–2, 5/5.1, 6–7, 10 (legal dependency graph, `Answer<Read<T>>`,
4096-byte cursors, array code context); 80 §4 bounded values/lean CLI, B1/B4.

**Witness:** core builds with the Atlas feature absent and no se-core -> se-atlas
edge; production validation/serialization preserves Present/Absent/Unknown/
Unreadable metadata and typed error causes, rejects foreign/oversize cursor domains,
and keeps `code_changes` an array or disabled null. This proves contracts, not indexing.

**Estimate:** 350–550 Rust LOC.

### A02 — Registered physical source access and revision verification

**Files:** `crates/se-atlas/src/{scope,source}.rs`;
`crates/se-host/src/atlas/source.rs`; safe native file adapters in
`crates/se-proc/src/fs/{mod,linux,windows,macos}.rs`.

**Depends on:** A01/se-types; se-store: none; host: retained physical-root and
registered gitdir/commondir handles, case policy and qualified native revision
capabilities. Native file APIs return generic facts, not Atlas-owned DTOs.

**Satisfies:** 60 §2 and §4.2 (no-follow, linked worktrees, body-byte hashes,
same-size writes, trusted-sequence/ctime shortcut and verified bounded ranges);
80 §4 bounded reads/one parse, B4 and Atlas's source/work limits.

**Witness:** through the real source adapter on each OS, same-size in-place edits
are detected even with unchanged mtime; replacement roots, reparse/symlink escapes
and unreadable paths refuse distinctly. A linked worktree reads its registered
HEAD/shared ref without reading outside-root source. Trusted revision fast paths
invalidate on journal/domain/qualification loss. A changing Text prefix produces
no accepted mixed-revision hits; unknown is never reported as Removed/Unchanged.

**Estimate:** 350–550 Rust LOC, including native file glue.

### A03 — Owned SQLite cache, schema and bounded read/write access

**Files:** `crates/se-atlas/src/cache/{mod,schema,connection,pointer}.rs`;
workspace dependency pins and `crates/se-atlas/Cargo.toml`.

**Depends on:** A01–A02/se-types; se-store: no code/database dependency, only the
workspace's single pinned rusqlite/bundled SQLite linkage; host: verified owner-only
cache location and writer lock. Epoch publication orchestration is A09.

**Satisfies:** 60 §3 and §4.1 (STRICT schema, nullable hashes, metadata-only FTS,
application/scope/version checks, epoch pointer, bounded WAL); 80 §3.2/§4, B4.

**Witness:** an independent RO connection reads back a committed owned cache and
correct Atlas provenance. Corrupt/newer/foreign/link targets refuse without mutation;
bodyless NULL differs from an actual empty-body hash. Inspect persisted tables/FTS
for absence of source bodies. Hold an external read transaction while writes reach
the WAL bound: writes stop truthfully and reader data remains readable. Observe
both in-host connections/caches inside the 603,082-byte SQL/query allocation (100,000 bytes transferred from the queue and 3,082 from allocator slack).

**Estimate:** 400–600 Rust LOC; no duplicate SQLite library or unbounded pool.

### A04 — Parser extraction and early memory admission qualification

**Files:** `crates/se-atlas/src/parse/{mod,budget,javascript,typescript,rust,python}.rs`;
`crates/se-atlas/queries/{javascript,typescript,rust,python}/*.scm` as needed;
shared JS/JSX and TS/TSX grammar selection in the registry.

**Depends on:** A01–A03/se-types and safe source snapshots; se-store: none;
host: existing background worker/admission resource facts and outside memory observer.
Grammar query packs share extractors rather than copying whole language pipelines.

**Satisfies:** 60 §§2–3, 4.2, 5 language matrix, 9/10 (optional signatures/bodies,
partial coverage, 512 KiB/200 ms limits, parser qualification); 80 §3.2/§4, B4.

**Witness:** actual production parser ports extract all six grammar variants,
including bodyless/synthetic modules and valid empty bodies, with original byte
spans. Parse errors/unsupported/generated/oversized inputs report coverage. Outside
measurements include grammar loads, one source/tree/extraction arena, SQLite and
retained allocator pages inside the **2,000,000-byte total**, with at most 1,000,000
for parser/source. Do this before building the full query surface. An unqualified
profile remains deferred with stale metadata/Text fallback; it is not enabled on
an assumed 16 KiB cap. Cold-child qualification completes in A09/A14.

**Estimate:** 800–1,200 Rust LOC plus 300–600 handwritten `.scm` lines.

### A05 — Import resolution and bounded reference graph

**Files:** `crates/se-atlas/src/resolve/{mod,imports,lexical}.rs`;
`crates/se-atlas/src/cache/graph.rs` alongside A03's schema.

**Depends on:** A01/A03/A04/se-types; se-store: none; host: authorized registered
source roots only. No git subprocess, compiler, LSP, network or execution of project code.

**Satisfies:** 60 §3 and §5 (three accuracy labels, supported language matrix,
late import targets, stale-target invalidation, hop limits); 80 §4 bounded work, B4.

**Witness:** supported local/import bindings return their declared confidence;
dynamic/package/glob/dispatch cases remain NameOnly/partial. Create a previously
missing import target without editing its importer, then independently read back
the repaired edge; remove/replace an export and prove no edge targets a reused
rowid. Reexports stop with explicit cycle/limit coverage, not a fabricated resolution.

**Estimate:** 450–700 Rust LOC.

### A06 — File transactions, stale baselines, change facts and attribution

**Files:** `crates/se-atlas/src/update/{mod,diff,authors}.rs`;
`crates/se-atlas/src/cache/write.rs` transaction helpers.

**Depends on:** A01–A05/se-types; se-store: none; host: trusted exact path/before/
after hashes and evidence IDs. The host supplies facts, not transcript text.

**Satisfies:** 60 §3 and §§5–7 (good->failed->good, FileOnly baseline reset,
null-vs-empty diff, atomic FTS/graph updates and latest-only author hints);
80 §4 bounded SQLite/work, B4 and Atlas save-to-searchable target.

**Witness:** separately read back one good edit, a failed/partial/deferred edit and
recovery. Last-good semantics stay visibly stale through the gap; recovery emits
FileOnly/reset rather than invented Added/Removed. Initial cold population creates
no changes. Trusted late self/other evidence updates provenance without inventing
a new edit; missing/mixed evidence never claims an agent. Reader sees one complete
file transaction, with no half-replaced FTS or stale resolved target.

**Estimate:** 450–650 Rust LOC; batching/publication policy belongs to A07.

### A07 — Incremental controller, coalescing and bulk publication

**Files:** `crates/se-atlas/src/{controller,scheduler,policy}.rs`;
`crates/se-atlas/src/update/batch.rs`; implementation of the existing lifecycle port.

**Depends on:** A01–A06/se-types; se-store: none; host: shared low-priority scheduler,
explicit enable/session/restart/source events and cancellation. Native watches A08
feed this same port; no second scheduler is created there.

**Satisfies:** 60 §§3–4/4.2 and §9 (50,000-byte/64-hint queue, logical bulk batches,
10-second unpublished grace, separate index/published fences, retained stale fallback);
80 §4 no polling/lazy/bounded work, B4–B6 and save-to-searchable <=200 ms.

**Witness:** a burst above 100 files produces one bounded Bulk row without flooding
retention. A slow real Git checkout whose file writes precede HEAD is grouped by
registered lock events/grace, including sub-100-file event fragments. Search sees
admitted saves within target while change publication waits visibly. Queue/SQL
staging overflow and interrupted reconcile expose incompleteness; ignore edits
reconcile incrementally, never launch cold rebuild. At rest next_work parks with
no polling, grace timer or parser retained; no incremental helper process appears.

**Estimate:** 450–650 Rust LOC.

### A08 — Native watches, Git activity and coverage limits

**Files:** `crates/se-host/src/atlas/watch.rs`;
`crates/se-proc/src/fs_watch/{mod,linux,windows,macos}.rs`;
`crates/se-atlas/src/cache/watch.rs` for watch-directory/coverage accessors.

**Depends on:** A02/A03/A07/se-types; se-store: none; host/se-proc: safe subscriptions
on the existing reactor/IOCP and generic events, with no Atlas runtime or unsafe
code in se-host. Reuse A02's Git metadata handles and A07's hint queue.

**Satisfies:** 60 §2 and §4 watch table/admission (watch-before-scan, loss, OS-fraction
limits, counters); 80 §4 fixed idle threads/no polling, §3.7, B3–B6.

**Witness:** on Linux install a directory watch before scanning preexisting new
children, skip ignored trees and never subscribe to IN_OPEN. On Windows exercise
the 65,536-byte buffer and zero-byte/ERROR_NOTIFY_ENUM_DIR reconciliation. On macOS
exercise directory-only/coalesced/drop flags. Exhaust watches and read back honest
watched/unwatched counts plus activation/limited-activation statistics. Native
measurements keep map/buffers/ignore/root metadata within **200,000 bytes** and
report actual OS limit/admitted count for both corpora; a quiet native interval
shows no Atlas-induced wakeups or idle thread churn.

**Estimate:** 650–1,000 Rust LOC, including native watch glue; no per-agent watcher.

### A09 — Transient cold child and atomic epoch adoption

**Files:** `crates/se-host/src/atlas/{cold,adopt}.rs`;
private entry routing in `crates/se/src/private_atlas_worker.rs` and its
existing entrypoint; cold writer support in
`crates/se-atlas/src/cold.rs`. Reuse A03's pointer and section 30's process custody.

**Depends on:** A02–A08/se-types; se-store: none inside Atlas/child; host/se-proc:
owned private pipe, exact birth identity, pressure policy, background priority,
containment, outside observation, cancellation and reap. No public index command.

**Satisfies:** 60 §4.1, §8/§9; 80 §§1/3.2/4 and final cold-window decision, B3/B4.

**Witness:** enable through the real host lifecycle, observe one owned child at
background priority and **<=64,000,000-byte peak**, then independently witness exit
and adopted epoch/readback. During Windows adoption an external old-epoch RO reader
continues safely; new readers get the new epoch or labelled retired snapshot,
never swap-as-Absent. Exercise stale job, cap/deadline failure, crash around pointer
publication, retained-handle deletion and dirty-event replay. Only one cold child
exists, no per-agent/resident child survives; B4 is measured outside the finite
cold window and incremental updates never acquire its exemption.

**Estimate:** 350–550 Rust LOC; process containment/reap internals are section 30 work.

### A10 — The five bounded queries and live keyset pagination

**Files:** `crates/se-atlas/src/query/{mod,find,refs,impact,changes,outline,cursor,text}.rs`;
production query implementation behind the shared A01 port.

**Depends on:** A01–A09/se-types and validated cache/source access; se-store: none;
host: bounded read worker/scoped source capability. Hostless CLI uses the same RO
cache reader without starting a host or scheduling repairs.

**Satisfies:** 60 §5/5.1, §4.2 Text rules, §7; 80 §4 lean/bounded reads and Atlas query
p95 <=50 ms. Core B7's <20 ms threshold is a separate obligation, not relaxed here.

**Witness:** exercise find/refs/impact/changes/outline through production readers,
then public consumers in A12/A14. Save between pages: continuation works with
snapshot_advanced rather than per-edit refusal. Epoch/filter/retention mismatches
remain typed refusals. Inspect NameOnly/stale/partial negative claims, bounded BFS,
commit/time baselines and same-size-changing Text prefixes. An external observer
retains query latency samples including cold calls; reads cause no cache mutation,
parse, repair, child or source-body persistence.

**Estimate:** 650–950 Rust LOC; query value/codec definitions counted only in A01.

### A11 — File-grouped resume and private delivered-cursor CAS

**Files:** `crates/se-atlas/src/resume.rs`;
`crates/se-core/src/resume/code.rs`;
`crates/se-store/src/write/resume_cursor.rs` for the private cursor/delivery CAS
(or the store owner's equivalent existing write module, without a second writer).

**Depends on:** A01/A06/A07/A10/se-types; se-store: ONLY core's private cursor/revision
and delivery-record CAS, never an Atlas import; host: verified viewer/recent edits,
actual context-delivery EventId and cancellation. Requires the core/store writer
and snapshot interfaces to be implemented by their owners.

**Satisfies:** 60 §6/§7/§10; 80 §3.1 resume allocation, §4 bounded reads, B1/B4.

**Witness:** real session context contains <=5 file groups/<=600 UTF-8 bytes,
including required omission/retrieval text. Known other edits rank correctly;
late self evidence, Unknown and Mixed never become false other-agent news.
Concurrent resumes, repeated offers, dropped/omitted responses and privacy retirement
cannot double-consume, advance on construction or overwrite a newer private cursor.
Read the stored cursor outside its writer after actual delivery. Measure <=20 ms
wall/<=5 ms SQL including a cold connection/cache; budget failure leaves the cursor
intact and core resume usable. Explicit changes retains its independent range.

**Estimate:** 300–500 Rust LOC across Atlas/core/store, excluding shared DTOs.

### A12 — Feature, configuration and CLI/MCP composition

**Files:** `crates/se-host/src/atlas/mod.rs` and `src/effects/atlas.rs`;
`crates/se-core/src/ops/atlas.rs` in the existing operation registry;
`crates/se/src/render/atlas.rs` and the Atlas entries in the existing generated CLI/
MCP dispatch. No second hand-maintained tool catalogue or transport implementation.
The core operation bridge is owned exclusively by A12: its **150 Rust LOC** are
included in this unit, not a separate K11 unit or another core/CLI allocation.

**Depends on:** A01–A11/se-types; the `config.toml` Atlas setting read at startup and on
change (no store record); host: normal ready/bind/startup composition, read dispatch and diagnostics.
The operation inventory remains exactly the existing five Atlas reads.

**Satisfies:** 60 §1, §4 state mapping, §§5–7/9/10; 80 §§3.1/3.3/3.5/4, B1–B3/B7.

**Witness:** CLI and MCP, both harnesses and attended/autonomous dispatch return the
same scoped standalone results/errors. Explicit enable schedules the after-ready effect and
background first index; ordinary reads/status/resume never enable or start it.
Disabled/not-built/absent/unreadable/updating/ready stay distinct. Embedded builds
link no Atlas and reject enablement with feature-unavailable; standalone first
bind/core agent work succeeds while Atlas is deferred/failed.
Outside observation confirms no new tool/alias/public worker command, and the six
core CLI read p95 values remain strictly <20 ms over 30 retained runs each.

**Estimate:** 250–400 Rust LOC of Atlas-specific composition: 150 for the core
operation bridge plus 100–250 for host/configuration and CLI/MCP composition.
This includes the bridge once and leaves the aggregate estimate unchanged.

### A13 — Drain, erasure, retention and abandoned-root cleanup

**Files:** `crates/se-atlas/src/{close,prune}.rs`;
`crates/se-atlas/src/cache/remove.rs`;
`crates/se-host/src/atlas/close.rs` for host close/remove integration. Reuse A06 transactions and A09 process/epoch cleanup.

**Depends on:** A01–A12/se-types; se-store: caller's existing removal/revocation
workflow only, no Atlas access; host: exact child lifecycle, source/root ownership,
physical-volume/deletion facts and independent absence observer.

**Satisfies:** 60 §3 pruning/disk bounds, §§4/4.1, 8; 80 §4 commit-driven maintenance,
B3–B6. Process closure is not configuration disable or proof of erased external copies.

**Witness:** through actual disable/remove/privacy paths, observe local handles and
owned child gone, then independently read absence of all owned pointer/epoch/WAL/
SHM/staging data. A pinned external epoch, stuck IO, unknown file or unreadable mount
returns Pending/incomplete and preserves source/history. At actual cache activity,
exercise 50,000-row/30-observed-day retention, author/name/generation GC, abandoned
root rules and disk ceilings; expired cursors refuse honestly. No idle cleanup tick,
old-offer resurrection, blanket recursive erase or source mutation occurs.

**Estimate:** 250–400 Rust LOC; common epoch/cache helpers counted in A03/A09.

### A14 — Integrated native qualification and release evidence

**Files:** no new product files planned. Use the independent runner
`journeys/{budgets,metrics,reaped,embedded}.mjs` named by section 80 and its existing
public-consumer observations, plus the optional Atlas observations specified by
section 60; retain their
artifacts outside product source. Any product defect returns to its owning unit.

**Depends on:** A01–A13, implemented se-types/core/store/host/process foundations,
and runner-owner access to Windows/macOS/Linux and both real corpora. Native
observer corrections (including macOS timebase accounting if still outstanding)
remain the runner owner's dependency, not new Atlas machinery.

**Satisfies:** 60 §§9–10; 80 §§1–2/5 and final cold-window decision, B1–B7 plus Atlas
latency/peak/idle targets. B8 handover and B9 core writes stay their existing owners'
contracts; optional Atlas must not delay or disable those core paths.

**Witness:** clean native public CLI/MCP runs on all three OSes with both harnesses;
standalone actual indexing/edit/query/resume/remove plus embedded feature-unavailable A/B
through first bind and real core work. Observe the complete attributed process set,
<=40,000,000-byte steady host after a real task, separate <=64,000,000-byte cold
peak/reap, admitted-save <=200 ms and query p95 <=50 ms. Use section 80's external
idle method, not endpoint-only/self-reported zeros; Atlas contributes zero settled
work/timers. Keep every failed/slow sample. A missing probe/observer is unavailable,
not green. Core journeys remain runnable with Atlas off; no reservation table or
compile success is substituted for native qualification.

**Estimate:** 0 additional production LOC; qualification/fixes do not become a new
runtime subsystem or an invented guard.

## Aggregate and completion boundaries

| Work | Estimated handwritten lines |
| --- | ---: |
| A01–A13 production Rust, including cross-crate Atlas glue | 5,700–8,700 |
| A04 production query-language files | 300–600 |
| Total handwritten product work | 6,000–9,300 |
| Generated/vendor code, tests and independent qualification tooling | excluded |

The range is broader than the earlier ~5.8k Rust prototype plan because it includes
typed shared/core/native glue, external-reader adoption, privacy/failure handling
and their accepted bounds. It is not an increase to any kernel/resource budget.
Existing declaration lines moved into shared ownership are counted once. Reuse
section 30 custody, the existing reactor, catalog, writer and operation registry;
do not build an Atlas version of each.

A01 is the ownership/dependency prerequisite. A04 is the early semantic-admission
risk decision; failed memory qualification leaves the documented Text/path/stale
fallback, not an unapproved incremental child. A09/A11 require real host/custody and
private delivery transactions, so their witnesses cannot be replaced by standalone
in-memory doubles. A14 supplies the final outside measurements and public-consumer
proof. Neither this breakdown nor the accepted design claims those implementations
or observations already exist, and implementation still waits for explicit implementation admission.
