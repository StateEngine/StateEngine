# 60 — Atlas: optional source understanding

Design revision, 2026-10-30. Owner: 5e. This document and the declaration-only
`crates/se-atlas` specify behavior for later implementation; they implement no
indexer, database, watcher or runtime. Jimmy's decisions and OPS.md govern, then
00, then this design. The appended cold-window decision in 80 governs resource
accounting. The Linux prototype is reference evidence, not production code or
proof that this revised design fits its budgets.

## 1. Scope, ownership and activation

Atlas answers where code is, who refers to it, what depends on it, what changed,
and what a file contains. It supplies optional code context to resume. It stores
no conversations, decisions, messages, memories, transcript bodies or provider
logs. The authoritative store, bind, messaging and resume work without Atlas.
An unreadable index never becomes an empty successful result. Removal still
reports Atlas handles or data it could not close or erase.

`se-atlas` depends only on se-types and its own parsing, SQLite and native-source
ports; never se-store, se-core, se-host or se-proc. It never opens the authoritative
database. Se-host adapts core's shared CodeIndex port, supplies authorized scope
and edit evidence, schedules work and owns native handles/processes. This
compile-only crate has only the se-types dependency. Later implementation uses
workspace-pinned rusqlite 0.40 with ONE bundled libsqlite3-sys, Tree-sitter with
JS/JSX/TS/TSX/Rust/Python grammars, ignore handling and event-only watches. No
process-global Tree-sitter allocator is installed by this embedded crate.

Exactly five OPS reads exist, with the same dispatch for CLI and MCP:

| Operation | CLI | MCP | Result family/data |
| --- | --- | --- | --- |
| atlas.find | atlas find QUERY | stateengine_atlas_find | se.code-hits/v1, Page<CodeHit> |
| atlas.refs | atlas refs SYMBOL | stateengine_atlas_refs | se.code-refs/v1, Page<Reference> |
| atlas.impact | atlas impact SYMBOL | stateengine_atlas_impact | se.impact/v1, Impact |
| atlas.changes | atlas changes | stateengine_atlas_changes | se.code-changes/v1, Page<CodeChange> |
| atlas.outline | atlas outline PATH | stateengine_atlas_outline | se.outline/v1, Read<Outline> |

Configuration is config.set; status is status. No public index, refresh, renew,
repair or watcher operation is added. The cold child uses a private inherited
host handle and authenticated entry mode, never another clap leaf or MCP tool.
Doctor's existing owned-cache repair workflow can retire a corrupt epoch and
schedule the same lifecycle, without a new command.

Embedded Atlas is OFF for alpha. Standalone includes the feature but defaults
`atlas.enabled=false`. Registration is metadata-only. **config.set false->true**
commits the project setting and records a host after-ready activation effect
(ConfigEnabled), which queues the first cold index if absent. If the host is not
running, its next normal startup drains that durable effect after ready; config
set does not start a daemon. Once-enabled host restart/first bound session schedules
HostRestart/FirstSession reconciliation after the bind response, including cold
index if its cache is absent. Already-true config set is idempotent. First bind
never waits for Atlas. Queries, status and resume never index, write, enable, start
a daemon or schedule an after-query action. A missing cache therefore remains
honestly absent until one of those explicit host activation events occurs.

## 2. Identity, physical paths and source revisions

One cache belongs to one registered canonical physical worktree. Linked worktrees
have separate caches. RootId and CacheEpoch reexport se_types::AtlasRootId and
IndexEpochId, including their validated prefixed UUIDv7 wire forms; no local ID
copy is introduced. Local Generation is a cache u64 counter, not the shared
session Generation. Window observations are checked SequenceValue conversions
with Source::Atlas { project, root, epoch }, never authoritative floor sequences.
FileId is the first 16 bytes of BLAKE3(root ID, normalized path key), with length-
delimited fields; it is stable across epochs. Rename is remove+add. SymbolId is
BLAKE3(root,file,kind,enclosing declaration chain,name,duplicate declaration ordinal).
A body/signature edit or moved line preserves identity; reordering indistinguishable
duplicates may change it. SQLite rowids never escape as public identifiers.

RootRegistration is trusted host input, not MCP input. Readers are already bound
to one project/root and authorized source visibility. Viewer and edit-evidence
AgentId come from the verified session/host, not request text. No cwd, environment
or fleet default substitutes for a binding. Code visibility is project-wide;
private viewer cursors and delivery records belong to core's private store.

RelativePath is UTF-8, 1..4096 bytes, slash separated: no absolute/device/drive/UNC
prefix, NUL, empty component, dot or dot-dot. Preserve spelling; lookup keys follow
the registered filesystem case mode, with ambiguous collisions refused. Non-UTF-8
names are counted as unsupported, never lossy-collapsed. Native no-follow opens
walk relative to a retained physical root handle, verify every component and root
identity, and refuse symlinks/reparse traversal. Same spelling with new physical
root identity needs owner rebind. Native unsafe code stays in the host adapter.

**Git metadata is an explicit narrow exception, not a source escape.** During
registration the host reads a bounded .git file (<=4096 bytes), validates linked-
worktree backpointer and registers physical gitdir/commondir handles and identities.
Atlas may read only HEAD, its bounded referenced ref, packed-refs, commondir,
worktree backpointer and info/exclude from these handles; observe only presence/
change events for index.lock and HEAD.lock as checkout hints (<=2,000,000 metadata
bytes per reconciliation). No objects, hooks, arbitrary config includes, remote
access or source outside the root. Physical metadata replacement requires rebind.
No GIT_* ambient variables or git subprocess. Per-worktree HEAD and shared refs
are resolved against the appropriate registered directory. This follows Git's
[repository layout](https://git-scm.com/docs/gitrepository-layout) and
[worktree metadata layout](https://git-scm.com/docs/git-worktree.html).

Source positions use original bytes: 1-based lines, 0-based UTF-8 byte columns,
end-exclusive spans and byte offsets. Do not normalize CRLF/BOM. Hash source with
BLAKE3. Signature hash covers header tokens without trivia/body; body hash covers
original body bytes, so body comments count. **Both are Option<ContentHash>** in
Rust and nullable in SQL. None means syntax absent, whereas Some(hash(empty)) means
an actual syntactic empty body. Bodyless trait/interface/overload declarations have
signature Some/body None; synthetic module symbols have both None. Do not infer
one state from another or fabricate a zero span/hash. Doc metadata is only the
first documentation line, truncated at a UTF-8 boundary to 160 bytes.

FileIdentity includes volume/file identity, size, mtime, optional ctime and native
change sequence. Timestamps are a cheap candidate filter, never a content revision.
Read checks size before allocating, opens no-follow, hashes bounded original bytes,
and rechecks metadata. **verify reopens the same physical file, rehashes all admitted
bytes and compares the full content hash plus identity immediately before commit.**
A same-size in-place edit is Changed even if timestamps are coarse or restored.
Restart reconciliation can skip a full rehash ONLY when the native adapter
provides a qualified persistent content-change sequence (same file and journal
domain), or ctime semantics qualified to detect EVERY relevant byte write across
that restart. RevisionTrust records that qualification; a journal reset/unknown
resolution, rollback, mount/domain change, unsupported ctime or uncertain clock
invalidates it. Plain size/inode/mtime is never sufficient. Without that proof,
watch loss/restart/uncertain timestamps require streamed rehash. Parsing a changed
file still verifies its full bytes immediately before commit, regardless of this
unchanged-file optimization. Reconcile holds at most a 16,384-byte hash buffer
and a bounded path batch; it may take many work quanta. A change after verification
can still happen: results carry indexed hash/freshness, and editors must reread
before acting. This is snapshot evidence, not a filesystem transaction guarantee.

## 3. Persistent schema, file transitions and bounds

Cache directory is owner-only StateEngine home `atlas/<project-id>/<root-id>/`.
It contains `current.json` and `epochs/<epoch>/atlas.db` (plus SQLite WAL/SHM).
Paths derive from validated IDs, never a user destination. Application_id is
0x41544c53 (ATLS), user_version 1. Only the host creates/upgrades/retires caches;
CLI is read-only. Newer schema preserves bytes and refuses. Foreign application,
foreign scope, links or corrupt bytes are unreadable, never an absent index.

Use WAL, synchronous NORMAL, foreign_keys ON, temp_store FILE, mmap_size 0 and
4,096-byte pages. At most two in-host connections exist globally: one writer and
one reader, including hostless requests delegated to the host; no hidden pool.
Each connection cache is **32 pages =131,072 bytes**, at most eight cached statements
within a 16,384-byte statement allowance each; query arena 98,304 bytes. Both
connection objects/SQLite overhead and these reservations must fit the 500,000-byte
SQL share. Excess statement/overhead allocations fail admission, not borrow an
unmeasured allowance. Hostless CLI has one RO connection in its own bounded process;
80's external budget runner accounts for it when present. Cold child cache is
<=2,000,000 bytes (488 pages =1,998,848 bytes), separate from its parser arena.
WAL admission stops at 8,000,000 bytes; checkpoint target 4,000,000. Reader transactions
have bounded query deadlines and close at response completion. External readers
cannot be forcibly expired: if their pins prevent checkpoint, suspend Atlas writes
with CacheBusy, preserve the old cache and report it. No idle checkpoint/expiry tick.

Normative relational layout follows. Checked nonnegative counters and blob/text
limits in this document also apply where SQL checks are abbreviated. All ordinary
tables are STRICT. Cached source bodies and transcript text are never stored.

```sql
CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), project TEXT NOT NULL,
 root TEXT NOT NULL, physical_root BLOB NOT NULL, epoch TEXT NOT NULL,
 extractor_version TEXT NOT NULL, ignore_digest BLOB NOT NULL,
 index_generation INTEGER NOT NULL, published_generation INTEGER NOT NULL,
 observed_serial INTEGER NOT NULL, retention_floor INTEGER NOT NULL,
 discovery_complete INTEGER NOT NULL, coverage_json TEXT NOT NULL, state_json TEXT NOT NULL
) STRICT;
CREATE TABLE files (
 id INTEGER PRIMARY KEY, key BLOB NOT NULL UNIQUE CHECK(length(key)=16),
 path TEXT NOT NULL, path_key TEXT NOT NULL UNIQUE, language TEXT,
 indexed_hash BLOB, observed_hash BLOB, bytes INTEGER NOT NULL,
 identity BLOB NOT NULL, coverage_json TEXT NOT NULL,
 last_good_generation INTEGER, last_code_generation INTEGER NOT NULL,
 last_author_generation INTEGER NOT NULL, baseline_reset INTEGER NOT NULL
) STRICT;
CREATE TABLE names(id INTEGER PRIMARY KEY, text TEXT NOT NULL UNIQUE) STRICT;
CREATE TABLE symbols (
 id INTEGER PRIMARY KEY, key BLOB NOT NULL UNIQUE CHECK(length(key)=32),
 file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
 parent INTEGER REFERENCES symbols(id) ON DELETE CASCADE,
 name INTEGER NOT NULL REFERENCES names(id), kind TEXT NOT NULL,
 start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
 start_line INTEGER NOT NULL, start_column INTEGER NOT NULL,
 end_line INTEGER NOT NULL, end_column INTEGER NOT NULL,
 exported INTEGER NOT NULL, signature_hash BLOB, body_hash BLOB, doc_line TEXT NOT NULL
) STRICT;
CREATE INDEX symbols_name ON symbols(name,file,start_byte);
CREATE INDEX symbols_file ON symbols(file,start_byte,id);
CREATE TABLE refs (
 id INTEGER PRIMARY KEY, file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
 enclosing INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 target INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 spelling INTEGER NOT NULL REFERENCES names(id), kind TEXT NOT NULL,
 start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
 start_line INTEGER NOT NULL, start_column INTEGER NOT NULL,
 end_line INTEGER NOT NULL, end_column INTEGER NOT NULL, accuracy TEXT NOT NULL
) STRICT;
CREATE INDEX refs_target ON refs(target,file,start_byte);
CREATE INDEX refs_spelling ON refs(spelling,file,start_byte);
CREATE TABLE imports (
 id INTEGER PRIMARY KEY, file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
 spelling TEXT NOT NULL, local_name INTEGER REFERENCES names(id),
 imported_name INTEGER REFERENCES names(id), target_file INTEGER REFERENCES files(id)
 ON DELETE SET NULL, target_symbol INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL, resolution TEXT NOT NULL
) STRICT;
CREATE TABLE import_candidates (
 import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
 path_key TEXT NOT NULL, PRIMARY KEY(import_id,path_key)
) STRICT;
CREATE INDEX candidates_path ON import_candidates(path_key,import_id);
CREATE VIRTUAL TABLE symbol_fts USING fts5(
 name, split_name, path, container, doc_line, content='', contentless_delete=1
);
CREATE TABLE generations (
 generation INTEGER PRIMARY KEY, observed_unix_ms INTEGER NOT NULL,
 event_serial INTEGER NOT NULL, batch_kind TEXT NOT NULL
) STRICT;
CREATE TABLE observed_commits (
 oid BLOB NOT NULL, generation INTEGER NOT NULL REFERENCES generations(generation),
 PRIMARY KEY(oid,generation)
) STRICT;
CREATE TABLE changes (
 generation INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 file_key BLOB, symbol_key BLOB, path TEXT, kind TEXT NOT NULL,
 pointer_json TEXT, previous_hash BLOB, current_hash BLOB,
 dependent_count INTEGER, dependent_complete INTEGER, dependent_generation INTEGER,
 baseline_reset INTEGER NOT NULL, bulk_json TEXT,
 PRIMARY KEY(generation,ordinal)
) STRICT;
CREATE INDEX changes_file_generation ON changes(file_key,generation,ordinal);
CREATE TABLE watch_directories (
 id INTEGER PRIMARY KEY, descriptor INTEGER NOT NULL UNIQUE,
 path TEXT NOT NULL, identity BLOB NOT NULL
) STRICT;
CREATE TABLE active_batch (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), kind TEXT NOT NULL,
 first_serial INTEGER NOT NULL, last_serial INTEGER NOT NULL,
 distinct_files INTEGER NOT NULL, bulk INTEGER NOT NULL, summary_json TEXT NOT NULL
) STRICT;
CREATE TABLE staged_changes (
 ordinal INTEGER PRIMARY KEY, file_key BLOB NOT NULL,
 payload_json TEXT NOT NULL
) STRICT;
CREATE TABLE authors (
 generation INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 resolved_at_generation INTEGER NOT NULL, hint_json TEXT NOT NULL,
 PRIMARY KEY(generation,ordinal),
 FOREIGN KEY(generation,ordinal) REFERENCES changes(generation,ordinal) ON DELETE CASCADE
) STRICT;
CREATE INDEX authors_resolution ON authors(resolved_at_generation,generation,ordinal);
```

FTS rowid is symbols.id; delete/reinsert in the same file transaction. It stores
names, split identifiers, paths, containers and first doc lines only. SQLite must
support [FTS5 contentless-delete](https://sqlite.org/fts5.html#contentless_delete_tables)
(>=3.43): ordinary DELETE is supported; do not use the legacy FTS delete command.
References retain syntactic call/import/type/value sites, not every identifier token.
Names are interned and GC checks every symbols/refs/imports foreign-key use.

A good->good file transaction compares complete parses, replaces that file's
semantic rows and FTS, repairs affected targets and increments index_generation.
SignatureChanged takes precedence over BodyChanged; unsupported/nonsemantic edits
use FileOnly. Replaced/removed exports invalidate incoming refs to NameOnly before
commit; targets are never reused rowids. New/deleted paths consult import_candidates,
including previously unresolved imports, so appearance of a target repairs its
importers without requiring importer edits. Resolution runs in bounded batches;
Updating remains until invalidations and the observed serial fence are accounted for.

**Good->failed/partial/deferred preserves ONE last-good semantic set** with indexed
hash/generation and explicit Stale coverage plus observed_hash when known. No newly
partial set replaces it and no stale edge counts as current resolved evidence.
Find/outline may return visibly stale pointers; refs/impact exclude stale resolved
edges, with optional NameOnly stale candidates labelled. With no good baseline,
keep file metadata/valid isolated declarations only as Partial, never a complete tree.
On recovery, atomically install the new good set and emit FileOnly with
baseline_reset=true; establish a fresh comparison baseline. Never compare across
the unknown interval to invent Added/Removed/SignatureChanged/BodyChanged. Consecutive
good parses resume semantic diffs. Confirmed deletion removes rows; denied/unreadable
source is Failed/Stale, never Removed. This handles Sol's good->failed->good case
without keeping unbounded historical graphs or fake deletions.

**Initial cold indexing emits NO changes rows.** It establishes an observation
baseline, not millions of additions. Subsequent file activity is grouped into a
source batch: ordinary file-event debounce 15 ms, at most 2 seconds after the
first event before closing that event batch, timers armed only by events. An explicit
HEAD/directory/loss reconcile is ONE logical batch through its completed discovery
fence, however many work quanta it needs; the 2-second event window does not split it.
For <=100 distinct files, provisional
per-file changes live in a bounded SQL staging table, never visible until batch
publication. On file 101, discard provisional symbol rows and switch to one Bulk
row (reason, distinct-file count, optional semantic count, <=5 sample paths,
complete flag). HEAD/directory/overflow reconciles share this rule, including when
the total is discovered incrementally. A slow checkout is not split into separately
published small batches: presence
of registered index.lock/HEAD.lock opens a checkout batch BEFORE HEAD moves, held
through lock removal/HEAD observation and reconciliation. Files update the search
index immediately while the changes publication fence waits. With no observed
Git lock, keep unattributed small event batches provisional for a **10-second
source-event-armed grace**; HEAD movement within that window merges them into ONE
HeadChange Bulk row even below 100 files. More than 100 distinct files inside the
grace also becomes one burst Bulk. A recognized Git checkout remains one logical
batch across work quanta, not a 2-second/100-file series. No per-symbol rows leak
before this grouping decision is known: changes reads use published_generation, separate from index_generation.
Completed large reconciles publish ONE summary even if processing spans quanta.
No lock polling loop: metadata events wake a waiting checkout; an abandoned lock
keeps pending_change_batches/Updating explicit and needs owner/Git inspection,
never automatic removal. The finite grace cannot predict an unobserved custom
checkout whose HEAD update comes later; do not rewrite already published history
or claim perfect checkout detection. This limitation is qualified with slow native
Git checkout before implementation acceptance. The grace delays the change feed,
not the <=200 ms admitted save-to-searchable target.
Interrupted bulk publishes an explicitly incomplete summary, not many ordinary rows.
active_batch has one row and staged_changes shares the normal retention/disk
ceiling. Publish clears both in the same transaction as published_generation;
a crash with an unfinished batch forces reconcile and a labelled incomplete Bulk
summary before reset, never silently advances a resume fence. A normal <=100-file batch is also bounded
by 50,000 change rows and 8,000,000 staging
bytes; hitting either converts it to Bulk. Branch checkout therefore cannot evict
50,000 historical rows merely through its symbol count. Bulk counts are changes
observed in this batch, not attribution to any particular agent.

All cache growth is bounded by actual work, with no maintenance daemon/timer:

- Changes: 30 days of observed activity or 50,000 rows, whichever first; prune at
  activation/commit/drain, advance retention_floor explicitly. Offline physical
  retention can be longer; no timed-deletion promise. Bulk occupies one row.
- Generations: one small row per PUBLISHED batch or author-resolution batch, never
  coverage_json per file save. Retain change anchors plus <=256 commit anchors;
  prune older unreferenced rows and cap at 50,256. Cursor expiry follows the actual
  retained floor; no immortal FK from files to the generations table.
- Authors: exactly one current hint per retained change; updates replace it, never
  append versions. Hint JSON <=2048 bytes, <=8 evidence IDs (both bounds apply); additional evidence
  yields Mixed with an explicit optional omitted count (unknown is None). Cascade with change pruning.
  Late evidence for an expired change is ignored as expired, not resurrected.
- Names/import-candidate garbage: cleanup with bounded SQL batches after row
  replacement/deletion, queued across work quanta and finished before Current;
  stale retained semantic rows keep their necessary names. No unreferenced-name
  accumulation through repeated saves. observed_commits caps at 256 observations;
  older commit baselines become BaselineUnavailable explicitly.
- Per-root disk ceiling: 512,000,000 bytes including DB, WAL, staging and retired
  epochs; host total Atlas home ceiling 2,000,000,000 bytes. Reserve space for status
  before writing; stop admission with a visible budget failure before exceeding
  the ceiling. Max_files=100,000; traversal and database results are streamed.
  Cold extraction <=65,536 rows/file AND <=8,000,000 emitted bytes; qualified host
  profiles impose smaller limits inside their parser arena. JSON coverage has
  fixed reason tags/counters, never a path list proportional to repository size.

Ignore digest changes reconcile eligible files incrementally, remove now-ignored
rows and add newly eligible paths; they NEVER trigger a cold rebuild. Only extractor/
schema changes or explicit owned-cache repair require retirement/full cold indexing.
Abandoned root cleanup runs on explicit unregister/proven deletion events and
bounded after-ready cache activity. Confirm the parent volume is accessible and
the physical root is gone; an unplugged/unreadable mount is not deletion. Preserve
its cache for 30 observed days, then remove only owned files with outside absence
readback. Unknown files or open retired handles produce Pending. No cleanup occurs
on unrelated cold start, or while no Atlas activity exists.

## 4. Lifecycle, native events and cold adoption

The state/coverage pair describes actual observations. Only explicit config
disable maps to disabled; closing host resources does not change that setting. Current means caught up to
an event fence, never full compiler semantics. Public section 50 state mapping is
exhaustive; reasons, progress, coverage and diagnostic accompany the six values.

| Private IndexState | $.atlas.state | Transition/meaning |
| --- | --- | --- |
| NotBuilt | not-built | embedded feature missing; no activation |
| Disabled | disabled | config false; enable -> Dormant |
| Dormant | absent | registered, no IO; explicit activation -> Opening |
| Absent | absent | verified no database; admitted child -> ColdIndexing |
| Opening | updating | validate pointer/scope/schema -> Current/VerificationNeeded/Absent/Unreadable |
| ColdIndexing | updating | owned child; adoption/replay -> Updating, failed child -> Suspended/Unreadable |
| Updating | updating | pending files/invalidations; fenced completion -> Current |
| Current | ready | event -> Updating; loss/restart -> VerificationNeeded |
| VerificationNeeded | updating | explicit reconcile; partial watch remains visible |
| Suspended | updating | resource/root unavailable; explicit host/resource event may retry |
| Unreadable | unreadable | corrupt/scope/IO error; owner repair may reopen |
| Draining | updating | reason draining, Pending on deadline; Closed only after real close |
| Closed | updating | reason closed/offline; new registration/activation required; retained cache is not declared absent |

register validates supplied scope/policy without source traversal. activate queues
an admitted host effect. enqueue coalesces hints without blocking. work_quantum
runs Discover->Read->Parse->Resolve->Diff->Commit->Prune->Checkpoint within allowance;
only complete file transactions commit. next_work is Park without actual work,
Ready with work, or AfterEventDebounce for an event-armed one-shot. reader is scoped;
status is cached metadata. captured_edit accepts exact registered path, before/after
content hashes and trusted evidence ID: None on one side is witnessed absence,
not unknown; both None is invalid. Close is idempotent, reports Pending/Refused and
never claims stuck filesystem IO disappeared at its deadline.

One global low-priority scheduler, one active parse and one global cold child serve
all roots. No per-agent process, thread, parser tree or watch duplication. Event
queue <=150,000 bytes and <=256 path hints shared across roots; overflow is a sticky
root reconcile bit. Discovery/hash scans are streamed and cancellation-aware. Ignore
policy uses nested .gitignore, registered info/exclude and already-loaded global
patterns plus <=32 generated prefixes, together <=32,768 bytes (within metadata share).
No ambient global config filename or environment supplies policy. Ignored subtrees
(.git source contents, node_modules, target, etc. according to rules) are pruned
before traversal/watch installation; registered Git metadata watches are separate.

Watch behavior is native and event-driven; no PollWatcher, periodic rescan, idle
retry, expiry or statistics timer. With no active sessions, release root watches,
SQLite connections, parser and scratch after the batch; the next session triggers
reconciliation. Observed sources carry watch coverage, not persistent Current.

| Adapter | Subscription, race and loss handling |
| --- | --- |
| Linux inotify | Eligible directories only; no IN_OPEN/access events. For a newly created/moved-in directory install its watch BEFORE streaming its contents; events during the scan dirty its serial fence and cause another bounded pass. Watch exhaustion/permission loss sets PartialWatch/VerificationNeeded with watched/unwatched counts, never Current with full coverage. IN_Q_OVERFLOW triggers full eligible-root reconcile. |
| Windows ReadDirectoryChangesW | One recursive root handle, **65,536-byte DWORD-aligned buffer**, shared host IOCP. Data/name/size/write events; no source-read wakes. Zero returned bytes or ERROR_NOTIFY_ENUM_DIR sets sticky full reconcile. Recursive Windows API cannot exclude child subtrees: discard ignored events before queueing; ignored churn can still cause overflow, which must remain visible. No pretense that filtering prevents OS buffer loss. |
| macOS FSEvents | Directory events trigger bounded subtree enumeration/hash comparison; coalesced events with MustScanSubDirs recurse eligible descendants, dropped events trigger full monitored-root reconcile. Root identity loss requires rebind. A directory event is not proof only its immediate children changed. |

The subscribe-before-scan race is documented in [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html).
Windows loss behavior follows [ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw);
coalescing/reconcile follows [Apple's FSEvents guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html).
Across platforms, partial registration reports Coverage.watched_directories,
unwatched_directories and watch_discovery_complete (unknown isn't zero). The host
reads Linux max_user_watches once per activation (not a poll), and supplies a global
WatchBudget: **min(floor(OS limit/8), 6144)** directory watches; unreadable OS limit
uses a labelled conservative 1024 fallback. This is admission, not a promise the
shared per-user OS quota is free: ENOSPC still yields explicit partial coverage.
Keep <=98,304 bytes of compact 16-byte entries (watch descriptor u32, root slot u32, SQLite directory ID u64),
not full paths in RAM. Path/physical identity mapping lives in the bounded cache
watch_directories table (at most the admitted watch count, cleared/rebuilt on
activation/close); a <=32,768-byte event buffer and <=32,768-byte ignore policy
leave 36,160 bytes of the 200,000-byte share for root/adapter metadata. No unbounded
hash-map/path allocation or separate parser connection hides behind watch count.
Windows uses its two 65,536-byte root buffers instead of the Linux map/event arena;
platform-specific layouts must independently qualify within the SAME share.

At most TWO active roots share these limits; excess roots remain partial, supplied
by harness events/session-triggered reconcile. Status also reports per-root
**watch_activation_attempts and watch_limited_activations**, process-lifetime scope
and watch_stats_started timestamp (unknown if the clock is unavailable), so chronic watch exhaustion is observable rather than permanently
"updating" without explanation. Native qualification reports those counts plus
eligible/watched directories for both real corpora and default OS limits; no
frequency claim is invented from a single successful subscription. Native/kernel
buffers and allocator retention are accounted outside the descriptor count in
resource measurements; if a platform cannot fit, reduce admission and report it.
Network/synced roots without reliable identity/events degrade with no polling fallback.

### 4.1 Cold child and atomic epoch discovery

80's approved cold-full-index window has a **64,000,000-byte child peak cap** and
is reported separately; **B4's 25,000,000-byte steady-state measurement is outside
that window**. No aggregate_ceiling_bytes exists: it falsely implied another cold
aggregate limit. Host allocation still targets its steady share; defer cold work
for machine pressure, never merely because parent+child exceeds 25 MB. Only first
index/extractor rebuild/owned repair uses this transient path. Ordinary incremental
updates always stay in-host inside B4; relabelling an edit as rebuild grants no exemption.

Host/se-proc owns exact spawn/birth identity, containment, background priority,
outside memory observation, cancellation and reaping. Atlas produces WorkerRequest
and consumes WorkerEvent, with one-use JobId/root/expected epoch and minimal constructed
environment, no network/provider/session capabilities and no bearer secret in argv.
Private inherited pipe frames <=65,536 bytes; progress follows completed batches,
not heartbeat timers. Whole-job deadline 15 minutes, per-file parse 200 ms. Hard
cap/observed breach or malformed output aborts; no next child until exact prior reap.

The child creates an exclusive staging epoch under the owner directory, checkpoints,
closes SQLite and exits. Parent independently observes exit/reap, validates job,
old epoch, project/root/physical identity, schema/application, extractor/ignore inputs
and staged integrity. Under the cache writer lock it installs the immutable-named
`epochs/<new-epoch>/atlas.db`, then atomically replaces the <=1024-byte **current.json**
pointer {schema,project,root,epoch}. Atomic replacement applies only to this small
pointer; NO open SQLite database is replaced. Independently reopen/read back the
pointer and new DB before acknowledging adoption. Crash leaves a validated old or
new pointer, never a choice by mtime; unreferenced staging remains cleanup-owned.

Every reader, including hostless CLI: read/validate pointer; derive fixed epoch path;
open that epoch RO/no-follow; validate all IDs/schema; reread pointer. If changed,
retry once within the query deadline; alternatively return the valid old epoch with
**epoch_retired=true**, stale coverage and its old epoch cursor. Never turn a swap
into Absent. A new-epoch reader doesn't need old readers to drain. Old handles continue
safe bounded RO queries on their epoch; the retired writer is closed and no new
writes target it. A continuation from a retired epoch on the new pointer refuses
CursorEpochMismatch with a restart remedy, not silently splice graphs.

Delete retired epoch files best-effort only after validation and local handle close;
Windows sharing violations remain explicit retired/Pending bytes. The host need
not discover or kill external CLI PIDs. Keep at most current+ONE retired+ONE staging
epoch, all inside the disk ceiling. If a still-pinned retirement would require a
second retired epoch, refuse/defer the next publication as CacheBusy and keep the
current pointer. Retry cleanup on actual later cache activity/drain, never an idle
timer or guessed PID kill. Unknown files are preserved. Child failure keeps prior
cache visibly stale or Absent if none; only exact owned staging is removed after reap.
Events during cold run coalesce into bounded dirty hints/sticky reconcile; replay
in-host after adoption. Current requires replay plus serial fence, not child exit alone.

### 4.2 Incremental parser admission and honest fallback

Global source cap is **524,288 bytes (512 KiB)** and progress deadline **200 ms**.
Generated markers (@generated, automatically generated, DO NOT EDIT, ASCII case-
insensitive first 4096 bytes) and explicit generated rules defer semantics, keeping
path/text eligibility. Token density alone doesn't prove generated code.

The former universal 16 KiB/100 ms host cap was unmeasured and is withdrawn. Host
admission requires a measured per-grammar/platform profile fitting source, tree,
extraction, grammar loads and retained allocator high-water mark inside its
1,000,000-byte parser share and the overall 2,000,000-byte Atlas share. Profile
limits cannot exceed 512 KiB/200 ms; they may lower source/row/work limits, stated
in coverage. Without a qualified profile, semantics are ParserUnqualified/deferred,
not a guessed promise of fit. Keep last-good rows visibly stale and offer bounded
literal text/path search; never delete the most-edited file's useful baseline just
because it no longer qualifies. No incremental helper process borrows the cold exemption.
Native qualification remains an implementation release blocker, not a reason to
claim this design or compilation passes B4. One parser/tree at a time, release scratch
and close inactive DB handles after work. Stuck source IO remains owned/Pending.

AtlasSource::read_chunk is a safe bounded range reader, not a revision guarantee
across calls. Text queries scan <=32 files and <=262,144 total source bytes INCLUDING
verification reads, in deterministic FileId order and within the query work budget.
They admit at most the first 16,384 bytes of each file per request; no intra-file
continuation. Read that prefix from one no-follow handle, reread/hash the SAME range
and compare bytes/hash plus physical identity before returning hits. A mismatch
returns SourceChangedDuringRead/partial with no accepted hits for that file. This
bounds the extra read cost without claiming stat identity proves content stability.

If the whole file fits that prefix, also verify EOF/size and return a whole-file
content_revision; otherwise the range_hash authenticates only those returned bytes,
CodePointer.content_hash=None/freshness Unknown, and coverage names unscanned bytes.
**Never resume mid-file from identity/offset or stitch chunks across requests.**
Continuation moves to the next FileId, leaving that file's rest explicitly unsearched.
Even an unchanging large file is a bounded prefix search, not exhaustive Text search;
the UI suggests the user's source-search tool for the remainder. A source change
can occur after verification, so editors must still reread. No source text persists.

## 5. Query contracts, precision and pagination

Reads are synchronous bounded operations on the host read worker, never its request
runtime. No subprocess, compiler/LSP, network or write scheduling. Defaults 20 rows,
max 50; 32,768-byte output/default, max 65,536; query work 25 ms, maximum 40 before
formatting. Query text <=1024 UTF-8 bytes, lists/selectors <=32; reject NUL, unknown
tags, zero/invalid limits and overlarge requests. All SQL values bind; restricted
literal metadata-FTS construction escapes input, never accepts SQL/regex/FTS syntax.
Dynamic query memory and returned strings count against the shared arena/response
reservation, not just row counts. Names are stored in full only up to 1024 UTF-8 bytes; an overlong declaration is
excluded from exact semantics with Partial/ByteLimit coverage and a file pointer,
never a falsely exact truncated key. Containers/doc strings have the same explicit
byte accounting; terminal rendering escapes controls.

Every method returns **AtlasResult<Answer<Read<T>>>**, including Page<T> inside
Read for list operations. IndexSummary and snapshot/epoch flags survive Absent,
Unknown and Unreadable. Admission failures before a scoped cache read use outer
SeError. A checked missing path is Read::Absent with checked provenance; unbuilt,
disabled/absent index, partial discovery and unreadable bytes cannot become Present
zero/Absent. Useful partial results use Present plus honest coverage/window stop.
The surface serializer includes index/coverage for every case, with existing
section 50 schema families; it does not replace $.code_changes with prose. Unknown
omission is None, never zero. Complete negative claims need current fenced discovery,
no relevant stale/deferred/failed files and complete applicable language coverage.
Hostless CLI labels VerificationNeeded/StaleSnapshot even when disk recorded Current.

find Symbol ranks ExactName, SplitIdentifier, MetadataFts, ordered by method rank,
normalized full name (bounded sortable key), FileId, byte offset, SymbolId; camel/snake/acronym/Unicode splitting
is deterministic under extractor version. Path mode is metadata only. Text mode is
explicit bounded source scanning as 4.2; default Symbol never silently reads bodies.

refs accepts ID, path+position (smallest containing declaration) or uniquely-qualified
name/path/container. Ambiguity returns <=20 candidate pointers plus omitted count;
missing selector in partial coverage is Unknown, not proof of absence. Order is
resolved first then NameOnly, FileId/site/kind/stable ID. Default includes labelled
NameOnly candidates, not compiler-precision claims; empty kinds means all five.

| Accuracy | Claim | Never inferred |
| --- | --- | --- |
| LexicalBinding | parsed local lexical scope links declaration/use | runtime dispatch, expansion |
| ExplicitImport | supported explicit import/export binding links indexed declaration | package loader/compiler truth |
| NameOnly | spelling candidate/unresolved/dynamic site | a resolved edge |

Coverage counts resolved and NameOnly references separately; report their share,
never describe counting every identifier as cross-file resolution. Stale resolved
edges do not contribute to current resolved counts.

| Language | Declaration/local support | Cross-file support | Explicit partial cases |
| --- | --- | --- | --- |
| JS/JSX | functions/classes/methods/bindings and syntactic call/type sites | static relative ESM/reexports and literal relative require, extension/index candidates | computed members, eval, dynamic import, package exports, prototype dispatch |
| TS/TSX | JS plus interfaces/types/enums/namespaces/type sites | relative ts/tsx/js/jsx and explicit reexports | tsconfig paths/project references, overload selection, conditional types |
| Rust | fn/impl/trait/struct/enum/type/const/static/mod/macro, lexical uses | explicit crate/self/super modules and non-glob aliases | macro expansion, cfg, trait dispatch, extern graph, glob inference |
| Python | def/async def/class/assignment, lexical calls/type names | literal relative imports/registered source-root modules | sys.path mutation, attributes, star import, metaclasses |

Reexports max 8 hops with visited-cycle coverage. External packages stay unresolved;
JSX custom components are value references, lowercase intrinsic tags excluded. No
project code is executed. Tests/impact remain candidates to inspect/run, not a
sound guarantee of every runtime dependent.

impact reverse-BFS default depth 2, valid 1..3; <=512 visited symbols and <=1024 examined
edges, interned integer IDs in the query arena. Result hop paths retain weakest-hop
accuracy. Include NameOnly only with explicit labelling. Return tests separately
using Rust #[test], Python test_ or labelled path heuristics; total row limit includes
tests. **Recompute this bounded BFS per page**, ordered hop depth/dependent stable ID/
site; keyset stores only last result key, no frontier/512-ID cursor. Graph work exhaustion
returns incomplete with an unknown/lower-bound omitted_frontier and NO misleading
continuation promising complete traversal. A next cursor is possible for ordinary
row/byte paging of that bounded graph. Narrow depth/scope for work-limit truncation.

changes returns immutable code facts oldest-first by (generation,ordinal), plus the
current latest author hint (provenance may advance independently). Baseline is saved
cache cursor, previously observed commit or observed Unix time, as OPS requires.
Agent-default baseline comes from its own verified private cursor; owner without one
starts at retained floor with explicit label. No request-triggered git diff/indexing.
Commit must be in <=256 retained observations; repeated commit chooses earliest
retained observation with working-tree label. Time is index observation time, not
Git author time; clock regression makes time baseline unavailable. Unknown/expired
baseline and changed epoch refuse with legal cursor/restart remedy. Bulk facts are
explicitly summarized, so "lossless" means all published change rows, not a fabricated
per-symbol history for a branch switch. Removed pointers describe old bytes. Dependent
counts name the generation/completeness at which they were computed, never fake current.

outline is flat preorder with parent IDs, ordered start_byte/end_byte descending/ID;
paged ancestors may be omitted but their ID remains. Unsupported/deferred/stale
coverage returns metadata/useful partial tree, not an invented empty current tree.
Signature/body None rules apply equally to bodyless declarations and synthetic modules.

### 5.1 Stable live keysets, not per-edit refusal

AtlasCursor is base64url canonical JSON {version,mode,project,root,epoch,query_digest,
last_key,generation_hint[,change_fence]}; **encoded maximum 4096 bytes**, decoded at
most 3072, fitting shared se_types::Cursor. No CBOR/checksum/frontier/resume-ID plan.
Ordering keys use fixed IDs/offsets and a normalized-name prefix of <=256 UTF-8
bytes plus full-name hash/ID tie-breaker, not a potentially 4096-byte path. Full
name equality still uses complete stored bounded names; a sortable prefix never
claims truncated-name equality. This keeps all keysets within the cursor bound.
Session scope authorizes the read; cursor is data, not a capability. Digest covers
mode/filter/order/selector/viewer, not requested page size. Validate lengths/types/
version/domain before use; shared Cursor isn't an unchecked cast to AtlasCursor.
Malformed/foreign-root/filter cursors refuse InvalidCursor/QueryMismatch, epoch
replacement refuses CursorEpochMismatch, retained-row expiry refuses CursorExpired.

**Ordinary saves never cause CursorSnapshotChanged.** Non-change queries use stable
keyset order across generations; if generation differs, return snapshot_advanced=true.
Moved/replaced/deleted keys may affect live-view coverage: mark window incomplete/
omission unknown and offer a fresh first page for exhaustive negative claims. No
OFFSET shifting and no promise of one frozen graph across pages. Changes fixes a
published change fence for chronological code facts, with latest-at-read author
metadata and snapshot_advanced when attribution advances. The first response binds
its fence; new rows wait for the next changes invocation. Resume uses its own fresh
fence and does not inherit this query continuation. During epoch adoption a returned
old answer also sets epoch_retired; restarting uses the new pointer explicitly.

## 6. Resume: file groups, late evidence and delivered-only CAS

resume_code is a private read port, not a sixth Atlas operation. Input is verified
viewer, saved cursor/revision and <=32 recent edited SymbolIds. Output `items` is
**$.code_changes: an array of <=5 ResumeChange values**, never pre-rendered text.
Group edits by FILE, aggregate kinds/change count, one latest pointer and a named
dependent count; Bulk is one item. Core renders/serializes the items within its
<=600 UTF-8-byte code-context allocation (including status/omission/retrieval text).
Atlas port must select items that fit that allocation; core may further omit whole
items, never silently cut a mandatory label. The compact changes-range cursor has
no last name/path/frontier and its retrieval text is charged to the SAME 600 bytes;
if even status plus required retrieval cannot fit, return BudgetExceeded/no advance,
not a hidden oversized section or an omitted legal route. Delivery/CAS metadata
is out-of-model control data, not extra uncharged model context.
Total resume wall budget <=20 ms, SQL
<=5 ms, including a cold connection/cold cache: unmeasured until native qualification.
On budget failure preserve the private cursor, show BudgetExceeded, keep core resume
working. Core can allocate less; Atlas doesn't take private-context capacity itself.

Capture one published fence and group qualifying files in one SQL snapshot.
Index changes by file/generation and authors by resolved_at_generation; union the
code/author generation ranges without scanning an unbounded file table. Scan at
most 512 candidate rows/32 file groups inside the time budget; reaching that bound
is incomplete, with unknown omitted count, never a checked Zero. Rank
known OTHER-agent changes affecting the viewer's recent symbols, then other known
other-agent files, newest first; Bulk is labelled repository activity, never another
agent's work. At render/query time exclude Captured(viewer), and **exclude Unknown/
Mixed from other-agent news**, reporting an explicit unattributed omitted count.
No current session, mtime, blame or filename implies author. Bash/formatter changes
without captured before/after evidence remain unattributed, not false other-agent news.

Captured hints require exact path AND before/after hashes plus trusted evidence ID.
Matching evidence from one distinct agent is Captured (select a stable evidence ID);
conflicting agents are Mixed, never a confident guess. Late evidence replaces the
single authors row, increments metadata generation and last_author_generation of
the affected file, without inventing another code edit. Resume scans files whose
last_code_generation OR last_author_generation exceeds its saved fence; late known
other-agent attribution can therefore surface an older edit, labelled
late_attribution=true. Late self evidence never becomes news. Unattributed facts
are still available through explicit changes. Expired facts can't be reintroduced.
A previously delivered true other-agent hint later becoming Mixed is corrected in
explicit changes/status; provenance uncertainty is visible, no claim of immutable author truth.

Available, checked Zero, NeverIndexed, Disabled, Unreadable, BaselineGap, Updating and
BudgetExceeded differ. Zero needs a valid baseline and complete relevant range;
no attributed items plus unattributed omissions is NOT "nothing changed". No old
64-ID plan or thirteen-resume drain: newest groups can appear each time.

The digest is a summary, not lossless delivery of every edit. `omitted_since` is
a changes-range cursor containing
the old window lower bound AND this response's published upper fence for explicit
`atlas changes --since CURSOR` retrieval; it is offered whenever digest items omit
files/unknown attribution. After the section is ACTUALLY delivered, advance resume
to that fence even if the summary intentionally omitted files, while the explicit
changes feed remains independent/lossless within retention. New arrivals beyond
the fence remain for next resume. Don't advance on query, packet construction,
timeout, dropped response or a section wholly omitted without its status/retrieval.

Core persists via private **compare_and_set(viewer, delivery EventId, ResumeAdvance)**:
expected old cursor AND revision must match; next cursor is the offered fence for
the same root/epoch, never backward. Delivery EventId must identify successful
context delivery for this offer/viewer, not arbitrary event existence. Offer ID
makes replay idempotent (AlreadyApplied); concurrent stale offers return Stale and
recompute from the current cursor, never double-consume or overwrite newer progress.
The cursor transaction belongs to core's store, never an Atlas write during resume.
A delivery-capable adapter records delivery before CAS; a consumer without an
acknowledgement keeps the old cursor and may repeat the summary. Cancellation and
privacy deletion invalidate old-epoch offers. The bounded offer/delivery association
has the same core-private retention as its saved cursor, no new Atlas history table.

## 7. One error contract and honest cause/remedy

Outer errors use shared SeError; DTO diagnostics use cloneable **ErrorBody**
(AtlasFailure), never a noncloneable internal causal chain. IndexSummary/Coverage
remain cloneable/equatable. Local AtlasErrorCode classifies implementation causes
only; it allocates no second wire catalog. Detail <=1024 bytes, relative paths,
no source bodies/secrets/private absolute home paths. Every local cause maps
exhaustively to typed shared detail; no catch returns an empty vector.

| Local cause | Shared catalog mapping | Cause and legal action |
| --- | --- | --- |
| FeatureDisabled | FeatureDisabled | explicitly disabled; config set atlas.enabled true |
| EmbeddedUnavailable | FeatureNotBuilt | use feature-enabled standalone build |
| ConfigurationInvalid | ConfigValueInvalid | correct the named project policy |
| RootUnavailable | RepoNotFound | restore registered physical source |
| RootIdentityChanged | RevisionConflict | inspect and explicitly rebind |
| CacheIo, CacheCorrupt, CacheScopeMismatch, CacheLinkRefused | AtlasUnreadable | owned cache IO/integrity/scope failure; doctor or inspect location, never source deletion |
| CacheTooNew | ConfigVersionUnsupported | preserve cache, upgrade binary |
| CacheBusy | AtlasResourceBudget | cache reader/lock/retired-epoch capacity unavailable, resource names that capacity with requested=1/available=0; retry after readers release it or use bounded text |
| InvalidPath | AtlasPathOutsideRoot | use registered root-relative path |
| UnsupportedPathEncoding, InvalidQuery, InvalidLimit | UsageInvalidValue | correct encoding/query/bounds |
| IndexAbsent | AtlasIndexAbsent | enable config schedules background first index |
| PathUnknown | AtlasPathUnknown | inspect path-mode result and coverage |
| SymbolUnknown | AtlasSymbolUnknown | search symbol; partial coverage stays Unknown |
| AmbiguousSymbol | AtlasSymbolAmbiguous | qualify returned candidates |
| LanguageUnsupported | AtlasLanguageUnsupported | bounded literal text search |
| FileOverBudget | AtlasFileOverBudget | actual per-file size/work admission; bounded text remains available |
| InvalidCursor, CursorQueryMismatch, CursorEpochMismatch | CursorInvalid | restart matching query/current epoch |
| CursorExpired | CursorExpired | choose retained baseline, never silent reset |
| BaselineUnavailable | CursorInvalid | observed commit/time unavailable; use returned cache cursor |
| WatchUnavailable, SourceChangedDuringRead | AtlasIndexing | explicitly partial updating; reconcile on next admitted host/source event |
| ResourceBudgetUnavailable | AtlasResourceBudget | GLOBAL reservation unavailable, resource/requested/available; wait for pressure or use bounded text |
| ParserFailed | AtlasParseFailed | grammar failure, path/language/reason; bounded text/report diagnostic |
| SourceReadFailed | AtlasSourceUnreadable | source path permission/IO, restore SOURCE access |
| ShuttingDown | Cancelled | explicit root/host drain cancels this Atlas operation; status says updating/draining and a later activation may retry |
| Cancelled | Cancelled | explicit cancellation; retry if still wanted |
| InternalInvariant | Internal | report diagnostic; preserve last safe cache |
| WorkerLost, WorkerProtocol | TaskFailed | exact worker lost/invalid frames; reap and inspect owned staging |
| WorkerLeaseStale | RevisionConflict | discard superseded job/epoch result |
| WorkerDeadline | DeadlineExceeded | actual cold deadline; preserve cache and inspect cause before retry |

Section 50 and the accepted main catalog supply the typed AtlasResourceBudget,
AtlasParseFailed and AtlasSourceUnreadable details/messages/remedies. Integration must use those approved Detail variants, not silently
map to AtlasFileOverBudget: a global shortage isn't an oversized file; a grammar
failure isn't a file limit; a source read failure isn't "can't read atlas.db".
AtlasErrorDetail reexports shared Detail, so constructor inputs retain typed
resource/count/path/language/cause fields rather than generic strings that would
need reparsing. AtlasErrorCode is only local classification; mismatch with the
selected typed detail is an InternalInvariant. The crate imports this accepted
catalog directly; it introduces no replacement
error types or runtime mapping implementation in this declaration-only pass.

## 8. Close, privacy and removal

Close stops admission, disarms watches, cancels/reaps the exact cold child, finishes
or rolls back the file transaction, releases parser and closes local readers/writer.
Pending IO leaves Draining/Pending; it doesn't become Closed at a deadline. All
jobs/handles belong to a host generation; replacement hosts reject stale jobs.
External RO epoch handles can outlive local Closed: remove_cache reports their
retired files/Pending and never claims those copies erased. Unknown files survive.

remove_cache verifies owner/root identity, removes only known pointer/epoch DB/WAL/
SHM/staging names after local Closed and readbacks their absence from outside the
writer. No recursive arbitrary-directory erase, source/.git/provider configuration
or authoritative history removal. forget_evidence cancels affected jobs, retires
all affected epochs, invalidates old cursor/offers and requires outside absence
before claiming this Atlas copy gone. User source/provider transcript residuals
are separately named. Pinned epochs/unreadable paths remain incomplete privacy
work, not a completed erase or a forced kill of an external CLI. No retired epoch
can become current again merely by an old completion/offer arriving.

## 9. Budgets, measurements and five journeys

All budget MB are decimal bytes; KiB is labelled explicitly. Proposed in-host Atlas
allocation is exactly **2,000,000 bytes** across ALL roots, not per connection/root:

| Allocation | Bytes | Bound |
| --- | ---: | --- |
| SQLite + query | 500,000 | two 131,072-byte caches, two <=16,384-byte statement allowances, 98,304-byte query arena, remaining 106,784 for connection/SQLite overhead |
| Source/parser/extraction/grammar | 1,000,000 | one measured admission profile, including retained allocator pages |
| Coalesced work queue | 150,000 | <=256 hints, overflow becomes sticky reconcile |
| Native watches/root/ignore metadata | 200,000 | <=2 active roots, path map cap and bounded policy |
| Remaining allocator/accounting slack | 150,000 | not an extra pool or a new parser |

These are proposed reservations, NOT measurements. A profile that exceeds one
share must reduce admission or stay deferred; unused other-core memory and 80's
4.5 MB reserve are not silently borrowed. No per-root parser/tree/cache pool. Source,
SQL response data and output serialization ownership must avoid overlapping copies
beyond these reservations; native adapters include their buffers and kernel charges
in the external measurement. Global root registration bounds also count here.

80's standalone spend 20.5 MB + reserve 4.5 MB is **25,000,000 bytes steady-state (B4)**.
Cold child **<=64,000,000 peak** is separately reported only during its finite
exception window, then reaped. B3 is zero persistent embedded processes/one standalone
daemon/zero per-agent helpers. Embedded Atlas off adds no grammar/DB/watcher at
startup; B1 <=30 MB and B2 <=100 ms/first authenticated bind are core budgets.
Settled Atlas contributes zero timers, CPU and context-switch wakes; B5 <60 CPU ms/
60 seconds and B6 <=1 context switch/s no session, <=2 one session remain whole-host
limits. Target save-to-searchable <=200 ms for ADMITTED small updates, query p95 <=50 ms;
parse deadline 200 ms is a cancellation ceiling, not proof debounce+IO+parse meets
latency. The six CORE CLI read p95 targets are strictly <20 ms with 30 samples each;
Atlas's query target isn't a replacement acceptance oracle.

Linux prototype (shared host, not revised-design qualification): StateEngine 6,179
files / 1,356,850 lines, cold 165.35 s, peak 19.89 MiB, settled 10.60 MiB, DB 275.79 MiB.
Current Rust SE Code 2,917 files / 851,724 lines, 72.30 s, peak 62.04 MiB, settled
11.45 MiB, DB 124.80 MiB. Full bodies/every identifier inflated the old DBs; neither
is retained here. That SE Code peak was **65,048,576 bytes**, exceeding the new
64,000,000 cap. A 958,433-byte generated Rust file alone peaked 59.25 MiB, motivating
source/generated admission but NOT proving a smaller file cap fits the parent.
Eight external-read save witnesses had p95 66.50/98.60 ms. Quiet 60 s endpoint deltas
were 0 CPU ticks/0 switches in 2 threads: useful proxy, not official oracle.
20-sample warm/CLI query p95: StateEngine def 0.140/7.50 ms, refs 0.269/12.08,
impact 1.026/16.15, old full-body FTS 6.437/26.01; Rust SE Code def 0.072/10.60,
refs 0.115/7.83, impact 0.028/9.75, FTS 1.845/13.45. These don't predict metadata-only
FTS or qualify 30-run core budgets. Full reference:
`/mnt/nvme/stateengine/5e-rust-atlas-s5-20261030/S5-REPORT.md`.

| Journey | Atlas behavior | Core boundary |
| --- | --- | --- |
| J1 Install | correct optional SQLite/grammar linkage, no Node | no index/child/watch at install/start |
| J2 Adopt/real work | explicit enable schedules after-ready cold work | launch/bind/work succeed absent/failed/deferred Atlas |
| J3 Come back | <=5 file groups, honest omissions and delivery CAS | no query indexing; zero/unknown/unreadable distinct |
| J4 Two agents | one source index, exact captured provenance | private cursor/revision belongs only to verified viewer |
| J5 Remove | reap/close/remove owned caches, outside absence | stuck IO/unknown files/pinned epochs reported, source preserved |

Five core journeys require neither Atlas enabled nor cold index. Native optional
qualification must exercise Windows/macOS/Linux, CLI/MCP and both harnesses; attended/
autonomous use the same readers and host effects. There is no autonomous renewer.
Read/write mirror: scheduler alone writes; all consumers share query contracts;
close/privacy covers writer AND readers/retired epochs. Reviewer-owned checks need
normal edit between pages, branch-switch bulk, initial zero changes, late own/other
evidence, concurrent resume CAS, good->failed->good/bodyless definitions, same-size
edits, linked worktrees, new-directory race, overflow/coalesced reconcile, cold
swap with external Windows reader, ignore growth/GC, absence/unknown/unreadable,
external save readback, idle and real removal. No author tests/new guards/process
documents are added. Compilation and static checks establish declarations only.

## 10. Cross-section integration and implementation blockers

This revision uses accepted main shared types directly. Source::Atlas and prefixed
RootId/CacheEpoch are resolved by se-types; there is no stale local clone or request
to invent a second source. Remaining work before implementation approval:

1. Core cannot import se-atlas. Section10 publishes the five query request/result
   DTOs, ResumeChange/ResumeCode/ResumeAdvance and the CodeIndex/ResumeCursorStore ports
   in shared se-types::code; Atlas reexports them. Native lifecycle/parser/source
   declarations stay local. This appendix is the assigned ownership draft, not a
   competing wire schema or permission for core->Atlas dependency. Surface serializers
   preserve Answer<Read<T>> metadata and the array code_changes contract.
2. The accepted catalog now supplies resource/parser/source causes. Implementation
   uses those typed Details directly, including named cache-capacity shortage;
   shutdown is cancellation, not an unreachable runtime. No catalog blocker remains.
3. Windows/macOS/Linux native measurements establish the 2,000,000-byte host share,
   parser grammar retention, cold 64,000,000 peak, event coverage limits and cold-
   connection resume 20 ms/SQL 5 ms. Failure means visibly deferred semantics + bounded
   text/path fallback, never a budget increase or incremental child by assumption.
4. Host/core owners connect explicit config-enable after-ready effect, generation-
   scoped worker reap/pointer adoption and delivery-record-backed private CAS.
   Standalone/embedded entry paths share these contracts; embedded stays off alpha.

Commit/time baselines and bounded Text remain because OPS explicitly admits them;
we simplified their storage/cursor rather than silently deleting operations. The
64-ID plan, author-version history and CBOR/checksum are removed. No runtime function
bodies, todo/unimplemented placeholders, SQL executor or test implementation appear
in the crate below.

## Appendix A — complete public Rust declarations

These are the exact formatted source files, not abridged examples. All callable
signatures are trait declarations; behavior awaits design approval.

### crates/se-atlas/src/lib.rs

```rust
//! Compile-only Atlas contract. See docs/design/60-atlas.md.
//! No indexer, watcher, SQL executor, runtime stub or transport is implemented.

#![allow(dead_code, reason = "Declarations only until design approval")]

pub mod errors;
pub mod lifecycle;
pub mod model;
pub mod queries;
```

### crates/se-atlas/src/errors.rs

```rust
pub use se_types::{Detail as AtlasErrorDetail, ErrorBody as AtlasFailure, SeError as AtlasError};

pub type AtlasResult<T> = Result<T, AtlasError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtlasErrorCode {
    FeatureDisabled,
    ConfigurationInvalid,
    RootUnavailable,
    RootIdentityChanged,
    CacheIo,
    CacheCorrupt,
    CacheTooNew,
    CacheScopeMismatch,
    CacheBusy,
    CacheLinkRefused,
    InvalidPath,
    UnsupportedPathEncoding,
    InvalidQuery,
    InvalidLimit,
    IndexAbsent,
    PathUnknown,
    SymbolUnknown,
    AmbiguousSymbol,
    LanguageUnsupported,
    FileOverBudget,
    InvalidCursor,
    CursorEpochMismatch,
    CursorExpired,
    CursorQueryMismatch,
    BaselineUnavailable,
    WatchUnavailable,
    ResourceBudgetUnavailable,
    SourceReadFailed,
    SourceChangedDuringRead,
    ParserFailed,
    ShuttingDown,
    Cancelled,
    InternalInvariant,
    EmbeddedUnavailable,
    WorkerLost,
    WorkerProtocol,
    WorkerLeaseStale,
    WorkerDeadline,
}

/// One wire error remains se-types::SeError. The final central Code allocation
/// maps every AtlasErrorCode exhaustively to typed shared Detail. A mismatched
/// cause/detail is an invariant failure, never a generic string-payload escape.
pub trait AtlasErrors {
    fn error(&self, code: AtlasErrorCode, detail: AtlasErrorDetail) -> AtlasError;
}
```

### crates/se-atlas/src/model.rs

```rust
use crate::errors::AtlasFailure;
use se_types::{AgentId, EventId, ProjectId};
pub use se_types::{AtlasRootId as RootId, IndexEpochId as CacheEpoch};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AtlasJobId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChangeId {
    pub generation: Generation,
    pub ordinal: u32,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SymbolId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentHash(pub [u8; 32]);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativePath(pub(crate) String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasCursor(pub(crate) String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryText(pub(crate) String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Rust,
    Python,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    Module,
    Namespace,
    Class,
    Interface,
    Trait,
    Struct,
    Enum,
    TypeAlias,
    Function,
    Method,
    Constant,
    Static,
    Variable,
    Parameter,
    Field,
    EnumVariant,
    Macro,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    Call,
    Import,
    Export,
    TypeUse,
    ValueUse,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Accuracy {
    LexicalBinding,
    ExplicitImport,
    NameOnly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageReason {
    UnsupportedLanguage,
    UnsupportedEncoding,
    Generated,
    SourceBytesLimit,
    ParseWorkLimit,
    FileCountLimit,
    ParseErrors,
    ReadFailure,
    ChangedDuringRead,
    UnresolvedImport,
    DynamicDispatch,
    StaleSnapshot,
    TimeLimit,
    ResultLimit,
    ByteLimit,
    WatchLoss,
    PartialWatch,
    ParserUnqualified,
    BaselineReset,
    BulkChange,
    RetentionGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Position {
    pub line: u32,
    pub byte_column: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: Position,
    pub end: Position,
    pub start_byte: u64,
    pub end_byte: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotFreshness {
    Current,
    Stale,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodePointer {
    pub file: FileId,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub content_hash: Option<ContentHash>,
    pub freshness: SnapshotFreshness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileCoverage {
    Indexed,
    Partial {
        reasons: Vec<CoverageReason>,
    },
    Deferred {
        reason: CoverageReason,
    },
    Failed {
        error: AtlasFailure,
    },
    Stale {
        reason: CoverageReason,
        last_good_generation: Generation,
        observed_hash: Option<ContentHash>,
        diagnostic: Option<AtlasFailure>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coverage {
    pub discovered_files: u64,
    pub indexed_files: u64,
    pub partial_files: u64,
    pub deferred_files: u64,
    pub failed_files: u64,
    pub discovery_complete: bool,
    pub stale_files: u64,
    pub resolved_references: u64,
    pub name_only_references: u64,
    pub watched_directories: u64,
    pub unwatched_directories: u64,
    pub watch_discovery_complete: bool,
    /// Process-lifetime counters; status reports scope/reset, never implies history.
    pub watch_stats_started: Option<se_types::UnixMicros>,
    pub watch_activation_attempts: u64,
    pub watch_limited_activations: u64,
    pub reasons: Vec<CoverageReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexState {
    NotBuilt,
    Disabled,
    Dormant,
    Absent,
    Opening,
    ColdIndexing {
        job: AtlasJobId,
        discovered_files: u64,
    },
    Updating {
        pending_files: u64,
        pending_change_batches: u32,
        discovery_complete: bool,
    },
    Current,
    VerificationNeeded {
        reason: CoverageReason,
    },
    Suspended {
        reason: AtlasFailure,
    },
    Unreadable {
        error: AtlasFailure,
    },
    Draining,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSummary {
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<Generation>,
    pub state: IndexState,
    pub coverage: Coverage,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer<T> {
    pub index: IndexSummary,
    pub snapshot_advanced: bool,
    pub epoch_retired: bool,
    pub data: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindMethod {
    ExactName,
    SplitIdentifier,
    MetadataFts,
    Text,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeHit {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub method: FindMethod,
    pub accuracy: Option<Accuracy>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    pub site: CodePointer,
    pub kind: ReferenceKind,
    pub spelling: String,
    pub enclosing: Option<SymbolId>,
    pub resolved_target: Option<SymbolId>,
    pub accuracy: Accuracy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactHop {
    pub from: SymbolId,
    pub to: SymbolId,
    pub site: CodePointer,
    pub accuracy: Accuracy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependent {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub hops: Vec<ImpactHop>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Impact {
    pub dependents: Vec<Dependent>,
    pub tests: Vec<Dependent>,
    pub omitted_frontier: u64,
    pub frontier_count_complete: bool,
    pub next: Option<AtlasCursor>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorHint {
    Captured {
        agent: AgentId,
        evidence: EventId,
    },
    Mixed {
        evidence: Vec<EventId>,
        omitted: Option<u64>,
    },
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Added,
    Removed,
    SignatureChanged,
    BodyChanged,
    FileOnly,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependentCount {
    pub count: u64,
    pub at_generation: Generation,
    pub complete: bool,
    pub reason: Option<CoverageReason>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeEdit {
    pub id: ChangeId,
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub kind: ChangeKind,
    pub baseline_reset: bool,
    pub previous_hash: Option<ContentHash>,
    pub author: AuthorHint,
    pub dependents: DependentCount,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkReason {
    HeadChange,
    FilesystemBurst,
    IgnoreReconcile,
    WatchReconcile,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkChange {
    pub id: ChangeId,
    pub reason: BulkReason,
    pub files: u64,
    pub semantic_changes: Option<u64>,
    pub sample_paths: Vec<RelativePath>,
    pub complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeChange {
    Edit(Box<CodeEdit>),
    Bulk(BulkChange),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceAtlasState {
    NotBuilt,
    Disabled,
    Absent,
    Updating,
    Ready,
    Unreadable,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutlineSymbol {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outline {
    pub file: CodePointer,
    pub language: Option<Language>,
    pub coverage: FileCoverage,
    pub symbols: Vec<OutlineSymbol>,
    pub complete: bool,
    pub next: Option<AtlasCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheLocation {
    pub directory: PathBuf,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePointer {
    pub schema: u32,
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: CacheEpoch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitMetadataRegistration {
    pub physical_git_directory: PathBuf,
    pub physical_common_directory: PathBuf,
    pub git_directory_identity: [u8; 32],
    pub common_directory_identity: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRegistration {
    pub project: ProjectId,
    pub root: RootId,
    pub canonical_source_root: PathBuf,
    pub cache: CacheLocation,
    pub git_metadata: Option<GitMetadataRegistration>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryBudget {
    pub max_results: u16,
    pub max_bytes: u32,
    pub work: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseBudget {
    pub max_source_bytes: u32,
    pub max_rows: u32,
    pub max_work: Duration,
    pub reserved_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IgnorePolicy {
    pub global_patterns: Vec<String>,
    pub generated_prefixes: Vec<RelativePath>,
    pub digest: ContentHash,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchBudget {
    /// Global host policy shared by roots, not a per-root allowance.
    pub max_directories: u32,
    pub max_mapping_bytes: u32,
    pub observed_os_limit: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasPolicy {
    pub ignore: IgnorePolicy,
    pub watch: WatchBudget,
    pub enabled: bool,
    pub max_files: u32,
    pub parse: ParseBudget,
    pub total_reserved_bytes: u32,
    pub change_retention_days: u16,
    pub max_change_rows: u32,
    pub max_cache_bytes: u64,
}
```

### crates/se-atlas/src/queries.rs

```rust
use crate::{errors::AtlasResult, model::*};
use se_types::{AgentId, Page, Read};

#[derive(Debug)]
pub struct SearchScope {
    pub paths: Vec<RelativePath>,
    pub languages: Vec<Language>,
}
#[derive(Debug)]
pub enum SymbolSelector {
    Id(SymbolId),
    At {
        path: RelativePath,
        position: Position,
    },
    Name {
        name: QueryText,
        path: Option<RelativePath>,
        container: Option<QueryText>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchKind {
    Symbol,
    Text,
    Path,
}
#[derive(Debug)]
pub struct FindQuery {
    pub kind: SearchKind,
    pub query: QueryText,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct RefsQuery {
    pub symbol: SymbolSelector,
    pub kinds: Vec<ReferenceKind>,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct ImpactQuery {
    pub symbol: SymbolSelector,
    pub depth: u8,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
#[derive(Debug)]
pub enum ChangeBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    ObservedUnixMillis(i64),
}
#[derive(Debug)]
pub struct ChangesQuery {
    pub since: ChangeBaseline,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct OutlineQuery {
    pub path: RelativePath,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}

#[derive(Debug)]
pub struct ResumeRequest {
    pub viewer: AgentId,
    pub saved_cursor: Option<AtlasCursor>,
    pub cursor_revision: u64,
    pub recently_edited_symbols: Vec<SymbolId>,
}
#[derive(Debug)]
pub enum ResumeCodeState {
    Available,
    Zero,
    NeverIndexed,
    Disabled,
    Unreadable,
    BaselineGap,
    Updating,
    BudgetExceeded,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeOfferId(pub [u8; 16]);
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeChange {
    File {
        pointer: CodePointer,
        kinds: Vec<ChangeKind>,
        changes: u64,
        author: AuthorHint,
        dependents: DependentCount,
        late_attribution: bool,
        baseline_reset: bool,
    },
    Bulk(BulkChange),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeAdvance {
    pub offer: ResumeOfferId,
    pub expected_cursor: Option<AtlasCursor>,
    pub expected_revision: u64,
    pub next_cursor: AtlasCursor,
    pub fence: Generation,
}
#[derive(Debug)]
pub enum ResumeCursorCommit {
    Applied { revision: u64 },
    AlreadyApplied { revision: u64 },
    Stale { actual_revision: u64 },
}
/// Implemented by core's private store. Atlas never writes the viewer cursor.
/// Delivery must identify a successful context delivery, not mere construction.
pub trait ResumeCursorStore {
    fn compare_and_set(
        &mut self,
        viewer: &AgentId,
        delivered: &se_types::EventId,
        advance: &ResumeAdvance,
    ) -> AtlasResult<ResumeCursorCommit>;
}
#[derive(Debug)]
pub struct ResumeCode {
    pub index: IndexSummary,
    pub state: ResumeCodeState,
    /// The surface's $.code_changes array, never a pre-rendered string.
    pub items: Vec<ResumeChange>,
    pub omitted: Option<u64>,
    pub unattributed_omitted: Option<u64>,
    pub complete: bool,
    /// Lossless explicit changes retrieval starts here, independently of digest delivery.
    pub omitted_since: Option<AtlasCursor>,
    pub advance: Option<ResumeAdvance>,
    pub diagnostic: Option<crate::errors::AtlasFailure>,
}

/// Bound by the host to one registered project/worktree and authorized source
/// scope. These methods never enable, open-for-write, index or launch anything.
pub trait AtlasQueries {
    fn find(&self, query: &FindQuery) -> AtlasResult<Answer<Read<Page<CodeHit>>>>;
    fn refs(&self, query: &RefsQuery) -> AtlasResult<Answer<Read<Page<Reference>>>>;
    fn impact(&self, query: &ImpactQuery) -> AtlasResult<Answer<Read<Impact>>>;
    fn changes(&self, query: &ChangesQuery) -> AtlasResult<Answer<Read<Page<CodeChange>>>>;
    fn outline(&self, query: &OutlineQuery) -> AtlasResult<Answer<Read<Outline>>>;
    fn resume_code(&self, request: &ResumeRequest) -> AtlasResult<ResumeCode>;
    fn status(&self) -> IndexSummary;
}

/// Required constructors/decoders, declared without implementation until design
/// approval. JSON/CLI adapters call these same validations.
pub trait AtlasValidation {
    fn relative_path(&self, value: String) -> AtlasResult<RelativePath>;
    fn query_text(&self, value: String) -> AtlasResult<QueryText>;
    fn cursor(&self, value: String) -> AtlasResult<AtlasCursor>;
    fn query_budget(&self, results: u16, bytes: u32) -> AtlasResult<QueryBudget>;
    fn selector(&self, value: SymbolSelector) -> AtlasResult<SymbolSelector>;
}

/// Implemented for RelativePath, AtlasCursor and QueryText after approval.
pub trait AtlasText {
    fn as_str(&self) -> &str;
}
```

### crates/se-atlas/src/lifecycle.rs

```rust
use crate::{errors::AtlasResult, model::*, queries::AtlasQueries};
use se_types::{AgentId, EventId};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileReason {
    ConfigEnabled,
    FirstSession,
    HostRestart,
    WatchOverflow,
    WatchFailure,
    IgnoreRulesChanged,
    GitHeadChanged,
    GitActivity,
    DirectoryChanged,
    ExtractorChanged,
    ConfigurationChanged,
}
#[derive(Debug)]
pub enum SourceHint {
    FileChanged(RelativePath),
    FileRemoved(RelativePath),
    Rename {
        from: RelativePath,
        to: RelativePath,
    },
    Reconcile(ReconcileReason),
}
#[derive(Debug)]
pub struct EditEvidence {
    pub agent: AgentId,
    pub event: EventId,
    pub path: RelativePath,
    pub before: Option<ContentHash>,
    pub after: Option<ContentHash>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleReceipt {
    Queued,
    Coalesced,
    ReconciliationRequired,
    Disabled,
    Closing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkPhase {
    Discover,
    Read,
    Parse,
    Resolve,
    Diff,
    Commit,
    Prune,
    Checkpoint,
}
#[derive(Debug)]
pub struct WorkReport {
    pub root: RootId,
    pub phase: WorkPhase,
    pub completed_files: u32,
    pub remaining_known: u32,
    pub generation: Option<Generation>,
    pub state: IndexState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextWork {
    Park,
    Ready,
    AfterEventDebounce(Duration),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Disabled,
    HostDrain,
    ProjectRemoved,
    PrivacyErasure,
}
#[derive(Debug)]
pub enum CloseResult {
    Closed,
    Pending { in_flight: u32 },
    Refused { error: crate::errors::AtlasFailure },
}
#[derive(Debug)]
pub struct CacheRemoval {
    pub root: RootId,
    pub database_absent: bool,
    pub wal_absent: bool,
    pub shm_absent: bool,
    pub remaining_paths: Vec<std::path::PathBuf>,
}

/// Host-internal lifecycle, never added to OPS as another user operation.
/// A single host-owned low-priority worker owns this mutable value.
pub trait AtlasController {
    type Reader: AtlasQueries;
    fn register(
        &mut self,
        root: RootRegistration,
        policy: AtlasPolicy,
    ) -> AtlasResult<IndexSummary>;
    fn activate(&mut self, root: RootId, reason: ReconcileReason) -> AtlasResult<ScheduleReceipt>;
    fn enqueue(&mut self, root: RootId, hint: SourceHint) -> AtlasResult<ScheduleReceipt>;
    fn captured_edit(
        &mut self,
        root: RootId,
        evidence: EditEvidence,
    ) -> AtlasResult<ScheduleReceipt>;
    fn work_quantum(&mut self, allowance: Duration) -> AtlasResult<Option<WorkReport>>;
    fn next_work(&self) -> NextWork;
    fn reader(&self, root: RootId) -> AtlasResult<Self::Reader>;
    fn close(
        &mut self,
        root: RootId,
        reason: CloseReason,
        deadline: Duration,
    ) -> AtlasResult<CloseResult>;
    fn remove_cache(&mut self, root: RootId) -> AtlasResult<CacheRemoval>;
    fn forget_evidence(&mut self, root: RootId, events: &[EventId]) -> AtlasResult<CacheRemoval>;
    fn take_child_request(&mut self) -> AtlasResult<Option<WorkerRequest>>;
    fn child_event(&mut self, event: WorkerEvent) -> AtlasResult<ScheduleReceipt>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerPurpose {
    ColdIndex,
}
#[derive(Debug)]
pub struct WorkerReservation {
    /// B4 is measured outside the separate cold window.
    pub host_steady_ceiling_bytes: u64,
    /// Hard cold-child peak, separately observed during the window.
    pub child_peak_bytes: u64,
    pub wall_deadline: Duration,
}
#[derive(Debug)]
pub struct WorkerRequest {
    pub job: AtlasJobId,
    pub root: RootRegistration,
    pub expected_epoch: Option<CacheEpoch>,
    pub purpose: WorkerPurpose,
    pub paths: Vec<RelativePath>,
    pub reservation: WorkerReservation,
    pub policy: AtlasPolicy,
}
#[derive(Debug)]
pub enum WorkerEvent {
    Started {
        job: AtlasJobId,
    },
    Progress {
        job: AtlasJobId,
        discovered: u64,
        completed: u64,
    },
    Exited {
        job: AtlasJobId,
        outcome: WorkerExit,
    },
}
#[derive(Debug)]
pub enum WorkerExit {
    Completed {
        staged_cache: CacheLocation,
        candidate_epoch: CacheEpoch,
    },
    Failed {
        error: crate::errors::AtlasFailure,
    },
    Cancelled,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseMode {
    Sensitive,
    InsensitivePreserving,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionTrust {
    Unverified,
    QualifiedChangeSequence,
    QualifiedCtime,
}
#[derive(Debug)]
pub struct FileIdentity {
    pub volume: [u8; 16],
    pub file: [u8; 16],
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub ctime_unix_nanos: Option<i128>,
    pub change_sequence: Option<u64>,
    /// Reset/replaced journal domains invalidate saved sequence comparisons.
    pub sequence_domain: Option<[u8; 16]>,
    /// Supplied only by a qualified native adapter, never request metadata.
    pub revision_trust: RevisionTrust,
}
#[derive(Debug)]
pub struct SourceSnapshot {
    pub path: RelativePath,
    pub identity: FileIdentity,
    pub content_hash: ContentHash,
    pub bytes: Vec<u8>,
}
#[derive(Debug)]
pub enum SourceRead {
    Bytes(SourceSnapshot),
    Deferred {
        identity: FileIdentity,
        reason: CoverageReason,
    },
    Removed,
}
#[derive(Debug)]
pub struct SourceChunk {
    pub path: RelativePath,
    pub identity: FileIdentity,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub end_of_file: bool,
    /// Hash of this verified range only; never a full-file revision by inference.
    pub range_hash: ContentHash,
    /// Present only after full-file verification, never inferred from stat identity.
    pub content_revision: Option<ContentHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceVerification {
    Unchanged,
    Changed,
    Removed,
}

/// Uses the registered physical root, no-follow opens and native identity checks.
/// OS-specific unsafe code remains behind the host/se-proc adapter.
/// verify rehashes the entire admitted file before semantic commit. Reconcile
/// may skip unchanged files only with a qualified native revision proof, never
/// plain identity/size/mtime. read_chunk rereads/verifies the requested bounded range and
/// never promises a resumable snapshot across calls.
pub trait AtlasSource {
    fn case_mode(&self) -> CaseMode;
    fn read(&self, path: &RelativePath, budget: ParseBudget) -> AtlasResult<SourceRead>;
    fn verify(&self, snapshot: &SourceSnapshot) -> AtlasResult<SourceVerification>;
    fn read_chunk(
        &self,
        path: &RelativePath,
        offset: u64,
        max_bytes: u32,
    ) -> AtlasResult<SourceChunk>;
}

#[derive(Debug)]
pub struct SymbolRecord {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
    pub exported: bool,
    /// None means absent syntax; Some(hash(empty)) means an actual empty body.
    pub signature_hash: Option<ContentHash>,
    pub body_hash: Option<ContentHash>,
    pub doc_line: String,
}
#[derive(Debug)]
pub struct ImportRecord {
    pub spelling: String,
    pub local_name: Option<String>,
    pub imported_name: Option<String>,
    pub target_file: Option<FileId>,
    pub target_symbol: Option<SymbolId>,
    pub span: Span,
}
#[derive(Debug)]
pub struct ParsedFile {
    pub file: FileId,
    pub language: Language,
    pub content_hash: ContentHash,
    pub coverage: FileCoverage,
    pub symbols: Vec<SymbolRecord>,
    pub imports: Vec<ImportRecord>,
    pub references: Vec<Reference>,
}

pub trait AtlasParser {
    fn parse(
        &mut self,
        snapshot: &SourceSnapshot,
        language: Language,
        budget: ParseBudget,
    ) -> AtlasResult<ParsedFile>;
    fn release_scratch(&mut self);
}
```
