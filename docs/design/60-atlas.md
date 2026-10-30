# 60 — Atlas: optional source understanding

Design candidate, 2026-10-30. Owner: 5e. This document and the declaration-only
`crates/se-atlas` specify the implementation; they do not implement it. Authority:
Jimmy's decisions and OPS.md, then 00, then this design; the appended cold-index
window decision in 80 supersedes its earlier aggregate-budget ambiguity. The
prototype remains reference material, not the implementation to copy wholesale.

## 1. Purpose, ownership and dependency boundary

Atlas answers where code is, who refers to it, what depends on it, what changed,
and what a file contains. It supplies a small optional code section to resume.
It never stores conversations, decisions, messages, memories or provider logs.
The authoritative store remains useful when Atlas is absent, corrupt or disabled.
No Atlas error prevents a core bind, message or resume. Shutdown/removal still
reports Atlas resources that could not be drained instead of claiming completion.

`se-atlas` depends on `se-types`, its own SQLite binding and parsing/walking
libraries. It does not depend on se-store, se-core, se-host or se-proc. It cannot
open the authoritative database. The core's CodeIndex port uses shared DTOs;
se-host adapts that port to the reader declared here, supplies verified project
scope and edit evidence, schedules work, and owns native process/watch adapters.
The compile-only crate currently needs only se-types. Future implementation pins
rusqlite 0.40 with the workspace's single bundled SQLite dependency, Tree-sitter
and six grammar variants, ignore and an event-only native watch adapter. Never
install a global Tree-sitter allocator in an embedded process.

There are exactly five OPS operations, shared by CLI and MCP:

| Operation | CLI | MCP | Result family |
| --- | --- | --- | --- |
| atlas.find | atlas find QUERY | stateengine_atlas_find | se.code-hits/v1 |
| atlas.refs | atlas refs SYMBOL | stateengine_atlas_refs | se.code-refs/v1 |
| atlas.impact | atlas impact SYMBOL | stateengine_atlas_impact | se.impact/v1 |
| atlas.changes | atlas changes | stateengine_atlas_changes | se.code-changes/v1 |
| atlas.outline | atlas outline PATH | stateengine_atlas_outline | se.outline/v1 |

Configuration uses config.set; status uses status. No public index, refresh,
renew, repair or watcher operation is added. The cold worker is an authenticated
private binary entry mode, reached only over an inherited host-owned handle; it
is not a clap leaf, MCP tool or user command. Doctor's existing repair workflow
may retire an owned corrupt cache and schedule the same lifecycle path.

Embedded builds have Atlas off in alpha. Standalone builds include the feature;
per-project activation is explicit `atlas.enabled`. Registering the feature or a
project does not open a database, walk source, load a grammar or spawn a thread.
After-ready host activation starts first-use indexing; read methods themselves
never enable, index or launch a process. A first query may report not indexed and
the host may separately admit a subsequent after-response activation action.

## 2. Identity, scope, paths and representation

One database belongs to one registered canonical physical worktree root. Two
worktrees of one Git repository have separate caches. The host assigns RootId
and stores cache location outside source, under its owner-only StateEngine home:
`atlas/<project-id>/<root-id>/atlas.db`. No user-controlled path is concatenated
into that destination. One global scheduler, one active parse, one global cold
child and a bounded connection pool serve all roots; there is no per-agent cache,
thread, process or duplicate watch subscription for the same physical root.

RootRegistration is trusted host input, never an MCP input. Reader handles are
already scoped to one root/project and authorized source visibility. AgentId in
ResumeRequest and EditEvidence comes from verified host authority, never decoded
from an agent's request as authority. No cwd, environment or default project can
replace a missing binding. Source visibility is project-wide; private agent
continuity and cursors remain in the core's private store.

RelativePath is UTF-8, nonempty, at most 4096 bytes, slash separated, with neither
absolute prefix, drive/UNC/device prefix, NUL, empty component, `.` nor `..`.
Wire paths preserve spelling. Lookup keys use the registered filesystem's case
mode; do not lowercase every platform. Ambiguous case collisions are refused.
Non-UTF-8 filenames are counted as unsupported encoding, never lossy-collapsed.
All opens walk relative to a retained physical root handle with no-follow checks
for every component, and verify native file/root identity after open. Symlinks,
Windows reparse points and paths escaping the physical root are not traversed.
A same-spelling replacement root requires an owner rebind, not silent adoption.

IDs on the wire are opaque, never SQLite rowids. Root/File/CacheEpoch/Job IDs
are 16 bytes; symbol IDs and content hashes 32 bytes. File IDs are stable within
an epoch while the normalized path exists. A rename is remove plus add; there is
no guessed semantic rename. SymbolId is BLAKE3(root ID, file ID, kind, enclosing
symbol chain, normalized name, duplicate ordinal in declaration order), with
length-delimited inputs. Moving lines or changing a body/signature preserves it;
reordering indistinguishable duplicate declarations may change their identity.
Every file has a synthetic module symbol, used for module/import impact edges.

Hash original source bytes with BLAKE3. Positions are line 1-based, UTF-8 byte
column 0-based; spans are end-exclusive and contain original byte offsets. CRLF
and BOM bytes are not normalized before positioning. Signature hashes use the
language declaration header token stream excluding trivia and body; body hashes
use original body bytes, so body comment edits count. Metadata doc text is the
first documentation line, truncated on a UTF-8 boundary to 160 bytes. Missing
span/hash is None, never a fabricated zero range or empty-source hash.

JSON uses snake_case fields, lowercase kebab-case enum tags, decimal counters,
hex fixed-size IDs/hashes and explicitly tagged states. Durations encode integer
milliseconds after checked conversion. The dispatcher supplies the schema family;
no enum Debug output is a wire format. Ordinary DTO text is terminal-escaped by
the shared renderer; source identifiers/doc comments cannot inject terminal
controls. The Rust appendix declares all public crate types and signatures;
future codecs must validate these rules before constructing private newtypes.

## 3. Persistent format: Atlas owns atlas.db

SQLite application_id is `0x41544c53` (ATLS), user_version 1. Only the host creates,
upgrades or retires the cache. CLI reads are read-only. A newer version refuses
without modifying bytes. Corrupt or foreign-application files are unreadable, not
empty. Doctor may rebuild only an owned cache after preserving diagnostic status;
never rename/delete an arbitrary file found at the configured path.

Use WAL, synchronous NORMAL, foreign_keys ON, temp_store FILE, mmap_size 0.
Host connection cache_size is -256 KiB, statement cache at most 16, query arena
128 KiB. Cold child cache_size at most -2048 KiB and 32 statements. The journal
size target is 4 MiB after checkpoints; active-reader WAL growth is separately
bounded by admitting no more than 8 MiB of writes before a reader-drain/checkpoint.
A busy bounded reader expires rather than allowing indefinite WAL accumulation.
No periodic checkpoint or expiration timer runs while idle.

The schema below is normative relational layout, not an executable migration in
this candidate. Integers are checked nonnegative and narrowed only after bounds
checks; fixed blobs have length constraints; all tables except FTS are STRICT.
All IDs in child tables refer to this database, never kernel table IDs. String
length checks omitted from the sketch must enforce the limits in sections 2/5.

```sql
CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), project BLOB NOT NULL,
 root BLOB NOT NULL, physical_root BLOB NOT NULL, epoch BLOB NOT NULL,
 extractor_version TEXT NOT NULL, ignore_digest BLOB NOT NULL,
 generation INTEGER NOT NULL, observed_serial INTEGER NOT NULL,
 discovery_complete INTEGER NOT NULL, retention_floor INTEGER NOT NULL,
 coverage_json TEXT NOT NULL, state_json TEXT NOT NULL
) STRICT;
CREATE TABLE files (
 id INTEGER PRIMARY KEY, key BLOB NOT NULL UNIQUE CHECK(length(key)=16),
 path TEXT NOT NULL, path_key TEXT NOT NULL UNIQUE, language TEXT,
 content_hash BLOB, last_good_hash BLOB, bytes INTEGER NOT NULL,
 identity BLOB NOT NULL, coverage_json TEXT NOT NULL, generation INTEGER NOT NULL
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
 exported INTEGER NOT NULL, signature_hash BLOB NOT NULL, body_hash BLOB NOT NULL,
 doc_line TEXT NOT NULL
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
 event_serial INTEGER NOT NULL, coverage_json TEXT NOT NULL
) STRICT;
CREATE TABLE observed_commits (
 oid BLOB NOT NULL, generation INTEGER NOT NULL REFERENCES generations(generation),
 PRIMARY KEY(oid,generation)
) STRICT;
CREATE TABLE changes (
 generation INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 file_key BLOB NOT NULL, symbol_key BLOB, path TEXT NOT NULL, kind TEXT NOT NULL,
 pointer_json TEXT NOT NULL, previous_hash BLOB, current_hash BLOB,
 dependent_count INTEGER NOT NULL, dependent_complete INTEGER NOT NULL,
 dependent_generation INTEGER NOT NULL,
 PRIMARY KEY(generation,ordinal)
) STRICT;
CREATE TABLE authors (
 generation INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 visible_from_generation INTEGER NOT NULL, hint_json TEXT NOT NULL,
 PRIMARY KEY(generation,ordinal,visible_from_generation),
 FOREIGN KEY(generation,ordinal) REFERENCES changes(generation,ordinal) ON DELETE CASCADE
) STRICT;
```

The pinned SQLite must support FTS5 contentless_delete (SQLite >=3.43; see [SQLite FTS5 contentless-delete](https://sqlite.org/fts5.html#contentless_delete_tables)); this is a
build dependency requirement, not a runtime fallback to duplicated full bodies.
FTS rowid equals symbols.id; explicit FTS deletion/reinsertion is in the same
transaction as symbol changes. FTS contains names, split identifiers, paths,
containers and first doc lines only. Original source bodies, full lines and
transcripts are never persisted. References record call/import/type/value sites,
not every identifier token. Interning reduces repeated spellings.

A file transaction replaces that file's symbols/refs/imports and FTS rows, computes
changes against the previous good parse, repairs affected import targets, and
increments generation atomically. Removing/replacing exported symbols invalidates
incoming refs before commit (target None and accuracy NameOnly); dependents are
re-resolved, never left pointing to a
reused rowid. New/deleted target paths consult import_candidates, including
previously unresolved imports. An unresolved import must become resolvable when
its file appears without requiring the importer to be edited.

On parse failure/read failure, delete current semantic rows for that file and
retain its last-good hash plus explicit failure coverage; stale symbols cannot
masquerade as current. FileOnly change records distinguish unknown semantic diff
from zero semantic change. On parse error nodes, retain only declarations whose
spans do not overlap error subtrees and label Partial; do not infer removed
symbols from an incomplete parse. Resolve affected importers in bounded batches;
state remains Updating until all admitted invalidations are accounted for.

Retain changes for 30 days of observed activity, capped at 50,000 rows; whichever
removes rows first advances retention_floor. Prune at activation, commit and drain,
not by an idle timer. Offline files can physically remain longer than 30 days;
this is not a timed deletion promise. IDs/hash pointers remain, never historical
source bodies. Author hints are versioned so an already-fenced page is stable.
No captured transcript text is accepted as author metadata.

## 4. Lifecycle, first index and scheduling

State is the pair (IndexState, Coverage); Current never means complete language
semantics. The following table accounts for every IndexState variant.

| State | Entered by | Next states and trigger |
| --- | --- | --- |
| Disabled | feature/project disabled | Dormant on enable; Closed on removal |
| Dormant | enabled registration, no activation | Opening after host ready/first-use action; Draining on close |
| Absent | open verified, database absent | ColdIndexing on admitted worker; Suspended on pressure; Draining |
| Opening | activated lazy root | Current/VerificationNeeded for validated cache; Absent; Unreadable; Draining |
| ColdIndexing | owned first full-index child started | Updating after validated adoption and replay; Suspended/Unreadable on failure; Draining |
| Updating | event/reconcile queue nonempty | Current after queue and serial fence agree; VerificationNeeded on watch loss; Suspended on budget; Draining |
| Current | caught up to observed event serial | Updating on event; VerificationNeeded on lost watcher/hostless read; Draining |
| VerificationNeeded | watch loss, host restart, offline reader | Updating on explicit reconcile; Suspended if unavailable; Draining |
| Suspended | pressure, no reservation, root temporarily unavailable | previous safe cache state on explicit resource/host event; Draining |
| Unreadable | bad cache/root identity/IO | Opening after owner repair; Draining; never empty Current |
| Draining | disable, host drain, removal, privacy | Closed after exact worker exit, reader drain and closed handles; remains Draining/Pending if deadline expires |
| Closed | all owned activity ended | Dormant only through a new registration/activation lifecycle |

register validates scope/policy without source IO. activate is host-only and may
open the cache or request work; enqueue is nonblocking, bounded and idempotent for
coalesced paths. work_quantum does at most the allowance, commits only complete
file transactions and returns to the host scheduler. next_work is Park unless
actual work exists, Ready when runnable, or AfterEventDebounce when a real event
armed a one-shot debounce. reader returns a scoped reader; status is in-memory
and never triggers IO. captured_edit accepts trusted exact before/after hashes
and evidence ID only. None on one side means witnessed file absence (create/delete),
not an unknown hash; both None is invalid and unverified evidence is not admitted.
close is idempotent and reports Pending/Refused truthfully;
remove_cache requires Closed. forget_evidence cancels jobs and retires the whole
cache before returning outside-observed absence of database, WAL and SHM.

The event queue is 256 KiB maximum, coalesces up to 1024 paths and is shared by
roots. Overflow sets a sticky per-root reconcile bit; it cannot silently drop
work and later report Current. Discovery is streaming, not a full file Vec.
Default max_files is 100,000; excess files count as deferred and discovery remains
explicitly bounded. Eligible discovery honors nested .gitignore, .git/info/exclude
and explicit host-supplied global-ignore policy; the digest includes every rule
source. IgnorePolicy contains already-loaded global patterns (<=64 KiB total),
registered generated path prefixes (<=32) and the host-computed digest; it never
opens an arbitrary global config filename. Repository ignore files are read under
the registered source boundary. The crate does not inspect ambient environment
for policy. Ignore
changes and directory rename/delete produce a subtree reconcile. Git HEAD/ref
changes are events plus safe metadata reads, never a spawned git command.

Native watches track directories without following links. No PollWatcher,
periodic rescan, expiry tick or idle polling is permitted. A 15 ms debounce is
armed only by a source event. Watch loss/overflow is visible immediately and
requests a reconcile; unsupported native watches report WatchUnavailable and
retain explicit verification-needed coverage. Reads do not repair that state.
A session/harness source-change signal can supply events where native watches
are unavailable. Do not subscribe to Linux IN_OPEN: unrelated source reads must
not wake the indexer (the prototype's notify backend did).

### 4.1 First full index: short-lived owned child

Prime’s direct decision msg-63375a5b exempts a cold full index from B4, separately capped
at **64,000,000 bytes peak RSS**. The daemon remains under B4. The host defers this
job for machine memory pressure, not merely because the active cold window would
exceed aggregate 25 MB. Incremental work has no such exemption and stays in-host.
WorkerPurpose therefore contains only ColdIndex. An explicit full rebuild after
cache retirement uses the same cold full-index path and separate window; an
ordinary saved file never acquires that exemption by being called a rebuild.

se-host/se-proc owns spawn, exact process birth identity, job/cgroup/QoS, outside
memory observation, cancellation and reaping. se-atlas only produces WorkerRequest
and consumes WorkerEvent. One child globally, background priority, no network,
no provider credentials or session capability in its constructed minimal environment.
An inherited private pipe carries a one-use JobId and registration/policy. No
bearer secret in argv, no user-supplied destination and no inherited agent
process privileges. Frame size <=64 KiB; progress is rate-limited by real completed
batches, not a periodic heartbeat. Parent cancellation closes the handle and
se-proc terminates only the exact owned child/job after reading its identity.

The child writes a unique staging database inside the owned cache directory,
using no authoritative DB. WorkerRequest specifies parent, child and aggregate
reservations; in the approved cold window the aggregate ceiling explicitly
includes parent plus child allowances, while post-window B4 remains 25 MB.
Default whole-job wall deadline is 15 minutes, cancellation-aware at each file.
An OS cap/observed budget breach aborts the job; it is never reported complete.
No next worker is started until the old child is externally reaped.

The child returns candidate epoch and staging location. Parent compares JobId,
expected old epoch, physical root, project, application/schema IDs, ignore/extractor
digest and integrity readback. It observes actual child exit outside the writer,
not just an `Exited` payload from an untrusted stream. Then it drains readers,
closes old SQLite handles, installs the staged cache under the owned lock, opens
read-only and reads the new epoch/generation back. A stale job/epoch cannot
publish. Windows never relies on replacing an open SQLite database. Adoption
records intent with old/new owned filenames before rename; crash recovery selects
only an intact cache matching that intent or leaves Unreadable, never guesses by
mtime. Old files are removed only after successful readback.

During the child run, the host keeps a bounded dirty-path queue and a sticky
reconcile marker on overflow. After adoption it replays pending changes in-host;
Current requires that replay plus a complete serial fence. On worker failure keep
the prior cache with stale labels, or Absent if none; cancel/delete only owned
staging files after reap. WorkerLost/Protocol/LeaseStale/Deadline are separate
causes, not empty-success results.

### 4.2 Incremental resource limits

The global hard source limit is 512 KiB. Larger files record SourceBytesLimit.
Generated files are detected by `@generated`, `automatically generated` or
`DO NOT EDIT` in the first 4096 bytes (ASCII case-insensitive), plus explicit
configured generated path rules. Numeric/token density alone does not prove a
file is generated. Generated and unsupported files retain path metadata and
bounded literal-text search eligibility, with zero semantic-resolution claims.

In-host parse admission starts at <=16 KiB source, <=2048 emitted semantic rows,
<=100 ms progress-callback deadline and a 768 KiB scratch reservation. The source
buffer, parser tree and extraction arena all count against it. If an input or
parser allocation cannot be kept inside the Atlas 2 MB share, record ParseWorkLimit
and keep path/text search available; do not launch a large incremental child or
borrow an unbounded global allocator. Source up to 512 KiB may be parsed by the
cold child under its <=200 ms per-file deadline and bounded row/work admission.
Thus a file fully indexed cold can become deferred after a later edit if it no
longer meets the smaller host budget; that regression is visible in coverage.

The input cap and callback are necessary admission limits, not proof of RSS. A
production parser must demonstrate the 2 MB parent share including grammar loads,
allocator high-water mark and SQLite before Atlas incremental parsing is enabled.
A failed reservation suspends/degrades optional semantics and never breaks core.
The host drops the tree, parser scratch and idle connection at the end of the
work batch; one parse at a time, no per-root retained trees. Native parsing and
source IO execute off the request/runtime thread. A deadline cannot make blocking
filesystem IO disappear: a stuck worker remains Pending at drain, with identity
and owned resources retained until its real completion.

The pipeline is Discover -> Read -> Parse -> Resolve -> Diff -> Commit -> Prune
-> Checkpoint. Parse is CPU-only over SourceSnapshot; no IO from the parser.
AtlasSource::read_chunk is the separate bounded-text path (max 16 KiB per chunk):
it reports identity, offset and EOF; a changed identity across chunks aborts with
partial coverage. A text pointer has no whole-file content hash unless already
known to match that identity; consumers must reread it. It never bypasses no-follow.
Read checks size before allocating, opens no-follow, reads bounded bytes, hashes,
and verifies identity/size again. verify runs before commit. ChangedDuringRead
requeues once per new event and keeps explicit deferred state; no retry spin.
Deleted files commit deletion; permission failure is Failed, not Removed. Partial
progress is durable per file, never one unbounded all-repository transaction.

## 5. Queries, accuracy, snapshots and bounded answers

All five methods are synchronous bounded cache reads executed on a host read
worker; no runtime blocking, subprocess, LSP, network or write-side scheduling.
Defaults: 20 results, max 50; 32 KiB response budget, max 64 KiB; 25 ms query work
budget, never more than 40 ms before formatting. Limit includes every returned
row, tests included. Inputs longer than 1024 UTF-8 bytes, embedded NUL, zero limits,
unknown enum values and over-budget requests refuse. Symbol candidates and scope
lists each cap at 32; recently_edited_symbols caps at 32. All dynamic SQL binds
values; literal queries are escaped before constructing restricted FTS expressions.
No arbitrary SQL, FTS syntax, regular expression or filesystem glob is executed.

Each read opens one SQLite read transaction, captures epoch/generation plus the
host's observed event serial, and returns IndexSummary with coverage. Current is
only caught-up-to-observations at that instant, not proof no future/unobserved file
change exists. A hostless CLI opens the same cache read-only and labels
VerificationNeeded/StaleSnapshot; it does not inherit a persisted Current claim.
An exact CodePointer includes a content hash: consumers must verify it against
source before using an offset to edit. Queries never guarantee source is still
unchanged when the caller later acts.

`Read::Present` contains a useful answer even when coverage is partial. A truly
checked missing file uses Read::Absent with Checked provenance; unreadable uses
Read::Unreadable or the shared SeError when admission failed before a read. An
unknown index/baseline uses Read::Unknown, never Absent. Present with zero items
means zero matches in the declared indexed population; complete negative claims
also require discovery complete, no deferred/failed eligible files, no relevant
partial-language edges and Current. Unsupported languages are counted, not
silently removed from the report. Disabled/not-built is an explicit refusal;
not-yet-indexed reports atlas-index-absent and status Absent, not empty results.

The shared Page/Window expresses transport bounds, omission and snapshot scope;
IndexSummary.coverage separately expresses corpus/parser completeness. A bounded
page can be complete for the indexed population while coverage is partial. Human
and MCP renderers must show both. An exact omitted count is optional: unknown is
not zero. Exhausting time/bytes yields partial data plus explicit stop reason,
remaining cursor where possible and incomplete status (shared CLI exit 2).
An error before any data returns the shared error envelope. Cancellation after
some data is explicit incomplete, never apparently exhausted.

### 5.1 find

SearchKind is Symbol (default), Text or Path, matching section 50. Symbol search
ranks exact qualified/name matches, identifier-split prefix matches, then FTS
metadata. Split camelCase, snake_case, acronym boundaries and Unicode identifier
boundaries deterministically under the pinned extractor version. Stable ordering
is method rank, normalized name, path, byte offset, symbol ID; no floating-score
rounding determines cursor order. Ties are deterministic. Explicit path mode
searches registered relative path metadata and returns a file-only pointer.

Text mode performs a bounded literal scan of at most 32 registered files and
256 KiB total source bytes per request, in path order, subject to the same time
budget and safe Source reader. It can search supported, generated, oversized and
unsupported-language files, but reports how much was scanned and has a continuation
for remaining files/offsets. It never reads an entire oversized file into memory.
Text hits contain a bounded match spelling and byte span, without persisting body
text. They have FindMethod::Text and no semantic accuracy. Name-only FTS or text
is never labelled a resolved reference. The default Symbol query does not secretly
fall back to scanning source; it can suggest `--kind text` for unsupported code.

### 5.2 refs

SymbolSelector accepts an opaque symbol ID, a path+position, or a name optionally
qualified by path/container. At chooses the smallest declaration span containing
the position, after validating its line/byte-column against indexed spans. Name
must resolve uniquely; otherwise return
atlas-symbol-ambiguous with <=20 candidate pointers and an explicit omitted count.
A selector not present in a partial index is unknown/incomplete, not proven absent.
Resolved references precede optional name-only candidates, then path/site/kind/ID.
Default includes name-only with its label, so useful candidates are visible without
claiming compiler precision. The internal kinds filter does not create new CLI
flags. An empty kinds set means all five reference kinds.

Accuracy has exactly three meanings:

| Label | Claim | Exclusions |
| --- | --- | --- |
| LexicalBinding | declaration and use linked through a parsed local lexical scope | not runtime dispatch or macro expansion |
| ExplicitImport | explicit supported import/export path and binding linked to an indexed declaration | not dynamic loader/package resolver truth |
| NameOnly | spelling candidate, including unresolved/dynamic cases | never a resolved edge |

Extraction support is fixed by the versioned language matrix:

| Language | Declarations and lexical sites | Explicit cross-file resolution | Known partial cases |
| --- | --- | --- | --- |
| JS/JSX | functions/classes/methods, const/let bindings, calls/types where syntactic | static relative ESM import/export, literal relative require; .js/.jsx and index variants | computed members, eval, dynamic import, package exports, prototype dispatch |
| TS/TSX | JS plus interfaces/types/enums/namespaces and type sites | relative .ts/.tsx/.js/.jsx imports, explicit reexports | tsconfig paths/project references, overload selection, conditional types |
| Rust | fn/impl/trait/struct/enum/type/const/static/mod/macro declarations, lexical uses | explicit crate/self/super module paths, source mod files and non-glob use aliases | macro expansion, trait dispatch, cfg evaluation, extern package graph, glob inference |
| Python | def/async def/class, assignments, lexical calls/type names | literal relative imports and registered source-root module files | sys.path mutation, runtime attributes, star imports, dynamic metaclasses |

Unsupported constructs produce NameOnly or partial reason, not fabricated binding.
Reexports are traversed with a visited set, max 8 hops, and explicit unresolved
coverage on a cycle/limit. Relative resolution tests only the documented extension
and index/module candidates; external package names remain unresolved. JSX custom
component names are value references; intrinsic lowercase tags are excluded.
No Python execution, Rust compiler, TypeScript server or import of project code.

### 5.3 impact

Default depth 2, valid 1..3. Traverse reverse resolved call/type/import edges in
breadth-first order, with <=512 visited symbols, <=1024 examined edges and the
request row/byte/time bounds. Each result carries its full hop path and per-hop
accuracy; a chain is never more certain than its least certain edge. Optional
NameOnly edges remain explicitly labelled throughout. Synthetic module symbols
permit file/import dependents without inventing a function call graph.

Return dependents and tests separately. Test classification uses Rust #[test],
Python test_ declarations or explicit test path conventions; the rendering labels
path-derived classification as a heuristic. A referencing test is a candidate to
run, not proof of the full affected suite. omitted_frontier is a lower bound unless
frontier_count_complete; unknown expansion cannot be represented as zero omitted.
A continuation contains the bounded BFS frontier and visited IDs; if it cannot
fit the cursor bound, return incomplete with no next and request a narrower query.

### 5.4 changes

Baselines are a cache cursor, a previously observed Git commit, or observed Unix
time. The optional `since` on an authenticated agent uses that agent's saved
Atlas cursor; an owner without one starts at the retained floor and receives a
label saying so. No implicit all-project agent identity. A commit baseline must
have been observed in this cache; no request-triggered git diff/indexing. Multiple
observations of the same commit select the earliest retained observation at that
commit with an explicit working-tree observation label. Time uses
index observation time, never Git author time; a detected clock regression makes
time-baseline resolution unavailable rather than guessing chronology.

Each change has (generation,ordinal), path/hash pointer, change kind and an author
hint. Added/Removed/SignatureChanged/BodyChanged are semantic diffs of two complete
file parses. Signature takes precedence when both signature and body change.
Whitespace-only outer-file changes can be FileOnly; parse failure/unsupported
changes are FileOnly with partial coverage. Removed pointers describe old bytes,
not an existing file. Dependent counts are computed at a named generation,
including completeness/reason; count is not called current after graph advances.

Author hints require exact same registered path and before/after hashes from
captured_edit. One matching agent/evidence is Captured; multiple matching evidence
facts are Mixed; absent or mismatched evidence is Unknown. Filesystem mtime, Git
blame, current session and a changed filename do not prove authorship. Later hint
updates get visible_from_generation, preserving prior query fences. Return changes
oldest-first by ChangeId for lossless pagination; resume may rank a bounded plan
separately. Retention gaps, changed epochs and unavailable baselines refuse with
an explicit restart option; they do not silently reset a caller's baseline.

### 5.5 outline

Return a flat pre-order symbol list with parent IDs and original spans; the UI may
render it as a tree. Pagination can omit an ancestor but preserves its ID and
states the page boundary. Stable order is start_byte, end_byte descending, ID.
Unsupported/deferred files return file metadata and FileCoverage, no invented empty
semantic tree. The outer Read distinguishes a checked missing path from unreadable
and not-yet-discovered. Surface adapters use atlas-language-unsupported or
atlas-file-over-budget with the same coverage detail and suggest bounded Text
search; a useful partial outline remains an explicit partial answer.

### 5.6 Cursor format and common Read/Page seam

AtlasCursor is versioned base64url of a bounded canonical CBOR structure:
`version, mode, project, root, epoch, fence, query_digest, last_key, state, checksum`.
Maximum decoded 8192 bytes, encoded 10924 bytes. Checksum detects accidental damage,
not authority; session/project binding is checked independently. Query digest
covers filters, order, selector and viewer where relevant, not the requested page
size. Unknown versions/oversize/malformed/foreign-root/epoch/filter cursors refuse.
`Page.next` carries the same string in se_types::Cursor; the adapter must validate
it through AtlasValidation before use. No unchecked cast between store and Atlas
cursor domains. Ordinary non-change pagination refuses CursorSnapshotChanged if
generation changed; it does not stitch pages from different symbol graphs. Changes
use immutable historical rows at a fence and continue until retention expires.

The se-types branch currently has Source::{Store,Host,Configuration}; it lacks an
honest Atlas database source. Required shared-type amendment (owned by section10):
`Source::Atlas { project: ProjectId, root: [u8;16], epoch: Option<[u8;16]> }`.
Window from/to are this cache's monotone generation observations converted through
checked SequenceValue; they are not authoritative event sequences. The distinct
source disambiguates them. Hostless reads must not claim Host or Configuration.
This is an integration blocker, not a duplicate Page/Read definition in Atlas.

## 6. Resume: useful change context without losing unseen work

resume_code is an internal read port, not a sixth Atlas tool. Core passes the
verified viewer, its persisted Atlas cursor and <=32 recent edited symbols. It
gets <=5 change bullets, <=600 UTF-8 bytes including status/omission text, <=20 ms
total wall budget with <=5 ms SQLite query work. Core may allocate less; Atlas
never takes unused private context budget by itself. The section includes paths,
change kinds, confidence/coverage and dependent counts where known. No file bodies,
provider transcript or another agent's private work state enters the section.

Rank at one fence: known other-agent edits affecting the viewer's recent symbols,
other known edits, unknown/mixed authors, then self edits; within rank newest first.
Counts are bounded/lower bounds when incomplete. NeverIndexed, Disabled, Unreadable,
BaselineGap, Updating, BudgetExceeded and checked Zero are distinct states. Zero
requires a valid baseline and complete scan of the relevant retained change range;
Updating with no found rows does not say nothing changed. Read errors carry a
redacted diagnostic and leave the old cursor intact.

To avoid advancing over unshown changes, the cursor carries a resume plan: at most
64 ChangeIds from the earliest unconsumed chronological window through a fixed
scan_tail, reordered only inside that window. Its remaining-ID list, viewer,
ranking-input digest and fence fit the bounded cursor; author hints are read as
of that fence. Each response consumes only items actually rendered inside its
byte budget. offered_cursor contains the remaining plan and old baseline; only
when the entire plan is shown does it advance baseline to scan_tail. A new plan
then covers the next chronological window. New arrivals are beyond the fence and
wait for a later plan, preventing starvation/loss. A changed recent-symbol list
finishes the old plan before reranking the next; expired rows yield BaselineGap.

Core persists offered_cursor only after the section has actually been delivered
in a successful context response/turn-delivery record. It must not commit that
cursor on query, timeout, dropped response, byte-budget omission or mere packet
construction. If a consumer cannot acknowledge delivery, retaining the old cursor
and repeating bounded bullets is safer than silently skipping them. Explicit
changes pagination uses its own baseline and does not mark resume items delivered.
The host/core owns private cursor storage; Atlas writes nothing during resume.

## 7. Error contract: cause and legal remedy

One wire envelope remains se-types::SeError and section50's se.error/v1. The local
AtlasErrorCode classifies causes for exhaustive mapping; it does not allocate a
second global catalog or serialize Rust variants. Detail strings are capped at
1024 bytes, relative paths only; source bodies, secrets and absolute private home
paths are never placed in diagnostics. Internal SeError cause is not serialized.
The following table covers every local variant and maps to existing central codes.
For common codes, detail.resource identifies Atlas so remedies never target the
kernel database. A catalog owner may refine the central code, preserving cause.

| Local cause(s) | Central code / class | Why / remedy |
| --- | --- | --- |
| FeatureDisabled | FeatureDisabled / Refused | project disabled; config set atlas.enabled true |
| EmbeddedUnavailable | FeatureNotBuilt / Refused | alpha embedded has no Atlas; use standalone build |
| ConfigurationInvalid | ConfigInvalid / Refused | invalid policy; correct named project setting |
| RootUnavailable | RepoNotFound / Refused | registered source missing; restore root |
| RootIdentityChanged | RevisionConflict / Conflict | physical root replaced; owner rebind after inspection |
| CacheIo, CacheCorrupt | AtlasUnreadable / Unreadable | cache IO/integrity failure; doctor --fix owned cache |
| CacheTooNew | ConfigVersionUnsupported / Refused | newer cache version; upgrade binary, preserve cache |
| CacheScopeMismatch, CacheLinkRefused | AtlasUnreadable / Unreadable | foreign scope/link; inspect owned cache location, refuse traversal |
| CacheBusy | StoreBusy / Unavailable, Atlas resource detail | bounded cache lock wait expired; retry after indicated duration |
| InvalidPath | AtlasPathOutsideRoot / Refused | path fails root-relative boundary; select registered relative path |
| UnsupportedPathEncoding | UsageInvalidValue / Usage | non-UTF-8 path cannot be represented; use supported filename encoding |
| InvalidQuery, InvalidLimit | UsageInvalidValue / Usage | malformed/over-budget request; narrow input or choose documented bounds |
| AmbiguousSymbol | AtlasSymbolAmbiguous / Usage | more than one declaration; choose returned path/container |
| InvalidCursor, CursorQueryMismatch | CursorInvalid / Usage | malformed/domain/filter mismatch; restart matching query |
| CursorEpochMismatch, CursorSnapshotChanged | CursorInvalid / Usage | cache/graph replaced; start a new snapshot |
| CursorExpired | CursorInvalid / Usage | retained rows expired; choose available baseline |
| BaselineUnavailable | CursorInvalid / Usage | commit/time baseline never observed or clock uncertain; use returned cursor |
| WatchUnavailable | AtlasIndexing / Incomplete | native events unavailable; start session reconciliation or use explicit source signal |
| ResourceBudgetUnavailable | AtlasFileOverBudget / Refused | resource admission failed; wait for pressure to clear or use text search |
| SourceReadFailed | AtlasUnreadable / Unreadable | source permission/IO failure; restore source access |
| SourceChangedDuringRead | AtlasIndexing / Incomplete | file changed while read; retry after next source event |
| ParserFailed | AtlasFileOverBudget / Refused | grammar/work failure; bounded text search, inspect source/diagnostic |
| ShuttingDown | DeadlineExceeded / Unavailable | root draining; reconnect to next ready generation |
| Cancelled | Cancelled / Cancelled | explicit cancellation; retry if still wanted |
| InternalInvariant | Internal / Internal | impossible cache invariant; report redacted diagnostic, keep old cache |
| WorkerLost | TaskFailed / Internal | owned worker gone without valid result; host may retry admitted first index |
| WorkerProtocol | TaskFailed / Internal | oversized/malformed/scope-invalid worker output; retire owned staging, report |
| WorkerLeaseStale | RevisionConflict / Conflict | job or expected epoch superseded; discard old result, use current job |
| WorkerDeadline | DeadlineExceeded / Unavailable | job deadline reached; retain partial status, retry after cause inspection |

Query-level symbol unknown/path unknown/language unsupported/file too large use
section50's existing Atlas codes, with the coverage rules above. `atlas-indexing`
is useful partial status, not a catch-all hiding corrupt cache reads. No catch
returns an empty vector. No automatic timer retries a refused/budgeted worker.

## 8. Shutdown, removal, privacy and operating systems

Drain stops admission, disarms watches, cancels/reaps the exact cold child, finishes
or rolls back the current file transaction, closes readers/connection/parser, then
returns Closed. A deadline with pending IO returns Pending and root stays Draining.
A replacement host cannot publish an old generation's worker result. All watchers,
handles and tasks belong to a host generation and are released on its close.

remove_cache verifies owner directory/root identity, removes only known cache/WAL/
SHM/staging files after Closed, reads absence back and returns remaining_paths.
Unknown files cause incomplete removal rather than recursive deletion. It never
removes source, .git, provider config or authoritative history. Privacy forgetting
cancels every job using the old epoch, removes the entire affected cache and
readbacks absence before claiming the Atlas copy is gone. User source and provider
transcript copies are separately named residual data; Atlas makes no claim to
erase them. Retired epochs/cursors cannot resurrect author evidence after deletion.

| OS | Native adapter and boundary | Performance/accounting consequences |
| --- | --- | --- |
| Windows | root/file IDs, owner-only protected ACL, component reparse refusal; ReadDirectoryChangesW data/name/size/write events; no replace-open SQLite assumption | owned child job and background priority; record WorkingSet64 plus private-byte diagnostic; pressure suspend is visible |
| Linux | retained directory handles, no-follow relative opens, device/inode identity; inotify without access/open events | low-priority owned child/cgroup, no per-event shell; watch limits yield explicit degraded coverage |
| macOS | physical file identity, owner modes, normalization-aware case lookup; FSEvents coalescing/loss mapped to reconcile | background QoS/owned process handle; no busy reconcile loop on directory coalescing |

Native unsafe code belongs to se-proc/host adapter, not this forbid-unsafe crate.
Filesystem case policy is measured from registration, not assumed from OS name.
Network/synced roots that cannot provide the required stable identity/event
semantics are explicit degraded/unsupported cases; no polling fallback is hidden.

## 9. Budget allocation, measurements and five journeys

All MB in budget claims below are decimal bytes; historical prototype MiB is
labelled separately. Atlas's in-host share is **2,000,000 bytes**, with a proposed
allocation: SQLite/query arena 512,000; one parser/source/extraction scratch 768,000;
queue 256,000; watcher/root metadata 128,000; grammar/allocator slack 336,000.
These are reservations to verify, not measured facts. The share includes retained
allocator pages after work. At most one active root connection/parser; inactive
roots keep bounded registration metadata and no parser/DB handle. Root registry
metadata beyond the share is subject to host registration bounds, not free memory.

The 80 daemon allocation is 20.5 MB spend plus 4.5 MB reserve =25 MB. Incremental
Atlas cannot consume that reserve silently. Embedded Atlas is off, with no startup
or memory charge. Cold work is after ready and outside first authenticated bind;
cold full-index child peak <=64 MB, one transient process, separately reported.
Its host allocation remains inside B4, and the child exits, leaving no settled
worker. No source activity means zero Atlas CPU/context switches/timers. Save-to-
searchable target <=200 ms for admitted small-file updates; deferred files retain
explicit incomplete coverage. Atlas query p95 target <=50 ms; the six core CLI
read targets remain strictly <20 ms, measured by their separate 30-sample oracle.

Prototype facts (Linux only, shared host, not budget qualification): StateEngine
6,179 files /1,356,850 lines indexed in 165.35 s, peak 19.89 MiB, settled watcher
10.60 MiB, DB 275.79 MiB. Current Rust SE Code 2,917 files /851,724 lines indexed in
72.30 s, peak 62.04 MiB, settled 11.45 MiB, DB 124.80 MiB. Full bodies and every
identifier occurrence inflated those DBs; this design explicitly omits both.
An isolated 958,433-byte generated Rust file peaked 59.25 MiB, motivating the
512 KiB rule and child exit. The SE Code prototype peak was 65,048,576 bytes,
which exceeds the new 64,000,000-byte child ceiling; this design needs a fresh
measurement with its generated/size/row limits before claiming compliance. A file cap alone does not establish the 2 MB host share.

Eight real save-to-external-SQLite-read samples had p95 66.50/98.60 ms respectively.
Sixty-second quiet windows saw zero CPU tick/context-switch deltas in two threads
on both corpora; endpoint deltas are a proxy, not the official native budget
runner. Warm production-query/whole-CLI p95 from 20 samples: StateEngine def 0.140/
7.50 ms, refs 0.269/12.08, impact 1.026/16.15, full-body FTS 6.437/26.01; Rust SECode
def 0.072/10.60, refs 0.115/7.83, impact 0.028/9.75, full-body FTS 1.845/13.45.
Those measurements are not a 30-run core acceptance claim or metadata-only FTS
prediction. Report: `/mnt/nvme/stateengine/5e-rust-atlas-s5-20261030/S5-REPORT.md`.

| Journey | Required behavior with Atlas | Failure/optional boundary |
| --- | --- | --- |
| J1 Install | optional grammar/SQLite linkage is packaged consistently; no Node | no DB, index, child or watcher at install/startup |
| J2 Adopt and real work | core agent launch/bind works, after-ready Atlas may show indexing | core work continues under absent/budgeted/failed Atlas; no first-bind indexing delay |
| J3 Come back | bounded delivered change section and honest saved cursor | no query-triggered index; disabled/zero/unknown/unreadable remain distinct |
| J4 Two agents | shared source index, exact captured authorship hints, project-bound reads | private viewer cursor remains core-private; no inferred author from active session |
| J5 Remove | drain child/readers, remove owned cache with outside absence readback | report unknown files/stuck IO; preserve source and unrelated/user history |

The five journeys do not require Atlas enabled or a cold index (80 decision).
They establish core budgets; reviewers additionally exercise optional Atlas's
real CLI and MCP consumer paths on Windows/macOS/Linux, both harnesses through
the same dispatch. Attended/autonomous have identical optional read behavior;
there is no autonomous-only renewer. Read/write mirror: scheduler owns writes,
CLI/MCP share read methods, privacy/removal closes both writer and readers.
Reviewer checks must include save+external readback, watcher loss, new unresolved
import target, partial parse, cursor epoch/retention change, unchanged idle, cold
child exit/failed adoption, privacy removal and response-delivery cursor safety.
Authors add no tests or new gate machinery. This candidate runs compilation,
formatting and static source review only; it makes no behavior-readiness claim.

## 10. Integration decisions and remaining blockers

Settled here: one DB per physical worktree, metadata-only FTS, explicit three-level
accuracy, read-only resume, delivered-only cursor progress, transient first index,
smaller in-host incremental admission, no idle polling and no additional OPS tools.
The published se-types foundation supplies IDs/Read/Page/SeError; Atlas depends on
it rather than defining duplicates. AtlasError DTOs own SeError and deliberately
are not Clone/Eq, because its causal chain is neither. No test-only fake types are
used to obtain a compile pass.

Remaining cross-section work before implementation approval:

1. Section10 must add Source::Atlas as specified in 5.6. Current declarations compile
   without constructing Window, but a truthful page implementation depends on it.
2. Section50's `atlas-file-over-budget` text says a file stays text-searchable;
   interpret this as bounded literal search, never a promise to scan every byte.
   Its doctor repair and disable/re-enable workflows must route through lifecycle,
   not introduce a new index command. This document adds no CLI flags.
3. The core registry cannot import Atlas-owned request/result DTOs without an
   illegal se-core -> se-atlas edge. Section10 must publish the five operation
   input/output DTOs and the optional resume port in se-types::code; the shapes
   are specified by this appendix. se-atlas then reexports those DTOs and retains
   lifecycle/parser/controller types locally. Host adapters implement the port;
   se-core owns validation/dispatch. This candidate keeps declarations in the
   assigned crate for review, not a second wire schema; implementation approval
   requires that shared ownership move.
4. Native measurements must establish grammar/allocator behavior inside the 2 MB
   share. If they cannot, reduce incremental semantic admission or defer parsing;
   do not silently increase B4, move incremental parsing to another helper, or
   describe a reservation as evidence. Cold prototype numbers do not settle this.

## Appendix A — complete public Rust declarations

The following files are the complete public signature surface of se-atlas. Traits
have no bodies, and structs/enums have no hidden runtime implementation. All are
compiled against the published se-types foundation; private fields await validated
constructors after design approval. No `todo!`, `unimplemented!` or fake returning
function is required to make the declarations compile.

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
pub use se_types::SeError as AtlasError;
use std::time::Duration;

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
    AmbiguousSymbol,
    InvalidCursor,
    CursorEpochMismatch,
    CursorExpired,
    CursorQueryMismatch,
    CursorSnapshotChanged,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasErrorDetail {
    pub path: Option<String>,
    pub observed: Option<String>,
    pub expected: Option<String>,
    pub retry_after: Option<Duration>,
}

/// One wire error remains se-types::SeError. The final central Code allocation
/// maps every AtlasErrorCode exhaustively; no catch-all or separate envelope.
pub trait AtlasErrors {
    fn error(&self, code: AtlasErrorCode, detail: AtlasErrorDetail) -> AtlasError;
}
```

### crates/se-atlas/src/model.rs

```rust
use crate::errors::AtlasError;
use se_types::{AgentId, EventId, ProjectId};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheEpoch(pub [u8; 16]);
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
#[derive(Debug)]
pub struct RelativePath(pub(crate) String);
#[derive(Debug)]
pub struct AtlasCursor(pub(crate) String);
#[derive(Debug)]
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
#[derive(Debug)]
pub struct CodePointer {
    pub file: FileId,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub content_hash: Option<ContentHash>,
}

#[derive(Debug)]
pub enum FileCoverage {
    Indexed,
    Partial { reasons: Vec<CoverageReason> },
    Deferred { reason: CoverageReason },
    Failed { error: AtlasError },
}
#[derive(Debug)]
pub struct Coverage {
    pub discovered_files: u64,
    pub indexed_files: u64,
    pub partial_files: u64,
    pub deferred_files: u64,
    pub failed_files: u64,
    pub discovery_complete: bool,
    pub reasons: Vec<CoverageReason>,
}

#[derive(Debug)]
pub enum IndexState {
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
        discovery_complete: bool,
    },
    Current,
    VerificationNeeded {
        reason: CoverageReason,
    },
    Suspended {
        reason: AtlasError,
    },
    Unreadable {
        error: AtlasError,
    },
    Draining,
    Closed,
}
#[derive(Debug)]
pub struct IndexSummary {
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<Generation>,
    pub state: IndexState,
    pub coverage: Coverage,
}
#[derive(Debug)]
pub struct Answer<T> {
    pub index: IndexSummary,
    pub data: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindMethod {
    ExactName,
    SplitIdentifier,
    MetadataFts,
    Text,
}
#[derive(Debug)]
pub struct CodeHit {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub method: FindMethod,
    pub accuracy: Option<Accuracy>,
}
#[derive(Debug)]
pub struct Reference {
    pub site: CodePointer,
    pub kind: ReferenceKind,
    pub spelling: String,
    pub enclosing: Option<SymbolId>,
    pub resolved_target: Option<SymbolId>,
    pub accuracy: Accuracy,
}
#[derive(Debug)]
pub struct ImpactHop {
    pub from: SymbolId,
    pub to: SymbolId,
    pub site: CodePointer,
    pub accuracy: Accuracy,
}
#[derive(Debug)]
pub struct Dependent {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub hops: Vec<ImpactHop>,
}
#[derive(Debug)]
pub struct Impact {
    pub dependents: Vec<Dependent>,
    pub tests: Vec<Dependent>,
    pub omitted_frontier: u64,
    pub frontier_count_complete: bool,
    pub next: Option<AtlasCursor>,
    pub complete: bool,
}

#[derive(Debug)]
pub enum AuthorHint {
    Captured { agent: AgentId, evidence: EventId },
    Mixed { evidence: Vec<EventId> },
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
#[derive(Debug)]
pub struct DependentCount {
    pub count: u64,
    pub at_generation: Generation,
    pub complete: bool,
    pub reason: Option<CoverageReason>,
}
#[derive(Debug)]
pub struct CodeChange {
    pub id: ChangeId,
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub kind: ChangeKind,
    pub previous_hash: Option<ContentHash>,
    pub author: AuthorHint,
    pub dependents: DependentCount,
}
#[derive(Debug)]
pub struct OutlineSymbol {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}
#[derive(Debug)]
pub struct Outline {
    pub file: CodePointer,
    pub language: Option<Language>,
    pub coverage: FileCoverage,
    pub symbols: Vec<OutlineSymbol>,
    pub complete: bool,
    pub next: Option<AtlasCursor>,
}

#[derive(Debug)]
pub struct CacheLocation {
    pub directory: PathBuf,
}
#[derive(Debug)]
pub struct RootRegistration {
    pub project: ProjectId,
    pub root: RootId,
    pub canonical_source_root: PathBuf,
    pub cache: CacheLocation,
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
#[derive(Debug)]
pub struct IgnorePolicy {
    pub global_patterns: Vec<String>,
    pub generated_prefixes: Vec<RelativePath>,
    pub digest: ContentHash,
}
#[derive(Debug)]
pub struct AtlasPolicy {
    pub ignore: IgnorePolicy,
    pub enabled: bool,
    pub max_files: u32,
    pub parse: ParseBudget,
    pub total_reserved_bytes: u32,
    pub change_retention_days: u16,
    pub max_change_rows: u32,
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
#[derive(Debug)]
pub struct ResumeCode {
    pub index: IndexSummary,
    pub state: ResumeCodeState,
    pub text: String,
    pub pointers: Vec<CodePointer>,
    pub returned: u8,
    pub omitted: Option<u64>,
    pub complete: bool,
    pub offered_cursor: Option<AtlasCursor>,
    pub diagnostic: Option<crate::errors::AtlasError>,
}

/// Bound by the host to one registered project/worktree and authorized source
/// scope. These methods never enable, open-for-write, index or launch anything.
pub trait AtlasQueries {
    fn find(&self, query: &FindQuery) -> AtlasResult<Read<Answer<Page<CodeHit>>>>;
    fn refs(&self, query: &RefsQuery) -> AtlasResult<Read<Answer<Page<Reference>>>>;
    fn impact(&self, query: &ImpactQuery) -> AtlasResult<Read<Answer<Impact>>>;
    fn changes(&self, query: &ChangesQuery) -> AtlasResult<Read<Answer<Page<CodeChange>>>>;
    fn outline(&self, query: &OutlineQuery) -> AtlasResult<Read<Answer<Outline>>>;
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
    FirstSession,
    HostRestart,
    WatchOverflow,
    WatchFailure,
    IgnoreRulesChanged,
    GitHeadChanged,
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
    Refused { error: crate::errors::AtlasError },
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
    pub parent_ceiling_bytes: u64,
    pub child_ceiling_bytes: u64,
    pub aggregate_ceiling_bytes: u64,
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
        error: crate::errors::AtlasError,
    },
    Cancelled,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseMode {
    Sensitive,
    InsensitivePreserving,
}
#[derive(Debug)]
pub struct FileIdentity {
    pub volume: [u8; 16],
    pub file: [u8; 16],
    pub size: u64,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceVerification {
    Unchanged,
    Changed,
    Removed,
}

/// Uses the registered physical root, no-follow opens and native identity checks.
/// OS-specific unsafe code remains behind the host/se-proc adapter.
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
    pub signature_hash: ContentHash,
    pub body_hash: ContentHash,
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
