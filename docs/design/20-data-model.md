# 20 — Authoritative data, SQLite and recovery

Status: design for review, not permission to implement. The S1 and import/write spikes are external measurements; this chapter contains the storage contract and compile-only declarations, with no executable backend or migration.

## Purpose and ownership

`se-store` owns the one per-user SQLite authority, event representation, transactional projections, idempotency, bounded snapshot reads, schema negotiation/migrations, backups, recovery and storage erasure. No SQL, SQLite handles, database paths derived from project labels, or backend-specific sequence arithmetic escape this crate. `se-core` owns authorization, operation policy and legal domain transitions; the store checks the same transition preconditions atomically against committed revisions. The host owns the runtime lease, process/OS witnesses, notifications and scheduling; a process row is never proof a process exists. Harnesses own transcript access and account stores. Atlas owns a separate rebuildable code index and cannot lock this database for indexing.

The store reads no environment and selects no repository. The caller supplies the resolved per-user state directory and typed scope. Its production layout is `STATE/state.db`, `STATE/backups/`, `STATE/recovery/`, with explicitly owned bounded staging files in `STATE/staging/`; platform defaults belong to configuration, not this crate. Every project uses this file. Registry-scoped events use a distinguished typed registry scope, not a magic user-controlled project name. New kernel IDs use the shared kind-prefixed UUIDv7 wire spelling. Imported IDs retain their exact accepted legacy spelling. Domain-ID BLOB columns use the canonical UUIDv7 bytes directly for new IDs; the expected field kind supplies the canonical wire prefix. Only imported spellings need a scoped `identities` row and a disjoint private UUIDv8 storage key. Imported public spelling is read from that dictionary, never regenerated from its private key. SQLite row numbers are internal commit positions, never public IDs or authorization.

### Fixed decisions

* WAL with `synchronous=NORMAL` for ordinary writes; the closed security-event set below commits under `FULL`, as Prime required in the review return. NORMAL acknowledgments survive writer-process crash but can lose several recent ordinary commits on OS failure or power loss, but not an application-process crash. FULL security acknowledgments require the successful sync. No caller/environment durability knob exists.
* One host-owned batched writer when the runtime lease is held; a direct no-host writer calls the identical transaction function while holding a shared runtime lease in client mode; the host alone holds it exclusively. There is no host/direct split in apply or authorization semantics.
* The only authority is the immutable operation envelope, event envelopes and their typed data/body/member rows, with only the narrow sanctioned body-erasure transition below. Projections update before the same COMMIT. The privacy operation is an explicitly audited exception for erasing content, specified below; an ordinary correction never rewrites history.
* No all-event hash chain, PostgreSQL implementation, file watcher, polling loop, dual-written JSONL or repair command. There is no new decision hash chain either: immutable typed decision transitions, expected revisions and exact imported provenance retain user history. The Node factory keeps its existing engine and ledger privately; it is not a Rust CLI/MCP client or a fleet-migration target.
* No store background startup scan. Opening validates the header and version, opens prepared access paths and returns; the sole owning host automatically applies supported additive migrations after a verified pre-migration backup; backup restore is an explicit owner action; an inconsistent projection is a named refusal rather than an unbounded startup rebuild.

## Public API and dependency direction

The compile-only declarations in `crates/se-store/src/` are the normative Rust signatures; this document explains every method's behavior. They contain types and traits, no placeholder implementation or `todo!()`/`unimplemented!()`. Shared kernel IDs, `Read`, `Page` and `Window` come from `se-types`; this crate does not mint a competing identity or completeness vocabulary. Store-domain errors preserve typed detail/remedy and are mapped exhaustively to the shared error envelope by the core/host adapter. A concrete SQLite implementation is deliberately absent until design approval. `RecordId` is a store-specific validated UUIDv7 for internal effect/import/cursor/erasure objects, not a second kernel ID namespace; process lifecycle, store, project, agent, human, session, event, message and decision identities reuse the shared types. The signatures expose no rusqlite, tokio, OS process handle, arbitrary SQL callback or unconstrained JSON event.


The commit bridge is declared in se-core, depending on se-store and se-types;
se-types never depends on se-store. Cx borrows the admitted se_store::Snapshot
read port. On the host route, synchronous validation/planning runs as a bounded
blocking-pool job which opens and drops its finite snapshot inside that job. It
returns OpStep::Commit with an owned se_store::AtomicBatch and typed continuation
`then`, without a held SQL transaction, borrowed read port or IO closure.
HostStore::start_writer yields WriterOwner, whose client submits and returns
Completion: CommitWait. Only that future await runs on the executor; after it,
a second bounded blocking-pool job opens a fresh snapshot and feeds the actual
CommitReceipt to `then`. The consumer owns/clones its reader handle across jobs.
On the hostless route, DirectStore::append uses the same transaction engine
synchronously under the shared runtime lease and returns CommitReceipt directly
to the same continuation. CommitWait has no blocking-wait method or caller.
Iris's compile-only consumer binds message.send and working_state.set across
both receipt routes.

There are four access objects:

1. A factory opens/creates under an explicit role. An owner `se init` creates an absent store and FULL-publishes its schema/header through create_direct under the shared bootstrap lease (or explicit owner create under exclusive custody); host open/embedded activation never creates it. A host holding the exclusive runtime lease can recover or run startup/shutdown backup; supported additive migration completes automatically during sole-host startup, before a ready HostStore is returned. Opening a missing store for a reader/direct client returns measured absence; it never creates an empty database.
2. A read snapshot owns one SQLite read transaction and a captured high-water position. Unlike the separate background backup transaction, it cannot be held across an async suspension or an external call. Typed methods return fully materialized bounded results, then release it.
3. A direct writer performs the same atomic write batch as the host worker, while the caller holds a shared runtime lease. It cannot coexist with a host that acquires that lease later: the host waits, then opens after the client releases it.
4. A bounded host submission handle and its owner control. Cloned submission handles cannot close/migrate the store. A dropped reply receiver does not cancel a committed operation. The unique owner drains and joins the worker on shutdown.

Writer ownership is structural: `start_writer(self, ...)` consumes the maintenance-capable HostStore, and only the awaited drain/join yields a `DrainedHost<HostStore>`. Migrate/erase/close cannot run on an object still held by a live writer. The worker owns `Arc<dyn RuntimeLease>` and revalidates its store/generation/mode before each group; external handle drop cannot release a live worker's lease. Online backup is the separate factory service over a read connection, not a mutable writer/maintenance call.

A revision identifies a last committed event, scoped to the same store incarnation. Each event/operation also retains its recorded incarnation; historical expected positions are replayed against their original logical predecessors, not re-authorized against a new live incarnation. Recovery/erasure may invalidate runtime cursors without rewriting the fact that an older event committed in an earlier incarnation. `Expected::Absent` and `Expected::Revision` are distinct from unchecked writes. Unconditional internal appends exist only for genuinely append-only facts; mutable projections require a revision precondition. The caller's verified scope is not an event field and is never recovered from a display name. The store checks project/actor consistency with the admitted batch; credential proof and OS-user admission remain core/host responsibilities inside the same process trust boundary.

## Event wire and storage formats

Each event has a version-1 envelope (the closed Rust variant determines kind and schema version; a caller cannot request an unknown numeric version): stable event ID; scope; authenticated actor; optional bound session; origin store ID; door (`cli`, `mcp`, `hook`, `host`, `import`); occurrence time in UTC microseconds; database-assigned recorded time; caller idempotency key; optional cause/supersedes event IDs; and one closed `EventBody` variant. The store assigns sequence only inside the transaction; recorded wall time is sampled before BEGIN, not by an external clock call while holding a transaction. Normal batches require header actor/scope to match admitted authority. Import-only batches may preserve a different historical actor/origin after strict source-ID mapping, but their initiating owner/import identity remains on the immutable operation envelope; that historical actor never becomes current session authority. A host group contains independently atomic operation batches; one operation batch can contain several events and their expected revisions. An immutable operation envelope owns scope/actor/request-key/fingerprint and an ordered membership map, so replay and uncertain-reply retries reconstruct the original atomic membership from authority rather than a disposable lookup index.

The database stores the small envelope and typed per-kind rows, **not a second serialized JSON envelope**. Long bodies have one `payloads` row referenced by their event. Recipient/disposition/decision/session/turn/process/working-state/cursor projections contain indexes and event references, never copied body text. Refs and agent profile/grant objects are bounded typed encodings; their only JSON is a versioned non-text field, not an arbitrary duplicate of the event. Readers reconstruct a typed event from its one owning representation.

Strings are UTF-8 with no normalization of user text. Times are signed 64-bit Unix microseconds, with a checked supported range; sequence/revision values are positive signed 64-bit integers. Body byte counts count UTF-8 bytes, not characters. All enum tags are the stable strings below; integer discriminants in Rust are not persisted. SHA-256 fields are 32-byte blobs. Stored UUID keys are exactly 16 bytes, never SQLite row IDs. Canonical-v7 keys reconstruct their wire spelling from the typed column; legacy-v8 keys require the scoped identity dictionary. Canonical public IDs include the shared kind prefix; legacy public IDs retain their exact validated spelling through the identity dictionary. File paths are lossless platform path encodings tagged `unix-bytes` or `windows-utf16`; display strings never become an ownership proof. Native non-UTF-8 path bytes are not silently replaced.

Bounded initial limits: 32 KiB per message body and 16 KiB per working-state body, from se-types::MESSAGE_BODY_MAX_BYTES and se-types::WORKING_STATE_MAX_BYTES, the shared DTO definitions generated into CLI/MCP/schema/store, 1 MiB per captured turn, 64 refs, 8 KiB per single ref or native identity, 64 events/2 MiB per atomic operation batch. Large turns are streamed from the trusted harness into a bounded staging record before submission; the worker never queues 1 MiB copies for every session. Rejection preserves the source transcript cursor and names the oversized record; it never advances capture past uncaptured text. Header/ID/enum decoding is strict and unknown versions refuse, not skip.

### Event catalogue

All following kinds have `schema_version = 1`; changing required fields or meaning requires a new kind version and a reader/migration decision. Fields in the common envelope are not repeated in the table. `expected` means the last revision of the affected projection; IDs in references must resolve in the same authorized scope unless explicitly registry-wide. Every generated event is attributed to the initiating operation or a cause event, never to an invented actor. A kind not listed here refuses.

| Kind | Typed body fields | Emitting operation / internal cause | Authoritative projection effect |
| --- | --- | --- | --- |
| `project.registered` | project ID, display name, canonical/lossless repository roots, owner ID, expected absent; safe agent profile/grant events share its atomic batch | `project.init`; supported project import | create registry/project heads; roots cannot collide |
| `project.updated` | project ID, complete display name/root snapshot, expected; general settings stay in config.toml | `project.init` idempotent adoption repair | append revision; preserve ID and registration history |
| `project.removed` | project ID, expected, stop/revocation/integration witness event refs, preserved-history facts | `project.remove` after outside effects | tombstone registration, remove active root lookup; retain history |
| `principal.registered` | principal ID, human/agent kind, owner ID, authenticated creator ID (unknown only for import/bootstrap), display name, role, expected absent | `project.init`, `agent.create`; owner/agent import | create principal; no authority from display name |
| `principal.renamed` | principal ID, name, expected | `agent.rename` | change lookup label, preserve ID |
| `alias.imported` | legacy alias, target principal ID, source ref, expected absent | `store.import_node` only | add historical lookup alias; never public alias creation |
| `profile.saved` | agent ID, provider, model, named permission profile, supported effort setting, expected | init/create/config and supported imported profiles | update saved profile, no launch claim |
| `grant.recorded` | principal ID, typed agent-create grant/scope, active/revoked, expected | owner init/config policy; historical import | update effective explicit grant; no bootstrap from old capability |
| `session.prepared` | session ID, agent ID, provider/native conversation ref, capture consent, generation, expected absent | `session.begin`, `agent.launch` preparation | insert prepared session; incumbent remains active |
| `session.activated` | session ID, expected, incumbent ID/revision if replacing, process ref, recorded containment fact and binding/witness refs | witnessed launch/bind | activate atomically with incumbent terminal transition; one active per agent |
| `session.ended` | session ID, expected, end reason, final captured-turn/cursor refs | `session.end`; observed provider termination | terminal ended state; revoke active capability projections |
| `session.revoked` | session ID, expected, reason | owner revocation/remove; governed takeover | terminal revoked state; cannot be reactivated |
| `credential.issued` | credential ID, session ID, purpose, secret hash, expiry, ≤10-minute activation deadline, expected absent | trusted bind/token helper | retain hash only; plaintext returned once outside event |
| `credential.activated` | credential, session, exact prepared revision, first admitted request | host capability verifier | prepared → active in the first-use transaction, activate binding/revoke incumbent atomically |
| `credential.revoked` | credential ID, expected, reason | session end/revoke/remove | irreversible revoked state |
| `message.sent` | message ID, recipient ID, kind, body payload, refs, reply-to ID | `message.send`; supported message import | create message/inbox row; delivery pending |
| `message.delivered` | message ID, recipient ID, actual consumer/offer evidence ref | internal witnessed mail settlement | first delivered marker; no read claim |
| `message.read` | message ID, recipient ID | `message.read`, `message.ack`; supported message import | first read marker, remove from unread page |
| `message.dismissed` | message ID, recipient ID | `message.dismiss`; supported message import | first dismissal, no manufactured read |
| `message.superseded` | message ID, replacement message ID, expected | supported message import only | retain both messages and a relation; cannot change another sender's body |
| `decision.proposed` | decision ID, key, statement payload, optional prior proposal, kind note/decision | `decision.propose`; decision import | pending proposal, no activation from supersedes hint |
| `decision.ratified` | decision ID, expected, owner approval ref | `decision.ratify`; proven decision transition | active ratification; immutable transition with expected revision |
| `decision.rejected` | decision ID, expected, reason payload | `decision.reject`; proven imported transition | terminal rejection, preserve proposal |
| `decision.retracted` | decision ID, expected, reason payload | `decision.retract`; proven imported transition | terminal withdrawal |
| `decision.superseded` | prior/replacement decision IDs and expected revisions, owner approval ref | `decision.supersede`; proven imported transition | replace governing decision atomically, retain statements |
| `session.turn` | turn ID, agent/session ID, provider, native turn ref, role, text payload, lossless source path/offset/length/hash | `session.turn`, Claude hooks, Codex app-server capture; turn import | insert turn, advance captured source cursor only with complete bytes |
| `capture.source` | source ID, session, consent, native ref, expected | bind/adopt/import | establish source without reading an account credential |
| `capture.progress` | source ID, expected, source incarnation/digest, old/new byte offsets, last turn ID | completed capture transaction | advance monotonically only for verified same source incarnation |
| `capture.failed` | source/session, unchanged start offset, attempted end offset, typed code/cause/retry | authenticated harness capture | durable named failure without advancing past uncaptured bytes |
| `capture.suppressed` | source/session ID, expected, suppression reason, offset window, count | explicitly incognito/disabled capture; conversation consent import | record suppression as suppression, not success/absence |
| `process.registered` | process ID, project/agent/session, machine/boot IDs, native birth identity, executable and argv fingerprint, custody group, initial state | internal witnessed agent/runtime launch only; no public process.start/control/list surface | all nine section-30 states, explicit absent/unreadable root at scope preparation/import, recorded containment/cause; no live witness implied |
| `process.transition` | process ID, complete current identity/custody checkpoint, expected, from/to state, observation ref, outcome, recorded containment fact | inspect/stop and actual OS exit/re-adoption observation | CAS state; reused/unreadable process never becomes owned |
| `working_state.set` | agent ID, text payload, expected | `working_state.set`; working-state import | update head; absent and stale expected differ |
| `cursor.recorded` | agent/session, cursor purpose, opaque value, snapshot window, expected | explicit context presentation/settlement/capture progress | update cursor without hiding unread work |
| `cursor.acknowledged` | cursor ID/revision, authenticated consumer evidence | actual packet/context/mail acknowledgment; user-history import | mark that exact cursor presented/read; issuance alone is not ack |
| `effect.requested` | effect ID, kind, optional affected principal, target, safe immutable intent data, cause event, idempotency ref | init/launch/stop/send/remove's transaction | durable pending work, no OS/network call inside transaction |
| `effect.offered` | effect, principal, unique attempt, offer evidence | host delivery executor | pending → offered; offer is not recipient read or settlement |
| `effect.settled` | effect ID, expected, witnessed/failed/abandoned state, outside evidence or failure, attempt summary | host/harness actual effect readback | terminal effect state; only evidence can select witnessed |
| `integration.recorded` | integration ID, path/key/marker, prior/written digest, scope, readback ref, expected | init/doctor owned edits; successful removal update | retain exact ownership for reversal, never agent credential content |
| `runtime.owner` | full HostEpoch, engine Generation, expected prior owner generation (None only before first owner), expected head, outside witness refs, optional RuntimeRecoveredTransfer | initial exclusive host admission or checked cold recovery | FULL; establish owner and atomically resolve a superseded Claimed transfer as Recovered; refuse unresolved pre-claim transfer or stale generation |
| `runtime.handover` | RuntimeHandoverRecord below, expected owner-head revision, phase witness refs | section-40 live handover barrier only | FULL; owner-generation + head CAS, ownership changes only at Claimed |
| `backup.recorded` | generation, checkpoint/snapshot position, file identity/hash, schema version, readback ref | completed backup | record completed snapshot manifest, not a backup attempt |
| `import.started` | import ID, source identity/prefix digest, supported format/version, policy version | `store.import_node` | create resumable import run |
| `import.progress` | import ID, family/path, expected source incarnation/prefix, byte/row cursor, counters | committed imported chunk | advance cursor atomically with its imported events |
| `import.finished` | import ID, expected, totals/omissions, artifact refs | completed bounded source walk | terminal complete/partial report; unreadable never becomes zero |
| `import.unreadable` | import ID, source path/offset/length/digest, typed failure, retained source ref | strict import decoder failure | preserve bounded failure provenance, not copied secret source text |
| `legacy.retained` | source family/version, source identity/hash/offset, imported object mapping, immutable legacy bytes payload where needed | user-decision provenance import | retain historical provenance with no live grants/process custody |
| `turn.erased` | target event, erasure ID, original byte length, owner | owner forget | sanctioned captured-body erasure marker; vendor ref remains deduplicated |
| `message.erased` | target event, erasure ID, original byte length, owner | owner forget | sanctioned message-body erasure marker; recipient/marks remain |
| `erasure.requested` | erasure ID, explicit target event/field IDs, approved scope/revision, external residual-copy inventory | `store.forget` after owner confirmation | maintenance pending; freeze ordinary writers |
| `erasure.completed` | erasure ID, erasure manifest, current DB/WAL readback witnesses, residual limits | completed in-place cleanup/readback | erasure completion, stale cursor epoch bump |
| `recovery.recorded` | recovery ID, optional source StoreId, exact source artifact, target StoreId, selected newest valid backup, restored high-water, known/unknown post-backup loss and outside validation | explicit owner restore of the newest valid automatic backup | record degraded origin; never claim a complete history across gaps |

Internal event kinds do not add CLI/MCP operations. Read-only `status`, `history`, `resume`, `search`, `decision.list`, `doctor.inspect` and all Atlas queries emit no events. `runtime.up/down` do not append periodic liveness; they record only actual custody/effect boundaries. Failed unauthenticated calls and normal refusals are not events (the synthesized plan drops refusal history). Cursor persistence is a separate explicit capture/settlement action, not a hidden write by every reader.

## SQLite schema version 1

`application_id = 0x53454E47` (`SENG`), `user_version = 1`. This chapter declares 52 event kinds and 42 application tables (excluding SQLite's sqlite_sequence); counts derive from the catalogue and CREATE TABLE statements below. This DDL is a design artifact; migrations will embed the approved bytes, not execute a Markdown parser. Every `*_data` table is an immutable component of an event. `payloads` owns content; `*_data` owns per-kind facts. The `facts` object in `aux_data` is a **closed typed per-kind versioned object excluding the envelope and payload bytes**, used for lower-frequency setup/import/effect facts; hot message/turn/decision/session/process/working-state/cursor records have typed columns. A projection may duplicate a small lookup key, not user text or an entire event serialization.

```sql
PRAGMA application_id=0x53454E47;
PRAGMA user_version=1;
CREATE TABLE store_info(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  store_id BLOB NOT NULL CHECK(length(store_id)=16),
  incarnation INTEGER NOT NULL CHECK(incarnation>0),
  created_at_us INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ready','migrating','recovering','erasing'))
) STRICT;
-- Rebuildable per-user owner head; immutable authority is in runtime.* events/aux_data.
CREATE TABLE runtime_owner(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  owner_generation INTEGER NOT NULL CHECK(owner_generation>0),
  owner_epoch TEXT NOT NULL CHECK(json_valid(owner_epoch)),
  transfer BLOB CHECK(transfer IS NULL OR length(transfer)=16),
  phase TEXT CHECK(phase IS NULL OR phase IN
    ('Prepared','Claimed','Finished','Aborted','Recovered')),
  last_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq),
  CHECK((transfer IS NULL)=(phase IS NULL))
) STRICT;
CREATE TABLE symbols(id INTEGER PRIMARY KEY, value BLOB NOT NULL UNIQUE) STRICT;
CREATE TABLE identities(
  storage_key BLOB PRIMARY KEY CHECK(length(storage_key)=16),
  kind TEXT NOT NULL CHECK(kind IN ('project','agent','human','session','message','decision','event','launch','observation','store','lifecycle')),
  wire_id TEXT NOT NULL,
  scope_key BLOB NOT NULL,
  encoding TEXT NOT NULL CHECK(encoding IN ('legacy-shape','registered-exception')),
  registration_source BLOB,
  CHECK(length(wire_id)>0 AND length(CAST(wire_id AS BLOB))<=512),
  CHECK(encoding!='registered-exception' OR registration_source IS NOT NULL),
  UNIQUE(kind,scope_key,wire_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  actor_id BLOB NOT NULL CHECK(length(actor_id)=16),
  session_id BLOB CHECK(session_id IS NULL OR length(session_id)=16),
  origin_id BLOB NOT NULL CHECK(length(origin_id)=16),
  door TEXT NOT NULL CHECK(door IN ('cli','mcp','hook','host','import')),
  kind TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK(schema_version>0),
  recorded_incarnation INTEGER NOT NULL CHECK(recorded_incarnation>0),
  writer_mode TEXT NOT NULL CHECK(writer_mode IN ('host','direct')),
  host_generation INTEGER CHECK(host_generation>0),
  durability TEXT NOT NULL CHECK(durability IN ('normal','full')),
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  occurred_at_us INTEGER NOT NULL,
  recorded_at_us INTEGER NOT NULL,
  cause_event_id BLOB CHECK(cause_event_id IS NULL OR length(cause_event_id)=16),
  supersedes_event_id BLOB CHECK(supersedes_event_id IS NULL OR length(supersedes_event_id)=16),
  CHECK((writer_mode='host' AND host_generation IS NOT NULL) OR (writer_mode='direct' AND host_generation IS NULL)),
  CHECK(kind!='session.turn' OR session_id IS NOT NULL)
) STRICT;
CREATE INDEX events_scope_seq ON events(project_id,seq);
CREATE INDEX events_actor_seq ON events(project_id,actor_id,seq);
CREATE INDEX events_session_seq ON events(project_id,session_id,seq);
CREATE TABLE operations(
  operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
  scope_key BLOB NOT NULL,
  actor_id BLOB NOT NULL CHECK(length(actor_id)=16),
  request_key TEXT CHECK(request_key IS NULL OR length(CAST(request_key AS BLOB)) BETWEEN 1 AND 512),
  fingerprint_codec INTEGER NOT NULL DEFAULT 1 CHECK(fingerprint_codec>0),
  fingerprint BLOB CHECK(fingerprint IS NULL OR length(fingerprint)=32),
  recorded_incarnation INTEGER NOT NULL CHECK(recorded_incarnation>0),
  writer_mode TEXT NOT NULL CHECK(writer_mode IN ('host','direct')),
  host_generation INTEGER CHECK(host_generation>0),
  durability TEXT NOT NULL CHECK(durability IN ('normal','full')),
  erased INTEGER NOT NULL DEFAULT 0 CHECK(erased IN (0,1)),
  CHECK((erased=0 AND request_key IS NOT NULL AND fingerprint IS NOT NULL) OR (erased=0 AND request_key IS NULL AND fingerprint IS NULL) OR (erased=1 AND fingerprint IS NULL)),
  CHECK((writer_mode='host' AND host_generation IS NOT NULL) OR (writer_mode='direct' AND host_generation IS NULL))
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX operations_caller_key ON operations(scope_key,actor_id,request_key) WHERE request_key IS NOT NULL;
CREATE TABLE operation_events(
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  ordinal INTEGER NOT NULL CHECK(ordinal>=0),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  newly_appended INTEGER NOT NULL CHECK(newly_appended IN (0,1)),
  PRIMARY KEY(operation_id,ordinal)
) STRICT, WITHOUT ROWID;
CREATE INDEX operation_events_event ON operation_events(event_seq,operation_id);
CREATE TABLE payloads(
  payload_id INTEGER PRIMARY KEY,
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  field TEXT NOT NULL,
  encoding TEXT NOT NULL CHECK(encoding IN ('utf8','bytes')),
  content BLOB NOT NULL,
  sha256 BLOB NOT NULL CHECK(length(sha256)=32),
  UNIQUE(event_seq,field)
) STRICT;
CREATE TABLE aux_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  facts TEXT NOT NULL CHECK(json_valid(facts))
) STRICT;
CREATE TABLE message_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  message_kind TEXT NOT NULL,
  body_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  refs TEXT NOT NULL CHECK(json_valid(refs)),
  reply_to BLOB CHECK(reply_to IS NULL OR length(reply_to)=16)
) STRICT;
CREATE TABLE mark_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  message_seq INTEGER NOT NULL REFERENCES message_data(event_seq),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  disposition TEXT NOT NULL CHECK(disposition IN ('delivered','read','dismissed')),
  evidence_event BLOB CHECK(evidence_event IS NULL OR length(evidence_event)=16)
) STRICT;
CREATE TABLE decision_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  decision_id BLOB NOT NULL CHECK(length(decision_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  decision_key TEXT,
  state TEXT NOT NULL CHECK(state IN ('proposed','ratified','rejected','retracted','superseded')),
  statement_payload INTEGER REFERENCES payloads(payload_id),
  reason_payload INTEGER REFERENCES payloads(payload_id),
  expected_seq INTEGER,
  prior_proposal_id BLOB CHECK(prior_proposal_id IS NULL OR length(prior_proposal_id)=16),
  decision_kind TEXT CHECK(decision_kind IN ('note','decision')),
  replacement_id BLOB CHECK(replacement_id IS NULL OR length(replacement_id)=16),
  replacement_expected_seq INTEGER
) STRICT;
CREATE INDEX decision_data_key ON decision_data(project_id,decision_key,event_seq DESC) WHERE decision_key IS NOT NULL;
CREATE TABLE session_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode')),
  native_ref INTEGER NOT NULL REFERENCES symbols(id),
  generation INTEGER NOT NULL CHECK(generation>0),
  consent TEXT NOT NULL CHECK(consent IN ('capture','suppressed')),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','ended','revoked')),
  expected_seq INTEGER,
  incumbent_id BLOB CHECK(incumbent_id IS NULL OR length(incumbent_id)=16),
  incumbent_expected_seq INTEGER,
  process_id BLOB CHECK(process_id IS NULL OR length(process_id)=16),
  containment_fact TEXT CHECK(containment_fact IS NULL OR json_valid(containment_fact)),
  reason_payload INTEGER REFERENCES payloads(payload_id),
  witness_refs TEXT NOT NULL CHECK(json_valid(witness_refs))
) STRICT;
CREATE TABLE turn_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  turn_id BLOB NOT NULL CHECK(length(turn_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode')),
  vendor_ref TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('system','user','assistant','tool')),
  text_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  source_path INTEGER REFERENCES symbols(id),
  source_offset INTEGER CHECK(source_offset>=0),
  source_length INTEGER CHECK(source_length>=0),
  source_sha256 BLOB CHECK(source_sha256 IS NULL OR length(source_sha256)=32),
  UNIQUE(project_id,session_id,provider,vendor_ref),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT;
CREATE INDEX turn_data_agent_seq ON turn_data(project_id,agent_id,event_seq);
CREATE INDEX turn_data_session_seq ON turn_data(project_id,session_id,event_seq);
CREATE TABLE process_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  target_session_id BLOB CHECK(target_session_id IS NULL OR length(target_session_id)=16),
  root_identity TEXT NOT NULL CHECK(root_identity IN ('no-child-created','unpublished','identified','unknown')),
  identity_state TEXT NOT NULL CHECK(identity_state IN ('present','absent','unreadable')),
  identity_cause TEXT,
  machine_id INTEGER REFERENCES symbols(id),
  boot_identity INTEGER REFERENCES symbols(id),
  pid INTEGER CHECK(pid>0),
  birth_identity BLOB,
  executable INTEGER REFERENCES symbols(id),
  argv_sha256 BLOB CHECK(length(argv_sha256)=32),
  custody_version INTEGER NOT NULL CHECK(custody_version=1),
  custody BLOB NOT NULL,
  containment TEXT NOT NULL CHECK(containment IN ('cgroup','job','process-group','uncontained','unknown','not-launched')),
  containment_cause TEXT,
  containment_unknown_reason TEXT,
  containment_observed_at_us INTEGER,
  containment_probe BLOB CHECK(containment_probe IS NULL OR length(containment_probe)=16),
  state TEXT NOT NULL CHECK(state IN ('reserved','starting','running','leader-exited','stop-requested','stop-unproved','exited','lost','historical')),
  expected_seq INTEGER,
  observation_event BLOB CHECK(observation_event IS NULL OR length(observation_event)=16),
  CHECK((identity_state='present' AND machine_id IS NOT NULL AND boot_identity IS NOT NULL AND pid IS NOT NULL AND birth_identity IS NOT NULL AND executable IS NOT NULL AND argv_sha256 IS NOT NULL AND identity_cause IS NULL)
     OR (identity_state IN ('absent','unreadable') AND machine_id IS NULL AND boot_identity IS NULL AND pid IS NULL AND birth_identity IS NULL AND executable IS NULL AND argv_sha256 IS NULL AND identity_cause IS NOT NULL)),
  CHECK((root_identity='identified' AND identity_state='present')
     OR (root_identity IN ('no-child-created','unpublished') AND identity_state='absent')
     OR (root_identity='unknown' AND identity_state IN ('absent','unreadable') AND state IN ('historical','lost'))),
  CHECK(state<>'reserved' OR root_identity='no-child-created'),
  CHECK(state NOT IN ('running','leader-exited') OR root_identity='identified'),
  CHECK(state NOT IN ('stop-requested','stop-unproved','exited') OR (root_identity<>'unknown' AND observation_event IS NOT NULL)),
  CHECK((containment='uncontained' AND containment_cause IN ('no-user-manager','no-delegation','cgroup-v2-absent','cgroup-unreadable','scope-create-failed') AND containment_cause IS NOT NULL AND containment_observed_at_us IS NOT NULL AND containment_unknown_reason IS NULL)
     OR (containment IN ('cgroup','job','process-group') AND containment_cause IS NULL AND containment_observed_at_us IS NOT NULL AND containment_unknown_reason IS NULL)
     OR (containment='unknown' AND containment_cause IS NULL AND containment_unknown_reason IS NOT NULL)
     OR (containment='not-launched' AND containment_cause IS NULL AND containment_unknown_reason IS NULL))
) STRICT;
CREATE TABLE working_state_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  text_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  expected_seq INTEGER
) STRICT;
CREATE TABLE cursor_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  cursor_id BLOB NOT NULL CHECK(length(cursor_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  purpose TEXT NOT NULL,
  value BLOB NOT NULL,
  expected_seq INTEGER,
  from_seq INTEGER NOT NULL CHECK(from_seq>=0),
  to_seq INTEGER NOT NULL CHECK(to_seq>=from_seq),
  returned INTEGER NOT NULL CHECK(returned>=0),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  omitted INTEGER CHECK(omitted>=0),
  acknowledged_event BLOB CHECK(acknowledged_event IS NULL OR length(acknowledged_event)=16)
) STRICT;

CREATE TABLE projects(
  project_id BLOB PRIMARY KEY CHECK(length(project_id)=16),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('active','removed'))
) STRICT, WITHOUT ROWID;
CREATE TABLE roots(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  canonical_key BLOB NOT NULL UNIQUE,
  encoded_path INTEGER NOT NULL REFERENCES symbols(id),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,canonical_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE owners(
  human_id BLOB PRIMARY KEY CHECK(length(human_id)=16),
  display_name TEXT NOT NULL,
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT, WITHOUT ROWID;
CREATE TABLE principals(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  principal_kind TEXT NOT NULL CHECK(principal_kind IN ('human','agent')),
  owner_id BLOB NOT NULL REFERENCES owners(human_id),
  created_by BLOB CHECK(created_by IS NULL OR length(created_by)=16),
  display_name TEXT NOT NULL,
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,principal_id),
  UNIQUE(project_id,display_name),
  FOREIGN KEY(project_id,created_by) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE aliases(
  project_id BLOB NOT NULL,
  alias TEXT NOT NULL,
  principal_id BLOB NOT NULL,
  imported_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,alias),
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE profiles(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,agent_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE grants(
  scope_key BLOB NOT NULL,
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  grant_key TEXT NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(scope_key,principal_id,grant_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE sessions(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  agent_id BLOB NOT NULL,
  first_seq INTEGER NOT NULL REFERENCES session_data(event_seq),
  last_seq INTEGER NOT NULL REFERENCES session_data(event_seq),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','ended','revoked')),
  PRIMARY KEY(project_id,session_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX sessions_one_active ON sessions(project_id,agent_id) WHERE state='active';
CREATE TABLE credentials(
  credential_id BLOB PRIMARY KEY CHECK(length(credential_id)=16),
  project_id BLOB NOT NULL,
  session_id BLOB NOT NULL,
  purpose TEXT NOT NULL,
  secret_sha256 BLOB NOT NULL UNIQUE CHECK(length(secret_sha256)=32),
  expires_at_us INTEGER NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  activation_deadline_us INTEGER NOT NULL,
  activated_seq INTEGER REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','revoked')),
  CHECK((state='prepared' AND activated_seq IS NULL) OR state='revoked' OR (state='active' AND activated_seq IS NOT NULL)),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE messages(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  sent_seq INTEGER NOT NULL UNIQUE REFERENCES message_data(event_seq),
  sender_id BLOB NOT NULL CHECK(length(sender_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  message_kind TEXT NOT NULL,
  superseded_by BLOB CHECK(superseded_by IS NULL OR length(superseded_by)=16),
  PRIMARY KEY(project_id,message_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX messages_project_seq ON messages(project_id,sent_seq DESC);
CREATE INDEX messages_sender_seq ON messages(project_id,sender_id,sent_seq DESC);
CREATE INDEX messages_recipient_seq ON messages(project_id,recipient_id,sent_seq DESC);
CREATE INDEX messages_kind_seq ON messages(project_id,message_kind,sent_seq DESC);
CREATE TABLE marks(
  message_seq INTEGER PRIMARY KEY REFERENCES message_data(event_seq),
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  delivered_seq INTEGER REFERENCES mark_data(event_seq),
  read_seq INTEGER REFERENCES mark_data(event_seq),
  dismissed_seq INTEGER REFERENCES mark_data(event_seq)
) STRICT;
CREATE INDEX marks_unread ON marks(project_id,recipient_id,message_seq DESC)
  WHERE read_seq IS NULL AND dismissed_seq IS NULL;
CREATE TABLE decisions(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  decision_id BLOB NOT NULL CHECK(length(decision_id)=16),
  proposed_seq INTEGER NOT NULL REFERENCES decision_data(event_seq),
  last_seq INTEGER NOT NULL REFERENCES decision_data(event_seq),
  state TEXT NOT NULL CHECK(state IN ('proposed','ratified','rejected','retracted','superseded')),
  PRIMARY KEY(project_id,decision_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX decisions_order ON decisions(project_id,last_seq,decision_id);
CREATE INDEX decisions_state ON decisions(project_id,state,last_seq,decision_id);
CREATE TABLE capture_sources(
  project_id BLOB NOT NULL,
  source_id BLOB NOT NULL CHECK(length(source_id)=16),
  session_id BLOB NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  source_incarnation BLOB NOT NULL,
  byte_offset INTEGER NOT NULL CHECK(byte_offset>=0),
  consent TEXT NOT NULL CHECK(consent IN ('capture','suppressed')),
  suppressed_count INTEGER NOT NULL CHECK(suppressed_count>=0),
  PRIMARY KEY(project_id,source_id),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE processes(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  first_seq INTEGER NOT NULL REFERENCES process_data(event_seq),
  last_seq INTEGER NOT NULL REFERENCES process_data(event_seq),
  state TEXT NOT NULL CHECK(state IN ('reserved','starting','running','leader-exited','stop-requested','stop-unproved','exited','lost','historical')),
  PRIMARY KEY(project_id,process_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX processes_live ON processes(project_id,state,last_seq) WHERE state NOT IN ('exited','historical');
CREATE TABLE working_state(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES working_state_data(event_seq),
  PRIMARY KEY(project_id,agent_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE cursors(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  purpose TEXT NOT NULL,
  cursor_id BLOB NOT NULL CHECK(length(cursor_id)=16),
  last_seq INTEGER NOT NULL REFERENCES cursor_data(event_seq),
  acknowledged_seq INTEGER REFERENCES cursor_data(event_seq),
  PRIMARY KEY(project_id,agent_id,purpose),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE effects(
  effect_id BLOB PRIMARY KEY CHECK(length(effect_id)=16),
  project_id BLOB,
  kind TEXT NOT NULL,
  principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id)=16),
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('pending','offered','witnessed','failed','abandoned')),
  FOREIGN KEY(project_id) REFERENCES projects(project_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX effects_pending ON effects(project_id,requested_seq) WHERE state IN ('pending','offered');
CREATE INDEX effects_principal_pending ON effects(project_id,principal_id,requested_seq) WHERE state IN ('pending','offered');
CREATE TABLE integrations(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  integration_id BLOB NOT NULL CHECK(length(integration_id)=16),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('installed','removed','conflict')),
  PRIMARY KEY(project_id,integration_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE import_runs(
  import_id BLOB PRIMARY KEY CHECK(length(import_id)=16),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('running','complete','partial'))
) STRICT, WITHOUT ROWID;
CREATE TABLE import_progress(
  import_id BLOB NOT NULL REFERENCES import_runs(import_id),
  family TEXT NOT NULL,
  source_key BLOB NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  byte_offset INTEGER NOT NULL CHECK(byte_offset>=0),
  row_offset INTEGER NOT NULL CHECK(row_offset>=0),
  prefix_sha256 BLOB NOT NULL CHECK(length(prefix_sha256)=32),
  PRIMARY KEY(import_id,family,source_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE legacy_ids(
  import_id BLOB NOT NULL REFERENCES import_runs(import_id),
  family TEXT NOT NULL,
  legacy_id TEXT NOT NULL,
  typed_id BLOB NOT NULL CHECK(length(typed_id)=16),
  imported_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(import_id,family,legacy_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE list_versions(
  scope_key BLOB NOT NULL,
  family TEXT NOT NULL CHECK(family IN ('message')),
  entity_key BLOB NOT NULL,
  valid_from INTEGER NOT NULL REFERENCES events(seq),
  valid_to INTEGER REFERENCES events(seq),
  sort_seq INTEGER NOT NULL REFERENCES events(seq),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL,
  sender_id BLOB,
  recipient_id BLOB,
  message_kind TEXT,
  delivered_seq INTEGER REFERENCES events(seq),
  read_seq INTEGER REFERENCES events(seq),
  dismissed_seq INTEGER REFERENCES events(seq),
  CHECK(valid_to IS NULL OR valid_to>valid_from),
  CHECK(sort_seq=first_seq),
  PRIMARY KEY(scope_key,family,entity_key,valid_from)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX list_versions_open ON list_versions(scope_key,family,entity_key) WHERE valid_to IS NULL;
CREATE INDEX list_versions_order ON list_versions(scope_key,family,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_state ON list_versions(scope_key,family,state,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_sender ON list_versions(scope_key,family,sender_id,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_recipient ON list_versions(scope_key,family,recipient_id,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_recipient_state ON list_versions(scope_key,family,recipient_id,state,sort_seq ASC,entity_key,valid_from DESC,valid_to);
-- Non-mail lists read current heads with live keysets, not temporal versions.
CREATE INDEX projects_order ON projects(first_seq,project_id);
CREATE INDEX principals_order ON principals(project_id,first_seq,principal_id);
CREATE INDEX sessions_order ON sessions(project_id,first_seq,session_id);
CREATE INDEX processes_order ON processes(project_id,first_seq,process_id);
CREATE INDEX effects_order ON effects(project_id,requested_seq,effect_id);
CREATE INDEX effects_state_order ON effects(project_id,state,requested_seq,effect_id);
CREATE INDEX integrations_order ON integrations(project_id,last_seq,integration_id);
CREATE TABLE erasures(
  erasure_id BLOB PRIMARY KEY CHECK(length(erasure_id)=16),
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  completed_seq INTEGER REFERENCES events(seq),
  manifest_payload INTEGER NOT NULL REFERENCES payloads(payload_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE erased_fields(
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  field TEXT NOT NULL,
  original_bytes INTEGER NOT NULL CHECK(original_bytes>=0),
  erasure_id BLOB NOT NULL REFERENCES erasures(erasure_id),
  PRIMARY KEY(event_seq,field)
) STRICT, WITHOUT ROWID;
```

`scope_key` is the disjoint binary encoding `0x00` for registry or `0x01 || project_uuid` for a project; using NULL as part of the idempotency primary key would not enforce uniqueness. `events.project_id = NULL` is allowed only for the registry event-kind subset. Scoped projections never use a NULL project to mean all projects. `symbols` stores only repeated lossless path/native-reference bytes, not user turn/message/working-state text, so an erasure does not have to delete a shared user's content.

Every immutable table has both fixed triggers below. Projections are not independent authority; operation envelopes/member rows are immutable authority for retries and atomic recovery groups. These statements are the complete finite list, not an instruction to infer immutability from table naming.

```sql
CREATE TRIGGER operations_no_update BEFORE UPDATE ON operations
WHEN NOT (NEW.operation_id=OLD.operation_id AND NEW.scope_key=OLD.scope_key AND NEW.actor_id=OLD.actor_id
  AND NEW.request_key IS OLD.request_key AND NEW.fingerprint_codec=OLD.fingerprint_codec AND NEW.recorded_incarnation=OLD.recorded_incarnation
  AND NEW.writer_mode=OLD.writer_mode AND NEW.host_generation IS OLD.host_generation AND NEW.durability=OLD.durability
  AND OLD.erased=0 AND NEW.erased=1 AND NEW.fingerprint IS NULL
  AND se_erase_operation_allowed(OLD.operation_id)=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operations_no_delete BEFORE DELETE ON operations
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operation_events_no_update BEFORE UPDATE ON operation_events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operation_events_no_delete BEFORE DELETE ON operation_events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER payloads_no_update BEFORE UPDATE ON payloads
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER payloads_no_delete BEFORE DELETE ON payloads
WHEN se_erase_body_allowed(OLD.event_seq,OLD.field)!=1
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_update BEFORE UPDATE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_delete BEFORE DELETE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER message_data_no_update BEFORE UPDATE ON message_data
WHEN NOT (NEW.event_seq=OLD.event_seq AND NEW.message_id=OLD.message_id AND NEW.recipient_id=OLD.recipient_id
  AND NEW.message_kind=OLD.message_kind AND NEW.refs=OLD.refs AND NEW.reply_to IS OLD.reply_to
  AND OLD.body_payload IS NOT NULL AND NEW.body_payload IS NULL AND se_erase_body_allowed(OLD.event_seq,'body')=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER message_data_no_delete BEFORE DELETE ON message_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER mark_data_no_update BEFORE UPDATE ON mark_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER mark_data_no_delete BEFORE DELETE ON mark_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER decision_data_no_update BEFORE UPDATE ON decision_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER decision_data_no_delete BEFORE DELETE ON decision_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER session_data_no_update BEFORE UPDATE ON session_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER session_data_no_delete BEFORE DELETE ON session_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER turn_data_no_update BEFORE UPDATE ON turn_data
WHEN NOT (NEW.event_seq=OLD.event_seq AND NEW.turn_id=OLD.turn_id AND NEW.project_id=OLD.project_id
  AND NEW.agent_id=OLD.agent_id AND NEW.session_id=OLD.session_id AND NEW.provider=OLD.provider
  AND NEW.vendor_ref=OLD.vendor_ref AND NEW.role=OLD.role AND NEW.source_path IS OLD.source_path
  AND NEW.source_offset IS OLD.source_offset AND NEW.source_length IS OLD.source_length
  AND OLD.text_payload IS NOT NULL AND NEW.text_payload IS NULL AND NEW.source_sha256 IS NULL
  AND se_erase_body_allowed(OLD.event_seq,'body')=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER turn_data_no_delete BEFORE DELETE ON turn_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER process_data_no_update BEFORE UPDATE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER process_data_no_delete BEFORE DELETE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER working_state_data_no_update BEFORE UPDATE ON working_state_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER working_state_data_no_delete BEFORE DELETE ON working_state_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER cursor_data_no_update BEFORE UPDATE ON cursor_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER cursor_data_no_delete BEFORE DELETE ON cursor_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER symbols_no_update BEFORE UPDATE ON symbols
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER symbols_no_delete BEFORE DELETE ON symbols
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER identities_no_update BEFORE UPDATE ON identities
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER identities_no_delete BEFORE DELETE ON identities
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
```

The implementation embeds these complete fixed trigger statements in version-1 DDL; a new immutable table must add its own triggers in its migration. Kind/table correspondence, required payload field/ownership, ID kinds, permitted registry scope and enum-specific nullability are validated by the closed codec before INSERT and by the offline verifier after recovery. The stored body SHA is not authentication; the trusted core's bound authority authorizes the event. Version 1 has no FTS. It uses bounded indexed scope/time candidates plus streamed text matching and reports budget exhaustion; forget clears its actual owned buffers/caches and reads live DB/WAL back.

## Atomic append, apply and idempotency

The common transaction engine uses `commit_group(connection, admitted_batches)` for ordinary independent operations and the private all-or-nothing `commit_first_binding(FirstBinding)` wrapper for the two maintenance operations below, both using `append_atomic` for one savepoint-isolated operation and `apply` for each event. Direct writes pass a one-element group; the host passes its bounded group. Both invoke the same `TransactionEngine` interface; neither reimplements a projection. Pseudocode here specifies ordering, not permission to implement before approval:

1. Bound input validation outside the write lock: closed kind/version, sizes, ID/encoding shape, scope, no plaintext credentials. Core has already resolved labels and supplied verified authority. For RequestIdentity compute the store fingerprint from the core-produced canonical IntentDigest plus admitted scope/actor, as below; do not hash newly allocated event/body IDs as though they were caller input. Verify inline/staged payload integrity independently.
2. The store derives the writer stamp from its owned runtime lease (host generation or direct), never Admission.generation or Door. It selects FULL if any group member is a security event, reads the pragma back before BEGIN, then the engine's commit entry (`commit_group` or `commit_first_binding`) issues one `BEGIN IMMEDIATE`, then `append_atomic` creates a savepoint per operation and rechecks schema/incarnation and transaction preconditions. It never starts a nested BEGIN inside that group. Consult `(scope_key, actor_id, request_key)` only when the caller supplied an explicit key; public mutation requests always supply one. Trusted capture/marker catch-up may use request=None and deduplicate solely by its mandatory natural key. Same fingerprint returns the original committed first/last event and typed receipt without adding events. Different fingerprint refuses `idempotency-key-reused`. An erased fingerprint refuses `content-erased`; it cannot accept/recreate the original body or silently replay an uncheckable request. A failed uncommitted batch consumes no key.
3. Validate natural keys and resolve no-ops before allocating operation/envelope rows; check each genuinely new event ID for collision before insertion. Insert one operation envelope only if there is a new event or an explicit caller-supplied request key. A different operation cannot reuse it even with identical text. Resolve natural-key no-ops: a second delivered/read/dismissed mark returns the original marker; a duplicate vendor turn returns the original turn only after verifying equal body/source identity. Different bytes at a natural key refuse `natural-key-conflict`. No new domain event/marker is generated just to make an idempotency receipt. A caller-supplied new request key still receives a durable operation/member correspondence even for a no-op, preserving conflict detection. A newly captured keyless operation stores no retry key/fingerprint and has no operations_caller_key index entry; its atomic member map still exists. A derived/keyless all-no-op capture sweep returns a transient NaturalKeyReplay receipt without any INSERT: members retain input natural-key order, primary is the first original event and supplies its retained writer, first/last bound those original revisions and request_key remains None. They need not have belonged to one prior operation; this aggregate does not invent a durable operation ID or claim all members had one writer. Repeating Stop hooks cannot grow history indefinitely. Keyless writes are restricted to natural-keyed capture/marks, never unchecked configuration or arbitrary events.
4. Insert the envelope, store-owned writer/durability stamp, typed data and body exactly once. `apply(event)` checks the current projection revision/state and changes all affected projections, resume heads and pending effect debt. An operation with multiple events is all-or-nothing. commit_first_binding additionally couples both scoped operations: either failure aborts the outer transaction, unlike ordinary independent group members. Unknown kinds/versions, missing referenced rows, stale CAS, wrong recipient or invalid transition abort the **whole operation**, not just the final event.
5. Insert the ordered operation-member map (including reused natural-key events) and return an internal `PreparedReceipt`; this is not yet a committed reply. The engine's commit entry (`commit_group` or `commit_first_binding`) alone issues outer COMMIT under the selected NORMAL/FULL policy, then materializes public `CommitReceipt` values. A receipt reconstructs its exact event-ID list from that map; ordinal zero is the fixed primary event and supplies `primary_event`, `writer` and `durability`, while the operation row separately preserves the actual committer of a newly recorded caller-key alias. This preserves the original event writer even when a new host/direct route encounters a natural-key no-op. Wakes are deterministically reconstructed from original member events (affected project/principal/position), never the current dispatcher; replay may repeat advisory watch bumps but cannot repeat a delivery effect. Exact-key replay returns the original stamps/wake targets. Each member event retains its own stamp if a compound receipt contains pre-existing natural-key facts alongside new events; its first/last positions are descriptive bounds, never permission to treat every intervening event as a member. Only then release successful replies and the committed high-water notification. A reply/notification failure does not undo COMMIT; retry with the same key resolves it. No OS call, filesystem edit, network request, await or expensive transcript scan occurs while holding the transaction.

SQL statement failure and COMMIT failure are not interchangeable. Before COMMIT, rollback is definite. A lost connection/IO error while committing is reported as `commit-outcome-unknown` with the original request key, or the bounded natural event IDs/source checkpoint when keyless; the caller queries/retries those same identities rather than inventing another. Flush/drain preserves the distinction as PendingOperation::CallerKey or NaturalEvents, never an invented empty key. Shutdown/drain does not report success until accepted work has a definite result or an explicit indeterminate receipt. The store never stamps a projection/bell as witnessed just because append succeeded.

### Semantic fingerprint encoding

Core computes IntentDigest from the **closed admitted operation input before allocating IDs or planning events**. It is an internal value, never a wire/MCP field; the store/core share the in-process trust boundary, so store does not depend on higher-layer Op types or accept an untrusted client hash. AtomicBatch.request is either None for the restricted natural-key path or RequestIdentity { key, intent }. Core obtains the static operation name from its closed generated registry, never user text; store validates the supported intent codec version and bounded domain-label shape and never dispatches an operation by that label. The store does not duplicate the 59-operation registry.

For codec 1, core streams `SEINTENT\0v1\0` plus the stable operation name and canonical typed semantic input into SHA256. Object field names are closed ASCII sorted by UTF-8 byte order, arrays retain semantic order, integers use checked decimal encoding without floats, and strings use JSON control escaping without Unicode normalization. Public IDs supplied by the operation's caller retain exact typed wire spelling; native paths have tagged raw bytes; text becomes a streamed {bytes,sha256} descriptor. The trusted staging pass exposes byte_length/sha256 through StagedTextValue, so core need not reread/duplicate a 1 MiB turn. Input admission happens before hashing; aliases resolve consistently to IDs. Exclude request key, transport retries, sampled times and **all operation-allocated output IDs**, including new message/decision/session/effect IDs. Caller-supplied entity IDs, expected revisions, target/body/config values remain included. The same request can therefore retry after core allocates different candidate event/effect IDs without a false key conflict.

Store computes fingerprint = SHA256(`SEOP\0v1\0` + unambiguous admitted scope/actor encoding + static operation name + intent codec version + intent SHA256). This binds scope/actor independently of the trusted core input digest. Store still validates the entire resulting closed event batch, payload digests, references and preconditions; it does not reconstruct operation intent by hashing generated event bodies. operations.fingerprint_codec retains the supported codec identity. Same caller key/fingerprint returns original membership/stamps; different intent refuses before any planned side effects. The existing operation's codec must remain supported or return a named version refusal, never reinterpret its bytes. Erasure invalidates affected composite fingerprints so no body-derived digest remains. Keyless natural operations retain neither an intent digest nor a retry index entry; their collision/body rules are separate.

#### General settings and agent metadata

config.toml is the only effective authority for general settings, resolved by
flag > env > config.toml > default. The store has no configuration head,
ConfigKey/ConfigValue, ConfigSet event, Snapshot.config or configuration-list
method. General config.set (including runtime.listen_port, provider defaults,
Atlas enablement) is the host's protected-file write with sync/readback and
readback reconciliation as defined in section 40; it emits no SQLite mirror
event or writer stamp and has no separate receipt journal. Manual edits
take effect at the next settings read or restart, without replaying an old store
value over the file. Explicit retries use section 40’s current-state readback
reconciliation, not a retained versioned result or journal.

Agent identity/name/creator, grants including agent.<A>.can-create, and saved
provider/model/profile revisions remain in principals/grants/profiles with their
existing PrincipalRenamed, GrantRecorded and ProfileSaved events and exact read
methods. config.set on those agent keys dispatches to those typed changes, not a
second configuration authority. No project settings layer exists. Dropping the
general-settings-only table/kind yields **42 application tables, 30 triggers and
52 event kinds**; SQLite's internal sqlite_sequence is excluded from the count.

### File-only retries

Section 40 owns current-state readback reconciliation for general config set,
uninstall and restore; these file-only retries have no separate receipt journal.
Store-backed effects keep their existing operation/effect facts, while a file
readback alone never invents an event or writer. Retained source/backups and
explicit restore consequences remain as specified below.

## Writer ownership, batching and durability

The host owns one write connection on one named blocking worker. It blocks on receive, then drains only already queued work up to 256 operations and the 2 MiB materialized group-byte cap. There is no gather window, gather timer or post-first-message sleep. Queue admission is capped at 256 requests and 1 MiB resident body bytes; large staged captures carry owned bounded references. A full queue immediately returns backpressure. Outer BEGIN/COMMIT is shared, each operation has a savepoint, and replies wait for outer COMMIT. Invalid members roll back independently; a poisoned connection, failed rollback or indeterminate COMMIT affects every unresolved member. This is section 80's protocol; S1's 250 µs/16 tuning is historical measurement only.

`CommitWait` is a Future that registers a waker without blocking; the async host awaits it or applies its own timeout. Flush/drain return futures too; joining the worker happens on the host's blocking pool, never the current-thread runtime. A timed-out/dropped future does not cancel accepted work. Successful drain/join returns the unique maintenance HostStore retaining the Arc lease and its report; failure keeps admission closed and names any indeterminate keys. The worker retains the Arc lease until its SQL handle closes and thread exits.

A direct client holds a **shared** OS runtime.lock for its complete transaction/connection lifetime; multiple direct clients may coexist and SQLite BEGIN IMMEDIATE + finite busy_timeout serializes their writes. The host needs the **exclusive** lock and cannot start until all direct clients finish. A direct client does not mistake another direct client for a host or forward to a nonexistent endpoint. After shared-lock acquisition it validates store/version; an endpoint without a live exclusive owner cannot grant host authority. Direct invokes the identical commit_group with one operation, creates no persistent worker, does no per-command startup/shutdown backup, and leaves durable effects for the next host. OS custody always auto-starts/uses the host.

WriterMode is an opaque store-owned value with a read-only WriterKind view (`Host { generation }` / `Direct`), with no public constructor, Deserialize or input field. Event and operation rows persist writer_mode, nullable host_generation and durability with CHECKs. The commit engine alone constructs new stamps from its owned lease; CLI-through-host remains Host, and request Door remains independent. History reads the persisted event stamp. Import commits new Rust envelopes with the importer's actual writer and retains Node provenance separately. Rebuild and backup restore retain valid historical stamps exactly; an invalid Rust stamp is an integrity refusal, never inferred from the restoring host. Event-log salvage is deferred. The final new recovery event gets the recovering committer's stamp.

The fixed FULL set is: credential.issued, credential.activated, credential.revoked, decision.ratified, decision.rejected, decision.retracted, decision.superseded, session.activated, session.ended, session.revoked, runtime.owner, runtime.handover, project.registered, project.removed, principal.registered, grant.recorded, profile.saved, erasure.requested, turn.erased, message.erased, erasure.completed, recovery.recorded; and fresh store/header creation, recovery adoption and the migration user_version publication. Conservatively treating every agent profile/grant event as security-sensitive avoids a caller-controlled field classifier. No untrusted durability flag exists. A mixed group takes FULL. Select/read back synchronous=FULL before BEGIN; only a successful FULL COMMIT may acknowledge those changes. Restore/read back NORMAL before the next ordinary group; failure to restore closes admission rather than silently changing the contract. NORMAL can lose several recent ordinary commits after OS failure or power loss, but acknowledged commits survive an application-process crash; FULL security revocation cannot be acknowledged before its WAL sync. Replay reports retained durability, not the current policy. This boundary must be measured against B2/write budgets rather than waived by median S1 numbers.

### Embedded first-owner/session commit

`se init` owns fresh store/header/schema publication, protected file publication
and project/principal setup. It completes and reads these back before reporting
an initialized project; a retry reuses an already valid store and completes only
missing setup. These required writes remain FULL. The embedded open path only
opens the initialized store: measured absence maps to `setup-required` with
`se --home HOME init --repo DIR`, without creating a DB, runtime
endpoint or empty replacement. Unreadable/foreign/newer files retain their own
refusals. SE Code handles this at each workspace's first-open repository trust
hook (40): its UI owner path runs bundled managed `se init --repo DIR` with the
selected workspace and same state home, then re-prepares. The public GitHub stub
silently skips init. This managed setup writes nothing inside DIR; all
schema/setup writes stay in the per-user state home outside it, so repository-write
consent is unnecessary. `se init --adopt` for user-started Claude/Codex sessions
instead writes the integration files in 70 §3.2 and reports them in
`repo.files_touched` and `integrations[]`. Setup failure presents the original
refusal to the user; this never runs from an agent tree. Bare se/status retain normal
not-set-up output and exit 0. Supported migration/backup remains the exclusive-host startup path.

For an ordinary embedded cold start with no unresolved transfer fence,
`HostStore::record_first_binding(FirstBinding, lease)` runs before start_writer.
It takes a registry-scoped owner AtomicBatch and a separately admitted,
project-scoped first-session AtomicBatch. Each retains its own actor, scope,
operation envelope, request key and normal validation; this is not a cross-scope
public mutation. The owner batch contains exactly one runtime.owner; the session
batch contains only required preparation/incumbent terminal facts and the actual
witnessed session.activated. It must bind the same store/incarnation, engine G,
native epoch, project, principal and native session selected before BEGIN.
No credential is issued or activated for the in-process binding.

The private TransactionEngine::commit_first_binding wrapper uses one outer
FULL BEGIN/COMMIT for both operations, applying the owner CAS before session
activation and checking every binding/incumbent precondition. Both operations
keep their own operation-member maps and FULL stamps. Unlike ordinary group
savepoint isolation, any member failure rolls back the entire first-binding
transaction; it cannot commit the owner alone. FirstBindingReceipt contains both
actual receipts from that commit. The issued binding revision identifies the
actual session.activated member, never the owner or preparation event. The
public IssuedSession exposes only the session receipt; the owner receipt remains
private maintenance data. Both batches require stable request keys. Their
canonical intents bind the pair of keys, exact epoch/G and admitted
project/agent/native-session identity; new output IDs remain excluded under the
semantic-fingerprint rule. A lost reply retries the same pair: bounded key/member readback must find both original matching receipts
or neither. Changed intent under either key returns idempotency-key-reused; a
partial pair despite matching intents or invalid recorded membership is an
integrity refusal, never a new owner or a second activation. No SQL transaction
spans native proof, a callback or await.

Only after this commit may the ordinary writer start, binding/continuity return
and ordinary mutation admission open. Concurrent first binds serialize before
this gate; a second distinct session uses the normal writer after it opens.
A known post-COMMIT resource/continuity failure retains the committed pair and
closes admission; it cannot claim rollback. An unknown COMMIT outcome preserves
both original keys for resolution. This changes neither the FULL event set nor
NORMAL's loss window. On a current preinitialized store the intended SQLite file
sync count is up to two (WAL header when needed and combined commit); actual
counts, including any checkpoint work, are reported. A required directory sync is
additional and must be reported, never suppressed to satisfy a count.

Standalone owner admission still uses its separate FULL runtime.owner. The
combined embedded path cannot absorb live Prepared/Claimed/Finished/Aborted or
Recovered/fence-settlement work: those maintenance phases and checked cold
recovery retain the protocol below, with any extra startup barriers measured.
If no first bind arrives by section 40's FIRST_BIND_WINDOW (10 s from activate
returning Prepared, with the original absolute deadline rechecked on resume), or
a first bind definitely refuses/rolls back within that window, the host fences
that gate and joins/resolves any accepted first-binding job before ordinary standalone-style FULL owner admission.
It starts the normal writer after that owner commit, without inventing a session.
Status then reports ready; a late first bind or retried bind uses the ordinary
session-activation path, like a second bind, without an expiry failure to SE Code.
If the pair already committed, retain both receipts and that owner instead of appending another owner;
an unknown outcome keeps both keys for resolution and cannot trigger speculative
fallback. Explicit drain cancels the fallback gate and closes only joined actual
resources. These are mutually exclusive ownership paths under the same lease,
not concurrent ways to commit G. Additional fallback barriers remain measured.
The ordinary first-binding pair is not admitted through direct append or the
public operation registry and adds no event kind, SQL table or transport DTO.

## Runtime ownership and live handover

One RuntimeHandoverRecord, two internal v1 event kinds and one runtime_owner head bind native custody to durable ownership. There is no public ownership operation or configuration flag. The host verifies native handles, peers, capture and queues; SQL checks their recorded references and CAS, and never treats a digest as native authority. The retained durable outcomes are **Prepared, Claimed, Finished, Aborted and Recovered**. Five are needed: Aborted proves verified restoration of the pre-claim source, while Recovered proves a fresh owner resolved a claimed transfer; merging those outcomes would lose the legal recovery path. ReadyToClaim and Activated are not durable states.

RuntimeHandoverRecord fixes transfer RecordId, the independent 128-bit nonce returned by se-proc, source/successor HostEpoch, source/successor engine Generation, manifest SHA-256, frozen_at Revision and deadline_at UnixMicros at Prepared. The store RecordId is separate from the native nonce; the host never generates a substitute nonce. The version-1 private codec uses exactly 32/64 lowercase hex characters for nonce/digests, checked lossless HostEpoch values and positive signed-i64 generations with successor greater than source. Except for phase and the optional terminal completion below, no field changes during a transfer. frozen_at is in this incarnation and equals the final committed head immediately before Prepared.

The source gates admission, finishes accepted launch/capture/debt work, holds or interrupts providers to exact native idle, stages inactive native copies, then drains and joins the writer and closes/cancels backup pins and readers. The source retains its exclusive runtime lease. Only then does exclusive source maintenance seal isolated FULL Prepared against that final head. There is no write-capable source writer or mutable manifest after this seal; this removes ReadyToClaim without a crash window. Before Prepared, inactive copies have no durable authority and close on source loss/deadline; ordinary native crash policy and actual holds apply.

After Prepared the source may release its exclusive lease to the proven successor. The successor acquires it and CAS-commits FULL Claimed on maintenance before any destination writer or ordinary native consumer. This is the only live-transfer change of owner epoch/generation. Source loss or a missing claim acknowledgment never authorizes source restoration after the claim. The successor retains native activation receipts in memory while all ordinary destination consumers remain disabled; it verifies final capture/queue positions and actual source-resource closure, then records FULL Finished with that completion evidence in the same event. Consumers and the writer may start only after that commit. This removes Activated without forgetting its native proof: a crash before Finished leaves Claimed and requires checked cold recovery, even if native activation or source closure had already happened.

RuntimeHandoverRecord.completion is None for Prepared/Claimed/Aborted and mandatory for Finished. RuntimeHandoverCompletion binds activated_custody_sha256, committed capture_at, queue_cut_sha256 and source_closed_sha256. The first three describe the activated destination and the retained original debt/holds/queue cut; the last binds the independently checked source-resource closure receipt. capture_at belongs to this incarnation and is between frozen_at and the committed head. The host validates all four against the exact transfer, fixed manifest, peer epochs/generations and real native readbacks. The store checks the typed shape, matching transfer, referenced revisions and phase/head CAS. A missing/unreadable proof leaves Claimed pending; no timeout or receipt hash alone permits consumers.

`runtime.owner` establishes initial or checked cold ownership under an exclusive lease and FULL. Initial ownership requires an absent head, Expected::Absent and no expected prior generation. Cold ownership requires exact prior head/generation, fresh outside custody proof and a strictly greater engine generation. It cannot implicitly cancel Prepared: verified FULL Aborted must settle that pre-claim transfer first. A cold owner replacing Claimed must include RuntimeRecoveredTransfer: original transfer RecordId and the exact Claimed EventId, fresh activated-custody digest, committed capture revision and retained queue-cut digest. Its own EventId is the completion reference. The single FULL owner transaction establishes the fresh owner and publishes Recovered on the original transfer without rewriting the original peers, nonce, manifest or frozen head. RuntimeHandoverRecorded refuses Recovered; it is only the terminal outcome carried by the checked fresh owner fact. A fresh cold owner while a Recovered fence remains unsettled retains the direct original completion reference, avoiding a history scan.

The non-secret runtime_owner singleton holds epoch/generation, last_seq and nullable paired transfer/phase. Each transition checks store/incarnation, lease generation, complete epochs, transfer, expected predecessor phase/head, fixed manifest fields and proof references, then uses `WHERE singleton=1 AND owner_generation=:expected_generation AND last_seq=:expected_seq AND transfer IS :expected_transfer AND phase IS :expected_phase`; exactly one affected row is required. First owner INSERT requires absence. Claimed changes the head to the successor; a resolving cold owner changes it to the fresh owner with the original transfer and Recovered. Rebuild derives that outcome from the owner event itself. Handover keeps store incarnation unchanged.

| Durable fact | Legal commit path | Crash/retry rule |
| --- | --- | --- |
| runtime.owner | exclusive initial/cold maintenance, FULL | no implicit pre-claim abort; Claimed requires the bound Recovered proof |
| Prepared | drained exclusive source maintenance, isolated FULL | frozen capture/queues and inactive copies; only Claimed or verified Aborted |
| Claimed | exclusive successor maintenance, FULL CAS | original source cannot resume; only proof-complete Finished or checked fresh-owner Recovered |
| Finished | exclusive successor maintenance, FULL with RuntimeHandoverCompletion | native activation, final capture/queue cut and source closure all precede commit; writer/consumers start afterward; lost ACK replays this receipt |
| Aborted | exclusive source/recovery maintenance, FULL from Prepared only | outside proof restores pre-claim source custody and preserves actual holds/debt; a recovered process must establish its fresh owner before ordinary work |
| Recovered | inside checked cold runtime.owner, FULL | settles the original Claimed transfer under fresh custody; never an ordinary phase append or stale-successor Finished |

record_runtime_ownership accepts exactly one registry-scoped runtime event under exclusive maintenance and uses the common TransactionEngine. The distinct record_first_binding maintenance entry above is the sole two-operation exception for ordinary embedded cold admission; record_runtime_ownership itself remains single-event. All live transfer phase writes are on this drained path; no runtime ownership event is admitted through direct mode or an ordinary writer group. Claimed maintenance can hold the successor lease while the prior head still names source, and checked abort recovery can hold a fresh recovery lease: these are narrow CAS exceptions, not permission to start a writer. Native HostGeneration and engine Generation remain separate namespaces; the host verifies their full native peer binding. Standby, Staged, native activation and acknowledgments are transient observations, not additional durable phases or authority from a deadline.

Prepared/Claimed fence ordinary host/direct writes and writer startup even if a crash released the physical lock. Finished, verified Aborted or verified Recovered permits clearing the transfer-keyed retained queue fence, only after the corresponding native/capture/queue proof and actual debt/human holds are settled. A new transfer requires this settlement; a reverse transfer after a failed receiver starts from the fresh owner after Recovered, never the dead successor. An absent head with existing ownership facts, or an unreadable head, refuses writes pending explicit diagnosis/restore; genuinely never-owned state retains direct bootstrap.

ReadStore.runtime_owner returns only epoch/generation, event/revision and transfer/phase. Public event/history/search/logical export excludes both runtime kinds, including exact-ID lookup; a known private event returns a typed refusal. HostStore.runtime_ownership_fact is a trusted bounded maintenance point read for these facts only. Native nonces are absent from public JSON, snippets, telemetry and Debug; protected whole-store backups may retain them. Both harnesses share this protocol. Qualification must exercise every FULL boundary, pre-seal drain/lease transfer, lost ACK after Claimed/Finished, native activation/source-close crashes before Finished, stale CAS and failed cold proof; no happy-path spike alone qualifies crash recovery.

## Recorded process, session and delivery facts

The store persists the same nine lifecycle states and complete transition table as accepted section 30 §3.1 (reproduced below). A prepared scope can lack a root PID/executable/birth identity. RootIdentityState distinguishes NoChildCreated, Unpublished (child/pre-exec work without a published complete root identity), Identified and Unknown; RecordedIdentity independently preserves Present(native ProcessInstance), Absent(reason) or Unreadable(cause). SQL stores all complete identity columns together or all NULL with an explicit cause. Identified requires Present; NoChildCreated/Unpublished require Absent; Unknown is limited to historical/lost records. Running and LeaderExited require Identified. Scope-only StopRequested/StopUnproved requires the exact reservation/scope/root checkpoint and stop-intent/attempt observation; Exited additionally requires the section-30 no-child/unpublished required-scope exit witness. None requires a guessed identity. A never-created scope's failed reservation can terminate with its exact reservation and failed-launch/no-live-scope observation. PinnedUnpublished retains its actual native PID/status inside the exit checkpoint without fabricating the missing ProcessInstance fields. Each transition carries the complete new ProcessIdentityRecord and expected revision; lifecycle/principal/session stay immutable. Once a full root identity is published it is retained through stop/exit/loss and must never be downgraded, replaced or relabelled NoChildCreated; recovery requires exact saved-identity/scope proof. SQL validates local shape; transactional apply validates this predecessor relationship and the closed native checkpoint/witness semantics. Leader exit alone never proves an empty scope.

NativeCustody format_version=1 is the closed se-proc checkpoint codec: a tagged UTF-8 JSON wrapper with variant reservation, scope (ScopeCheckpoint), root (RootCheckpoint), process (ProcessRecord), exit (retained source checkpoint plus StopWitness), failed-reservation (LaunchReservation plus failed-validation/native-error outcome, observation reference and explicit no-scope-created fact), or historical. Each variant carries exactly the accepted section-30 type's fields, tagged native path bytes/UTF16, lifecycle/principal/session, host/generation/nonce, exact scope identity/guarantee and explicit root publication state. Exit records preserve NoChildCreated, UnpublishedScope, PinnedUnpublished or Identified and the required-scope exit/status/observation. Failed-reservation is allowed only when no native scope/child was created; it retains that fact instead of fabricating the ScopeIdentity required by StopWitness. Unknown historical fields remain absent/unreadable. Record schema version is mandatory; unknown fields/versions refuse, integers are checked and no OS handle/address is serialized. The host adapter converts the accepted se-proc record at this boundary; se-store validates the versioned shape before insertion and never treats it as permission to signal. Indexed columns must agree with the checkpoint. Replay retains original checkpoint bytes; historical import cannot synthesize live custody.

ContainmentFact is persisted on process registration/transitions and session activation, with the session pointing to the exact lifecycle/fact that launched it. Known contained kind is cgroup (Linux), job (Windows), or process-group (macOS), observed time present, cause NULL. Linux uncontained requires observed time and exactly one cause: no-user-manager, no-delegation, cgroup-v2-absent, cgroup-unreadable, scope-create-failed; cause is never NULL. Unknown historical facts retain a reason and produce unknown/null with an explicit incomplete status, never inferred containment from the OS or today's probe. NotLaunched is distinct and renders the section-50 null pair for a never-launched session. Persist only the compact cause and optional probe observation reference here; full OS probe text is separate doctor evidence, not the user-facing cause code. The CHECKs enforce all combinations; the closed session JSON uses the same tagged union. A fresh read after restart renders these saved facts, with current OS observations reported separately.

The landed se-proc reasons map one-to-one into section 50: NoUserManager→no-user-manager, NoDelegation→no-delegation, CgroupV2Absent→cgroup-v2-absent, CgroupUnreadable→cgroup-unreadable, ScopeCreateFailed→scope-create-failed. These are the same five facts in ContainmentCause; no older helper/kernel/delegation enum survives at this boundary. Full native probe detail stays in doctor/checkpoint evidence rather than being substituted for the compact cause. Linux fallback tracks only its process group and cannot claim escaped descendants are contained. A later observation corrects a fact only through a new transition, never by rewriting launch history.

Credential issuance stores prepared, not active, with activation_deadline no later than issued_at+600 seconds. The trusted first-use verifier checks hash, session/process binding and deadline, then commits credential.activated and the required session activation/incumbent revocation atomically under FULL before admitting that first operation. Prepared never authenticates an ordinary call by itself; expired preparation fails without a timer, no owner fallback and no incumbent displacement. Revocation/expiry cannot reactivate. Historical imported credentials never become active. Launch uses C1 FULL reservation plus prepared session/credential issuance, C2 scope-prepared, and C3 FULL witnessed actual root plus credential/session activation and readiness. Unix terminal, macOS and uncontained helper paths retain an additional durable RootCheckpoint between C2 and C3 before authorize_exec: otherwise vendor execution can precede recoverable native group/start identity. This four-commit exception is explicit. Embedded in-process binding issues/activates no credentials. Explicit se init FULL-publishes the fresh schema before embedded open; ordinary cold first binding combines runtime.owner and required session preparation/activation in one FULL maintenance transaction before writer startup. E2 measures that complete binding path; init retains its separately measured FULL cost.

CaptureFailed records the actual failed source window/code/cause, leaves the durable source cursor at the last fully captured bytes and can be followed by a successful retry; a hook's required exit 0 is not a capture-success claim. EffectOffered records a unique actual offer attempt/evidence, moves pending to offered and leaves recipient-read debt outstanding. Only recipient marking or independently witnessed settlement changes that fact. Host-only offers require the deterministic explicit request key derived from effect+attempt and check that key/body correspondence; retrying that same attempt cannot create a new offer under a fresh random key. effects.principal_id is checked against the typed intent/target and updates that principal's pending/offer debt without a global scan.

## Projection rules

Apply is exhaustive over the catalogue and runs only inside the canonical transaction. Replay uses the same function with explicit historical provenance and no external effects; it never launches a process, remints a credential or delivers old mail. A replayed imported terminal fact is historical evidence, not current OS authority.

| Projection | Preconditions and mutation | Replay / conflict rule |
| --- | --- | --- |
| projects / roots | register absent ID/root after canonical ownership validation; update requires expected revision; remove requires terminal effect/revocation facts supplied by core | same registration replayed via key is no-op; root collision is conflict; tombstone releases active root lookup, not history |
| principals | register registry-scoped humans in owners and project membership in principals; agent creation records created_by from the authenticated actor and checks the current create grant; rename requires expected head and no name/alias collision with another principal | ID cannot change kind/owner/creator through rename; imported unknown creator grants no creator control; current create grant plus exact same-project created_by permits launch/wake/stop of direct helpers only, never grandchildren/all/private reads |
| aliases | only an imported source mapping; target principal must exist and ambiguous names refuse | identical mapping deduplicates; different target is an import conflict, never last-write-wins |
| profiles / configuration / grants | known key/profile and expected revision; private data object owns settings; grants record authenticated owner policy | invalid/insecure profile refuses; imported opt-in bypass stays an explicit profile, never new default |
| sessions / credentials | prepared session does not displace incumbent; activation checks prepared revision and incumbent revision/terminal events in one batch; end/revoke invalidates active credential projection | one active session per agent enforced by partial index; terminal session cannot reactivate; imported bindings are ended and have no live credentials |
| messages / marks | sender comes from admitted actor; recipient registered and authorized; sent row points to one body; delivered/read/dismissed each sets only its first marker | read/dismiss requires authenticated recipient; delivered requires outside consumer evidence; repeated same mark returns original sequence; read and dismissal may coexist as separate facts |
| decisions | proposed absent; transitions enforce table below and expected revision; replacement proposal/ratification must exist; append immutable typed transitions only, without a decision-chain table/hash | compare both heads for supersession; import retains old byte provenance; no all-event chain or synthetic ratification |
| turn_data / capture_sources | capture consent and session/source binding must be valid; native turn natural key/body/source digest match; insert turn and progress together | same native key + bytes replays; source rotation/truncation refuses offset reuse until new source incarnation is explicitly recorded; failed capture leaves offset unchanged |
| processes | initial recorded identity is complete, including machine/boot/native birth/executable/argv/custody; transition checks expected head and full observation reference | store does not call OS; reused/unknown evidence cannot produce running/owned; imported processes are historical only |
| working_state | absent or exact revision precondition; new head references one immutable text payload | stale revision conflicts; empty string is present text, not absent |
| cursors | typed purpose/scope/session and valid snapshot bounds; issuance distinct from acknowledgment | exact prior cursor revision needed for ack; cannot ack a foreign/newer cursor or turn incomplete context into complete |
| effects / integrations | requested effect has stable cause/idempotency; settle requires expected pending revision and evidence for witnessed; integration records exact owned prior/written digest | failed/abandoned retain reason; unrelated file edits are conflict; replay never executes the intended effect |
| import runs / progress / legacy_ids | source incarnation/prefix unchanged, monotonic row/byte cursor; imported events and progress commit together | ID map fixed per source identity; changed source prefix refuses; unreadable counter/record retained; no cursor beyond failed unaccounted bytes |
| erasures | explicit owner-approved target IDs/revisions, complete copy inventory, exclusive maintenance state | retry resumes the same manifest; no completed receipt until live DB/WAL readback; retained backups are named residuals; erased-key replay cannot recreate text |

Current-head readers return a `ProjectionRecord` containing the current event and, when needed, the original immutable creation/proposal/binding event. For a rename, terminal session, decision transition or process transition this is a fixed two-event join, not an unbounded walk through expected revisions; a complete current snapshot (profile/config/working state) needs no original object. Project updates carry a complete name/root snapshot. Core composes public wire DTOs from these records; these internal Rust field names are not CLI JSON field-path promises. The original event preserves an agent's immutable creator, while the current principal projection supplies the atomic creator check.

`config.set` with typed `agent.<A>.can-create` emits `grant.recorded` for A (not two competing copies of that boolean). Config get/list resolves that key through the same grant head. Only owner admission may change it; an agent's create grant cannot grant itself or another agent new permissions. Unsupported historical grant names remain provenance, never silently active grants.

`resume_heads` is a derived acceleration table with `(project,principal)` primary key (agents and the owner can receive messages), last turn/state/cursor/session revisions, unread count, pending effect count and last applied sequence. A principal registration creates it; each affected apply updates it from the actual changed row counts, not rescans. A natural-key no-op changes no counts. A rebuild verifies it against grouped authoritative message marks/events. Negative counts or a missing expected head abort as `projection-inconsistent`; status never guesses zero. The version-1 DDL includes:

```sql
CREATE TABLE resume_heads(
  project_id BLOB NOT NULL,
  principal_id BLOB NOT NULL,
  last_turn_seq INTEGER REFERENCES events(seq),
  last_working_state_seq INTEGER REFERENCES events(seq),
  last_cursor_seq INTEGER REFERENCES events(seq),
  last_session_seq INTEGER REFERENCES events(seq),
  unread_count INTEGER NOT NULL CHECK(unread_count>=0),
  pending_effect_count INTEGER NOT NULL CHECK(pending_effect_count>=0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,principal_id),
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
```

### State machines (no implicit transitions)

| Entity | Allowed transitions | Forbidden / concurrency behavior |
| --- | --- | --- |
| Store admission | absent → creating → ready; ready → draining → closed; ready → migrating/recovering/erasing → ready or maintenance-failed | readers/ordinary writers refuse non-ready state; failed maintenance never opens as an empty fresh store; process-crash recovery uses the durable phase manifest |
| Project | absent → active; active → active revision; active → removed | removed ID cannot be silently reused; a new adoption creates a new ID with explicit retained history linkage |
| Session | absent → prepared; prepared → active/ended/revoked; active → ended/revoked | ended/revoked terminal; active → prepared forbidden; takeover is predecessor terminal + prepared successor active in one CAS batch after outside witness |
| Credential | absent → prepared → active → revoked; active → expired by timestamp predicate | no resurrection, no plaintext event; expired/revoked token never falls back to owner |
| Message | absent → sent; sent → sent+delivered/read/dismissed; sent → superseded relation | markers are independent monotonic facts; dismiss does not imply read; no ordinary body rewrite/delete or recipient change; approved forget alone erases content |
| Decision | absent → proposed; proposed → ratified/rejected/retracted; ratified → retracted/superseded | rejected/retracted/superseded terminal; superseding requires ratified replacement and both expected heads; proposed supersedes hint has no activation effect |
| Process | exactly the section-30 §3.1 table below | CAS and native witnesses required; no PID-only revival or implicit stop success |
| Effect | absent → pending; pending → offered → witnessed/failed/abandoned (or pending → terminal on failed offer) | terminal result immutable; retry after failed uses a new attempt/request linked to the same cause, never changes failed into witnessed invisibly |
| Import | absent → running; running → running checkpoint/complete/partial | source mismatch pauses/refuses without advancing; resume of partial requires same policy/source identity and explicit remaining window |
| Backup | absent → writing → verified → published; writing/verified → failed | published generation immutable until owned rotation; partial file never counts as a backup |
| Erasure | absent → inventoried → approved → draining → content-erased/pending-cleanup → WAL/cache-cleaned → verified → complete | failure freezes ordinary writers and preserves phase evidence; no successful tombstone-only shortcut; restart resumes exactly this erasure ID |
| Restore | diagnosed → newest automatic backup validated → owner confirmed → source preserved → adopted/read back | no valid generation refuses; corrupt source/WAL retained; post-backup loss is explicit, never partial event salvage |

The complete accepted process transition matrix (section 30 §3.1) is:

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
| retained historical native record | supported native history/migration | Historical; cannot become live custody; user-history import adds no process authority |

Stored read/disposition facts can be imported as historical states only when the Node row actually supports them. A bell offer, stdout flush, packet creation, launch readiness and task completion never substitute for one another.

## Bounded reads, snapshots and cursors

A read captures the committed maximum event position and store incarnation under one deferred read transaction. Backup-file inspection is a separate read API: snapshot its manifest/event metadata, release SQL, then inspect immutable owned files and report per-file observed/absent/unreadable facts; it does not pretend filesystem observations share a SQLite snapshot. Every row and head it materializes belongs to that snapshot; there is no read of a projection at one position and bodies at another. Reader connections are read-only, with `query_only=ON`; closing a snapshot releases its transaction even on decoder failure. Readers never rebuild, migrate, mark mail read or advance durable cursors.

All lists are keyset paged, with indexes beginning with authorized scope and relevant actor/recipient. Order is operation-specific: section 50 messages/inbox are oldest sent event first; decisions are oldest current latest-transition first in a labelled live list; raw history/replay/import is ascending, while recent-turn queries are descending. No shared default may override those public orders. No OFFSET scan or cold-cache full-file count is required for a page. Read at most `limit + 1` candidates plus a bounded byte budget. `ReadBudget` wraps the canonical se-types PageRequest and a finite deadline; it does not introduce a second cursor/limit/byte vocabulary. Full message listing yields only complete bodies that fit, with continuation before the first omitted item, and never appends read/delivered markers. Owner may inspect any selected-project message; session scope is sent-or-received by that actor. The extra candidate establishes `has_more`; exact omitted count is `None` when computing it would require an unbounded scan. Zero, absent and count-not-computed stay distinct. A rejected/undecodable candidate is not skipped into a deceptively complete page: return an unreadable error with the checked sequence/source or an explicitly incomplete window, preserving the continuation before that row.

An opaque page cursor encodes version, mail-window/live/history mode, store ID/incarnation, the mail/history fixed high-water (or the live page observation), query/scope fingerprint, order and last returned key. Its canonical binary form is version byte + 16-byte store ID + fixed-width integers + 32-byte query digest, base64url without padding; mail/history maximum 192 bytes; live-keyset cursors encode the bounded typed last key within the shared Cursor maximum of 4096 bytes. Import source_key is a fixed 32-byte digest of tagged source identity/incarnation/format, with the original identity retained in source evidence and conflicting correspondence refused. It is not a capability: the supplied authorized scope is rechecked for every query even with a syntactically valid cursor. Reject wrong store/incarnation/query/order, positions outside the captured window, overflow and unsupported cursor version. Newly arrived mail above the mail cursor's high-water is reported as outside this page's window and appears in a new inbox read; it is never silently hidden as “no unread mail.” An old mail/history high-water remains readable while records exist, except after an explicit erasure/restore incarnation bump; live lists use fresh current heads on each page.

`Window` states from/to positions, returned count, byte consumption, completeness, omission reason/count if known and continuation. Row limit, bytes, deadline, unreadable row, feature unavailable and source rotation are different stop reasons. If the first full item cannot fit, return `read-budget-too-small` with the required bounded minimum; do not return a non-advancing apparently successful empty page. Previews explicitly expose body-incomplete; full `message.read` must obtain the full bounded body before core appends a read marker. Renderers clamp only at UTF-8 boundaries, never slice an encoded path as text. An exact-ID query returning no matching record is measured absence; adding a state filter can instead produce zero matches without implying the ID is absent.

`Snapshot` exposes typed queries for projects/principals/profiles/grants, sessions and credential hashes, messages/inbox/marks, decisions (including typed exact ID), turns/sources, internal recorded custody for status/agent control, working state, cursors/resume heads, effects/integrations, history/events, import progress and operation receipts. Shared text search is bounded over an explicitly scoped candidate stream; it reports incomplete when its scan budget ends. There is no arbitrary SQL/predicate callback API for kernel callers.

### Exact capture history filters

The sole captured-turn event name is `session.turn` / EventBody::SessionTurn /
EventKind::SessionTurn in storage and wire A.14. Its envelope session_id is
mandatory and equals the typed turn's session, including user-history imports;
a source binding cannot be reconstructed from a display label. Suppressed
content has no session.turn event/body and retains the separate existing
capture.suppressed counter fact.

HistoryQuery has typed session: Option<SessionId> and exact kinds: Vec<EventKind>
in addition to agent/family/since. Empty kinds means all authorized kinds;
unknown strings refuse in the shared codec and duplicates normalize once.
Session, exact kind, authorized scope, high-water and since predicates are
applied before candidate selection, count/byte/step/deadline accounting and
limit+1. Cursor fingerprints bind every filter. A session/kind page never takes
a broad page and post-filters it into false exhaustion.

A.14's exact session + session.turn query reads the existing turns projection:
`turn_data AS t INDEXED BY turn_data_session_seq JOIN events AS e ON e.seq=t.event_seq`,
with t.project_id, t.session_id and t.event_seq cursor/high-water predicates,
ordered by t.event_seq. The narrow scoped session/sequence index lives only on
turn_data; it replaces the two all-event exact-kind indexes from the earlier
sketch, reducing indexing for unrelated hot writes. Typed decoding verifies the
joined event is session.turn with the same session; a broken projection is an
explicit integrity error. Bodies still join their single owning payload rows.

Other event kinds keep the existing scoped event/session/actor sequence indexes
and finite SQL-side predicates before LIMIT, with the same shared byte/step/time
budget. Sparse general-kind queries can return explicitly incomplete windows;
they do not acquire unmeasured all-event indexes or guess exhaustion. Additional
all-event exact-kind indexes require measured E3 insert/footprint cost before review. EXPLAIN and the
actual `se history --session S --kind session.turn --json` consumer must witness
the turns path at 1M scale, including sparse matches, unreadable rows and old
windows. No SQL snapshot or per-kind buffer survives an external await.

### Mail windows and live keysets

Message/inbox pages retain a fixed high-water H and their existing temporal semantics. `list_versions` contains **message summaries only**: sent sequence, immutable sender/recipient/kind and disposition/supersession state. A message mutation closes its open interval at S and appends a text-free summary at S in the same transaction. A version is eligible when valid_from≤H and (valid_to IS NULL or H<valid_to); sent_seq stays the sort key. Bodies join the immutable owning rows. Current marks_unread serves a fresh read; an older mail cursor must use historical summaries and must not silently apply today's unread state.

Canonical unread SQL remains `list_versions AS v INDEXED BY list_versions_recipient_state WHERE v.scope_key=? AND v.family='message' AND v.recipient_id=? AND v.state='unread' AND v.sort_seq<=? AND (v.sort_seq>? OR (v.sort_seq=? AND v.entity_key>?)) AND v.valid_from<=? AND (v.valid_to IS NULL OR ?<v.valid_to) ORDER BY v.sort_seq ASC,v.entity_key ASC LIMIT ?`. Bind H to the validity comparisons and sort ceiling. Owner/sender/recipient lists use the corresponding scoped temporal index; sent-or-received merges two indexed streams and deduplicates entity keys. Each query takes limit+1 eligible candidates within its byte/step/deadline budget. Old-window amplification returns read-incomplete instead of guessed exhaustion or a guessed next cursor. No transaction is kept between CLI requests.

All other mutable lists use current projections and **live keysets**. Their output is explicitly labelled live, and each page reports its own observed Window; it does not promise the first page's H. Concurrent changes may move, add, remove or repeat an item between pages. A caller requiring a stable fact uses exact IDs/revisions or immutable history, rather than treating a live list as an audit snapshot. Authorization is rechecked on every page. The cursor binds live/mail mode, query/scope/order and last key; a mail cursor cannot be reused as a live cursor. Canonical Page/Window still expresses the completeness of the individual finite read; there is no competing completeness type.

| List | Current scoped keyset order/index |
| --- | --- |
| projects / principals / sessions / recorded processes | first_seq then typed ID; projects_order / principals_order / sessions_order / processes_order |
| decisions, including pending | latest transition last_seq then decision ID; decisions_order / decisions_state; no historical membership promise |
| effects, including pending/offered | requested_seq then effect ID; effects_order / effects_state_order; merge the pending and offered streams |
| integrations | last_seq then integration ID; integrations_order |
| import progress | import ID, family, source_key (existing primary key) |
| immutable turns / events / decision history | ascending or operation-specific recent-turn descending event sequence bounded by H; existing scoped event/turn indexes |

No non-mail mutation writes list_versions. Exact heads reconstruct a fixed original/current event pair where needed, with no entity-history walk. EXPLAIN must show scoped index SEARCH rather than a global scan/temp sort; the progress budget still bounds pathological work. The existing message-window checks remain acceptance obligations; no new generic temporal census or schema-freeze machinery is added.

## Migrations and version skew

Connection setup: confirm a regular owned state file in an owner-only directory through the host's filesystem custody service; open without following a final symlink, no URI paths from a remote input; validate `application_id`, `user_version`, store ID/incarnation and ready/maintenance state before queries. Wrong application ID, unreadable header, newer schema or configured synced/network storage returns a distinct error/remedy. A missing file is absent. An empty/truncated existing file is unreadable, not permission to initialize over it. Create uses a new exclusively reserved pathname and refuses collision; 16 KiB pages are set before first WAL activation. Hostless init uses create_direct under a shared runtime lock: construct a protected same-volume uniquely reserved staging DB, commit the complete schema/header under FULL, close/read back it, then publish with no-replace. Another direct initializer may race but cannot see partial schema or overwrite the winner; the loser receives store-already-exists and core reopens/re-resolves the winner's identities. Both staged data and destination parent are under the host filesystem-custody adapter. No host generation is fabricated and no daemon is required just to init. A lease with unknown StoreId is admitted only after measured absence for this bootstrap or for explicit unreadable-source recovery, never for ordinary writes; existing-store open must bind the actual StoreId.

Pragmas: WAL, NORMAL, foreign_keys=ON, trusted_schema=OFF, mmap_size=0, temp_store=FILE, bounded cache, busy_timeout=5000 and a 4 MiB journal-size target. Read back required settings before write admission. Startup under the sole host's exclusive runtime lease automatically applies supported additive migrations after a verified pre-migration online-backup snapshot, before returning a ready HostStore, opening ordinary readers or accepting work. The startup path prints the schema change and backup result; no manual migration command, MigrationApproval, plan fingerprint or old-schema maintenance-only HostStore is exposed. An old host still holding its lease makes the new version refuse with **run se down first**; it never migrates around a running old binary or kills it. A too-new, foreign, corrupt or unsupported-old schema refuses with a distinct compatible-version/restore remedy.

Older-schema reader/direct detection automatically invokes the same private bootstrap path; it does not ask the user to run se up. A hostless reader/direct client detecting a supported old schema closes its SQL handle and releases its shared runtime lease before asking the private runtime bootstrap to start the current sole host. That host performs the automatic migration, then the command retries its read/write under the new schema. The direct connection never upgrades its shared lease in place or migrates concurrently. Missing state remains measured absence: opening/diagnosing cannot initialize over an existing empty/truncated file. Read methods themselves never migrate or rebuild projections.

Migrations apply compiled, supported additive DDL/backfills in bounded phases under BEGIN EXCLUSIVE; version 0 means fresh creation, not an arbitrary SQLite import. The final FULL transaction publishes user_version together with the completed schema, followed by integrity/FK/version readback before ready. A required immutable-row backfill temporarily drops only its fixed triggers inside that transaction, recreates the complete approved trigger set and validates it before COMMIT; rollback restores both old data and guards. Long preparation modifies only new/unpublished tables until final publication. A failed migration retains source and verified backup, refuses ordinary admission and names the compatible binary/restore remedy. No ordinary connection gains a trigger-disable flag.

The compiled old-version range and event/cursor readers are explicit. Older binaries refuse newer stores; an unknown event codec is an unreadable complete-history boundary, not silently skipped data. Every write rechecks schema/incarnation in its transaction after filesystem lease admission. A stale generation reopens/re-admits. Automatic backup restore is forbidden: the separate owner `se restore` action selects the newest valid automatic backup and preserves the corrupt source/WAL. Restoring changes incarnation (or uses the caller-supplied fresh target StoreId if source identity is unreadable), invalidates old cursors/credentials/adoption assumptions, and reports the backup high-water and any known/unknown events lost afterward. No Node rollback writer or fleet cutover is part of this design.

## Automatic backups and explicit restore

Backups are SQLite online-backup snapshots, not copies of a live main file without its WAL. Normal first-session admission, writes/custody and re-adoption start as soon as the supported store is ready; the normal automatic start-of-day backup is **after ready**, at most once per local calendar day; clean shutdown takes a backup after drain/flush. The required pre-migration backup is a separate prerequisite before ready. StoreFactory.backup owns one independent bounded read connection from the fixed reader allocation and begins one read transaction, reads the source header/H to establish its WAL snapshot, then holds that **same transaction for the whole copy** through SQLITE_DONE or abort. Check the 64 MiB abort condition before the first step as well as between steps. Copy at most 64 pages per step at background priority and yield for foreground work. This explicit stable snapshot prevents writes on the separate writer from restarting the copy; see [SQLite backup source-connection locking](https://www.sqlite.org/backup.html). It never takes the writer connection, drains the writer or gates first bind. A slow/failed backup names source/cause and retained generations through diagnosis; it cannot turn ready into a false backup success. A throwaway SQLite 3.46.1 measurement held H=1000 across 65 one-page steps while a second connection committed 65 inserts: backup max remained 1000, writer max reached 1065 and remaining pages decreased every step. This measures SQLite snapshot convergence only, not the future store's WAL-limit cancellation or runtime budgets.

The store-owned opaque BackupContext is cloned from WriterOwner.backup_context (or HostStore.backup_context for maintenance/shutdown) and passed to the factory. It shares private store/incarnation/generation-bound pin/cancel state with the writer, without globals, a new worker or a queued barrier. The factory validates context and exclusive lease against the source, atomically reserves the single pending-backup slot, registers its pin intent **before** starting the read transaction, then clears it on every return/error/unwind. start_writer/drain preserve that same context; a stale context refuses. While a backup pin is active, the commit-driven writer defers checkpoint work that cannot finish and **never returns store-backpressure because of backup WAL growth**, including at 16 MiB. Commit-driven auto-checkpoint work is suppressed while the pin is registered and restored to the 256-page trigger on release; this never waits on the reader. Existing commit/WAL accounting records backlog and sets the backup abort flag at **64 MiB WAL**. The backup checks the flag/deadline between finite steps, finishes/closes the backup handle, rolls back the read transaction and releases its pin on abort, then returns backup-failed with WAL-limit cause and retained generations. Checkpointing can then resume on normal commits. The threshold is an abort trigger, not a physical hard cap: already-running bounded steps/commit groups can overshoot. Foreign pinned readers are diagnosed separately after backup release; backup cannot be relabelled as foreign-reader backpressure. No retry loop or polling timer runs: automatic retry is **next start-of-day**, not another attempt in this run.

Keep two published generations and at most one owned pending generation. Each manifest carries store/incarnation, schema/application ID, the stable captured H, byte count, digest and validation result. No machine credential, launch secret or active endpoint is in a manifest; copied hashes are not live authority. Reserve the pending path exclusively; step the snapshot copy; release its source transaction/pin; close and independently reopen the destination read-only; validate integrity/FKs/version/captured H; sync owned files/directories where supported; no-replace publish and atomically update the manifest pointer. Remove the oldest owned generation only after publication. Failed/aborted owned pending copies never publish and retain both prior valid generations; cleanup removes only that exact owned pending artifact. The fixed source snapshot never restarts to chase new writes. Migration/recovery/erasure remain explicit maintenance barriers and require backup pin release/join. Shutdown drains/flushes, then makes its requested clean backup within the explicit deadline; failure is named, not called clean.

Normal open reads only header/version and indexed readiness metadata, not whole-history validation. SQLite WAL recovery preserves acknowledged process-crash commits under NORMAL; it is not a promise against OS/power loss. Security events use FULL as specified above. Recovery restores at an explicit owner action; backup credentials are revoked/inactivated on adoption and process rows cannot become live custody just because they were copied. New incarnation invalidates old cursors/leases before admission.

Event-log salvage and a manual backup operation are deferred. The supported recovery action is owner `se restore`, separate from doctor configuration repair. It inventories the two retained automatic generations without requiring a normal reader of the corrupt live store, chooses the newest generation with independent integrity/FK/header/hash readback, and prints the selected high-water, agents/credentials ended, known loss since the backup or explicit unknown loss, and preserved source locations before owner confirmation. Recheck that generation's identity/digest and that it is still the newest valid one under exclusive custody before adoption. No valid backup means a named refusal with the corrupt source/WAL preserved; never an empty replacement or partial event salvage. Close all SQLite/backup handles, stage and validate the complete selected image, then perform a host-owned guarded swap, retaining the original until outside readback succeeds. Existing valid event/operation groups and stamps copy exactly. If the source identity is unreadable, source is None and the caller supplies a fresh canonical target StoreId; otherwise retain its ID and increase incarnation. RecoveryRecorded identifies the actual source artifact, selected backup, target and loss bounds, with no invented source ID. Restore never reactivates copied credentials/process custody or erases the source archive. A retained backup can contain bodies forgotten afterward; the printed restore plan names that possible reappearance as well as post-backup event loss before owner confirmation.

### Storage action hazards

| Action | Printed consequence and required boundary |
| --- | --- |
| remove | stop/revoke the selected project and reverse owned integrations; preserve repository, provider accounts and history; owner presence before irreversible work |
| forget | exact body targets/revisions, live DB/WAL deletion scope and retained backup/provider/import/SSD copies; owner presence; no typed-ID prompt |
| import | read-only original, user-state families, collisions/omissions and historical ended sessions; explicit owner action; no credentials/fleet/runtime adoption |
| migrate | sole-host supported additive startup change after verified backup; no confirmation step; old host requires se down first; failure preserves source/backup |
| restore (`se restore`) | newest valid automatic snapshot, exact/unknown post-backup loss, sessions/credentials ended and retained corrupt source; separate confirmed owner action |
| rotate (`se credential rotate`) | exact credential/session revocations and required rebind; separate confirmed owner action |
| doctor (`se doctor --fix CHECK-ID`) | one diagnosed owned-configuration plan printed first; no credential rotation, history restore, salvage or migration hidden in the repair |

Human presence is a mistake/drift guard; it is not proof against a determined agent acting on the same OS user's account. These storage outcomes are rendered through the shared operation/receipt vocabulary, not new prompts or private commands.

## Forget and content erasure

Prime's review decision adopts section 70 §6: owner-only, explicit captured-turn or message body event IDs with expected revisions; **in-place**, one content-erasure transaction, no whole-store rebuild. Decisions, reasons, configuration, identity and arbitrary legacy blobs are not public erase targets. EraseTarget contains only event/expected revision and implicitly selects Body; SourceDigest is internal dependent metadata, never a separate user-selectable arbitrary field. Keep event identity/actor/time/vendor ref and original byte length, remove plaintext and body-derived hashes. Source artifacts, automatic backups and raw-media remnants are named residuals rather than silently deleted. Version 1 has no FTS. Search is a bounded streamed scan; erase covers its actual buffers/caches, not a nonexistent index.

Limit one request to 60 explicit targets so its audit batch stays within the 64-event bound; larger selections use separate explicit operations. Estimate extra WAL/dirty-page space from those targets, with bounded streaming buffers rather than whole-store replacement space. The factory erasure_plan uses an independent scoped reader while the writer is live, so inventory/owner confirmation does not freeze ordinary work; erase rechecks every target/revision after drain. Before mutation inventory the target owning payloads/source digests, affected operation fingerprints, host render/search buffers and owned staging, WAL and known backups/provider/import originals. Drain consumes/deletes accepted staging by exact custody identity; any remaining owned orphan that cannot be safely removed is explicitly named as a residual, never ignored. Approval binds owner, expected incarnation, exact target revisions and acceptance of named residuals; only an owner outside agent process trees can supply it through core. Drain/join the writer to obtain the maintenance HostStore. Block new writes through this maintenance phase; close owned readers and require bounded checkpoint access, while a foreign owner's direct SQLite reader can still make the checkpoint busy. That is an explicit erasure-incomplete outcome, never proof old pages disappeared.

Register private read-only, innocuous SQLite connection functions (so trusted_schema=OFF remains enabled) se_erase_body_allowed(event_seq,field) and se_erase_operation_allowed(operation_id), returning zero on every ordinary connection. Only the exclusive, owner-approved erase connection enables a finite in-memory exact target/operation set for its transaction; there is no SQL table, environment flag or remote input that enables it. The callbacks expose only membership in nonsecret ID sets, perform no SQL/IO or state mutation, are audited for information leaks before INNOCUOUS registration, and are not marked deterministic because the connection guard changes between transactions. [SQLite function flags](https://www.sqlite.org/c3ref/c_deterministic.html). The DDL's payload/message/turn/operation trigger predicates allow only: detach the approved body ref; null that turn's derived source hash; delete its owning payload; invalidate fingerprints of operations whose members depend on that erased field. Every other column must compare unchanged. Event/envelope/member/history deletion stays prohibited. The connection-local set is cleared on success, error or rollback; normal statements never disable triggers.

With secure_delete=ON read back, begin a FULL transaction. Recheck target revisions/type and identity of the sole owning payload; append erasure.requested, detach body refs/delete payload rows and hashes, record erased_fields with original byte length, append turn.erased/message.erased for each target, null/mark every dependent operation fingerprint, and bump incarnation. Update/rebuild affected bounded search/summary caches and mark store erasing. COMMIT atomically; a rollback retains the original complete bodies and audit state. No original text/hash is put into the audit event/manifest. Re-capture hits the preserved provider/vendor natural key and returns Erased, never re-inserts the body; a retry key with an erased fingerprint returns content-erased. An erased natural key never accepts replacement text or claims byte equality after its digest was removed: it reports that existing record as erased and suppresses re-ingestion regardless of incoming text.

After COMMIT, invalidate actual owned search/render caches, checkpoint(TRUNCATE), and independently verify the exact erased bodies are absent from database/WAL bytes and queries, using streaming bounded-memory reads, with user-visible scan cost. Secure deletion is not physical SSD or filesystem-snapshot sanitization. A pinned reader/busy checkpoint or failed readback leaves erasing/pending, returns cleanup_complete=false plus the committed target facts/residuals, and names the owner remedy; it cannot claim full completion. A subsequent explicit owner resume finishes this finite cleanup without re-erasing or resurrecting content. Only after readback append erasure.completed under FULL and return completed_event/cleanup_complete=true. The small completion transaction contains no old body pages. Reader generation checks refuse old cursors rather than pretending their prior content still exists.

The receipt lists every retained automatic backup generation containing the target and its rotation condition, provider transcripts and imported Node originals with custody/location/reason, plus filesystem/SSD remnants. No backup rotation or foreign file deletion is silently accelerated by forget. The logical guarantee is exactly absence from the live StateEngine DB/WAL and query surface after witnessed cleanup; surviving named copies remain residuals. Wider historical/third-party/cryptographic erasure needs a separate product decision, not an extra supported target in this crate.

## Public ID decoding and exact legacy preservation

This contract replaces the early sketch that exposed fresh UUIDs for imported identities. New `FromStr` remains strict: exactly the shared type's prefix plus canonical lowercase RFC-variant UUIDv7; no trimming, case folding, UUIDv4 acceptance or legacy fallback. Canonical prefixes are Project `prj_`, Agent `ag_`, Human `hu_`, Session `ses_`, Message `msg_`, Decision `dec_`, Event `ev_`, Launch `lch_`, Observation `obs_`, Store `store_`, Lifecycle `life_`. A canonical-looking value with an incorrect type prefix/version is an error, never a registered-exception escape. This reserves namespaces that Node formerly allowed as project names; such rare imports remain explicit unreadable/collision records until an owner-reviewed correspondence policy exists.

The following matrix is pinned to Node source available at `a1b09788ef79fcbcd3bca7f6cdd9535d80afcf3d` (the current author's pre-redesign tree). Patterns are full-string ASCII matches unless explicitly described otherwise. They describe historical representation, not existence, ownership or authority. Wire decoding accepts only canonical new values or the named type's legacy shape. Context-dependent exceptions use an explicit importer/registry resolver carrying the expected type and source evidence; ordinary state-free serde must not accept every opaque string as every type. Broad project names must first reject every known canonical/legacy foreign namespace, including malformed reserved-prefix values. No wire decoder consults environment, disk or a global mutable registry.

| Shared type | Accepted legacy shape | Exact registration / source qualification |
|---|---|---|
| ProjectId | `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; reject trailing `.`, case-insensitive `(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?`, and all reserved foreign ID namespaces | `src/validation.mjs:validateProjectId`; actual project registration required before lookup/admission. Overlapping historic project spellings in another ID namespace are a named import collision: preserve source/provenance and refuse typed activation; do not silently rename or import them under the wrong kind. Supporting them requires an explicit cross-area decoder decision. |
| AgentId | `agt-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}` minted; older validators admit `[a-z0-9]` in each 4-character group | `src/agent-registry.mjs:generateAgentId`, `src/commissioning-internals.mjs:AGENT_ID`. Non-Crockford serials and mnemonic IDs are exact registry exceptions. An alias remains a lookup input resolved to its canonical recorded principal, not a second agent. |
| HumanId | `hum-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}` | `src/humans-registry.mjs:generateHumanId/validateHumanId`. Legacy `user`/actor labels retained as provenance need recorded principal kind and owner binding; never infer a registered owner from their spelling. |
| SessionId | `se-session-sha256-[0-9a-f]{64}`, `se-` plus lowercase canonical bare UUIDv4, or lowercase canonical bare UUIDv4 with RFC variant | `src/session-reference.mjs`, `src/identity-session-adapter.mjs:mintSessionId`, `src/session-loop.mjs:createSessionState`; provider-supplied IDs outside those shapes require a capture-pin/source registration. Raw `selp-` bearer values are never public IDs: derive the existing reference, do not import the secret. Native provider IDs retain their separate ProviderSessionId type where appropriate. |
| MessageId | `msg-[0-9a-f]{8,}` within the 512-byte shared storage/wire budget | `src/msg-id.mjs:MSG_ID_RE`; current mint is 24 hex digits, newer-write validator permits 16–64, existing-reader grammar starts at 8 and has no upper bound. Longer historical IDs become explicit over-budget import refusals, not truncations. Historic bare UUID mail from the documented old hook requires exact message-source exception registration, not generic UUID MessageId decoding. |
| DecisionId | lowercase canonical bare UUIDv4 with RFC variant | `src/service.mjs:propose` mints `randomUUID`; `validateDecisionId` historically accepts a trimmed nonempty 160-code-unit string. Such custom IDs require exact decision-source registration, never that broad validator as a shared grammar. |
| EventId | `evt-[0-9a-f]{64}` | `src/capture-event-id.cjs:captureEventId` derives SHA256 from the exact project/agent/session/turn/role tuple. Message exchange keys and ledger transaction UUIDs are natural/source keys, not automatically EventIds; importer records their correspondence and emits new envelope IDs. Explicit other historic event_id values require source-event registration. |
| LaunchId | lowercase canonical bare UUIDv4 with RFC variant | `src/launch/seat-launch-handle.mjs` claim `launch_id:randomUUID()`. A reservation ID and lifecycle ID remain distinct typed fields even when also UUIDs. |
| ObservationId | `semantic-observation:[0-9a-f]{64}` | `src/semantic-freshness.mjs:observationId`, `src/terminal-completion.mjs`, `src/health-signals.mjs`. The latter two produce `observation-<decimal milliseconds>` / `health-terminal-lineage-<decimal milliseconds>` as historical runtime evidence and require exact source registration, alongside arbitrary supplied observation IDs; they do not widen state-free decoding. F17/F18 drop their live authority; this matrix does not add an observation import operation. |
| StoreId | none | Node peer IDs are not Rust StoreIds. Initial import creates a canonical StoreId; origin/source peer labels remain provenance. No generic bare UUID legacy StoreId decoding. |
| LifecycleId | lowercase canonical bare UUIDv4 with RFC variant | `src/process-lifecycle.mjs:process registration`, `src/launch-reservation.mjs` mint UUIDs. Explicit custom lifecycle IDs require registration in that source family; import never revives PID authority. |

Bare UUIDv4 is deliberately a representation shared by the four documented producing families, not proof those families describe the same entity. UUIDv4 syntax here is `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`. A MessageId, StoreId, AgentId or ProjectId must not accept it via a generic fallback. Project grammar excludes bare UUID shapes to avoid that ambiguity. Registered-exception data preserves exact validated source spelling, bounded by its producing field and 512 UTF-8 bytes; no whitespace normalization during Rust round-trip. Node trimming/case folding is applied only when reproducing an explicitly named Node source reader's persisted identity, with original bytes retained as provenance. Unsupported Unicode/control-bearing exception encodings refuse visibly rather than silently re-spelling identity.

Exception registration is a typed source correspondence, not a public constructor granting arbitrary identity: expected kind + project scope + exact source identity/incarnation + source offset/hash + public spelling + private storage key. Conflicting registrations refuse. After authenticated lookup/import resolution, serializers emit the exact stored public spelling. To decode a later registered exception, the operation's contextual resolver must resolve it under the declared expected type before constructing the ID; state-free `Deserialize` returns a typed invalid-ID error with the explicit lookup route. Unknown legacy shapes remain unreadable provenance, not invented valid IDs. This boundary is required even if a convenience `from_legacy` currently exists in the unmerged shared foundation.

Canonical domain IDs store their UUIDv7 bytes directly with no dictionary row; the typed column supplies the shared prefix on read. Imported domain IDs alone use private RFC-variant UUIDv8 keys and a legacy dictionary row, atomically allocated on first use with collision checking. The disjoint UUID version prevents a later canonical-v7 ID from colliding with a private legacy key. Internal RecordIds remain direct UUIDv7 bytes. The legacy dictionary is immutable under normal writes, exact `(kind,scope_key,wire_id)` unique across this store. Project/human/store dictionaries use registry scope; agent/session/message/decision/event/launch/observation/lifecycle dictionaries use the source project scope. Equal legacy spellings in different projects may therefore have different storage keys without changing their public spelling. Project scope is resolved before any principal/object lookup; a global string lookup must never borrow another tenant's registration. Registry scope is the single byte `00`; project scope is `01` followed by the 16-byte project dictionary key, making the scope encoding unambiguous. Resolve actor kind from the authenticated Actor tag or the recorded principal kind; never compare only a string or permit project names to impersonate principals. Projection IDs, foreign references and fingerprints resolve through the same dictionary. Internal keys can change during an explicit rebuild only if every reference is rewritten together; public ID spelling remains stable. No extra per-read filesystem lookup is needed: dictionary keys join in the same snapshot, with bounded cached hot identities. Only legacy dictionaries count as exceptional identity-row overhead; the earlier prototype's bytes/event estimate must be remeasured with mixed legacy IDs before accepting it.


## User-history import

Import is an explicit owner action from an immutable/read-only source copy, streamed and resumable. The adapter decodes supported Node user-state formats into the same closed event batches; it cannot execute Node code, copy credentials or directly insert projections. Source identity binds canonical file identity/incarnation, format/version, byte-prefix digest and cursor. Changed incarnation/prefix refuses resume without moving the checkpoint; an unchanged appended suffix may continue the same run. Import checkpoints commit atomically with complete operations. Source duplicates map to the same typed object/native turn, with conflicting bytes a visible conflict. Forward references stage until dependencies exist. Unreadable rows produce bounded import.unreadable provenance and counted omissions, not zero-success or skipped history. The run's versioned policy fixes prior keep/drop decisions. ImportFamily is the closed user-state enum below; an arbitrary family string cannot add a protocol.

| Supported user-state family | Retain | Authority excluded |
| --- | --- | --- |
| projects/owners | exact registered IDs, user roots, owner correspondence and tombstones with source evidence | labels or old machine credentials as owner proof |
| agents/profiles | names, owner/creator when verified, lookup aliases and supported Claude/Codex models/permission profiles | guessed creator, copied capabilities, implicit bypass or factory coordinator/machine defaults |
| messages/marks | exact IDs/text/refs/replies and real delivered/read/dismiss/supersession history | bell as recipient read; mirror/retry duplication; factory task admission or gate outcomes |
| decisions | original proposals and proven ratify/reject/retract/supersede transitions, actor/source bytes and expected relationships | synthetic human ratification, a proposed supersedes hint as activation, any new decision hash chain |
| working state | user working text and supported saved conversation/resume references with explicit author correspondence | factory lanes, campaign packets, stale overwrite authority or a generated packet called read |
| conversations/turns | ended historical bindings, exact provider/native conversation references, consented attributable text/role/native keys and source offsets/hashes | active session/process adoption, provider account files/credentials, suppressed text that was never captured |

These are the complete admitted import families. The Node repository remains the private factory with its existing engine/history; there is no fleet migration, campaign/review/landing/gate/queue/process-recovery import or factory CLI-only adaptation. Incidental caches, locks, generated indexes, backend-transition machinery and old host configuration are not additional product import protocols. The adapter must still prove which user-history source is authoritative when old backend transitions exist; an unresolved source window is an import blocker. A separately authenticated export may provide immutable user records from an old database, but se-store has no PostgreSQL client or copied database credential. Preserve originals and named residual copies rather than deleting them.

Legacy mapping is allocated atomically in the scoped identities dictionary using disjoint private v8 keys with collision checking; legacy_ids retains correspondence provenance. Canonical v7 IDs bypass the dictionary entirely. Exact original wire spelling round-trips; source aliases require recorded correspondence, not label inference. Reserved namespaces/unsupported encodings remain explicit collisions/unreadable records until an owner correspondence policy exists. No active grants are manufactured by historical identity rows.

Import does not delete user repositories, original history or provider accounts. Forget therefore reports those retained sources as residuals. Missing/unsupported native references yield explicit missing/unsupported resume facts; a new conversation cannot be called a resumed one. E6 must use real non-fleet user history, interrupt and retry import safely, and resume **both Claude and Codex** through their actual retained conversation references. The bounded factory-history/Codex spike is useful source/retry evidence but does not qualify that wider acceptance.

## Error catalogue

The error type carries the stable code, typed offending entity/range/revision, cause and an actionable remedy. Adapters map it to the shared `SeError` envelope; no SQL string, credential, turn body or raw account path leaks into a default message. Preserve IO/SQLite extended causes for redacted diagnosis. Expected absence is a `Read` value, not a generic error. Retryability never means “retry with a new idempotency key.”

| Internal cause | Cause / typed detail | Remedy | Public code / class |
| --- | --- | --- | --- |
| `setup-required` | missing state on a non-init route that requires initialization; embedded preparation reports it to the per-workspace repository trust hook | run owner `se --home HOME init --repo DIR`; the UI workspace hook invokes this managed no-repository-write setup without repository-write consent, then re-prepares; public GitHub stub silently skips init, otherwise show setup failure; bare se/status return not-set-up and exit 0 | setup-required / Refused |
| `store-already-exists` | exclusive create/no-replace publication found existing state | reopen the validated existing store and reuse its identities; never overwrite | state-conflict / Conflict |
| `store-unreadable` | permission, malformed/truncated header, undecodable row or IO error; source/range preserved | restore access or inspect with doctor; do not initialize over it | store-unreadable / Unreadable |
| `store-application-mismatch` | application_id belongs to another database | select the correct home; never migrate the foreign file | configuration-invalid / Refused |
| `store-too-new` | user_version above binary's supported range | install a compatible newer binary; old binary stays read/write refused | store-too-new / Refused |
| `store-migration-required` | supported older schema encountered by a reader/direct connection | release shared custody and use private host bootstrap; sole host migrates automatically after backup; a running old host requires se down first | store-migration-required / Unavailable |
| `store-version-unsupported` | older version/event/cursor codec outside supported range | use the named supported migration/import version | feature-unavailable / Refused |
| `store-not-ready` | creating/migrating/recovering/erasing or failed maintenance phase | finish/resume the named owner maintenance operation | store-busy / Unavailable |
| `store-generation-changed` | incarnation/schema/generation changed after admission | reopen and re-admit using a fresh scope/cursor | state-conflict / Conflict |
| `store-location-unsafe` | non-owned/linked/unsupported network or synced state location | choose a local owned per-user state directory; preserve original data | home-unsupported-location / Refused |
| `store-pragma-refused` | required WAL/NORMAL/FK pragmas do not read back | correct filesystem/build support; do not admit writes | configuration-invalid / Refused |
| `store-busy` | finite SQLite lock deadline expired | wait for named writer/maintenance; retry the same operation key | store-busy / Unavailable |
| `store-backpressure` | queue request/byte bound or non-backup pinned-reader WAL high-water reached | await outstanding work or release the diagnosed reader/checkpoint, then retry same key; never blame a backup pin or spawn another writer | store-busy / Unavailable |
| `store-writer-closed` | runtime writer drained/stopped before acceptance | reopen the current runtime generation and resubmit same key | runtime-not-running / Unavailable |
| `commit-outcome-unknown` | IO/connection/reply deadline cannot prove COMMIT outcome | CLI: rerun the same command with --key K; MCP: repeat the call with the same idempotency_key; never generate a replacement key | commit-outcome-unknown / Unknown (transient) |
| `idempotency-key-reused` | same scope/actor/key with a different semantic fingerprint | recover the original arguments or choose a new key for an intentionally new operation | idempotency-key-reused / Conflict |
| `event-id-conflict` | event ID already belongs to another operation | preserve that event; repair caller ID generation/request reuse | state-conflict / Conflict |
| `natural-key-conflict` | turn/message/source identity repeats with different bytes | inspect original/refused source evidence; do not overwrite | state-conflict / Conflict |
| `revision-conflict` | expected absent/revision differs from committed head | reread that entity and decide again | revision-conflict / Conflict |
| `invalid-transition` | transition not in the closed state machine or missing prerequisite | use the legal state/operation named in the error | state-conflict / Conflict |
| `reference-missing` | required same-scope entity/event absent | supply/import the prerequisite, or report the original operation incomplete | target-unknown / Unknown |
| `scope-mismatch` | event/reference/target does not match admitted scope/actor/recipient | rebind to the correct session; labels cannot override authority | state-conflict / Conflict |
| `creator-control-refused` | current create grant or immutable direct-created relation missing | use owner control or the actual authorized creator; no descendant/bulk expansion | grant-required / Unauthorized (missing grant); owner-required / Unauthorized (not a direct child) |
| `event-invalid` | unknown kind/version/enum, malformed typed field or forbidden registry event | use the current generated input/schema; no partial insertion | usage-invalid-value / Usage |
| `body-too-large` | body/ref/batch exceeds its documented bound | reduce/chunk the source using the supported capture contract without advancing past uncaptured bytes | input-too-large / Usage |
| `projection-inconsistent` | expected projection/head/count disagrees with authoritative material | stop mutation and diagnose; diagnosed restore or a supported compiled projection migration, never catch-and-empty | store-corrupt / Unreadable |
| `cursor-invalid` | wrong version/store/query/order or invalid bounds | start a new explicitly bounded read | cursor-invalid / Usage |
| `cursor-stale` | erasure/recovery changed incarnation | restart the read and acknowledge the changed history window | cursor-expired / Incomplete |
| `read-budget-too-small` | first complete item cannot fit | retry with the stated bounded minimum or explicit preview | usage-invalid-value / Usage |
| `read-incomplete` | finite deadline expires before a valid bounded result/continuation can be constructed | retry the same read with its named finite budget; ordinary budget exhaustion is Page/Window incomplete | deadline-exceeded / Unavailable (see bounded-read rule below) |
| `source-changed` | transcript/import source incarnation/prefix differs | register/review a new source incarnation; never advance an old cursor | state-conflict / Conflict |
| `migration-failed` | DDL/backfill/validation failed under maintenance | retain source/backup and resume the named migration with compatible binary | store-migration-failed / Refused |
| `backup-failed` | snapshot, sync, validation or owned rotation failed | retain prior generations; inspect source/destination/free space and retry | backup-failed / Refused |
| `recovery-incomplete` | no valid automatic backup or restored source/loss boundary cannot be verified | preserve source and backups; diagnose or install the named compatible recovery version; event salvage is unavailable | store-corrupt / Unreadable |
| `content-erased` | requested body/key was explicitly forgotten | use the erasure receipt/retained metadata; never reconstruct it from an old owned copy | state-conflict / Conflict |
| `erasure-incomplete` | owned copy/reader/buffer cannot be replaced or acknowledged | finish the named phase/custodian before claiming completion | forget-incomplete / Incomplete |
| `erasure-external-copies` | known vendor/import/export/snapshot copies outside store custody remain | act through those owners or accept a precisely scoped result; no automatic foreign deletion | forget-incomplete / Incomplete |
| `erasure-physical-guarantee-unavailable` | requested raw-media guarantee exceeds logical store custody | use an approved encrypted-storage/media-erasure workflow; this store cannot attest it | feature-unavailable / Refused |

The 38 rows map every StoreErrorCode variant (Absent uses setup-required) to the one section-50 public catalogue; internal cause strings are not additional transport codes. Exact cause, redacted typed detail and legal next step survive the many-to-one mapping. ScopeMismatch here means a precondition drift after verified Admission, not an authorization bypass: core/host authorization failures retain their own Unauthorized codes. CreatorControlRefused distinguishes absent current grant from a non-child target. ReadIncomplete is an error only when the finite deadline expires before a valid result/continuation can be constructed; ordinary row/byte/step exhaustion returns an explicitly incomplete Page/Window and never a fabricated timeout. All unknown SQLite/IO integrity failures remain diagnosed failures rather than guessed domain conflicts. `StoreError` reuses the shared typed Remedy/Retry, boxes the area-specific error result, and preserves typed version/conflict/request/source/budget/maintenance detail. The shared catalogue is the one transport-code source; the adapter preserves each storage cause and remedy in its typed detail.

Decode, FK, constraint, invariant and IO failures are never all flattened into busy/conflict. A constraint is mapped to a domain conflict only when its fixed constraint name and checked precondition identify that case. Any other constraint failure is integrity/internal failure with cause. Logs redact payloads/credential bytes by construction; diagnostic support bundles carry counts/IDs/ranges rather than text.

## Platform and resource contract

The storage algorithm and schema are identical on Windows, macOS and Linux. Only owned-file creation/replacement, lease/peer proof and directory-sync semantics use the host's platform custody adapter. Embedded code never changes the process umask: owner-only DB/WAL/SHM/staging/backup creation and per-file mode/ACL readback are local to each owned file. A standalone binary may set its own umask. Windows must close all old SQLite/backup handles before replacement and use the owned atomic replacement API; a sharing violation is a real failed phase, not success after deleting a pathname. Unix directory fsync/readback protects published names; macOS and Windows durability caveats remain within NORMAL's documented OS/power-loss boundary. No PowerShell, shell spawn, bundled Node or process-name stop appears in the store. Platform path bytes are preserved as tagged lossless values. The store is not allowed `unsafe`; `se-proc` alone owns unsafe platform code.

A configured network/synced location refuses by explicit configuration/path classification supplied by the host; path heuristics cannot prove that an arbitrary mount is safe. Unsupported/unknown storage semantics are a named limitation, not a claimed successful qualification. All temporary/backup/recovery files are in the same owned state volume for atomic publication. Free-space checks estimate the **additional** staged restore + two backup generations + retained source/WAL and bounded erasure WAL growth; insufficient space refuses before copying, with checked required/available bytes (unknown space is not zero).

Section 80 owns the single startup/RSS/read/write budget table and its allocations; section 95 owns the generated size table and schedule. Store connections use one bounded write cache and two lazy readers, never one connection per session. Queue, staging and materialized-result bounds apply before admission; large captured text is streamed/staged rather than multiplied per session. Automatic backup/explicit restore/erasure use bounded buffers and named costs, and do not add idle workers. After supported startup migration, ordinary open checks only header/version/indexed readiness. Start-of-day backup runs after ready and never gates first bind; the writer blocks without polling or WAL watchers when idle.

The storage footprint target and all process/startup/write budgets are named once in section 80. Earlier schema-only sizing (1,265.50/1,356.43 B/event canonical variants and 1,390.18 B/event under a different legacy/keyless policy) used SQLite 3.46.1, foreign_keys disabled and the older temporal/chain schema; none qualifies this reduced schema, real import overhead, full 1M composition, native platforms or backups/WAL. The read-only history spike used the complete original DDL with FKs enabled, retained exact source bytes externally, imported registered legacy identities, and independently compared text/references after interrupted retries. Its omissions and factory-history/Codex-only scope remain explicit. The revised schema needs a fresh apples-to-apples native host measurement with real body sizes, FULL decision mix and all retained metadata/index costs; no sizing or latency win is asserted from subtraction alone.

Warm 1M inbox uses an indexed 50-message page with no full-history scan; section 80 supplies the sole budget table, including B9. B9 remains **FAIL/unqualified**: the retained common-window mixed-write spike measured p95 37.47 ms serial and 66.92 ms with twenty clients on Linux. It was a bounded Python batching writer, not the native Rust host or a PC qualification. E3 must split queue, append, COMMIT, restore and checkpoint/sync time and repeat the native host writer on the box and PC before attributing the regression or claiming acceptance. Queue/window tuning alone did not establish the tail. Build acceptance must measure signed native Windows with Defender, macOS and Linux; a median win does not establish the required p95/burst budgets. Checkpoint-in-COMMIT remains a measured hypothesis rather than an approved policy change. E3 diagnostics do not replace the baseline; any proposed change requires one reviewed policy across 20/40/80/95 with its sync/queue/WAL/memory costs. Checkpoint work is commit-driven on both host and direct connections via SQLite auto-checkpoint at 256 16-KiB pages (4 MiB), with TRUNCATE on clean shutdown. There is no scheduled PASSIVE worker or checkpoint timer. journal_size_limit is a reuse target, not a hard WAL cap: if non-backup pinned readers prevent checkpoint and WAL exceeds the 16 MiB high-water, reject new ordinary writes with store-backpressure, identify the pinned-reader condition, and retry only after reader release/checkpoint; never delete a live WAL. During a backup pin, defer checkpointing and keep accepting writes; at 64 MiB abort/release the backup and retry next start-of-day as specified above. A security revocation must not be silently dropped for this pressure: close agent admission and report a FULL commit failure if it cannot be persisted. A busy checkpoint reports backlog and yields; it never blocks a query indefinitely or reports a fully flushed WAL when frames remain.

The future backend uses the SE Code-compatible caret range rusqlite "0.40" (its lock currently selects 0.40.1 / libsqlite3-sys 0.38.1), with one links="sqlite3" dependency across the workspace; it adds no Tokio dependency to se-store. A patched bundled SQLite must be shared with SE Code and avoid the documented WAL-reset defect (fixed in 3.51.3, with 3.50.7 backport); dependency/link versions are workspace coordination, not a private second SQLite build. The implementation must validate `cargo tree -d`/links compatibility at integration. [SQLite synchronous semantics](https://www.sqlite.org/pragma.html#pragma_synchronous), [WAL-reset advisory](https://www.sqlite.org/wal.html#walreset).

## Journey trace and reviewer acceptance

Authors add no tests. These are the externally observable obligations for the independent journey owner/reviewers, not a new suite or gate implementation.

| Journey | Store paths actually exercised | Observable proof / failure boundary |
| --- | --- | --- |
| J1 Install | correct per-user home, application/version negotiation; read-only status/version do not create state | fresh install identifies its own binary/store support, not enclosing Git; wrong/newer store refuses with remedy |
| J2 Adopt | registry/principal/profile/grant/integration events, existing-repo registration, session binding, capture and real agent output | existing files/Git untouched; committed task/turn read back by event ID; owner/session binding and safe defaults retained |
| J3 Come back | restart WAL recovery, saved native conversation, source cursor, working state/resume heads and explicit cursor ack | same native conversation and actual recalled work; no synthetic fresh thread, missing capture reported; NORMAL acknowledged writes survive process kill |
| J4 Two agents | message send/inbox/read/dismiss, exact key replay, effect delivery, creator relation/current grant, bounded windows | second agent receives/reads actual message and responds; recipient witnesses distinct; creator can control only its direct helpers; incomplete pages never appear empty/complete |
| J5 Remove | owned process/integration effect references, credential revocation and project tombstone, clean backup/stop | exact outside stop/reversal witnesses; provider accounts/repo/history preserved; no active lease/token silently left; failed cleanup named |

Reviewers additionally exercise crash boundaries unreachable from a happy journey: pre-/mid-COMMIT/savepoint/backup rotation/migration/swap, duplicate and conflicting keys, stale revisions/versions/cursors, foreign actor/recipient, direct-host lease race, corrupted/unknown body versions, failed backup validation/restore and failed erasure custodian. No in-process hostile caller/injected fake reader is a process-boundary security claim. Measurements and independent readbacks must be bound to implementation bytes later; this design/compilation is not platform or durability qualification.

## Open questions and implementation admission

1. Shared `se-types` and process declarations are consumed directly from the accepted rust-se main base, not copied into this crate. StoreId, all kernel IDs, Page/Window/PageRequest and native process/path types are reused, not recreated. Store-specific records/traits live here; wire DTO/auth ownership remains with their assigned crates.
2. Prime resolved forget scope to section 70: live captured-turn/message bodies, in-place secure deletion and honest residual copies. Physical/third-party erasure is outside the supported claim; it does not block the approved narrow operation.
3. Section 80's p95 read/startup/burst budgets govern; B9's target in section 80 is fixed; a measured failure is reported with its cause rather than relaxing that target. NORMAL is ratified here; neither disabling durability entirely nor early acknowledgment is authorized. Native measurements may require scheduling/checkpoint changes, reviewed against this same commit/receipt contract.

4. The section-50 global code catalogue supplies the exhaustive typed mapping for these store causes; do not implement a catch-all Internal conversion while that integration is pending.

5. The strict shared ID namespaces reserve some names that Node accepted as projects or custom identifiers. Those collisions must remain visible import refusals with original provenance until an explicit identity-correspondence policy is approved; neither a broad arbitrary-string decoder nor a silent public-ID rename resolves the conflict.

Store payload records have no Debug derivation; diagnostic code handles only redacted IDs/ranges. The critic, 5c, Otto and Alpha's Rust reviewer assess this complete design/craft candidate; Prime integrates it. Only a later explicit implementation admission activates the signatures and DDL as product code.

## Method contract index

This index binds the following declarations to the algorithms above. All methods return the exact typed error/absence/window distinctions already specified; none is a convenient catch-and-empty wrapper.

| Trait / functions | Preconditions, effect and completion |
| --- | --- |
| StagedTextValue.byte_length / sha256 | metadata from the same protected staging pass, available before canonical input hashing without duplicating body bytes |
| RecordIdentity.from_parts / from_bytes / as_bytes | explicit caller time/entropy or checked UUIDv7 bytes for internal RecordId; reject wrong UUID version/variant and timestamp overflow; no clock, RNG or authority lookup |
| WriterModeValue.kind | read-only view of the opaque retained stamp; no public construction or input deserialization |
| ReadStore.runtime_owner / HostStore.runtime_ownership_fact / record_runtime_ownership | non-secret owner/fence view; trusted maintenance-only point read of private runtime facts; exclusive maintenance FULL append following the phase/path table and epoch/generation/head/phase CAS |
| RuntimeLease.identity | host's held filesystem-custody lease identity; unknown store only for witnessed-absent owner bootstrap or owner maintenance of an unreadable source; no lock acquisition by reading an endpoint |
| StoreFactory.open_reader / open_direct / open_host | validate existing header/version/path/role; missing → Read::Absent, foreign/newer/corrupt → typed unreadable/refusal; direct requires shared lease, host exclusive; sole-host startup migrates supported additive schemas after a verified backup before returning ready; reader/direct old-version detection releases custody and requests host bootstrap |
| StoreFactory.create / create_direct | explicit owner init only: exclusively reserve/publish a new path under host-exclusive or owner-bootstrap shared lease; caller-supplied StoreId; FULL DDL/header publication/readback; never overwrite existing bytes or use as an embedded-open fallback |
| HostStore.record_first_binding | exclusive pre-writer ordinary embedded cold admission; registry owner and project session retain distinct admissions/operations, one all-or-nothing FULL commit; return FirstBindingReceipt for both original keyed operations; no unresolved handover fence |
| StoreFactory.inspect_backups / restore_backup | inspect protected generations without opening a corrupt live store; owner selects the newest independently validated automatic backup, prints loss/revocation consequences, preserves source/WAL, then rechecks exact generation under exclusive custody before guarded adoption |
| ReadStore.info / snapshot / credential | header metadata; finite scope-bound snapshot; trusted pre-auth hash lookup returns only credential/session metadata and cannot obtain history or manufacture an authority |
| ReadStore.inspect_backups | snapshot manifest metadata, then separately inspect bounded published files; each item's absent/unreadable/current observation is explicit; never a live-DB filesystem copy |
| TextStaging.stage_text | bounded owned stream to protected staging under held lease; UTF-8/length/digest checked; opaque handle has no caller-path constructor; used/failed staging is reclaimed by exact identity |
| DirectStore.append / close | one-element canonical commit_group under direct-client lease; success only after COMMIT; close releases handles before lease release |
| HostStore.start_writer | consumes the ready HostStore, retains Arc lease, independent of background startup backup; yields unique control owner and cloneable bounded submission handle |
| StoreFactory.backup / HostStore.backup_context / WriterOwner.backup_context / HostStore.checkpoint / close_clean | opaque shared pin/cancel state; whole-copy fixed read transaction, 64 MiB abort rather than backup-induced write backpressure; background rotation without writer drain; checkpoint/close require the unique maintenance object after all work joins (including a never-started writer case); close_clean preserves required backup/closure facts and reports failure truthfully |
| StoreFactory.erasure_plan / HostStore.erase | exact target/revision inventory then approved in-place transaction and witnessed live DB/WAL cleanup; narrow approved body UPDATE/DELETE trigger exception with secure_delete and witnessed WAL cleanup; named backup/provider residuals |
| WriterOwner.client / flush / drain | clone handle, async barrier through accepted work, then awaited stop/join yields unique HostStore; flush is not a new backup or a claim of power-loss durability |
| WriterClient.submit / CommitWait Future | immediate bounded admission/rejection and awaitable one-shot result; no blocking-wait API; timeout/drop cannot cancel a possibly committed write; retry same key resolves outcome |
| TransactionEngine.commit_group / append_atomic / apply | private common implementation seam: one outer transaction, isolated operation savepoints, exhaustive per-event apply; PreparedReceipt cannot escape as durable success before COMMIT |
| Snapshot.legacy_registry | scoped source-evidence resolver borrowing this admitted snapshot; exact kind/text membership only, absent false and unreadable error; no global string registry or grants |
| Snapshot.info / event / history / search | snapshot metadata; exact typed event; indexed/bounded history and budgeted search with honest omissions |
| Snapshot.projects / project / principals / principal / profile / grant | authorized current metadata, resolved immutable originals where required; grant key and creator checks use committed heads |
| Snapshot.session / sessions / turns / capture_source | native binding/consent/capture state; bounded attributable text; never provider account credentials or a fake native conversation |
| Snapshot.message / messages / decision / decisions | full or explicitly previewed bodies, correct sent-or-received/owner scope and exact-ID filtering; no read/delivery/disposition writes |
| Snapshot.process / processes | recorded identity plus actual recorded observation, never live OS proof or a PID-only stop handle |
| Snapshot.working_state / cursor / resume_head | present-empty distinct from absent; expected revisions/window/ack facts and nonnegative derived debt counts |
| Snapshot.pending_effects / effect / integrations | durable pending/terminal intentions and exact outside-witness references; reads do not execute effects |
| Snapshot.operation_receipt / import_progress / close | original request-key result and bounded source checkpoint windows; close ends snapshot, never advances a durable cursor |

## Canonical Rust declarations

The compile-only signatures live only in the crate: [lib.rs](../../crates/se-store/src/lib.rs) exports [model.rs](../../crates/se-store/src/model.rs), [event.rs](../../crates/se-store/src/event.rs) and [api.rs](../../crates/se-store/src/api.rs). Those four source files are the single Rust declaration authority; this document owns the behavioral contracts and SQL. Workspace check, formatting and Linux/Windows-MSVC/macOS-AArch64 Clippy check the declarations; they do not qualify a runtime backend.
