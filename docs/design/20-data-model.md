# 20 — Authoritative data, SQLite and recovery

Status: design for review, not permission to implement. This replaces the storage choices in the section drafts wherever they conflict. Governing inputs are the reviewed `docs/OPS.md`, Jimmy's design-first order relayed by Prime (`msg-5d1776a93c972d4ecceeaca3`), the synthesized Rust plan and the five shared section drafts in `prime-handoff-20261030`. The S1 prototype is measurement evidence, not production source. The earlier migration sketch is retained outside this repository as reference; no executable migration or writer lands with this design.

## Purpose and ownership

`se-store` owns the one per-user SQLite authority, event representation, transactional projections, idempotency, bounded snapshot reads, schema negotiation/migrations, backups, recovery and storage erasure. No SQL, SQLite handles, database paths derived from project labels, or backend-specific sequence arithmetic escape this crate. `se-core` owns authorization, operation policy and legal domain transitions; the store checks the same transition preconditions atomically against committed revisions. The host owns the runtime lease, process/OS witnesses, notifications and scheduling; a process row is never proof a process exists. Harnesses own transcript access and account stores. Atlas owns a separate rebuildable code index and cannot lock this database for indexing.

The store reads no environment and selects no repository. The caller supplies the resolved per-user state directory and typed scope. Its production layout is `STATE/state.db`, `STATE/backups/`, `STATE/recovery/`, with explicitly owned bounded staging files in `STATE/staging/`; platform defaults belong to configuration, not this crate. Every project uses this file. Registry-scoped events use a distinguished typed registry scope, not a magic user-controlled project name. New kernel IDs use the shared kind-prefixed UUIDv7 wire spelling. Imported IDs retain their exact accepted legacy spelling. Domain-ID BLOB columns use the canonical UUIDv7 bytes directly for new IDs; the expected field kind supplies the canonical wire prefix. Only imported spellings need a scoped `identities` row and a disjoint private UUIDv8 storage key. Imported public spelling is read from that dictionary, never regenerated from its private key. SQLite row numbers are internal commit positions, never public IDs or authorization.

### Fixed decisions

* WAL with `synchronous=NORMAL` for ordinary writes; the closed security-event set below commits under `FULL`, as Prime required in the review return. NORMAL acknowledgments survive writer-process crash but may lose recent ordinary writes on OS failure/power loss. FULL security acknowledgments require the successful sync. No caller/environment durability knob exists.
* One host-owned batched writer when the runtime lease is held; a direct no-host writer calls the identical transaction function while holding a shared runtime lease in client mode; the host alone holds it exclusively. There is no host/direct split in apply or authorization semantics.
* The only authority is the immutable operation envelope, event envelopes and their typed data/body/member rows, with only the narrow sanctioned body-erasure transition below. Projections update before the same COMMIT. The privacy operation is an explicitly audited exception for erasing content, specified below; an ordinary correction never rewrites history.
* No all-event hash chain, PostgreSQL implementation, file watcher, polling loop, dual-written JSONL or repair command. A decision-only chain and imported provenance remain supported. PostgreSQL preparation is typed IDs, opaque cursors and confined SQL.
* No store background startup scan. Opening validates the header and version, opens prepared access paths and returns; migration/recovery are explicit approved maintenance phases, never automatic startup work; an inconsistent projection is a named refusal rather than an unbounded startup rebuild.

## Public API and dependency direction

The compile-only declarations in `crates/se-store/src/` are the normative Rust signatures; this document explains every method's behavior. They contain types and traits, no placeholder implementation or `todo!()`/`unimplemented!()`. Shared kernel IDs, `Read`, `Page` and `Window` come from `se-types`; this crate does not mint a competing identity or completeness vocabulary. Store-domain errors preserve typed detail/remedy and are mapped exhaustively to the shared error envelope by the core/host adapter. A concrete SQLite implementation is deliberately absent until design approval. `RecordId` is a store-specific validated UUIDv7 for internal effect/import/cursor/erasure objects, not a second kernel ID namespace; process lifecycle, store, project, agent, human, session, event, message and decision identities reuse the shared types. The signatures expose no rusqlite, tokio, OS process handle, arbitrary SQL callback or unconstrained JSON event.

There are four access objects:

1. A factory opens/creates under an explicit role. A host holding the exclusive runtime lease can create/recover or run startup/shutdown backup; an owner CLI can bootstrap an absent store through create_direct under its shared runtime lease; migration additionally requires explicit owner/upgrade approval. Opening a missing store for a reader/direct client returns measured absence; it never creates an empty database.
2. A read snapshot owns one SQLite read transaction and a captured high-water position. Unlike the separate background backup transaction, it cannot be held across an async suspension or an external call. Typed methods return fully materialized bounded results, then release it.
3. A direct writer performs the same atomic write batch as the host worker, while the caller holds a shared runtime lease. It cannot coexist with a host that acquires that lease later: the host waits, then opens after the client releases it.
4. A bounded host submission handle and its owner control. Cloned submission handles cannot close/migrate the store. A dropped reply receiver does not cancel a committed operation. The unique owner drains and joins the worker on shutdown.

Writer ownership is structural: `start_writer(self, ...)` consumes the maintenance-capable HostStore, and only the awaited drain/join yields a `DrainedHost<HostStore>`. Migrate/erase/close cannot run on an object still held by a live writer. The worker owns `Arc<dyn RuntimeLease>` and revalidates its store/generation/mode before each group; external handle drop cannot release a live worker's lease. Online backup is the separate factory service over a read connection, not a mutable writer/maintenance call.

A revision identifies a last committed event, scoped to the same store incarnation. Each event/operation also retains its recorded incarnation; historical expected positions are replayed against their original logical predecessors, not re-authorized against a new live incarnation. Recovery/erasure may invalidate runtime cursors without rewriting the fact that an older event committed in an earlier incarnation. `Expected::Absent` and `Expected::Revision` are distinct from unchecked writes. Unconditional internal appends exist only for genuinely append-only facts; mutable projections require a revision precondition. The caller's verified scope is not an event field and is never recovered from a display name. The store checks project/actor consistency with the admitted batch; credential proof and OS-user admission remain core/host responsibilities inside the same process trust boundary.

## Event wire and storage formats

Each event has a version-1 envelope (the closed Rust variant determines kind and schema version; a caller cannot request an unknown numeric version): stable event ID; scope; authenticated actor; optional bound session; origin store ID; door (`cli`, `mcp`, `hook`, `host`, `import`); occurrence time in UTC microseconds; database-assigned recorded time; caller idempotency key; optional cause/supersedes event IDs; and one closed `EventBody` variant. The store assigns sequence only inside the transaction; recorded wall time is sampled before BEGIN, not by an external clock call while holding a transaction. Normal batches require header actor/scope to match admitted authority. Import-only batches may preserve a different historical actor/origin after strict source-ID mapping, but their initiating owner/import identity remains on the immutable operation envelope; that historical actor never becomes current session authority. A host group contains independently atomic operation batches; one operation batch can contain several events and their expected revisions. An immutable operation envelope owns scope/actor/request-key/fingerprint and an ordered membership map, so salvage/replay can reconstruct atomic groups and retries from authority rather than a disposable lookup index.

The database stores the small envelope and typed per-kind rows, **not a second serialized JSON envelope**. Long bodies have one `payloads` row referenced by their event. Recipient/disposition/decision/session/turn/process/working-state/cursor projections contain indexes and event references, never copied body text. Refs and configuration objects are bounded typed encodings; their only JSON is a versioned non-text field, not an arbitrary duplicate of the event. Readers reconstruct a typed event from its one owning representation.

Strings are UTF-8 with no normalization of user text. Times are signed 64-bit Unix microseconds, with a checked supported range; sequence/revision values are positive signed 64-bit integers. Body byte counts count UTF-8 bytes, not characters. All enum tags are the stable strings below; integer discriminants in Rust are not persisted. SHA-256 fields are 32-byte blobs. Stored UUID keys are exactly 16 bytes, never SQLite row IDs. Canonical-v7 keys reconstruct their wire spelling from the typed column; legacy-v8 keys require the scoped identity dictionary. Canonical public IDs include the shared kind prefix; legacy public IDs retain their exact validated spelling through the identity dictionary. File paths are lossless platform path encodings tagged `unix-bytes` or `windows-utf16`; display strings never become an ownership proof. Native non-UTF-8 path bytes are not silently replaced.

Bounded initial limits: 32 KiB per message/working-state body, 1 MiB per captured turn, 64 refs, 8 KiB per single ref or native identity, 64 events/2 MiB per atomic operation batch. Large turns are streamed from the trusted harness into a bounded staging record before submission; the worker never queues 1 MiB copies for every session. Rejection preserves the source transcript cursor and names the oversized record; it never advances capture past uncaptured text. Header/ID/enum decoding is strict and unknown versions refuse, not skip.

### Event catalogue

All following kinds have `schema_version = 1`; changing required fields or meaning requires a new kind version and a reader/migration decision. Fields in the common envelope are not repeated in the table. `expected` means the last revision of the affected projection; IDs in references must resolve in the same authorized scope unless explicitly registry-wide. Every generated event is attributed to the initiating operation or a cause event, never to an invented actor. A kind not listed here refuses.

| Kind | Typed body fields | Emitting operation / internal cause | Authoritative projection effect |
| --- | --- | --- | --- |
| `project.registered` | project ID, display name, canonical/lossless repository roots, owner ID, expected absent; safe config/profile events share its atomic batch | `project.init`; supported F1/F4/F6 import | create registry/project heads; roots cannot collide |
| `project.updated` | project ID, complete display name/root snapshot, expected; configuration changes have their own typed event | `project.init` idempotent adoption repair; `config.set` only for project metadata | append revision; preserve ID and registration history |
| `project.removed` | project ID, expected, stop/revocation/integration witness event refs, preserved-history facts | `project.remove` after outside effects | tombstone registration, remove active root lookup; retain history |
| `principal.registered` | principal ID, human/agent kind, owner ID, authenticated creator ID (unknown only for import/bootstrap), display name, role, expected absent | `project.init`, `agent.create`; F2/F3 import | create principal; no authority from display name |
| `principal.renamed` | principal ID, name, expected | `agent.rename` | change lookup label, preserve ID |
| `alias.imported` | legacy alias, target principal ID, source ref, expected absent | `store.import_node` only | add historical lookup alias; never public alias creation |
| `profile.saved` | agent ID, provider, model, named permission profile, supported effort setting, expected | init/create/config and supported imported profiles | update saved profile, no launch claim |
| `grant.recorded` | principal ID, typed agent-create grant/scope, active/revoked, expected | owner init/config policy; historical import | update effective explicit grant; no bootstrap from old capability |
| `config.set` | user/project scope, typed key/value, expected | `config.set`, initial setup | update effective persisted setting; secrets disallowed |
| `session.prepared` | session ID, agent ID, provider/native conversation ref, capture consent, generation, expected absent | `session.begin`, `agent.launch` preparation | insert prepared session; incumbent remains active |
| `session.activated` | session ID, expected, incumbent ID/revision if replacing, process ref, recorded containment fact and binding/witness refs | witnessed launch/bind | activate atomically with incumbent terminal transition; one active per agent |
| `session.ended` | session ID, expected, end reason, final captured-turn/cursor refs | `session.end`; observed provider termination | terminal ended state; revoke active capability projections |
| `session.revoked` | session ID, expected, reason | owner revocation/remove; governed takeover | terminal revoked state; cannot be reactivated |
| `credential.issued` | credential ID, session ID, purpose, secret hash, expiry, ≤10-minute activation deadline, expected absent | trusted bind/token helper | retain hash only; plaintext returned once outside event |
| `credential.activated` | credential, session, exact prepared revision, first admitted request | host capability verifier | prepared → active in the first-use transaction, activate binding/revoke incumbent atomically |
| `credential.revoked` | credential ID, expected, reason | session end/revoke/remove | irreversible revoked state |
| `message.sent` | message ID, recipient ID, kind, body payload, refs, reply-to ID | `message.send`; supported F9 import | create message/inbox row; delivery pending |
| `message.delivered` | message ID, recipient ID, actual consumer/offer evidence ref | internal witnessed mail settlement | first delivered marker; no read claim |
| `message.read` | message ID, recipient ID | `message.read`, `message.ack`; supported F9 import | first read marker, remove from unread page |
| `message.dismissed` | message ID, recipient ID | `message.dismiss`; supported F9 import | first dismissal, no manufactured read |
| `message.superseded` | message ID, replacement message ID, expected | supported F9 import only | retain both messages and a relation; cannot change another sender's body |
| `decision.proposed` | decision ID, key, statement payload, optional prior proposal, kind note/decision | `decision.propose`; F7/F33 import | pending proposal, no activation from supersedes hint |
| `decision.ratified` | decision ID, expected, owner approval ref | `decision.ratify`; proven F7/F33 transition | active ratification, append decision chain |
| `decision.rejected` | decision ID, expected, reason payload | `decision.reject`; proven imported transition | terminal rejection, preserve proposal |
| `decision.retracted` | decision ID, expected, reason payload | `decision.retract`; proven imported transition | terminal withdrawal |
| `decision.superseded` | prior/replacement decision IDs and expected revisions, owner approval ref | `decision.supersede`; proven imported transition | replace governing decision atomically, retain statements |
| `turn.captured` | turn ID, agent/session ID, provider, native turn ref, role, text payload, lossless source path/offset/length/hash | `session.turn`, Claude hooks, Codex app-server capture; F14/F15 import | insert turn, advance captured source cursor only with complete bytes |
| `capture.source` | source ID, session, consent, native ref, expected | bind/adopt/import | establish source without reading an account credential |
| `capture.progress` | source ID, expected, source incarnation/digest, old/new byte offsets, last turn ID | completed capture transaction | advance monotonically only for verified same source incarnation |
| `capture.failed` | source/session, unchanged start offset, attempted end offset, typed code/cause/retry | authenticated harness capture | durable named failure without advancing past uncaptured bytes |
| `capture.suppressed` | source/session ID, expected, suppression reason, offset window, count | explicitly incognito/disabled capture; F16 import | record suppression as suppression, not success/absence |
| `process.registered` | process ID, project/agent/session, machine/boot IDs, native birth identity, executable and argv fingerprint, custody group, initial state | `process.start`, witnessed agent/runtime launch; F17 historical import | all nine section-30 states, explicit absent/unreadable root at scope preparation/import, recorded containment/cause; no live witness implied |
| `process.transition` | process ID, complete current identity/custody checkpoint, expected, from/to state, observation ref, outcome, recorded containment fact | inspect/stop and actual OS exit/re-adoption observation | CAS state; reused/unreadable process never becomes owned |
| `working_state.set` | agent ID, text payload, expected | `working_state.set`; F19 import | update head; absent and stale expected differ |
| `cursor.recorded` | agent/session, cursor purpose, opaque value, snapshot window, expected | explicit context presentation/settlement/capture progress | update cursor without hiding unread work |
| `cursor.acknowledged` | cursor ID/revision, authenticated consumer evidence | actual packet/context/mail acknowledgment; F19 historical import | mark that exact cursor presented/read; issuance alone is not ack |
| `effect.requested` | effect ID, kind, optional affected principal, target, safe immutable intent data, cause event, idempotency ref | init/launch/stop/send/remove's transaction | durable pending work, no OS/network call inside transaction |
| `effect.offered` | effect, principal, unique attempt, offer evidence | host delivery executor | pending → offered; offer is not recipient read or settlement |
| `effect.settled` | effect ID, expected, witnessed/failed/abandoned state, outside evidence or failure, attempt summary | host/harness actual effect readback | terminal effect state; only evidence can select witnessed |
| `integration.recorded` | integration ID, path/key/marker, prior/written digest, scope, readback ref, expected | init/doctor owned edits; successful removal update | retain exact ownership for reversal, never agent credential content |
| `backup.recorded` | generation, checkpoint/snapshot position, file identity/hash, schema version, readback ref | completed backup | record completed snapshot manifest, not a backup attempt |
| `import.started` | import ID, source identity/prefix digest, supported format/version, policy version | `store.import_node` | create resumable import run |
| `import.progress` | import ID, family/path, expected source incarnation/prefix, byte/row cursor, counters | committed imported chunk | advance cursor atomically with its imported events |
| `import.finished` | import ID, expected, totals/omissions, artifact refs | completed bounded source walk | terminal complete/partial report; unreadable never becomes zero |
| `import.unreadable` | import ID, source path/offset/length/digest, typed failure, retained source ref | strict import decoder failure | preserve bounded failure provenance, not copied secret source text |
| `legacy.retained` | source family/version, source identity/hash/offset, imported object mapping, immutable legacy bytes payload where needed | F7 user-law provenance import | retain historical provenance with no live grants/process custody |
| `turn.erased` | target event, erasure ID, original byte length, owner | owner forget | sanctioned captured-body erasure marker; vendor ref remains deduplicated |
| `message.erased` | target event, erasure ID, original byte length, owner | owner forget | sanctioned message-body erasure marker; recipient/marks remain |
| `erasure.requested` | erasure ID, explicit target event/field IDs, approved scope/revision, external residual-copy inventory | `store.forget` after owner confirmation | maintenance pending; freeze ordinary writers |
| `erasure.completed` | erasure ID, erasure manifest, current DB/WAL readback witnesses, residual limits | completed in-place cleanup/readback | erasure completion, stale cursor epoch bump |
| `recovery.recorded` | recovery ID, optional source StoreId, exact source artifact, target StoreId, selected backup, recovered ranges/gaps, schema policy and outside validation | successful explicit salvage/adoption | record degraded origin; never claim a complete history across gaps |

Internal event kinds do not add CLI/MCP operations. Read-only `status`, `history`, `resume`, `search`, `decision.list`, `doctor.inspect` and all Atlas queries emit no events. `runtime.up/down` do not append periodic liveness; they record only actual custody/effect boundaries. Failed unauthenticated calls and normal refusals are not events (the synthesized plan drops refusal history). Cursor persistence is a separate explicit capture/settlement action, not a hidden write by every reader.

## SQLite schema version 1

`application_id = 0x53454E47` (`SENG`), `user_version = 1`. This DDL is a design artifact; migrations will embed the approved bytes, not execute a Markdown parser. Every `*_data` table is an immutable component of an event. `payloads` owns content; `*_data` owns per-kind facts. The `facts` object in `aux_data` is a **closed typed per-kind versioned object excluding the envelope and payload bytes**, used for lower-frequency setup/import/effect facts; hot message/turn/decision/session/process/working-state/cursor records have typed columns. A projection may duplicate a small lookup key, not user text or an entire event serialization.

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
  CHECK((writer_mode='host' AND host_generation IS NOT NULL) OR (writer_mode='direct' AND host_generation IS NULL))
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
CREATE TABLE configuration(
  scope_key BLOB NOT NULL,
  key TEXT NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(scope_key,key)
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
CREATE INDEX decisions_state ON decisions(project_id,state,last_seq);
CREATE TABLE decision_chain(
  event_seq INTEGER PRIMARY KEY REFERENCES decision_data(event_seq),
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  previous_hash BLOB CHECK(previous_hash IS NULL OR length(previous_hash)=32),
  entry_hash BLOB CHECK(entry_hash IS NULL OR length(entry_hash)=32),
  erasure_id BLOB CHECK(erasure_id IS NULL OR length(erasure_id)=16),
  CHECK((erasure_id IS NULL AND previous_hash IS NOT NULL AND entry_hash IS NOT NULL)
     OR (erasure_id IS NOT NULL AND previous_hash IS NULL AND entry_hash IS NULL))
) STRICT;
CREATE INDEX decision_chain_project ON decision_chain(project_id,event_seq);
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
  family TEXT NOT NULL CHECK(family IN ('project','principal','configuration','session','message','decision','process','effect','integration','import-progress')),
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
  CHECK(sort_seq=CASE WHEN family='decision' THEN last_seq ELSE first_seq END),
  PRIMARY KEY(scope_key,family,entity_key,valid_from)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX list_versions_open ON list_versions(scope_key,family,entity_key) WHERE valid_to IS NULL;
CREATE INDEX list_versions_order ON list_versions(scope_key,family,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_state ON list_versions(scope_key,family,state,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_sender ON list_versions(scope_key,family,sender_id,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_recipient ON list_versions(scope_key,family,recipient_id,sort_seq ASC,entity_key,valid_from DESC,valid_to);
CREATE INDEX list_versions_recipient_state ON list_versions(scope_key,family,recipient_id,state,sort_seq ASC,entity_key,valid_from DESC,valid_to);
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

Every immutable table has both fixed triggers below. Projections and decision-chain rows are not independent authority; operation envelopes/member rows are immutable authority for retries and atomic recovery groups. These statements are the complete finite list, not an instruction to infer immutability from table naming.

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

The implementation embeds these complete fixed trigger statements in version-1 DDL; a new immutable table must add its own triggers in its migration. Kind/table correspondence, required payload field/ownership, ID kinds, permitted registry scope and enum-specific nullability are validated by the closed codec before INSERT and by the offline verifier after recovery. The stored body SHA is not authentication; the trusted core's bound authority authorizes the event. FTS is deferred: version 1 uses bounded indexed scope/time candidates plus streamed text matching and reports budget exhaustion. Adding an external-content FTS projection later must add an additive migration and erase its postings on forget; it may not copy full text into another authority.

## Atomic append, apply and idempotency

The sole write algorithm is `commit_group(connection, admitted_batches)`, using `append_atomic` for one savepoint-isolated operation and `apply` for each event. Direct writes pass a one-element group; the host passes its bounded group. Both invoke the same `TransactionEngine` interface; neither reimplements a projection. Pseudocode here specifies ordering, not permission to implement before approval:

1. Bound input validation outside the write lock: closed kind/version, sizes, ID/encoding shape, scope, no plaintext credentials. Core has already resolved labels and supplied verified authority. For RequestIdentity compute the store fingerprint from the core-produced canonical IntentDigest plus admitted scope/actor, as below; do not hash newly allocated event/body IDs as though they were caller input. Verify inline/staged payload integrity independently.
2. The store derives the writer stamp from its owned runtime lease (host generation or direct), never Admission.generation or Door. It selects FULL if any group member is a security event, reads the pragma back before BEGIN, then `commit_group` issues one `BEGIN IMMEDIATE`, then `append_atomic` creates a savepoint per operation and rechecks schema/incarnation and transaction preconditions. It never starts a nested BEGIN inside that group. Consult `(scope_key, actor_id, request_key)` only when the caller supplied an explicit key; public mutation requests always supply one. Trusted capture/marker catch-up may use request=None and deduplicate solely by its mandatory natural key. Same fingerprint returns the original committed first/last event and typed receipt without adding events. Different fingerprint refuses `idempotency-key-reused`. An erased fingerprint refuses `content-erased`; it cannot accept/recreate the original body or silently replay an uncheckable request. A failed uncommitted batch consumes no key.
3. Validate natural keys and resolve no-ops before allocating operation/envelope rows; check each genuinely new event ID for collision before insertion. Insert one operation envelope only if there is a new event or an explicit caller-supplied request key. A different operation cannot reuse it even with identical text. Resolve natural-key no-ops: a second delivered/read/dismissed mark returns the original marker; a duplicate vendor turn returns the original turn only after verifying equal body/source identity. Different bytes at a natural key refuse `natural-key-conflict`. No new domain event/marker is generated just to make an idempotency receipt. A caller-supplied new request key still receives a durable operation/member correspondence even for a no-op, preserving conflict detection. A newly captured keyless operation stores no retry key/fingerprint and has no operations_caller_key index entry; its atomic member map still exists. A derived/keyless all-no-op capture sweep returns a transient NaturalKeyReplay receipt without any INSERT: members retain input natural-key order, primary is the first original event and supplies its retained writer, first/last bound those original revisions and request_key remains None. They need not have belonged to one prior operation; this aggregate does not invent a durable operation ID or claim all members had one writer. Repeating Stop hooks cannot grow history indefinitely. Keyless writes are restricted to natural-keyed capture/marks, never unchecked configuration or arbitrary events.
4. Insert the envelope, store-owned writer/durability stamp, typed data and body exactly once. `apply(event)` checks the current projection revision/state and changes all affected projections, resume heads and pending effect debt. An operation with multiple events is all-or-nothing. Unknown kinds/versions, missing referenced rows, stale CAS, wrong recipient or invalid transition abort the **whole operation**, not just the final event.
5. Insert the ordered operation-member map (including reused natural-key events) and return an internal `PreparedReceipt`; this is not yet a committed reply. `commit_group` alone issues outer COMMIT under the selected NORMAL/FULL policy, then materializes public `CommitReceipt` values. A receipt reconstructs its exact event-ID list from that map; ordinal zero is the fixed primary event and supplies `primary_event`, `writer` and `durability`, while the operation row separately preserves the actual committer of a newly recorded caller-key alias. This preserves the original event writer even when a new host/direct route encounters a natural-key no-op. Wakes are deterministically reconstructed from original member events (affected project/principal/position), never the current dispatcher; replay may repeat advisory watch bumps but cannot repeat a delivery effect. Exact-key replay returns the original stamps/wake targets. Each member event retains its own stamp if a compound receipt contains pre-existing natural-key facts alongside new events; its first/last positions are descriptive bounds, never permission to treat every intervening event as a member. Only then release successful replies and the committed high-water notification. A reply/notification failure does not undo COMMIT; retry with the same key resolves it. No OS call, filesystem edit, network request, await or expensive transcript scan occurs while holding the transaction.

SQL statement failure and COMMIT failure are not interchangeable. Before COMMIT, rollback is definite. A lost connection/IO error while committing is reported as `commit-outcome-unknown` with the original request key, or the bounded natural event IDs/source checkpoint when keyless; the caller queries/retries those same identities rather than inventing another. Flush/drain preserves the distinction as PendingOperation::CallerKey or NaturalEvents, never an invented empty key. Shutdown/drain does not report success until accepted work has a definite result or an explicit indeterminate receipt. The store never stamps a projection/bell as witnessed just because append succeeded.

### Semantic fingerprint encoding

Core computes IntentDigest from the **closed admitted operation input before allocating IDs or planning events**. It is an internal value, never a wire/MCP field; the store/core share the in-process trust boundary, so store does not depend on higher-layer Op types or accept an untrusted client hash. AtomicBatch.request is either None for the restricted natural-key path or RequestIdentity { key, intent }. Core obtains the static operation name from its closed generated registry, never user text; store validates the supported intent codec version and bounded domain-label shape and never dispatches an operation by that label. The store does not duplicate the 59-operation registry.

For codec 1, core streams `SEINTENT\0v1\0` plus the stable operation name and canonical typed semantic input into SHA256. Object field names are closed ASCII sorted by UTF-8 byte order, arrays retain semantic order, integers use checked decimal encoding without floats, and strings use JSON control escaping without Unicode normalization. Public IDs supplied by the operation's caller retain exact typed wire spelling; native paths have tagged raw bytes; text becomes a streamed {bytes,sha256} descriptor. The trusted staging pass exposes byte_length/sha256 through StagedTextValue, so core need not reread/duplicate a 1 MiB turn. Input admission happens before hashing; aliases resolve consistently to IDs. Exclude request key, transport retries, sampled times and **all operation-allocated output IDs**, including new message/decision/session/effect IDs. Caller-supplied entity IDs, expected revisions, target/body/config values remain included. The same request can therefore retry after core allocates different candidate event/effect IDs without a false key conflict.

Store computes fingerprint = SHA256(`SEOP\0v1\0` + unambiguous admitted scope/actor encoding + static operation name + intent codec version + intent SHA256). This binds scope/actor independently of the trusted core input digest. Store still validates the entire resulting closed event batch, payload digests, references and preconditions; it does not reconstruct operation intent by hashing generated event bodies. operations.fingerprint_codec retains the supported codec identity. Same caller key/fingerprint returns original membership/stamps; different intent refuses before any planned side effects. The existing operation's codec must remain supported or return a named version refusal, never reinterpret its bytes. Erasure invalidates affected composite fingerprints so no body-derived digest remains. Keyless natural operations retain neither an intent digest nor a retry index entry; their collision/body rules are separate.

### Writer ownership, batching and durability

The host owns one write connection on one named blocking worker. It blocks on receive, then drains only already queued work up to 256 operations and the 2 MiB materialized group-byte cap. There is no gather window, gather timer or post-first-message sleep. Queue admission is capped at 256 requests and 1 MiB resident body bytes; large staged captures carry owned bounded references. A full queue immediately returns backpressure. Outer BEGIN/COMMIT is shared, each operation has a savepoint, and replies wait for outer COMMIT. Invalid members roll back independently; a poisoned connection, failed rollback or indeterminate COMMIT affects every unresolved member. This is section 80's protocol; S1's 250 µs/16 tuning is historical measurement only.

`CommitWait` is a Future that registers a waker without blocking; the async host awaits it or applies its own timeout. `wait_blocking` exists only for synchronous CLI consumers. Flush/drain return futures too; joining the worker happens on the host's blocking pool, never the current-thread runtime. A timed-out/dropped future does not cancel accepted work. Successful drain/join returns the unique maintenance HostStore retaining the Arc lease and its report; failure keeps admission closed and names any indeterminate keys. The worker retains the Arc lease until its SQL handle closes and thread exits.

A direct client holds a **shared** OS runtime.lock for its complete transaction/connection lifetime; multiple direct clients may coexist and SQLite BEGIN IMMEDIATE + finite busy_timeout serializes their writes. The host needs the **exclusive** lock and cannot start until all direct clients finish. A direct client does not mistake another direct client for a host or forward to a nonexistent endpoint. After shared-lock acquisition it validates store/version; an endpoint without a live exclusive owner cannot grant host authority. Direct invokes the identical commit_group with one operation, creates no persistent worker, does no per-command startup/shutdown backup, and leaves durable effects for the next host. OS custody always auto-starts/uses the host.

WriterMode is an opaque store-owned value with a read-only WriterKind view (`Host { generation }` / `Direct`), with no public constructor, Deserialize or input field. Event and operation rows persist writer_mode, nullable host_generation and durability with CHECKs. The commit engine alone constructs new stamps from its owned lease; CLI-through-host remains Host, and request Door remains independent. History reads the persisted event stamp. Import commits new Rust envelopes with the importer's actual writer and retains Node provenance separately. Salvage/rebuild copies valid historical stamps exactly; a missing/invalid Rust stamp is an explicit recovery gap, never inferred from the recovering host. The final new recovery event gets the recovering committer's stamp.

The fixed FULL set is: credential.issued, credential.activated, credential.revoked, session.activated, session.ended, session.revoked, project.registered, project.removed, principal.registered, grant.recorded, profile.saved, config.set, erasure.requested, turn.erased, message.erased, erasure.completed, recovery.recorded; and fresh store/header creation, recovery adoption and the migration user_version publication. Conservatively treating every profile/config event as security-sensitive avoids a caller-controlled field classifier. No untrusted durability flag exists. A mixed group takes FULL. Select/read back synchronous=FULL before BEGIN; only a successful FULL COMMIT may acknowledge those changes. Restore/read back NORMAL before the next ordinary group; failure to restore closes admission rather than silently changing the contract. NORMAL ordinary writes may be lost after OS/power loss; FULL security revocation cannot be acknowledged before its WAL sync. Replay reports retained durability, not the current policy. This boundary must be measured against B2/write budgets rather than waived by median S1 numbers.

## Recorded process, session and delivery facts

The store persists the same nine lifecycle states and complete transition table as accepted section 30 §3.1 (reproduced below). A prepared scope can lack a root PID/executable/birth identity. RootIdentityState distinguishes NoChildCreated, Unpublished (child/pre-exec work without a published complete root identity), Identified and Unknown; RecordedIdentity independently preserves Present(native ProcessInstance), Absent(reason) or Unreadable(cause). SQL stores all complete identity columns together or all NULL with an explicit cause. Identified requires Present; NoChildCreated/Unpublished require Absent; Unknown is limited to historical/lost records. Running and LeaderExited require Identified. Scope-only StopRequested/StopUnproved requires the exact reservation/scope/root checkpoint and stop-intent/attempt observation; Exited additionally requires the section-30 no-child/unpublished required-scope exit witness. None requires a guessed identity. A never-created scope's failed reservation can terminate with its exact reservation and failed-launch/no-live-scope observation. PinnedUnpublished retains its actual native PID/status inside the exit checkpoint without fabricating the missing ProcessInstance fields. Each transition carries the complete new ProcessIdentityRecord and expected revision; lifecycle/principal/session stay immutable. Once a full root identity is published it is retained through stop/exit/loss and must never be downgraded, replaced or relabelled NoChildCreated; recovery requires exact saved-identity/scope proof. SQL validates local shape; transactional apply validates this predecessor relationship and the closed native checkpoint/witness semantics. Leader exit alone never proves an empty scope.

NativeCustody format_version=1 is the closed se-proc checkpoint codec: a tagged UTF-8 JSON wrapper with variant reservation, scope (ScopeCheckpoint), root (RootCheckpoint), process (ProcessRecord), exit (retained source checkpoint plus StopWitness), failed-reservation (LaunchReservation plus failed-validation/native-error outcome, observation reference and explicit no-scope-created fact), or historical. Each variant carries exactly the accepted section-30 type's fields, tagged native path bytes/UTF16, lifecycle/principal/session, host/generation/nonce, exact scope identity/guarantee and explicit root publication state. Exit records preserve NoChildCreated, UnpublishedScope, PinnedUnpublished or Identified and the required-scope exit/status/observation. Failed-reservation is allowed only when no native scope/child was created; it retains that fact instead of fabricating the ScopeIdentity required by StopWitness. Unknown historical fields remain absent/unreadable. Record schema version is mandatory; unknown fields/versions refuse, integers are checked and no OS handle/address is serialized. The host adapter converts the accepted se-proc record at this boundary; se-store validates the versioned shape before insertion and never treats it as permission to signal. Indexed columns must agree with the checkpoint. Replay retains original checkpoint bytes; historical import cannot synthesize live custody.

ContainmentFact is persisted on process registration/transitions and session activation, with the session pointing to the exact lifecycle/fact that launched it. Known contained kind is cgroup (Linux), job (Windows), or process-group (macOS), observed time present, cause NULL. Linux uncontained requires observed time and exactly one cause: no-user-manager, no-delegation, cgroup-v2-absent, cgroup-unreadable, scope-create-failed; cause is never NULL. Unknown historical facts retain a reason and produce unknown/null with an explicit incomplete status, never inferred containment from the OS or today's probe. NotLaunched is distinct and renders the section-50 null pair for a never-launched session. Persist only the compact cause and optional probe observation reference here; full OS probe text is separate doctor evidence, not the user-facing cause code. The CHECKs enforce all combinations; the closed session JSON uses the same tagged union. A fresh read after restart renders these saved facts, with current OS observations reported separately.

The landed se-proc reasons map one-to-one into section 50: NoUserManager→no-user-manager, NoDelegation→no-delegation, CgroupV2Absent→cgroup-v2-absent, CgroupUnreadable→cgroup-unreadable, ScopeCreateFailed→scope-create-failed. These are the same five facts in ContainmentCause; no older helper/kernel/delegation enum survives at this boundary. Full native probe detail stays in doctor/checkpoint evidence rather than being substituted for the compact cause. Linux fallback tracks only its process group and cannot claim escaped descendants are contained. A later observation corrects a fact only through a new transition, never by rewriting launch history.

Credential issuance stores prepared, not active, with activation_deadline no later than issued_at+600 seconds. The trusted first-use verifier checks hash, session/process binding and deadline, then commits credential.activated and the required session activation/incumbent revocation atomically under FULL before admitting that first operation. Prepared never authenticates an ordinary call by itself; expired preparation fails without a timer, no owner fallback and no incumbent displacement. Revocation/expiry cannot reactivate. Historical imported credentials never become active.

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
| decisions / decision chain | proposed absent; transitions enforce table below and expected revision; replacement proposal/ratification must exist; append chain over canonical decision events only | compare both heads for supersession; import retains old byte provenance; no all-event chain or synthetic ratification |
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
| Erasure | absent → inventoried → approved → draining → content-erased/pending-cleanup → WAL/FTS-cleaned → verified → complete | failure freezes ordinary writers and preserves phase evidence; no successful tombstone-only shortcut; restart resumes exactly this erasure ID |
| Salvage | diagnosed → source-frozen → scanning → candidate-built → validated → owner-adopted | gaps remain explicit; invalid candidate never replaces source; ordinary open does not auto-adopt salvage |

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
| imported | import | Historical; cannot become live custody |

Stored read/disposition facts can be imported as historical states only when the Node row actually supports them. A bell offer, stdout flush, packet creation, launch readiness and task completion never substitute for one another.

## Bounded reads, snapshots and cursors

A read captures the committed maximum event position and store incarnation under one deferred read transaction. Backup-file inspection is a separate read API: snapshot its manifest/event metadata, release SQL, then inspect immutable owned files and report per-file observed/absent/unreadable facts; it does not pretend filesystem observations share a SQLite snapshot. Every row and head it materializes belongs to that snapshot; there is no read of a projection at one position and bodies at another. Reader connections are read-only, with `query_only=ON`; closing a snapshot releases its transaction even on decoder failure. Readers never rebuild, migrate, mark mail read or advance durable cursors.

All lists are keyset paged, with indexes beginning with authorized scope and relevant actor/recipient. Order is operation-specific: section 50 messages/inbox are oldest sent event first; decisions are oldest latest-transition-at-H first; raw history/replay/import is ascending, while recent-turn queries are descending. No shared default may override those public orders. No OFFSET scan or cold-cache full-file count is required for a page. Read at most `limit + 1` candidates plus a bounded byte budget. `ReadBudget` wraps the canonical se-types PageRequest and a finite deadline; it does not introduce a second cursor/limit/byte vocabulary. Full message listing yields only complete bodies that fit, with continuation before the first omitted item, and never appends read/delivered markers. Owner may inspect any selected-project message; session scope is sent-or-received by that actor. The extra candidate establishes `has_more`; exact omitted count is `None` when computing it would require an unbounded scan. Zero, absent and count-not-computed stay distinct. A rejected/undecodable candidate is not skipped into a deceptively complete page: return an unreadable error with the checked sequence/source or an explicitly incomplete window, preserving the continuation before that row.

An opaque page cursor encodes version, store ID/incarnation, fixed snapshot high-water position, query/scope fingerprint, order and last returned position. Its canonical binary form is version byte + 16-byte store ID + fixed-width integers + 32-byte query digest, base64url without padding; maximum 192 bytes. It is not a capability: the supplied authorized scope is rechecked for every query even with a syntactically valid cursor. Reject wrong store/incarnation/query/order, positions outside the captured window, overflow and unsupported cursor version. Newly arrived mail above the cursor's high-water is reported as outside this page's window and appears in a new inbox read; it is never silently hidden as “no unread mail.” An old high-water remains readable while records exist, except after an explicit erasure/recovery incarnation bump.

`Window` states from/to positions, returned count, byte consumption, completeness, omission reason/count if known and continuation. Row limit, bytes, deadline, unreadable row, feature unavailable and source rotation are different stop reasons. If the first full item cannot fit, return `read-budget-too-small` with the required bounded minimum; do not return a non-advancing apparently successful empty page. Previews explicitly expose body-incomplete; full `message.read` must obtain the full bounded body before core appends a read marker. Renderers clamp only at UTF-8 boundaries, never slice an encoded path as text. An exact-ID query returning no matching record is measured absence; adding a state filter can instead produce zero matches without implying the ID is absent.

`Snapshot` exposes typed queries for projects/principals/profiles/config, sessions and credential hashes, messages/inbox/marks, decisions (including typed exact ID), turns/sources, processes, working state, cursors/resume heads, effects/integrations, history/events, import progress and operation receipts. Shared text search is bounded over an explicitly scoped candidate stream; it reports incomplete when its scan budget ends. There is no arbitrary SQL/predicate callback API for kernel callers.

### Mutable lists at a cursor high-water

Current projections and their partial indexes serve fresh status/exact lookups. A first page may use that fast path only when its SQL snapshot high-water equals the chosen H; after later commits a cursor must use the temporal path, not current state for its historical filter. `list_versions` is a rebuildable, text-free temporal list index. Apply closes an entity's open interval with valid_to=S and inserts its new summary at valid_from=S in the same transaction as event S. Intervals are [from,to); exactly one is eligible when from≤H and (to IS NULL or H<to). sort_seq is the family's published order key: message sent_seq; decision last_seq for this version; first_seq for the other mutable families. A transition can change a decision's sort_seq in its new version without moving its old-H version. Every page selects the version at the same H before filtering or ordering, so later transitions cannot move items across that cursor. One event changing several entities creates one version per affected entity; source history can rebuild all summaries. Body text is joined through first_seq/last_seq, never copied into this index.

| Snapshot list | Historical candidate/filter index; materialization |
| --- | --- |
| projects / principals / configuration / sessions / processes / integrations / import_progress | list_versions_order on exact scope_key/family, ascending (first_seq,entity_key), validity predicate at H; first_seq + last_seq reconstruct the state at H |
| messages owner list | family=message, scope + order index, ascending (sent_seq,entity_key); immutable sender/recipient/kind and historical mark sequences in that version |
| messages sender or recipient | list_versions_sender / list_versions_recipient; sent-or-received is two indexed streams merged/deduplicated by entity key, never OR over the whole project |
| unread inbox | list_versions_recipient_state on exact scope/recipient/state='unread'; validity at H, independent of today's marks_unread partial index |
| pending decisions | list_versions_state on exact scope/family=decision/state='proposed', validity at H; this version's last_seq is sort_seq, ascending (sort_seq,entity_key), for all decision states including pending |
| pending effects | list_versions_state, merge pending and offered streams at H; principal-debt exact lookup uses effects_principal_pending |
| immutable turns / event or decision history | turn_data_agent_seq / events_scope_seq / events_session_seq and sequence≤H; no temporal index row per captured turn |

Temporal summaries exist only for listed mutable families, not every turn/event. MessageSent creates unread; delivered/read/dismiss/supersession close/append a summary preserving every marker visible at that time. Owner/sender/full-body message lists use the same as-of summary to populate marks. Decision transitions, project removal, agent rename, session/process/effect state, configuration/integration/import-progress changes all append corresponding versions. Exact non-paged reads use the new snapshot's actual H; caller membership/current authorization is revalidated on every page, so revocation overrides a historical window.

Canonical unread SQL uses `list_versions AS v INDEXED BY list_versions_recipient_state WHERE v.scope_key=? AND v.family='message' AND v.recipient_id=? AND v.state='unread' AND v.sort_seq<=? AND (v.sort_seq>? OR (v.sort_seq=? AND v.entity_key>?)) AND v.valid_from<=? AND (v.valid_to IS NULL OR ?<v.valid_to) ORDER BY v.sort_seq ASC,v.entity_key ASC LIMIT ?`. Bind H to both validity comparisons and the sort-key ceiling; the ASC/ASC keyset predicate follows sent_seq, then entity_key. Decision lists use the same predicate/order with their versioned latest-transition sort_seq; they never sort by proposed_seq. Cursor fingerprint binds family, filters, sort-key meaning and direction. Messages therefore return 01,02 at H=2; decisions with creation 1/2/3 and latest transitions 8/4/6 return B,C,A, while an older H retains each prior transition order. The query retrieves limit+1 eligible rows, then fixed-PK joins materialize their immutable owning events/payloads. No SQLite transaction is retained across CLI requests. Point reconstruction uses PK (scope,family,entity_key,valid_from), scanned in reverse from H to return the latest version≤H; direct ID reads never walk full entity history.

The shared temporal summaries are retained for Sol R3: current rows alone cannot reconstruct mutable membership/filters at H, including low-volume families. They are text-free, scoped and rebuildable; no per-turn version is added.

The matching indexes lead with scope/family/filter then the per-family sort key in ascending order, so EXPLAIN must show a SEARCH of that scoped index and no global event/mark scan or project-wide temp sort. Validity may reject historical versions; SQL's progress callback enforces the request's finite step/time budget. If this old window cannot produce limit+1 or prove exhaustion within budget, return read-incomplete with H/cause/remedy, not a successful empty/complete Page or a guessed next pointer. Only a known additional eligible row yields next. This does not pretend B7 is qualified for pathological old windows; measure latest 1M unread, state changes between pages and old-window amplification independently. An index mismatch is an implementation defect, not permission to ignore H.

## Migrations and version skew

Connection setup: confirm a regular owned state file in an owner-only directory through the host's filesystem custody service; open without following a final symlink, no URI paths from a remote input; validate `application_id`, `user_version`, store ID/incarnation and ready/maintenance state before queries. Wrong application ID, unreadable header, newer schema or configured synced/network storage returns a distinct error/remedy. A missing file is absent. An empty/truncated existing file is unreadable, not permission to initialize over it. Create uses a new exclusively reserved pathname and refuses collision; 16 KiB pages are set before first WAL activation. Hostless init uses create_direct under a shared runtime lock: construct a protected same-volume uniquely reserved staging DB, commit the complete schema/header under FULL, close/read back it, then publish with no-replace. Another direct initializer may race but cannot see partial schema or overwrite the winner; the loser receives store-already-exists and core reopens/re-resolves the winner's identities. Both staged data and destination parent are under the host filesystem-custody adapter. No host generation is fabricated and no daemon is required just to init. A lease with unknown StoreId is admitted only after measured absence for this bootstrap or for explicit unreadable-source recovery, never for ordinary writes; existing-store open must bind the actual StoreId.

Pragmas: WAL, NORMAL, `foreign_keys=ON`, `trusted_schema=OFF`, `mmap_size=0`, `temp_store=FILE`, bounded cache, `busy_timeout=5000`, 4 MiB journal-size target. Read back journal/synchronous/foreign-key settings; refusal to apply is fatal to write admission. Only an explicitly owner-approved migration/upgrade under the exclusive runtime lease performs forward migrations under `BEGIN EXCLUSIVE`. Version 0 is fresh creation, not an arbitrary SQLite importer. The explicit owner path is a diagnosed supported migration through existing doctor.repair (`se down` then `se doctor --fix`), or an explicit application upgrade action with the old host down; this adds no public operation/command. An ordinary host/auto-start/status never migrates: a supported older schema returns store-migration-required with the explicit owner upgrade remedy, distinct from too-new and unsupported-old. A maintenance-only HostStore may inspect/plan an older schema but cannot start a writer; migrate requires MigrationApproval binding the plan fingerprint, owner and ExplicitOwnerCommand/ExplicitUpgrade trigger. Before each migration take/verify a backup; apply additive DDL/backfill in explicit bounded phases, update `user_version` in the same final FULL transaction, then check integrity/foreign keys/version before ready. Version metadata outside SQLite is only a recovery hint, never authority over a contradictory database header.

A migration changing immutable rows drops only the named fixed immutability triggers inside its exclusive migration transaction, performs the versioned backfill, recreates the complete approved trigger set, validates it, then publishes user_version with FULL COMMIT. SQL rollback restores both rows and triggers; a crash before COMMIT leaves the old complete schema. No disable flag or permanent exemption leaks into a normal connection. Long staged migration phases modify only new/unpublished tables until the final exclusive transaction, never unguarded old authority.

Alpha migrations add tables/indexes/nullable columns or supported event readers; they do not reinterpret old tags or drop history. A migration needing a long replay opens a visible maintenance generation, writes to a new projection generation, validates it and atomically publishes; readers do not guess which half is current. A host can open a supported older header as a maintenance-only object to plan/migrate; it cannot construct a working writer or query missing projections until migration completes. Corrupt/newer/foreign headers return refusal without a HostStore. The exact old version range accepted by a binary is compiled metadata. Older binaries refuse write admission to a newer version and cannot “repair” it. Reader compatibility is also explicit, not assumed because SELECT happens to work. Unknown event body versions block a complete replay/read rather than being ignored. Only a negotiated rollback to a compatible Rust binary exists; no Node-format rollback writer is planned.

The runtime lease serializes old/new hosts and direct clients before migration. Database locks alone cannot protect a stale binary that releases its SQL transaction and writes later; each write rechecks version/incarnation under its transaction. A stale generation gets `store-generation-changed` and must reopen/re-admit. Restoring a backup or adopting salvage creates a fresh incarnation and invalidates cached positions/cursors, credentials and process-adoption assumptions.

## Backups, restart and salvage

Backups are SQLite online-backup snapshots, not copies of a live main file without its WAL. Normal first-session admission, writes/custody and re-adoption start as soon as the supported store is ready; startup backup is **after ready**. StoreFactory.backup owns one independent bounded read connection from the fixed reader allocation and begins one read transaction, reads the source header/H to establish its WAL snapshot, then holds that **same transaction for the whole copy** through SQLITE_DONE or abort. Check the 64 MiB abort condition before the first step as well as between steps. Copy at most 64 pages per step at background priority and yield for foreground work. This explicit stable snapshot prevents writes on the separate writer from restarting the copy; see [SQLite backup source-connection locking](https://www.sqlite.org/backup.html). It never takes the writer connection, drains the writer or gates first bind. A slow/failed backup names source/cause and retained generations through diagnosis; it cannot turn ready into a false backup success. A throwaway SQLite 3.46.1 measurement held H=1000 across 65 one-page steps while a second connection committed 65 inserts: backup max remained 1000, writer max reached 1065 and remaining pages decreased every step. This measures SQLite snapshot convergence only, not the future store's WAL-limit cancellation or runtime budgets.

The store-owned opaque BackupContext is cloned from WriterOwner.backup_context (or HostStore.backup_context for maintenance/shutdown) and passed to the factory. It shares private store/incarnation/generation-bound pin/cancel state with the writer, without globals, a new worker or a queued barrier. The factory validates context and exclusive lease against the source, atomically reserves the single pending-backup slot, registers its pin intent **before** starting the read transaction, then clears it on every return/error/unwind. start_writer/drain preserve that same context; a stale context refuses. While a backup pin is active, the commit-driven writer defers checkpoint work that cannot finish and **never returns store-backpressure because of backup WAL growth**, including at 16 MiB. Commit-driven auto-checkpoint work is suppressed while the pin is registered and restored to the 256-page trigger on release; this never waits on the reader. Existing commit/WAL accounting records backlog and sets the backup abort flag at **64 MiB WAL**. The backup checks the flag/deadline between finite steps, finishes/closes the backup handle, rolls back the read transaction and releases its pin on abort, then returns backup-failed with WAL-limit cause and retained generations. Checkpointing can then resume on normal commits. The threshold is an abort trigger, not a physical hard cap: already-running bounded steps/commit groups can overshoot. Foreign pinned readers are diagnosed separately after backup release; backup cannot be relabelled as foreign-reader backpressure. No retry loop or polling timer runs: automatic retry is **next start-of-day**, not another attempt in this run.

Keep two published generations and at most one owned pending generation. Each manifest carries store/incarnation, schema/application ID, the stable captured H, byte count, digest and validation result. No machine credential, launch secret or active endpoint is in a manifest; copied hashes are not live authority. Reserve the pending path exclusively; step the snapshot copy; release its source transaction/pin; close and independently reopen the destination read-only; validate integrity/FKs/version/captured H; sync owned files/directories where supported; no-replace publish and atomically update the manifest pointer. Remove the oldest owned generation only after publication. Failed/aborted owned pending copies never publish and retain both prior valid generations; cleanup removes only that exact owned pending artifact. The fixed source snapshot never restarts to chase new writes. Migration/recovery/erasure remain explicit maintenance barriers and require backup pin release/join. Shutdown drains/flushes, then makes its requested clean backup within the explicit deadline; failure is named, not called clean.

Normal open reads only header/version and indexed readiness metadata, not whole-history validation. SQLite WAL recovery preserves acknowledged process-crash commits under NORMAL; it is not a promise against OS/power loss. Security events use FULL as specified above. Recovery restores at an explicit owner action; backup credentials are revoked/inactivated on adoption and process rows cannot become live custody just because they were copied. New incarnation invalidates old cursors/leases before admission.

Salvage remains factory maintenance so an unreadable store need not first construct a normal HostStore. Freeze/preserve the source and its WAL, inventory readable operation/envelope/data boundaries, build a separate candidate through the same approved codec/apply, retain complete operation groups and original writer stamps, and report corrupt/unknown/dependency gaps. Never advance a claimed complete cursor across an unaccounted gap. Independently reopen/validate the candidate before explicit owner adoption; preserve original bytes and require sufficient additional space. If source StoreId cannot be read, source is None/unknown, target is a fresh canonical StoreId, and RecoveryRecorded retains exact source-artifact path/incarnation/offset/length/available digest plus target identity; it never invents a source ID. If a readable source ID exists, retain it and increment incarnation. Adoption is a guarded host-owned swap with handles closed, rollback copy retained until independent readback, and no automatic adoption on corruption. Unknown writer stamps in purported Rust events are gaps; Node historical facts enter through the separate importer with a newly stamped Rust envelope.

## Forget and content erasure

Prime's review decision adopts section 70 §6: owner-only, explicit captured-turn or message body event IDs with expected revisions; **in-place**, one content-erasure transaction, no whole-store rebuild. Decisions, reasons, configuration, identity and arbitrary legacy blobs are not public erase targets. EraseTarget contains only event/expected revision and implicitly selects Body; SourceDigest is internal dependent metadata, never a separate user-selectable arbitrary field. Keep event identity/actor/time/vendor ref and original byte length, remove plaintext and body-derived hashes. Source artifacts, automatic backups and raw-media remnants are named residuals rather than silently deleted. FTS is absent in v1; if later added, the same operation must remove/optimize its postings before completion.

Limit one request to 60 explicit targets so its audit batch stays within the 64-event bound; larger selections use separate explicit operations. Estimate extra WAL/dirty-page space from those targets, with bounded streaming buffers rather than whole-store replacement space. The factory erasure_plan uses an independent scoped reader while the writer is live, so inventory/owner confirmation does not freeze ordinary work; erase rechecks every target/revision after drain. Before mutation inventory the target owning payloads/source digests, affected operation fingerprints, host render/search buffers and owned staging, WAL and known backups/provider/import originals. Drain consumes/deletes accepted staging by exact custody identity; any remaining owned orphan that cannot be safely removed is explicitly named as a residual, never ignored. Approval binds owner, expected incarnation, exact target revisions and acceptance of named residuals; only an owner outside agent process trees can supply it through core. Drain/join the writer to obtain the maintenance HostStore. Block new writes through this maintenance phase; close owned readers and require bounded checkpoint access, while a foreign owner's direct SQLite reader can still make the checkpoint busy. That is an explicit erasure-incomplete outcome, never proof old pages disappeared.

Register private read-only, innocuous SQLite connection functions (so trusted_schema=OFF remains enabled) se_erase_body_allowed(event_seq,field) and se_erase_operation_allowed(operation_id), returning zero on every ordinary connection. Only the exclusive, owner-approved erase connection enables a finite in-memory exact target/operation set for its transaction; there is no SQL table, environment flag or remote input that enables it. The callbacks expose only membership in nonsecret ID sets, perform no SQL/IO or state mutation, are audited for information leaks before INNOCUOUS registration, and are not marked deterministic because the connection guard changes between transactions. [SQLite function flags](https://www.sqlite.org/c3ref/c_deterministic.html). The DDL's payload/message/turn/operation trigger predicates allow only: detach the approved body ref; null that turn's derived source hash; delete its owning payload; invalidate fingerprints of operations whose members depend on that erased field. Every other column must compare unchanged. Event/envelope/member/history deletion stays prohibited. The connection-local set is cleared on success, error or rollback; normal statements never disable triggers.

With secure_delete=ON read back, begin a FULL transaction. Recheck target revisions/type and identity of the sole owning payload; append erasure.requested, detach body refs/delete payload rows and hashes, record erased_fields with original byte length, append turn.erased/message.erased for each target, null/mark every dependent operation fingerprint, and bump incarnation. Update/rebuild affected bounded search/summary caches and mark store erasing. COMMIT atomically; a rollback retains the original complete bodies and audit state. No original text/hash is put into the audit event/manifest. Re-capture hits the preserved provider/vendor natural key and returns Erased, never re-inserts the body; a retry key with an erased fingerprint returns content-erased. An erased natural key never accepts replacement text or claims byte equality after its digest was removed: it reports that existing record as erased and suppresses re-ingestion regardless of incoming text.

After COMMIT, remove/optimize any future FTS segments, checkpoint(TRUNCATE), and independently verify the exact erased bodies are absent from database/WAL bytes and queries, using streaming bounded-memory reads, with user-visible scan cost. Secure deletion is not physical SSD or filesystem-snapshot sanitization. A pinned reader/busy checkpoint or failed readback leaves erasing/pending, returns cleanup_complete=false plus the committed target facts/residuals, and names the owner remedy; it cannot claim full completion. A subsequent explicit owner resume finishes this finite cleanup without re-erasing or resurrecting content. Only after readback append erasure.completed under FULL and return completed_event/cleanup_complete=true. The small completion transaction contains no old body pages. Reader generation checks refuse old cursors rather than pretending their prior content still exists.

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


## Node import mapping (all contract families)

Import is an explicit owner operation, streaming and resumable, with the source read-only. The importing adapter decodes Node formats into the same closed event batches; it cannot run Node code, copy credentials to become an owner, or insert directly into projections. Use the inventory's F1–F37 boundaries rather than every historical filename as a new protocol. Source identity includes canonical file identity, format/version, byte prefix digest and cursor. A changed source incarnation/prefix refuses resume; an unchanged appended suffix may be imported under the same run. Distinct files containing the same source event map to the same typed object/event, not duplicate conversation turns.

Legacy-to-storage-key mapping is created transactionally on first use in `identities` and its import provenance retained in `legacy_ids`; it is never a hash truncated without collision checking. The public typed ID keeps the exact accepted legacy spelling, rather than exposing a replacement UUID. Existing references therefore round-trip through the CLI/MCP wire without converting historical identity. Message refs, decisions, session/conversation links and supersession links resolve through that mapping, including cross-file forward references staged until their dependencies exist. Stable origin references retain exact source row/byte/hash evidence. Import checkpoints commit only with their complete imported operation batches. Bad rows generate bounded `import.unreadable` provenance and visible omissions, never a success count of zero. Importer decisions are versioned in the run policy; a future rerun cannot silently change a prior drop decision.

| Family | Import / retain | Explicitly not restored as authority |
| --- | --- | --- |
| F1 projects | registration revisions/IDs, roots, owner and tombstones → project events; preserve source provenance | live host/machine defaults, stale grants inferred from labels |
| F2 humans | owner/human identity and declared historical permission facts → principal/grant history | old seed possession or copied machine credential as current owner proof |
| F3 agents | IDs, display names, roles, owner, supported explicit grants; imported aliases as lookup data; creator only when a verified source event actually records it | alias creation API; guessed creator from owner/name; dead session authority |
| F4 manifests | registered roots, typed product configuration/capture declarations | campaigns, gate/runner/factory blocks, engine-root defaults |
| F5 launch profiles | Claude/Codex provider/model/permission profiles, original conversation refs and supported settings | fleet coordinator/machine paths; implicit bypass defaults; obsolete provider forks as supported stock integrations |
| F6 init profile | setup identities/roots and local configuration values as provenance/defaults after owner validation | treating home defaults as a capability or overwriting an existing repo |
| F7 event ledger | decisions and user identity history as typed events; retain exact legacy ledger bytes/head/validation evidence in owned payloads when needed for old law provenance | all-event Rust hash chain; replayed refusal/factory policy as product work authority |
| F8 indexes/Markdown | rebuild equivalent projections from F7; preserve explicitly user-authored material as source artifacts if not derivable | index/Markdown as governing authority; Node repair sidecars |
| F9 messages | bodies, IDs, refs/replies, actual read/delivered/dismiss/supersession history → message/mark events | bell offer as read/task completion; duplicate mirror/retry rows; factory completion vocabulary as new product operations |
| F10 inbox caches | no data import; rebuild from message authority and compare counts within the import report | SQLite cache generations/partial-cache absence claims |
| F11 capture bindings | provider/native conversation mapping and ended historical session bindings | live binding/session grant from a raw session string/window marker |
| F12 capabilities | retained historical issuance/revocation metadata only if user history needs it, with secret hashes redacted from imported authority | no active capability or reusable old secret |
| F13 launch/local tokens | preserve historical lifecycle references, not token bytes | all old active launch/local bearer authority |
| F14 turns/raw logs | attributable original text, role, native turn ref/session/provider and source evidence → turn events; deduplicate repeated exports | executable-basename/session-filename attribution guesses |
| F15 capture spools/receipts | verified pending user turns through normal bound import policy; pending/rejected/suppressed facts and exact unreadable windows in report | a sent receipt as captured text; retention/projection-drain machinery; advancing beyond an unaccounted spool record |
| F16 incognito/suppression | consent/suppression history and explicit capture-disabled state | importing a suppression-owner token or attributing suppressed text that was never captured |
| F17 process lifecycle | historical process facts with native identity evidence | live process adoption, stop authority or reused PID claims; all imported instances are historical |
| F18 runtime/owner receipts | historical user-visible launch/stop/outcome references where needed by retained conversation/stop handles | active runtime lock/endpoint/generation, owner lease, periodic organ receipts |
| F19 continuity/working state | working text, supported saved conversation/stop references, explicit presented/read packet/cursor facts | factory lane/campaign packet sections, a created packet as read acknowledgment, stale overwrite authority |
| F20 local HTTP token | none; new product mints/protects its credential separately | all token bytes; never copy them into the new DB/history/report |
| F21 key/PG stores | human-readable historical ownership/member references if needed; owner rebinds through new product | signing/private/member/PG passwords; no bundled PG or old trust topology |
| F22 backend transition records | source provenance sufficient to choose the actual authoritative family/window; unresolved transitions are an explicit import blocker | current files/postgres selector, dual-writer state or Node transition locks |
| F23 Postgres floor/capture | supported durable user events exported by a separately authenticated reader into the same importer with source identity; preserve IDs/cursors/provenance | database credentials, Zero replicas/caches, running multiplayer backend; no PostgreSQL client in se-store |
| F24 Claude host configuration | ownership manifests/digests needed to migrate/remove verified owned entries; integrate through host's readback plan | copy/overwrite of unrelated config or embedding old bearer/header secrets |
| F25 Claude hooks | supported ownership markers, prior/written digests and supported capture source mapping | executing old hook commands, broad settings overwrite, baked agent identity |
| F26 Codex TOML | owned marker/table evidence for safe migration, provider conversation refs | unrelated TOML/account data, stale user MCP credentials |
| F27 Codex hook/trust | historical source/ownership evidence and supported transcript refs | fork-only hooks, copied trust as current consent; managed stock Codex uses app-server |
| F28 Claude plugin/store | historical actual offers/settlements tied to imported messages when verifiable; owned install evidence | per-seat Node door, plugin credential/state as current session authority |
| F29 vendor stores | read supported transcript/native thread references only through harness's consented reader; preserve native accounts/files | account credentials, `.credentials.json`, Keychain, `auth.json`, deletion/export of provider accounts |
| F30 SE Code artifacts | compatible context identity/conversation/working-state provenance and read acknowledgment evidence | active service/session pin, copied protected config/capabilities or old packet as new binding |
| F31 terminal envelopes | historical custody/launch references if needed by stop/resume history | active one-use envelope, secret environment, live terminal ownership |
| F32 remote topology/mail | retain supported message/history and source machine references as historical data | remote compute/member/SSH runtime, active remote capability/cursor or fleet default |
| F33 memories | note/decision proposals plus original author/time/tags/refs; preserve ratification/rejection/retraction only when original human evidence proves it | optional memory engine/decay/suggest API or automatic ratification |
| F34 checkpoints | list/reference original stores as preserved external user artifacts; retain applicable history pointers | interpreting encrypted ENV secrets; restoring STATE over product history; importing checkpoint CLI/engine implementation |
| F35 release/build metadata | source version/commit/build custody in import/recovery provenance | install stamp as running-host identity or rewriting the installed release |
| F36 locks/temporary/backups | inventory retained recovery artifacts and their ownership; pick verified complete authoritative source, record omissions/conflicts | leases/locks as current ownership, deletion of foreign/linked files, incidental temp names as stable APIs |
| F37 factory records | report exclusion and retained original location; no product import | campaigns, reviews, landings, routing, gates, mutation/census/queue state and operator defaults |

Import never deletes originals, provider accounts or user work. Retaining an external source means forget must report that source as a residual copy; import receipts do not promise ownership over it. The plan drops full fleet import, Node rollback exports and multiplayer; those are not secretly reintroduced through “generic import.” A missing supported native conversation reference yields an explicit unsupported/missing resume fact, not a fresh conversation called a successful resume.

## Error catalogue

The error type carries the stable code, typed offending entity/range/revision, cause and an actionable remedy. Adapters map it to the shared `SeError` envelope; no SQL string, credential, turn body or raw account path leaks into a default message. Preserve IO/SQLite extended causes for redacted diagnosis. Expected absence is a `Read` value, not a generic error. Retryability never means “retry with a new idempotency key.”

| Code | Cause / typed detail | Remedy |
| --- | --- | --- |
| `store-absent` | read/direct open found no state file | run owner `se init` for the selected state home |
| `store-already-exists` | exclusive create/no-replace publication found existing state | reopen the validated existing store and reuse its identities; never overwrite |
| `store-unreadable` | permission, malformed/truncated header, undecodable row or IO error; source/range preserved | restore access or inspect with doctor; do not initialize over it |
| `store-application-mismatch` | application_id belongs to another database | select the correct home; never migrate the foreign file |
| `store-too-new` | user_version above binary's supported range | install a compatible newer binary; old binary stays read/write refused |
| `store-migration-required` | supported older schema; ordinary host/status/auto-start cannot upgrade | owner runs se down, then se doctor --fix with the reviewed plan; explicit upgrade likewise requires old host down; no implicit daemon migration |
| `store-version-unsupported` | older version/event/cursor codec outside supported range | use the named supported migration/import version |
| `store-not-ready` | creating/migrating/recovering/erasing or failed maintenance phase | finish/resume the named owner maintenance operation |
| `store-generation-changed` | incarnation/schema/generation changed after admission | reopen and re-admit using a fresh scope/cursor |
| `store-location-unsafe` | non-owned/linked/unsupported network or synced state location | choose a local owned per-user state directory; preserve original data |
| `store-pragma-refused` | required WAL/NORMAL/FK pragmas do not read back | correct filesystem/build support; do not admit writes |
| `store-busy` | finite SQLite lock deadline expired | wait for named writer/maintenance; retry the same operation key |
| `store-backpressure` | queue request/byte bound or non-backup pinned-reader WAL high-water reached | await outstanding work or release the diagnosed reader/checkpoint, then retry same key; never blame a backup pin or spawn another writer |
| `store-writer-closed` | runtime writer drained/stopped before acceptance | reopen the current runtime generation and resubmit same key |
| `commit-outcome-unknown` | IO/connection/reply deadline cannot prove COMMIT outcome | inspect/replay the original operation key before any replacement work |
| `idempotency-key-reused` | same scope/actor/key with a different semantic fingerprint | recover the original arguments or choose a new key for an intentionally new operation |
| `event-id-conflict` | event ID already belongs to another operation | preserve that event; repair caller ID generation/request reuse |
| `natural-key-conflict` | turn/message/source identity repeats with different bytes | inspect original/refused source evidence; do not overwrite |
| `revision-conflict` | expected absent/revision differs from committed head | reread that entity and decide again |
| `invalid-transition` | transition not in the closed state machine or missing prerequisite | use the legal state/operation named in the error |
| `reference-missing` | required same-scope entity/event absent | supply/import the prerequisite, or report the original operation incomplete |
| `scope-mismatch` | event/reference/target does not match admitted scope/actor/recipient | rebind to the correct session; labels cannot override authority |
| `creator-control-refused` | current create grant or immutable direct-created relation missing | use owner control or the actual authorized creator; no descendant/bulk expansion |
| `event-invalid` | unknown kind/version/enum, malformed typed field or forbidden registry event | use the current generated input/schema; no partial insertion |
| `body-too-large` | body/ref/batch exceeds its documented bound | reduce/chunk the source using the supported capture contract without advancing past uncaptured bytes |
| `projection-inconsistent` | expected projection/head/count disagrees with authoritative material | stop mutation and diagnose; explicit replay/recovery, never catch-and-empty |
| `cursor-invalid` | wrong version/store/query/order or invalid bounds | start a new explicitly bounded read |
| `cursor-stale` | erasure/recovery changed incarnation | restart the read and acknowledge the changed history window |
| `read-budget-too-small` | first complete item cannot fit | retry with the stated bounded minimum or explicit preview |
| `read-incomplete` | row/byte/time/source budget ends with more possible data | follow continuation or increase the named budget; retain incomplete flag |
| `source-changed` | transcript/import source incarnation/prefix differs | register/review a new source incarnation; never advance an old cursor |
| `migration-failed` | DDL/backfill/validation failed under maintenance | retain source/backup and resume the named migration with compatible binary |
| `backup-failed` | snapshot, sync, validation or owned rotation failed | retain prior generations; inspect source/destination/free space and retry |
| `recovery-incomplete` | salvage contains gaps/dependency exclusions | inspect the exact gap manifest and explicitly choose recovery or another backup |
| `content-erased` | requested body/key was explicitly forgotten | use the erasure receipt/retained metadata; never reconstruct it from an old owned copy |
| `erasure-incomplete` | owned copy/reader/buffer cannot be replaced or acknowledged | finish the named phase/custodian before claiming completion |
| `erasure-external-copies` | known vendor/import/export/snapshot copies outside store custody remain | act through those owners or accept a precisely scoped result; no automatic foreign deletion |
| `erasure-physical-guarantee-unavailable` | requested raw-media guarantee exceeds logical store custody | use an approved encrypted-storage/media-erasure workflow; this store cannot attest it |

These are store-domain cause codes (`StoreErrorCode`), not a second transport envelope. The global section-50 adapter must retain the exact cause/remedy/detail and map existing shared equivalents (`StoreAbsent`, `StoreUnreadable`, `StoreTooNew`, `StoreBusy`, `RevisionConflict`, `IdempotencyKeyReused`, `CursorInvalid`, `CursorExpired`, `BackupFailed`, `ForgetIncomplete`, `GrantRequired`) where semantics match. Remaining distinct causes above are proposed additions to the shared code catalogue at design integration, especially commit-outcome-unknown, generation-changed, backpressure and partial recovery/erasure. They must not be silently mapped to success or an undifferentiated Internal. `StoreError` reuses the shared typed Remedy/Retry, boxes the area-specific error result, and preserves typed version/conflict/request/source/budget/maintenance detail. Consolidating these additions with Iris's global catalogue is an explicit cross-area review requirement before implementing its conversion; it does not require another store error envelope.

Decode, FK, constraint, invariant and IO failures are never all flattened into busy/conflict. A constraint is mapped to a domain conflict only when its fixed constraint name and checked precondition identify that case. Any other constraint failure is integrity/internal failure with cause. Logs redact payloads/credential bytes by construction; diagnostic support bundles carry counts/IDs/ranges rather than text.

## Platform and resource contract

The storage algorithm and schema are identical on Windows, macOS and Linux. Only owned-file creation/replacement, lease/peer proof and directory-sync semantics use the host's platform custody adapter. Windows must close all old SQLite/backup handles before replacement and use the owned atomic replacement API; a sharing violation is a real failed phase, not success after deleting a pathname. Unix directory fsync/readback protects published names; macOS and Windows durability caveats remain within NORMAL's documented OS/power-loss boundary. No PowerShell, shell spawn, bundled Node or process-name stop appears in the store. Platform path bytes are preserved as tagged lossless values. The store is not allowed `unsafe`; `se-proc` alone owns unsafe platform code.

A configured network/synced location refuses by explicit configuration/path classification supplied by the host; path heuristics cannot prove that an arbitrary mount is safe. Unsupported/unknown storage semantics are a named limitation, not a claimed successful qualification. All temporary/backup/recovery files are in the same owned state volume for atomic publication. Free-space checks estimate the **additional** live replacement + two backup generations + retained source/WAL needed for recovery/erasure; insufficient space refuses before copying, with checked required/available bytes (unknown space is not zero).

Budget allocation within the 30 MB embedded envelope: target <=8 MiB store steady RSS and <=10 MiB normal peak for normal message/turn operations, including one 2 MB write cache and two lazy 2 MB reader caches (section 80 cache_size=-2000 each), bounded queue/staging buffers and decoded page material. No connection per session. Reader pool limit is two, with one materialized result budget per borrower; oversized capture text is staged/streamed rather than multiplied through queue copies. Backup/recovery/erasure are explicit maintenance with bounded buffers and visible resource costs; they must not starve the host's runtime or run idle workers. Startup open/header/version check targets section 80's 4 ms allocation within the <=100 ms budget including the first bound session; backup/re-adoption run after ready and never block the binding transaction. Idle store worker blocks without timers; no polling or WAL watcher is necessary for in-host commits.

Storage target is <=1.4 KiB/event on the unchanged S1 825k-turn/100k-message/75k-marker composition at 1M, with complete source/body equality independently verified. A schema-only remeasurement addressing the review's 1,527 B/event result uses its 100k turns/200-byte bodies, 16 KiB pages and time-ordered keys: the corrected canonical/caller-key schema is **1,265.50 B/event**. Remove canonical identity dictionary rows (derive kind prefix from UUIDv7 bytes), eliminate the redundant turns projection (indexed owning turn_data suffices), and make the retry-key index partial. No body is omitted or compressed. A separate all-legacy EventId fixture with the actual keyless natural-capture policy is **1,390.18 B/event**; that is a different retry-key policy, not an apples-to-apples legacy overhead comparison. A scaled unchanged mix (82,500 turns +10,000 messages +7,500 read marks, 200-byte turn/message bodies, caller keys on every operation and all temporal indexes) is **1,356.43 B/event**. These are raw SQLite 3.46.1 schema fixtures adapted from Opus's sizing script with foreign_keys disabled, not a production writer/import/recovery implementation or full 1M/native qualification. They include commit stamps, reverse lookup and temporal indexes; WAL was checkpointed and backups are separate. Full product acceptance still measures its actual bodies, metadata, imported IDs and backup/WAL costs without hiding them. The sizing scripts/databases are external throwaway measurements, not product source or an author test suite.

Warm 1M inbox target <=6 ms in-host/<=20 ms whole CLI, with an indexed 50-message page; no full history scan. Section 80's CLI-read p95 <20 ms and measured hook/write burst targets remain **unproven by this design**: NORMAL measured 3.14/72.15 and 3.42/19.21 ms p50/p99 at 20-agent bursts, with worse later tails. Queue/window tuning alone did not establish the tail. Build acceptance must measure signed native Windows with Defender, macOS and Linux; a median win does not establish the required p95/burst budgets. Checkpoint work is commit-driven on both host and direct connections via SQLite auto-checkpoint at 256 16-KiB pages (4 MiB), with TRUNCATE on clean shutdown. There is no scheduled PASSIVE worker or checkpoint timer. journal_size_limit is a reuse target, not a hard WAL cap: if non-backup pinned readers prevent checkpoint and WAL exceeds the 16 MiB high-water, reject new ordinary writes with store-backpressure, identify the pinned-reader condition, and retry only after reader release/checkpoint; never delete a live WAL. During a backup pin, defer checkpointing and keep accepting writes; at 64 MiB abort/release the backup and retry next start-of-day as specified above. A security revocation must not be silently dropped for this pressure: close agent admission and report a FULL commit failure if it cannot be persisted. A busy checkpoint reports backlog and yields; it never blocks a query indefinitely or reports a fully flushed WAL when frames remain.

A patched bundled SQLite must be shared with SE Code and avoid the documented WAL-reset defect (fixed in 3.51.3, with 3.50.7 backport); dependency/link versions are workspace coordination, not a private second SQLite build. The implementation must validate `cargo tree -d`/links compatibility at integration. [SQLite synchronous semantics](https://www.sqlite.org/pragma.html#pragma_synchronous), [WAL-reset advisory](https://www.sqlite.org/wal.html#walreset).

## Journey trace and reviewer acceptance

Authors add no tests. These are the externally observable obligations for the independent journey owner/reviewers, not a new suite or gate implementation.

| Journey | Store paths actually exercised | Observable proof / failure boundary |
| --- | --- | --- |
| J1 Install | correct per-user home, application/version negotiation; read-only status/version do not create state | fresh install identifies its own binary/store support, not enclosing Git; wrong/newer store refuses with remedy |
| J2 Adopt | registry/principal/profile/grant/integration events, existing-repo registration, session binding, capture and real agent output | existing files/Git untouched; committed task/turn read back by event ID; owner/session binding and safe defaults retained |
| J3 Come back | restart WAL recovery, saved native conversation, source cursor, working state/resume heads and explicit cursor ack | same native conversation and actual recalled work; no synthetic fresh thread, missing capture reported; NORMAL acknowledged writes survive process kill |
| J4 Two agents | message send/inbox/read/dismiss, exact key replay, effect delivery, creator relation/current grant, bounded windows | second agent receives/reads actual message and responds; recipient witnesses distinct; creator can control only its direct helpers; incomplete pages never appear empty/complete |
| J5 Remove | owned process/integration effect references, credential revocation and project tombstone, clean backup/stop | exact outside stop/reversal witnesses; provider accounts/repo/history preserved; no active lease/token silently left; failed cleanup named |

Reviewers additionally exercise crash boundaries unreachable from a happy journey: pre-/mid-COMMIT/savepoint/backup rotation/migration/swap, duplicate and conflicting keys, stale revisions/versions/cursors, foreign actor/recipient, direct-host lease race, corrupted/unknown body versions, salvage gaps and failed erasure custodian. No in-process hostile caller/injected fake reader is a process-boundary security claim. Measurements and independent readbacks must be bound to implementation bytes later; this design/compilation is not platform or durability qualification.

## Open questions and implementation admission

1. Shared `se-types` and process declarations are consumed directly from the accepted rust-se main base, not copied into this crate. StoreId, all kernel IDs, Page/Window/PageRequest and native process/path types are reused, not recreated. Store-specific records/traits live here; wire DTO/auth ownership remains with their assigned crates.
2. Prime resolved forget scope to section 70: live captured-turn/message bodies, in-place secure deletion and honest residual copies. Physical/third-party erasure is outside the supported claim; it does not block the approved narrow operation.
3. Section 80's p95 read/startup/burst budgets govern; the write tail remains measured and must be set by Jimmy rather than invented as an already passed hard per-write 20 ms guarantee. NORMAL is ratified here; neither disabling durability entirely nor early acknowledgment is authorized. Native measurements may require scheduling/checkpoint changes, reviewed against this same commit/receipt contract.

4. The section-50 global code catalogue must integrate the distinct store causes listed above and its exhaustive typed mapping; do not implement a catch-all Internal conversion while that integration is pending.

5. The strict shared ID namespaces reserve some names that Node accepted as projects or custom identifiers. Those collisions must remain visible import refusals with original provenance until an explicit identity-correspondence policy is approved; neither a broad arbitrary-string decoder nor a silent public-ID rename resolves the conflict.

Store payload records have no Debug derivation; diagnostic code handles only redacted IDs/ranges. The critic, 5c, Otto and Alpha's Rust reviewer assess this complete design/craft candidate; Prime integrates it. Only a later explicit implementation admission activates the signatures and DDL as product code.

## Method contract index

This index binds the following declarations to the algorithms above. All methods return the exact typed error/absence/window distinctions already specified; none is a convenient catch-and-empty wrapper.

| Trait / functions | Preconditions, effect and completion |
| --- | --- |
| StagedTextValue.byte_length / sha256 | metadata from the same protected staging pass, available before canonical input hashing without duplicating body bytes |
| RecordIdentity.from_parts / from_bytes / as_bytes | explicit caller time/entropy or checked UUIDv7 bytes for internal RecordId; reject wrong UUID version/variant and timestamp overflow; no clock, RNG or authority lookup |
| WriterModeValue.kind | read-only view of the opaque retained stamp; no public construction or input deserialization |
| RuntimeLease.identity | host's held filesystem-custody lease identity; unknown store only for witnessed-absent owner bootstrap or owner maintenance of an unreadable source; no lock acquisition by reading an endpoint |
| StoreFactory.open_reader / open_direct / open_host | validate existing header/version/path/role; missing → Read::Absent, foreign/newer/corrupt → typed unreadable/refusal; direct requires shared lease, host exclusive; supported old host is maintenance-only and ordinary caller receives store-migration-required |
| StoreFactory.create / create_direct | exclusively reserve/publish a new path under host-exclusive or owner-bootstrap shared lease; caller-supplied StoreId; full DDL/header validation; never overwrite existing bytes |
| StoreFactory.recovery_plan / build_salvage / adopt_salvage / restore_backup | owner maintenance over explicit owned paths even if no readable store exists; preserve source, validate candidate, swap only after approved gaps; fresh incarnation/identity rules apply |
| ReadStore.info / snapshot / credential | header metadata; finite scope-bound snapshot; trusted pre-auth hash lookup returns only credential/session metadata and cannot obtain history or manufacture an authority |
| ReadStore.inspect_backups | snapshot manifest metadata, then separately inspect bounded published files; each item's absent/unreadable/current observation is explicit; never a live-DB filesystem copy |
| TextStaging.stage_text | bounded owned stream to protected staging under held lease; UTF-8/length/digest checked; opaque handle has no caller-path constructor; used/failed staging is reclaimed by exact identity |
| DirectStore.append / close | one-element canonical commit_group under direct-client lease; success only after COMMIT; close releases handles before lease release |
| HostStore.start_writer | consumes the ready HostStore, retains Arc lease, independent of background startup backup; yields unique control owner and cloneable bounded submission handle |
| HostStore.migration_plan / migrate | explicit owner/upgrade approval bound to plan fingerprint, maintenance-only supported old store; drain/join and close snapshots; verified backup, temporary transactional trigger recreation, FULL version publication |
| StoreFactory.backup / HostStore.backup_context / WriterOwner.backup_context / HostStore.checkpoint / close_clean | opaque shared pin/cancel state; whole-copy fixed read transaction, 64 MiB abort rather than backup-induced write backpressure; background rotation without writer drain; checkpoint/close require the drained maintenance object; close_clean drains and reports backup failure truthfully |
| StoreFactory.erasure_plan / HostStore.erase | exact target/revision inventory then approved in-place transaction and witnessed live DB/WAL cleanup; narrow approved body UPDATE/DELETE trigger exception with secure_delete and witnessed WAL cleanup; named backup/provider residuals |
| WriterOwner.client / flush / drain | clone handle, async barrier through accepted work, then awaited stop/join yields unique HostStore; flush is not a new backup or a claim of power-loss durability |
| WriterClient.submit / CommitWait Future / wait_blocking | immediate bounded admission/rejection and awaitable one-shot result; blocking wait is CLI-only; timeout/drop cannot cancel a possibly committed write; retry same key resolves outcome |
| TransactionEngine.commit_group / append_atomic / apply | private common implementation seam: one outer transaction, isolated operation savepoints, exhaustive per-event apply; PreparedReceipt cannot escape as durable success before COMMIT |
| Snapshot.legacy_registry | scoped source-evidence resolver borrowing this admitted snapshot; exact kind/text membership only, absent false and unreadable error; no global string registry or grants |
| Snapshot.info / event / history / search | snapshot metadata; exact typed event; indexed/bounded history and budgeted search with honest omissions |
| Snapshot.projects / project / principals / principal / profile / configuration / config / grant | authorized current metadata, resolved immutable originals where required; config/grant key and creator checks use committed heads |
| Snapshot.session / sessions / turns / capture_source | native binding/consent/capture state; bounded attributable text; never provider account credentials or a fake native conversation |
| Snapshot.message / messages / decision / decisions | full or explicitly previewed bodies, correct sent-or-received/owner scope and exact-ID filtering; no read/delivery/disposition writes |
| Snapshot.process / processes | recorded identity plus actual recorded observation, never live OS proof or a PID-only stop handle |
| Snapshot.working_state / cursor / resume_head | present-empty distinct from absent; expected revisions/window/ack facts and nonnegative derived debt counts |
| Snapshot.pending_effects / effect / integrations | durable pending/terminal intentions and exact outside-witness references; reads do not execute effects |
| Snapshot.operation_receipt / import_progress / close | original request-key result and bounded source checkpoint windows; close ends snapshot, never advances a durable cursor |

## Canonical Rust declarations

The compile-only signatures live only in the crate: [lib.rs](../../crates/se-store/src/lib.rs) exports [model.rs](../../crates/se-store/src/model.rs), [event.rs](../../crates/se-store/src/event.rs) and [api.rs](../../crates/se-store/src/api.rs). Those four source files are the single Rust declaration authority; this document owns the behavioral contracts and SQL. Workspace check, formatting and Linux/Windows-MSVC/macOS-AArch64 Clippy check the declarations; they do not qualify a runtime backend.
