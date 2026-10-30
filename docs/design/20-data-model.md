# 20 — Authoritative data, SQLite and recovery

Status: design for review, not permission to implement. This replaces the storage choices in the section drafts wherever they conflict. Governing inputs are the reviewed `docs/OPS.md`, Jimmy's design-first order relayed by Prime (`msg-5d1776a93c972d4ecceeaca3`), the synthesized Rust plan and the five shared section drafts in `prime-handoff-20261030`. The S1 prototype is measurement evidence, not production source. The earlier migration sketch is retained outside this repository as reference; no executable migration or writer lands with this design.

## Purpose and ownership

`se-store` owns the one per-user SQLite authority, event representation, transactional projections, idempotency, bounded snapshot reads, schema negotiation/migrations, backups, recovery and storage erasure. No SQL, SQLite handles, database paths derived from project labels, or backend-specific sequence arithmetic escape this crate. `se-core` owns authorization, operation policy and legal domain transitions; the store checks the same transition preconditions atomically against committed revisions. The host owns the runtime lease, process/OS witnesses, notifications and scheduling; a process row is never proof a process exists. Harnesses own transcript access and account stores. Atlas owns a separate rebuildable code index and cannot lock this database for indexing.

The store reads no environment and selects no repository. The caller supplies the resolved per-user state directory and typed scope. Its production layout is `STATE/state.db`, `STATE/backups/`, `STATE/recovery/`, with explicitly owned bounded staging files in `STATE/staging/`; platform defaults belong to configuration, not this crate. Every project uses this file. Registry-scoped events use a distinguished typed registry scope, not a magic user-controlled project name. New kernel IDs use the shared kind-prefixed UUIDv7 wire spelling. Imported IDs retain their exact accepted legacy spelling. All domain-ID BLOB columns below hold private 16-byte storage keys resolved through `identities`, not the public ID bytes; the public spelling is never regenerated from a storage key. SQLite row numbers are internal commit positions, never public IDs or authorization.

### Fixed decisions

* WAL with `synchronous=NORMAL`, the measured decision in Prime's build assignment. An acknowledgment survives a writer-process crash; it does not promise persistence across OS failure or power loss. No code may report FULL durability for this mode. There is no ambient durability knob.
* One host-owned batched writer when the runtime lease is held; a direct no-host writer calls the identical transaction function after obtaining the same exclusive runtime lease in client mode. There is no host/direct split in apply or authorization semantics.
* The only authority is the immutable operation envelope, event envelopes and their immutable typed data/body/member rows. Projections update before the same COMMIT. The privacy operation is an explicitly audited exception for erasing content, specified below; an ordinary correction never rewrites history.
* No all-event hash chain, PostgreSQL implementation, file watcher, polling loop, dual-written JSONL or repair command. A decision-only chain and imported provenance remain supported. PostgreSQL preparation is typed IDs, opaque cursors and confined SQL.
* No store background startup scan. Opening validates the header and version, opens prepared access paths and returns; migration, recovery and index replay are explicit host startup phases with visible state.

## Public API and dependency direction

The compile-only declarations in `crates/se-store/src/` are the normative Rust signatures; this document explains every method's behavior. They contain types and traits, no placeholder implementation or `todo!()`/`unimplemented!()`. Shared kernel IDs, `Read`, `Page` and `Window` come from `se-types`; this crate does not mint a competing identity or completeness vocabulary. Store-domain errors preserve typed detail/remedy and are mapped exhaustively to the shared error envelope by the core/host adapter. A concrete SQLite implementation is deliberately absent until design approval. `RecordId` is a store-specific validated UUIDv7 for internal effect/import/cursor/erasure objects, not a second kernel ID namespace; process lifecycle, store, project, agent, human, session, event, message and decision identities reuse the shared types. The signatures expose no rusqlite, tokio, OS process handle, arbitrary SQL callback or unconstrained JSON event.

There are four access objects:

1. A factory opens/creates under an explicit role. Only a host holding the runtime lease can create/migrate/recover or run startup/shutdown backup. Opening a missing store for a reader/direct client returns measured absence; it never creates an empty database.
2. A read snapshot owns one SQLite read transaction and a captured high-water position. It cannot be held across an async suspension or an external call. Typed methods return fully materialized bounded results, then release it.
3. A direct writer performs the same atomic write batch as the host worker, while the caller holds the exclusive runtime lease. It cannot coexist with a host that acquires that lease later: the host waits, then opens after the client releases it.
4. A bounded host submission handle and its owner control. Cloned submission handles cannot close/migrate the store. A dropped reply receiver does not cancel a committed operation. The unique owner drains and joins the worker on shutdown.

A revision identifies a last committed event, scoped to the same store incarnation. Each event/operation also retains its recorded incarnation; historical expected positions are replayed against their original logical predecessors, not re-authorized against a new live incarnation. Recovery/erasure may invalidate runtime cursors without rewriting the fact that an older event committed in an earlier incarnation. `Expected::Absent` and `Expected::Revision` are distinct from unchecked writes. Unconditional internal appends exist only for genuinely append-only facts; mutable projections require a revision precondition. The caller's verified scope is not an event field and is never recovered from a display name. The store checks project/actor consistency with the admitted batch; credential proof and OS-user admission remain core/host responsibilities inside the same process trust boundary.

## Event wire and storage formats

Each event has a version-1 envelope (the closed Rust variant determines kind and schema version; a caller cannot request an unknown numeric version): stable event ID; scope; authenticated actor; optional bound session; origin store ID; door (`cli`, `mcp`, `hook`, `host`, `import`); occurrence time in UTC microseconds; database-assigned recorded time; caller idempotency key; optional cause/supersedes event IDs; and one closed `EventBody` variant. The store assigns sequence only inside the transaction; recorded wall time is sampled before BEGIN, not by an external clock call while holding a transaction. Normal batches require header actor/scope to match admitted authority. Import-only batches may preserve a different historical actor/origin after strict source-ID mapping, but their initiating owner/import identity remains on the immutable operation envelope; that historical actor never becomes current session authority. A host group contains independently atomic operation batches; one operation batch can contain several events and their expected revisions. An immutable operation envelope owns scope/actor/request-key/fingerprint and an ordered membership map, so salvage/replay can reconstruct atomic groups and retries from authority rather than a disposable lookup index.

The database stores the small envelope and typed per-kind rows, **not a second serialized JSON envelope**. Long bodies have one `payloads` row referenced by their event. Recipient/disposition/decision/session/turn/process/working-state/cursor projections contain indexes and event references, never copied body text. Refs and configuration objects are bounded typed encodings; their only JSON is a versioned non-text field, not an arbitrary duplicate of the event. Readers reconstruct a typed event from its one owning representation.

Strings are UTF-8 with no normalization of user text. Times are signed 64-bit Unix microseconds, with a checked supported range; sequence/revision values are positive signed 64-bit integers. Body byte counts count UTF-8 bytes, not characters. All enum tags are the stable strings below; integer discriminants in Rust are not persisted. SHA-256 fields are 32-byte blobs. Private storage keys are exactly 16 bytes, never SQLite row IDs or public wire IDs. Canonical public IDs include the shared kind prefix; legacy public IDs retain their exact validated spelling through the identity dictionary. File paths are lossless platform path encodings tagged `unix-bytes` or `windows-utf16`; display strings never become an ownership proof. Native non-UTF-8 path bytes are not silently replaced.

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
| `session.activated` | session ID, expected, incumbent ID/revision if replacing, binding/witness refs | witnessed launch/bind | activate atomically with incumbent terminal transition; one active per agent |
| `session.ended` | session ID, expected, end reason, final captured-turn/cursor refs | `session.end`; observed provider termination | terminal ended state; revoke active capability projections |
| `session.revoked` | session ID, expected, reason | owner revocation/remove; governed takeover | terminal revoked state; cannot be reactivated |
| `credential.issued` | credential ID, session ID, purpose, secret hash, expiry, expected absent | trusted bind/token helper | retain hash only; plaintext returned once outside event |
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
| `capture.suppressed` | source/session ID, expected, suppression reason, offset window, count | explicitly incognito/disabled capture; F16 import | record suppression as suppression, not success/absence |
| `process.registered` | process ID, project/agent/session, machine/boot IDs, native birth identity, executable and argv fingerprint, custody group, initial state | `process.start`, witnessed agent/runtime launch; F17 historical import | recorded custody claim; no live witness implied |
| `process.transition` | process ID, expected, from/to state, observation ref, outcome | inspect/stop and actual OS exit/re-adoption observation | CAS state; reused/unreadable process never becomes owned |
| `working_state.set` | agent ID, text payload, expected | `working_state.set`; F19 import | update head; absent and stale expected differ |
| `cursor.recorded` | agent/session, cursor purpose, opaque value, snapshot window, expected | explicit context presentation/settlement/capture progress | update cursor without hiding unread work |
| `cursor.acknowledged` | cursor ID/revision, authenticated consumer evidence | actual packet/context/mail acknowledgment; F19 historical import | mark that exact cursor presented/read; issuance alone is not ack |
| `effect.requested` | effect ID, kind, target, safe immutable intent data, cause event, idempotency ref | init/launch/stop/send/remove's transaction | durable pending work, no OS/network call inside transaction |
| `effect.settled` | effect ID, expected, witnessed/failed/abandoned state, outside evidence or failure, attempt summary | host/harness actual effect readback | terminal effect state; only evidence can select witnessed |
| `integration.recorded` | integration ID, path/key/marker, prior/written digest, scope, readback ref, expected | init/doctor owned edits; successful removal update | retain exact ownership for reversal, never agent credential content |
| `backup.recorded` | generation, checkpoint/snapshot position, file identity/hash, schema version, readback ref | completed backup | record completed snapshot manifest, not a backup attempt |
| `import.started` | import ID, source identity/prefix digest, supported format/version, policy version | `store.import_node` | create resumable import run |
| `import.progress` | import ID, family/path, expected source incarnation/prefix, byte/row cursor, counters | committed imported chunk | advance cursor atomically with its imported events |
| `import.finished` | import ID, expected, totals/omissions, artifact refs | completed bounded source walk | terminal complete/partial report; unreadable never becomes zero |
| `import.unreadable` | import ID, source path/offset/length/digest, typed failure, retained source ref | strict import decoder failure | preserve bounded failure provenance, not copied secret source text |
| `legacy.retained` | source family/version, source identity/hash/offset, imported object mapping, immutable legacy bytes payload where needed | F7 user-law provenance import | retain historical provenance with no live grants/process custody |
| `erasure.requested` | erasure ID, explicit target event/field IDs, approved scope/revision, external residual-copy inventory | `store.forget` after owner confirmation | maintenance pending; freeze ordinary writers |
| `erasure.completed` | erasure ID, removed-field manifest, replacement DB/backup generation witnesses, residual limits | completed erasure swap/readback | erasure completion, stale cursor epoch bump |
| `recovery.recorded` | recovery ID, original store/backup identity, recovered ranges, unreadable gaps, schema policy, outside validation | successful explicit salvage/adoption | record degraded origin; never claim a complete history across gaps |

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
  encoding TEXT NOT NULL CHECK(encoding IN ('canonical-v7','legacy-shape','registered-exception')),
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
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  occurred_at_us INTEGER NOT NULL,
  recorded_at_us INTEGER NOT NULL,
  cause_event_id BLOB CHECK(cause_event_id IS NULL OR length(cause_event_id)=16),
  supersedes_event_id BLOB CHECK(supersedes_event_id IS NULL OR length(supersedes_event_id)=16)
) STRICT;
CREATE INDEX events_scope_seq ON events(project_id,seq);
CREATE INDEX events_actor_seq ON events(project_id,actor_id,seq);
CREATE TABLE operations(
  operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
  scope_key BLOB NOT NULL,
  actor_id BLOB NOT NULL CHECK(length(actor_id)=16),
  request_key TEXT NOT NULL,
  fingerprint BLOB CHECK(fingerprint IS NULL OR length(fingerprint)=32),
  recorded_incarnation INTEGER NOT NULL CHECK(recorded_incarnation>0),
  erased INTEGER NOT NULL DEFAULT 0 CHECK(erased IN (0,1)),
  CHECK((erased=0 AND fingerprint IS NOT NULL) OR (erased=1 AND fingerprint IS NULL)),
  UNIQUE(scope_key,actor_id,request_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE operation_events(
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  ordinal INTEGER NOT NULL CHECK(ordinal>=0),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  newly_appended INTEGER NOT NULL CHECK(newly_appended IN (0,1)),
  PRIMARY KEY(operation_id,ordinal)
) STRICT, WITHOUT ROWID;
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
  reason_payload INTEGER REFERENCES payloads(payload_id),
  witness_refs TEXT NOT NULL CHECK(json_valid(witness_refs))
) STRICT;
CREATE TABLE turn_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  turn_id BLOB NOT NULL CHECK(length(turn_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode')),
  vendor_ref TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('system','user','assistant','tool')),
  text_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  source_path INTEGER REFERENCES symbols(id),
  source_offset INTEGER CHECK(source_offset>=0),
  source_length INTEGER CHECK(source_length>=0),
  source_sha256 BLOB CHECK(source_sha256 IS NULL OR length(source_sha256)=32)
) STRICT;
CREATE TABLE process_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  target_session_id BLOB CHECK(target_session_id IS NULL OR length(target_session_id)=16),
  machine_id INTEGER NOT NULL REFERENCES symbols(id),
  boot_identity INTEGER NOT NULL REFERENCES symbols(id),
  pid INTEGER NOT NULL CHECK(pid>0),
  birth_identity BLOB NOT NULL,
  executable INTEGER NOT NULL REFERENCES symbols(id),
  argv_sha256 BLOB NOT NULL CHECK(length(argv_sha256)=32),
  custody BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','running','stop-requested','exited','lost','historical')),
  expected_seq INTEGER,
  observation_event BLOB CHECK(observation_event IS NULL OR length(observation_event)=16)
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
  state TEXT NOT NULL CHECK(state IN ('active','revoked')),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE messages(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  sent_seq INTEGER NOT NULL UNIQUE REFERENCES message_data(event_seq),
  sender_id BLOB NOT NULL CHECK(length(sender_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  superseded_by BLOB CHECK(superseded_by IS NULL OR length(superseded_by)=16),
  PRIMARY KEY(project_id,message_id)
) STRICT, WITHOUT ROWID;
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
CREATE TABLE turns(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  turn_id BLOB NOT NULL CHECK(length(turn_id)=16),
  event_seq INTEGER NOT NULL UNIQUE REFERENCES turn_data(event_seq),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  provider TEXT NOT NULL,
  vendor_ref TEXT NOT NULL,
  PRIMARY KEY(project_id,turn_id),
  UNIQUE(project_id,session_id,provider,vendor_ref),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX turns_agent_seq ON turns(project_id,agent_id,event_seq);
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
  state TEXT NOT NULL CHECK(state IN ('reserved','running','stop-requested','exited','lost','historical')),
  PRIMARY KEY(project_id,process_id)
) STRICT, WITHOUT ROWID;
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
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('pending','witnessed','failed','abandoned')),
  FOREIGN KEY(project_id) REFERENCES projects(project_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX effects_pending ON effects(project_id,requested_seq) WHERE state='pending';
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
CREATE TABLE erasures(
  erasure_id BLOB PRIMARY KEY CHECK(length(erasure_id)=16),
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  completed_seq INTEGER REFERENCES events(seq),
  manifest_payload INTEGER NOT NULL REFERENCES payloads(payload_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE erased_fields(
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  field TEXT NOT NULL,
  erasure_id BLOB NOT NULL REFERENCES erasures(erasure_id),
  PRIMARY KEY(event_seq,field)
) STRICT, WITHOUT ROWID;
```

`scope_key` is the disjoint binary encoding `0x00` for registry or `0x01 || project_uuid` for a project; using NULL as part of the idempotency primary key would not enforce uniqueness. `events.project_id = NULL` is allowed only for the registry event-kind subset. Scoped projections never use a NULL project to mean all projects. `symbols` stores only repeated lossless path/native-reference bytes, not user turn/message/working-state text, so an erasure does not have to delete a shared user's content.

Every immutable table has both fixed triggers below. Projections and decision-chain rows are not independent authority; operation envelopes/member rows are immutable authority for retries and atomic recovery groups. These statements are the complete finite list, not an instruction to infer immutability from table naming.

```sql
CREATE TRIGGER operations_no_update BEFORE UPDATE ON operations
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
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_update BEFORE UPDATE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_delete BEFORE DELETE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER message_data_no_update BEFORE UPDATE ON message_data
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

1. Bound input validation outside the write lock: closed kind/version, sizes, ID/encoding shape, scope, no plaintext credentials. Core has already resolved labels and supplied verified authority. Compute the operation fingerprint over the deterministic encoding specified below of semantic inputs, expected revisions and scope/actor; exclude generated event IDs/recorded time/transport retries. Payload bytes are included once in this digest. The codec fixes field ordering and enum strings; ordinary JSON map iteration is not its canonicalization rule.
2. `commit_group` issues one `BEGIN IMMEDIATE`, then `append_atomic` creates a savepoint per operation and rechecks schema/incarnation and transaction preconditions. It never starts a nested BEGIN inside that group. Consult `(scope_key, actor_id, request_key)`. Same fingerprint returns the original committed first/last event and typed receipt without adding events. Different fingerprint refuses `idempotency-key-reused`. An erased fingerprint refuses `content-erased`; it cannot accept/recreate the original body or silently replay an uncheckable request. A failed uncommitted batch consumes no key.
3. Insert one immutable operation envelope for an accepted new request, then check each event ID for collision before insertion. A different operation cannot reuse it even with identical text. Resolve natural-key no-ops: a second delivered/read/dismissed mark returns the original marker; a duplicate vendor turn returns the original turn only after verifying equal body/source identity. Different bytes at a natural key refuse `natural-key-conflict`. No new domain event/marker is generated just to make an idempotency receipt. The immutable operation envelope/member map records a new request key even when all members refer to prior natural-key results, preserving conflicting-key detection without duplicating read markers.
4. Insert the envelope, typed data and body exactly once. `apply(event)` checks the current projection revision/state and changes all affected projections, resume heads and pending effect debt. An operation with multiple events is all-or-nothing. Unknown kinds/versions, missing referenced rows, stale CAS, wrong recipient or invalid transition abort the **whole operation**, not just the final event.
5. Insert the ordered operation-member map (including reused natural-key events) and return an internal `PreparedReceipt`; this is not yet a committed reply. `commit_group` alone issues outer COMMIT under NORMAL, then materializes public `CommitReceipt` values. A receipt reconstructs its exact event-ID list from that map; its first/last positions are descriptive bounds, never permission to treat every intervening event as a member. Only then release successful replies and the committed high-water notification. A reply/notification failure does not undo COMMIT; retry with the same key resolves it. No OS call, filesystem edit, network request, await or expensive transcript scan occurs while holding the transaction.

SQL statement failure and COMMIT failure are not interchangeable. Before COMMIT, rollback is definite. A lost connection/IO error while committing is reported as `commit-outcome-unknown` with the original request key; the caller queries/retries that key rather than inventing another. Shutdown/drain does not report success until accepted work has a definite result or an explicit indeterminate receipt. The store never stamps a projection/bell as witnessed just because append succeeded.

### Semantic fingerprint encoding

Fingerprint bytes are `SEOP\0v1\0` followed by canonical UTF-8 JSON of the semantic input. Object field names are the closed ASCII schema names sorted by UTF-8 byte order; arrays retain semantic order; integers are checked decimal i64/u64 with no floats; strings use JSON UTF-8/control-character escapes without Unicode normalization. IDs use their exact shared typed wire spelling (canonical kind-prefixed lower-case UUIDv7 or accepted legacy spelling), never the private storage key; native paths use their explicit encoding tag and base64url raw encoding; payloads are streamed into `{bytes,sha256}` descriptors, never buffered into a second full JSON text copy. Include kind/version, source/native natural keys, expected revisions and scope/actor. Exclude generated envelope IDs, origin transport metadata, recorded clock time and retry key. Caller-created domain IDs (message/decision/session IDs) remain semantic inputs. This specification fixes the representation independently of a serde map's incidental iteration order. Erasure invalidates every operation fingerprint whose member/data dependencies included the erased field; no old composite digest is retained as a loophole.

### Group commit

The host owns one write connection on one blocking worker. Default coalescing is 250 µs, maximum 16 operation requests, bounded additionally by encoded bytes and operation size. The S1 measurements show this is a starting setting, not proof of a 20 ms hard bound. A failing outer `commit_group` result applies to every accepted member; its successful vector preserves request order and each member's savepoint result. The worker blocks indefinitely when idle; a deadline is armed only after the first queued write. A zero-window setting drains only already queued work and is an explicit build-time tuning alternative, not an environment override.

Each operation has a savepoint inside the group transaction. Its own failing validation/apply rolls back that savepoint and records that request's error; other valid operations may proceed. SQL/IO errors that poison the connection, failed savepoint rollback or failed outer COMMIT fail/indeterminate **all** affected requests. Replies are withheld until outer COMMIT; a rolled-back member's error also arrives after its group is resolved. Replayed/no-op members return their existing receipt and create no duplicate events. Decision-chain heads are read/updated transactionally, so savepoint rollback cannot leave an in-memory speculative head.

Admission has both a request cap (64 queued operations) and a 1 MiB resident queue-body budget; large staged captures use bounded owned staging references, not arbitrary paths or buffers copied into every queue item. The worker validates the staging digest/ownership before beginning SQL. A group whose materialized bytes would exceed its 2 MiB work cap commits earlier. Queue full returns `store-backpressure` immediately with retry guidance, not a blocking send on the host runtime. Accepted requests are FIFO except adjacent grouping; there is no per-agent permanent writer/process. Replies use a one-shot completion object; host async integration waits without spawning a process per request. A timeout means unknown acceptance/commit status unless the ticket says rejected; dropping the waiter is never cancellation after admission.

A direct no-host operation acquires the same runtime lock exclusively in client mode, checks again that no host endpoint/generation became current, opens the existing store without migrations, and executes `commit_group` with a single operation on its own connection. It holds the lease until COMMIT/rollback and connection close. A host starting concurrently waits for this finite operation; a stale endpoint never authorizes a second writer owner. Direct append uses the same limits/idempotency/preconditions/NORMAL pragmas. It does not make startup/shutdown backups per CLI invocation. The next host catches up from committed event positions; post-commit notification is advisory, never authority.

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
| turns / capture_sources | capture consent and session/source binding must be valid; native turn natural key/body/source digest match; insert turn and progress together | same native key + bytes replays; source rotation/truncation refuses offset reuse until new source incarnation is explicitly recorded; failed capture leaves offset unchanged |
| processes | initial recorded identity is complete, including machine/boot/native birth/executable/argv/custody; transition checks expected head and full observation reference | store does not call OS; reused/unknown evidence cannot produce running/owned; imported processes are historical only |
| working_state | absent or exact revision precondition; new head references one immutable text payload | stale revision conflicts; empty string is present text, not absent |
| cursors | typed purpose/scope/session and valid snapshot bounds; issuance distinct from acknowledgment | exact prior cursor revision needed for ack; cannot ack a foreign/newer cursor or turn incomplete context into complete |
| effects / integrations | requested effect has stable cause/idempotency; settle requires expected pending revision and evidence for witnessed; integration records exact owned prior/written digest | failed/abandoned retain reason; unrelated file edits are conflict; replay never executes the intended effect |
| import runs / progress / legacy_ids | source incarnation/prefix unchanged, monotonic row/byte cursor; imported events and progress commit together | ID map fixed per source identity; changed source prefix refuses; unreadable counter/record retained; no cursor beyond failed unaccounted bytes |
| erasures | explicit owner-approved target IDs/revisions, complete copy inventory, exclusive maintenance state | retry resumes the same manifest; no completed receipt until replacement live store/backups read back; erased-key replay cannot recreate text |

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
| Credential | absent → active → revoked; active → expired by timestamp predicate | no resurrection, no plaintext event; expired/revoked token never falls back to owner |
| Message | absent → sent; sent → sent+delivered/read/dismissed; sent → superseded relation | markers are independent monotonic facts; dismiss does not imply read; no body rewrite/delete or recipient change |
| Decision | absent → proposed; proposed → ratified/rejected/retracted; ratified → retracted/superseded | rejected/retracted/superseded terminal; superseding requires ratified replacement and both expected heads; proposed supersedes hint has no activation effect |
| Process | absent → reserved/running/historical; reserved → running/lost/exited; running → stop-requested/exited/lost; stop-requested → exited/lost | historical/exited/lost terminal for that exact instance; re-adoption is a witness on a still-valid recorded instance, not a new PID claim; no stop-requested → running reset |
| Effect | absent → pending; pending → witnessed/failed/abandoned | terminal result immutable; retry after failed uses a new attempt/request linked to the same cause, never changes failed into witnessed invisibly |
| Import | absent → running; running → running checkpoint/complete/partial | source mismatch pauses/refuses without advancing; resume of partial requires same policy/source identity and explicit remaining window |
| Backup | absent → writing → verified → published; writing/verified → failed | published generation immutable until owned rotation; partial file never counts as a backup |
| Erasure | absent → inventoried → approved → draining → rewriting → backups-rewritten → swapping → verified → complete | failure freezes ordinary writers and preserves phase evidence; no successful tombstone-only shortcut; restart resumes exactly this erasure ID |
| Salvage | diagnosed → source-frozen → scanning → candidate-built → validated → owner-adopted | gaps remain explicit; invalid candidate never replaces source; ordinary open does not auto-adopt salvage |

Stored read/disposition facts can be imported as historical states only when the Node row actually supports them. A bell offer, stdout flush, packet creation, launch readiness and task completion never substitute for one another.

## Bounded reads, snapshots and cursors

A read captures the committed maximum event position and store incarnation under one deferred read transaction. Backup-file inspection is a separate read API: snapshot its manifest/event metadata, release SQL, then inspect immutable owned files and report per-file observed/absent/unreadable facts; it does not pretend filesystem observations share a SQLite snapshot. Every row and head it materializes belongs to that snapshot; there is no read of a projection at one position and bodies at another. Reader connections are read-only, with `query_only=ON`; closing a snapshot releases its transaction even on decoder failure. Readers never rebuild, migrate, mark mail read or advance durable cursors.

All lists are keyset paged, with indexes beginning with authorized scope and relevant actor/recipient. The default order is descending commit position for inbox/history and ascending position for replay/import. No OFFSET scan or cold-cache full-file count is required for a page. Read at most `limit + 1` candidates plus a bounded byte budget. `ReadBudget` wraps the canonical se-types PageRequest and a finite deadline; it does not introduce a second cursor/limit/byte vocabulary. Full message listing yields only complete bodies that fit, with continuation before the first omitted item, and never appends read/delivered markers. Owner may inspect any selected-project message; session scope is sent-or-received by that actor. The extra candidate establishes `has_more`; exact omitted count is `None` when computing it would require an unbounded scan. Zero, absent and count-not-computed stay distinct. A rejected/undecodable candidate is not skipped into a deceptively complete page: return an unreadable error with the checked sequence/source or an explicitly incomplete window, preserving the continuation before that row.

An opaque page cursor encodes version, store ID/incarnation, fixed snapshot high-water position, query/scope fingerprint, order and last returned position. Its canonical binary form is version byte + 16-byte store ID + fixed-width integers + 32-byte query digest, base64url without padding; maximum 192 bytes. It is not a capability: the supplied authorized scope is rechecked for every query even with a syntactically valid cursor. Reject wrong store/incarnation/query/order, positions outside the captured window, overflow and unsupported cursor version. Newly arrived mail above the cursor's high-water is reported as outside this page's window and appears in a new inbox read; it is never silently hidden as “no unread mail.” An old high-water remains readable while records exist, except after an explicit erasure/recovery incarnation bump.

`Window` states from/to positions, returned count, byte consumption, completeness, omission reason/count if known and continuation. Row limit, bytes, deadline, unreadable row, feature unavailable and source rotation are different stop reasons. If the first full item cannot fit, return `read-budget-too-small` with the required bounded minimum; do not return a non-advancing apparently successful empty page. Previews explicitly expose body-incomplete; full `message.read` must obtain the full bounded body before core appends a read marker. Renderers clamp only at UTF-8 boundaries, never slice an encoded path as text. An exact-ID query returning no matching record is measured absence; adding a state filter can instead produce zero matches without implying the ID is absent.

`Snapshot` exposes typed queries for projects/principals/profiles/config, sessions and credential hashes, messages/inbox/marks, decisions (including typed exact ID), turns/sources, processes, working state, cursors/resume heads, effects/integrations, history/events, import progress and operation receipts. Shared text search is bounded over an explicitly scoped candidate stream; it reports incomplete when its scan budget ends. There is no arbitrary SQL/predicate callback API for kernel callers.

## Migrations and version skew

Connection setup: confirm a regular owned state file in an owner-only directory through the host's filesystem custody service; open without following a final symlink, no URI paths from a remote input; validate `application_id`, `user_version`, store ID/incarnation and ready/maintenance state before queries. Wrong application ID, unreadable header, newer schema or configured synced/network storage returns a distinct error/remedy. A missing file is absent. An empty/truncated existing file is unreadable, not permission to initialize over it. Create uses a new exclusively reserved pathname and refuses collision; 16 KiB pages are set before first WAL activation.

Pragmas: WAL, NORMAL, `foreign_keys=ON`, `trusted_schema=OFF`, `mmap_size=0`, `temp_store=MEMORY`, bounded cache, `busy_timeout=5000`, 64 MiB journal-size target. Read back journal/synchronous/foreign-key settings; refusal to apply is fatal to write admission. Only the host under the exclusive runtime lease performs forward migrations under `BEGIN EXCLUSIVE`. Version 0 is fresh creation, not an arbitrary SQLite importer. Before each migration take/verify a backup; apply additive DDL/backfill in explicit bounded phases, update `user_version` in the same final transaction, then check integrity/foreign keys/version before ready. Version metadata outside SQLite is only a recovery hint, never authority over a contradictory database header.

Alpha migrations add tables/indexes/nullable columns or supported event readers; they do not reinterpret old tags or drop history. A migration needing a long replay opens a visible maintenance generation, writes to a new projection generation, validates it and atomically publishes; readers do not guess which half is current. A host can open a supported older header as a maintenance-only object to plan/migrate; it cannot construct a working writer or query missing projections until migration completes. Corrupt/newer/foreign headers return refusal without a HostStore. The exact old version range accepted by a binary is compiled metadata. Older binaries refuse write admission to a newer version and cannot “repair” it. Reader compatibility is also explicit, not assumed because SELECT happens to work. Unknown event body versions block a complete replay/read rather than being ignored. Only a negotiated rollback to a compatible Rust binary exists; no Node-format rollback writer is planned.

The runtime lease serializes old/new hosts and direct clients before migration. Database locks alone cannot protect a stale binary that releases its SQL transaction and writes later; each write rechecks version/incarnation under its transaction. A stale generation gets `store-generation-changed` and must reopen/re-admit. Restoring a backup or adopting salvage creates a fresh incarnation and invalidates cached positions/cursors, credentials and process-adoption assumptions.

## Backups, restart and salvage

Backups are SQLite online-backup snapshots, not filesystem copies of a live main file without its WAL. The runtime owner takes one verified snapshot at startup before admitting writes and one after clean drain/flush at shutdown. It retains two published generations plus at most one owned staging generation. Each has a manifest containing store ID/incarnation, schema/application IDs, captured position, byte count, file hash and validation result. No machine credential, launch secret or active runtime endpoint is included. Credential hashes in a copied database do not make copied capabilities live.

A normal host/direct lease must carry the validated StoreId; an unknown StoreId is permitted only for owner-approved recovery planning that creates a fresh target identity. The persistent store_info state describes SQL maintenance; creating/draining/closed and backup-pending are resource/host admission phases, not misleading extra SQL-ready states. No writer handle is published before the host's startup backup barrier. Startup backup is an asynchronous **admission phase after lightweight readiness**, visible as `starting/backup-pending`; private reads can remain available from a validated store, but mutation/custody admission waits for the backup or a named failure. This preserves the <=100 ms open/readiness target without claiming the full startup phase already completed. A full 1 GiB copy cannot fit 100 ms; it must not secretly become startup work on the critical path. Shutdown success requires the requested clean backup to finish, otherwise the result says backup failed and names its staging/prior generations. The host selects a finite user-visible shutdown deadline; expiration does not turn the prior backup into a fresh one.

Rotation sequence: create an exclusive `.pending-<generation>` file; run online backup with bounded page steps and busy deadline, yielding between steps; close and independently reopen read-only; run integrity/foreign-key/version checks; record captured position and digest; fsync file and containing directory where supported; publish a new immutable generation by no-replace rename; update a small atomic manifest pointer; only then remove the oldest previously owned generation. A failure retains the last two published valid generations. There is no in-place overwrite of a good backup. Startup reconciles an orphaned pending file by identity/manifest, never promotes it because its filename looks complete. Incremental backup scheduling runs only while work exists, without an idle timer.

Normal process death uses SQLite WAL recovery, then validates the header and the last committed schema; no projection replay is needed because log and projections shared COMMIT. A corrupt store is not automatically replaced with a backup or scanned into an empty database. Recovery planning/build/adoption and backup restoration are factory methods over explicit owned paths and a maintenance lease; they do not require first constructing a healthy HostStore. If the source store ID cannot be established, the report says unknown and the approved recovered target gets a fresh explicit StoreId rather than guessing one from a surviving row. `doctor.inspect` reports the actual read failure and available verified generations. `doctor.repair` requests an owner-approved recovery plan under the exclusive runtime lease, with old binaries and readers drained.

Salvage builds a **different candidate file** from independently decodable authoritative envelopes/data/payloads. It never repairs the source in place. Source bytes and any WAL are first retained as a protected read-only recovery artifact with identities/digests; database locks/OS handles must establish a coherent frozen source, not a main-file-only copy. Scan by event position with bounded IO; validate kind/version/IDs/body ownership/digests and reference preconditions. Replay complete operation ranges using the same apply rules. If any member of an atomic operation is missing/corrupt, exclude the entire operation and record the exact gap/range. Dependent later events are excluded with dependency-gap reasons rather than supplied invented prerequisites. Unknown versions and unreadable ranges are counted separately from absent rows.

A candidate passes structural integrity, foreign keys, full authoritative replay/projection comparison, decision-chain verification for available material, idempotency range consistency and an explicit gap manifest. A candidate with gaps may be useful, but `RecoveryReport.complete` is false and the user must explicitly choose it; no script can label it complete by counting only recovered rows. Adoption closes all readers, atomically swaps the protected file set, increments incarnation, revokes active credentials, treats imported/recovered process claims as requiring fresh OS witness, and appends `recovery.recorded` describing every omission. The original store/WAL and validated backup generations remain recoverable until a separate owner retention decision. Nothing launches or rings historical effects during salvage.

## Forget and content erasure

The owner-only `store.forget` targets body/statement/reason/legacy-byte fields and derived source digests on explicit captured event IDs/revisions, never an unbounded search-and-delete. Unsupported identity/config/native-reference fields refuse during inventory rather than substituting empty values. Core establishes interactive owner approval outside an agent process tree. Before mutation the store produces an erasure inventory: live payload/data fields, indexes, idempotency digests, derived caches, its two backups, pending backup/recovery/import artifacts and referenced vendor/source copies. The request and completion manifests contain field identifiers and copy identities, not the erased text or its plaintext hash. Aliased/shared payload ownership is prohibited, so a body is not secretly shared by an unrelated event.

A read-only dry plan is not successful erasure. A tombstone alone is insufficient. After approval:

1. Drain the writer, refuse new mutations/backup/import, close snapshots and revoke streaming reads that could retain the body. Host/harness/SE Code clear their owned resident context/search buffers by explicit acknowledgment; a lost/unacknowledged holder is a named incomplete erasure. Kernel callbacks cannot pretend a foreign provider forgot its conversation.
2. Persist an owner-only phase manifest with target IDs/revisions, owned file identities and generation, never body bytes. Enter erasing maintenance. Build a replacement SQLite database through the current schema/codec, preserving envelope IDs/order and retained fields, omitting the selected body/derived plaintext hashes and recording `erased_fields`. Required body references become an explicit erased-value representation, not an empty string that looks like original content. The builder first copies authoritative operation/envelope/data components and validates the approved erasure manifest; it then replays projections with those explicit erased values. Redaction metadata/erasure references are installed before final foreign-key validation and publication, so a temporarily missing body is never accepted by an ordinary reader as an authorized erasure. Event envelopes themselves remain immutable; erasure is an explicit content exception, with later reads returning `Erased`, not falsely unchanged text.
3. Remove every selected field from typed auxiliary facts, working-state/context copies, search postings and owned indexes. Null the affected idempotency fingerprints and mark those keys erased: they cannot reinsert the secret. For erased decision material, retain the event/state history and an explicit chain discontinuity tied to the erasure event; null the erased row's old chain hashes and recompute all subsequent derived links in that project from a public erasure-ID/event-ID sentinel, so no later link retains the old content digest. Never claim that the original content chain still verifies across that discontinuity. Imported legacy-byte payloads containing the target must also be removed or erasure remains incomplete.
4. Rebuild both owned backup generations from redacted material and independently validate them. Destroy owned pending backups/recovery copies that still contain the target, or refuse completion and name why the copy cannot be removed. Original Node source files, provider transcripts, external backups, filesystem snapshots, support bundles already copied elsewhere and a user's editor/terminal are outside the store's custody; report each known residual copy and never delete another owner's data automatically.
5. Validate the new database/projections, checkpoint it, close all handles and atomically replace the owned file set under the lease. Retire the old main/WAL/SHM files, increment incarnation and independently reopen the new store and its backup generations; queries for each target must return erased metadata with no original body/digest. Append `erasure.completed` only after these effects and buffer acknowledgments are witnessed. Failure at any phase keeps maintenance visible and resumes from the same manifest on restart; it does not admit ordinary writers to the unredacted old store.

This is logical erasure from all **owned, enumerated product copies**, including WAL/free-page copies eliminated by constructing a new file. Unlinking an SSD block cannot promise physical media sanitization or erase copies in an OS snapshot/vendor account. If the user's requirement includes those copies, return `erasure-external-copies`/`erasure-physical-guarantee-unavailable` with the exact outstanding custodians; do not claim a completed universal erasure. Cryptographic media erasure would require a separately approved encrypted-storage/key-lifecycle design and is not invented by this crate. No automatic backup after a failed erasure may reintroduce old plaintext. All supported restoration/import paths consult the retained erasure manifest so an owned old generation cannot silently resurrect the target; untracked external sources require explicit conflict reporting on matching known source identities.

The schema's ordinary immutable triggers remain in every published database. The replacement builder inserts the approved redacted representation in a new file; it never disables triggers on the live authority. A redacted body is represented by `erased_fields` plus a nullable payload reference only for that exact recorded field. Codecs enforce the exclusive states `Present(payload)` or `Erased(erasure_id)`, never missing-without-erasure. Pre-erasure records that fail this invariant are unreadable, not presumed forgotten. The DDL therefore has nullable payload references for erasure-capable message/turn/working-state rows; ordinary append still requires a present body.


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

Every domain ID BLOB in the DDL is an identity dictionary storage key; every internal RecordId is directly 16 UUIDv7 bytes. The dictionary is immutable under normal writes, populated atomically with the first event, exact `(kind,scope_key,wire_id)` unique across this store. Project/human/store dictionaries use registry scope; agent/session/message/decision/event/launch/observation/lifecycle dictionaries use the source project scope. Equal legacy spellings in different projects may therefore have different storage keys without changing their public spelling. Project scope is resolved before any principal/object lookup; a global string lookup must never borrow another tenant's registration. Registry scope is the single byte `00`; project scope is `01` followed by the 16-byte project dictionary key, making the scope encoding unambiguous. Resolve actor kind from the authenticated Actor tag or the recorded principal kind; never compare only a string or permit project names to impersonate principals. Projection IDs, foreign references and fingerprints resolve through the same dictionary. Internal keys can change during an explicit rebuild only if every reference is rewritten together; public ID spelling remains stable. No extra per-read filesystem lookup is needed: dictionary keys join in the same snapshot, with bounded cached hot identities. Dictionary bytes count against the measured storage budget; the earlier prototype's bytes/event estimate must be remeasured with mixed legacy IDs before accepting it.


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
| `store-unreadable` | permission, malformed/truncated header, undecodable row or IO error; source/range preserved | restore access or inspect with doctor; do not initialize over it |
| `store-application-mismatch` | application_id belongs to another database | select the correct home; never migrate the foreign file |
| `store-too-new` | user_version above binary's supported range | install a compatible newer binary; old binary stays read/write refused |
| `store-version-unsupported` | older version/event/cursor codec outside supported range | use the named supported migration/import version |
| `store-not-ready` | creating/migrating/recovering/erasing or failed maintenance phase | finish/resume the named owner maintenance operation |
| `store-generation-changed` | incarnation/schema/generation changed after admission | reopen and re-admit using a fresh scope/cursor |
| `store-location-unsafe` | non-owned/linked/unsupported network or synced state location | choose a local owned per-user state directory; preserve original data |
| `store-pragma-refused` | required WAL/NORMAL/FK pragmas do not read back | correct filesystem/build support; do not admit writes |
| `store-busy` | finite SQLite lock deadline expired | wait for named writer/maintenance; retry the same operation key |
| `store-backpressure` | queue request/byte bound reached | await outstanding work then retry same key; do not spawn another writer |
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

Budget allocation within the 30 MB embedded envelope: target <=6 MiB store steady RSS and <=10 MiB peak for normal message/turn operations, including one 2 MiB write cache, two lazy 1 MiB reader caches, bounded queue/staging buffers and decoded page material. No connection per session. Reader pool limit is two, with one materialized result budget per borrower; oversized capture text is staged/streamed rather than multiplied through queue copies. Backup/recovery/erasure are explicit maintenance with bounded buffers and visible resource costs; they must not starve the host's runtime or run idle workers. Startup open/header/version check target <=10 ms of the <=100 ms embedding budget; backup/adoption are visible admission phases after readiness. Idle store worker blocks without timers; no polling or WAL watcher is necessary for in-host commits.

Storage target is <=1.4 KiB/event on the unchanged S1 825k-turn/100k-message/75k-marker fixture at 1M, with source/body equality verified by the reviewer. The prototype achieved 1,218.9 bytes/event by removing duplicate JSON/text/index fields; this new schema has additional product metadata, so that number is evidence for the representation choice, not a claim already met by these declarations. No omission/compression of user bodies may be used to pass the comparison. Size is reported after a checked checkpoint, with WAL and backups reported separately rather than hidden.

Warm 1M inbox target <=6 ms in-host/<=20 ms whole CLI, with an indexed 50-message page; no full history scan. Append and whole CLI <20 ms remain hard product targets, **unproven by the prototype**: NORMAL measured 3.14/72.15 and 3.42/19.21 ms p50/p99 at 20-agent bursts, with worse later tails. Queue/window tuning alone did not establish the tail. Build acceptance must measure signed native Windows with Defender, macOS and Linux; a median win does not waive a hard per-call budget. Checkpoint work is event-driven: auto-checkpoint is enabled for no-host direct writes; host schedules bounded PASSIVE checkpoint after an actual write burst and explicit TRUNCATE on clean drain, with no perpetual idle timer or concurrent second checkpoint writer. A busy checkpoint reports backlog and yields; it never blocks a query indefinitely or reports a fully flushed WAL when frames remain.

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

1. Shared `se-types` declarations are consumed from Iris's `seat-agt-8wmm-rjcy-2r83/se-types-foundation` branch for signature verification; integration must use its reviewed/landed revision. StoreId, all kernel IDs, Page/Window/PageRequest and native process/path types are reused, not recreated. Store-specific records/traits live here; wire DTO/auth ownership remains with their assigned crates.
2. Universal physical/third-party erasure is not achievable by deleting SQLite rows or unlinking owned files. This design promises fully enumerated logical owned-copy erasure and honest residual reporting; if Jimmy requires cryptographic raw-media erasure, that key-lifecycle decision precedes implementation of forget, without blocking ordinary append/read design review.
3. The hard 20 ms write tail remains an implementation acceptance problem. NORMAL is ratified here; neither disabling durability entirely nor early acknowledgment is authorized. Native measurements may require scheduling/checkpoint changes, reviewed against this same commit/receipt contract.

Store records with user payloads intentionally have no Debug derivation that could log their text; diagnostic code handles only redacted IDs/ranges.

4. The section-50 global code catalogue must integrate the distinct store causes listed above and its exhaustive typed mapping; do not implement a catch-all Internal conversion while that integration is pending.

No other row is permission for a discretionary factory feature or backend. The critic, 5c, Otto and Alpha's Rust reviewer assess the complete data design and compile-only declarations; Prime integrates it. Only a later explicit implementation admission activates these signatures and DDL as product code.

5. The strict shared ID namespaces reserve some names that Node accepted as projects or custom identifiers. Those collisions must remain visible import refusals with original provenance until an explicit identity-correspondence policy is approved; neither a broad arbitrary-string decoder nor a silent public-ID rename resolves the conflict.

## Method contract index

This index binds the following declarations to the algorithms above. All methods return the exact typed error/absence/window distinctions already specified; none is a convenient catch-and-empty wrapper.

| Trait / functions | Preconditions, effect and completion |
| --- | --- |
| RecordIdentity.from_parts / from_bytes / as_bytes | explicit caller time/entropy or checked UUIDv7 bytes for internal RecordId; reject wrong UUID version/variant and timestamp overflow; no clock, RNG or authority lookup |
| RuntimeLease.identity | host's held filesystem-custody lease identity; unknown store only for owner maintenance of an unreadable source; no lock acquisition by reading an endpoint |
| StoreFactory.open_reader / open_direct / open_host | validate existing header/version/path/role; missing → Read::Absent, foreign/newer/corrupt → typed unreadable/refusal; direct/host require held matching lease; only supported-old host opens maintenance-only |
| StoreFactory.create | exclusively reserve a new path under host lease; caller-supplied StoreId; full DDL/header validation; never overwrite existing bytes |
| StoreFactory.recovery_plan / build_salvage / adopt_salvage / restore_backup | owner maintenance over explicit owned paths even if no readable store exists; preserve source, validate candidate, swap only after approved gaps; fresh incarnation/identity rules apply |
| ReadStore.info / snapshot / credential | header metadata; finite scope-bound snapshot; trusted pre-auth hash lookup returns only credential/session metadata and cannot obtain history or manufacture an authority |
| ReadStore.inspect_backups | snapshot manifest metadata, then separately inspect bounded published files; each item's absent/unreadable/current observation is explicit; never a live-DB filesystem copy |
| TextStaging.stage_text | bounded owned stream to protected staging under held lease; UTF-8/length/digest checked; opaque handle has no caller-path constructor; used/failed staging is reclaimed by exact identity |
| DirectStore.append / close | one-element canonical commit_group under direct-client lease; success only after COMMIT; close releases handles before lease release |
| HostStore.start_writer | once per host object, only after schema/startup-backup readiness; yields unique control owner and cloneable bounded submission handle |
| HostStore.migration_plan / migrate | calculate supported forward plan/free space; drain writer/snapshots; backup, migrate/validate, publish before writer re-admission |
| HostStore.backup / checkpoint / close_clean | owned snapshot/rotation and finite checkpoint; maintenance only with writer drained or the scheduled single worker; close_clean drains and reports backup failure truthfully |
| HostStore.erasure_plan / erase | complete copy/revision inventory then approved, witnessed maintenance swap; never ordinary UPDATE/DELETE, never automatic foreign deletion |
| WriterOwner.client / flush / drain | clone handle, barrier through accepted work, then stop/join; flush is not a new backup or a claim of power-loss durability |
| WriterClient.submit / CommitWait.wait | immediate bounded admission/rejection and one-shot result; timeout/drop cannot cancel a possibly committed write; retry same key resolves outcome |
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

## Complete Rust declarations

The following files are reproduced exactly from this candidate's compile-only crate. Rustfmt and Clippy with warnings denied used Rust 1.97.1 against Iris's published **foundation revision `e4106bf6c3d8f2c0713b39af0b5456952e6fecb6`** in a separately owned verification worktree; those checks establish compilation of this contract, not a concrete SQLite backend or clean-platform journeys. The foundation supplies strict new-ID parsing, own-kind legacy wire decoding and an explicit scoped LegacyIdRegistry seam; contextual custom-spelling reconstruction is separate from state-free serde. A later shared-types revision must be integrated/rechecked before implementation. The candidate has no implementation blocks, executable defaults, placeholder macros or author tests. The DDL was parsed as an empty schema using SQLite 3.46.1 (43 tables, 30 immutable-table triggers); that syntax check is not product/recovery testing or the required patched production SQLite selection.

### crates/se-store/src/lib.rs

```rust
//! Compile-only storage design contract. No SQLite implementation is admitted.
//!
//! Normative behavior and formats: docs/design/20-data-model.md.
//! All executable functions are trait declarations, without stub/default bodies.
mod api;
mod event;
mod model;

pub use api::*;
pub use event::*;
pub use model::*;
```

### crates/se-store/src/model.rs

```rust
use crate::HistoryFamily;
pub use se_types::StoreId;
use se_types::{
    AgentId, Cursor, EventId, HumanId, IdempotencyKey, NativePath, ProjectId, Sequence, SessionId,
    Window,
};
use std::{
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
    time::Duration,
};

/// Logical internal object (effect/source/import/erasure/process record), never an OS PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordId {
    _bytes: [u8; 16],
}
/// UUIDv7 representation only; allocation supplies explicit time/entropy.
pub trait RecordIdentity: Sized {
    fn from_parts(unix_millis: u64, random: [u8; 10]) -> StoreResult<Self>;
    fn from_bytes(bytes: [u8; 16]) -> StoreResult<Self>;
    fn as_bytes(&self) -> &[u8; 16];
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision {
    pub incarnation: u64,
    pub position: Sequence,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expected {
    Absent,
    Revision(Revision),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Actor {
    Human(HumanId),
    Agent(AgentId),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Registry,
    Project(ProjectId),
}
/// Supplied by admitted core policy; this is not a deserializable authority credential.
#[derive(Clone, Debug)]
pub struct Admission {
    pub scope: Scope,
    pub actor: Actor,
    pub session: Option<SessionId>,
    pub generation: u64,
}
#[derive(Clone, Debug)]
pub enum Visibility {
    Owner,
    SelfOnly(AgentId),
    SharedProject(AgentId),
}
#[derive(Clone, Debug)]
pub struct ReadScope {
    pub admission: Admission,
    pub visibility: Visibility,
}
#[derive(Clone, Debug)]
pub struct StoreOptions {
    pub state_directory: PathBuf,
    pub busy_timeout: Duration,
}
#[derive(Clone, Debug)]
pub struct StoreInfo {
    pub id: StoreId,
    pub incarnation: u64,
    pub schema_version: u32,
    pub head: Option<Revision>,
    pub state: StoreState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreState {
    Ready,
    Migrating,
    Recovering,
    Erasing,
}
#[derive(Clone, Debug)]
pub struct LeaseIdentity {
    pub store: Option<StoreId>,
    pub generation: u64,
    pub mode: LeaseMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseMode {
    Host,
    DirectClient,
}
#[derive(Clone, Debug)]
pub struct WriterOptions {
    pub coalesce: Duration,
    pub maximum_requests: NonZeroU16,
    pub queue_requests: NonZeroU16,
    pub resident_bytes: NonZeroU32,
    pub group_bytes: NonZeroU32,
}
#[derive(Clone, Debug)]
pub struct ReadBudget {
    pub page: se_types::PageRequest,
    pub deadline: Duration,
}

#[derive(Clone, Debug)]
pub struct CommitReceipt {
    pub request_key: IdempotencyKey,
    pub state: CommitState,
    pub first: Revision,
    pub last: Revision,
    pub events: Vec<EventId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitState {
    Committed,
    Replayed,
    NaturalKeyReplay,
}
#[derive(Clone, Debug)]
pub struct FlushReport {
    pub through: Option<Revision>,
    pub pending_requests: u32,
    pub indeterminate_keys: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct CheckpointReport {
    pub wal_frames: u64,
    pub checkpointed_frames: u64,
    pub busy: bool,
}
#[derive(Clone, Debug)]
pub struct BackupGeneration {
    pub id: RecordId,
    pub through: Revision,
    pub schema_version: u32,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct BackupReport {
    pub published: BackupGeneration,
    pub retained: Vec<BackupGeneration>,
    pub removed: Vec<RecordId>,
}
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    pub from: u32,
    pub to: u32,
    pub source: StoreId,
    pub required_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct MigrationReport {
    pub schema_version: u32,
    pub incarnation: u64,
    pub backup: BackupGeneration,
}
#[derive(Clone, Debug)]
pub struct RecoveryGap {
    pub from: Option<Revision>,
    pub to: Option<Revision>,
    pub source_offset: Option<u64>,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct SalvagePlan {
    pub source_store: Option<StoreId>,
    pub target_store: StoreId,
    pub source: PathBuf,
    pub candidate: PathBuf,
    pub source_sha256: [u8; 32],
    pub required_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct SalvageReport {
    pub candidate: PathBuf,
    pub source: Option<StoreId>,
    pub target: StoreId,
    pub recovered_events: u64,
    pub gaps: Vec<RecoveryGap>,
    pub complete: bool,
}
#[derive(Clone, Debug)]
pub enum EraseField {
    Body,
    Statement,
    Reason,
    LegacyBytes,
    SourceDigest,
}
#[derive(Clone, Debug)]
pub struct EraseTarget {
    pub event: EventId,
    pub expected: Revision,
    pub fields: Vec<EraseField>,
}
#[derive(Clone, Debug)]
pub struct ResidualCopy {
    pub custodian: String,
    pub location: NativePath,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct ErasurePlan {
    pub id: RecordId,
    pub targets: Vec<EraseTarget>,
    pub owned_generations: Vec<RecordId>,
    pub residuals: Vec<ResidualCopy>,
    pub required_bytes: u64,
}
/// Host supplies actual buffer/consumer readback; mere callback completion is not a witness.
#[derive(Clone, Debug)]
pub struct ErasureApproval {
    pub erasure: RecordId,
    pub owner: HumanId,
    pub expected_incarnation: u64,
    pub buffer_witnesses: Vec<EventId>,
    pub accept_named_residuals: bool,
}
#[derive(Clone, Debug)]
pub struct ErasureReport {
    pub erasure: RecordId,
    pub completed_event: EventId,
    pub incarnation: u64,
    pub erased_fields: Vec<EraseTarget>,
    pub residuals: Vec<ResidualCopy>,
}
#[derive(Clone, Debug)]
pub struct ImportCheckpoint {
    pub import: RecordId,
    pub family: String,
    pub source_key: Vec<u8>,
    pub source_sha256: [u8; 32],
    pub byte_offset: u64,
    pub row_offset: u64,
    pub expected: Expected,
}
#[derive(Clone, Debug)]
pub struct ImportCounts {
    pub read: u64,
    pub imported: u64,
    pub duplicate: u64,
    pub unreadable: u64,
    pub dropped_by_policy: u64,
}
#[derive(Clone, Debug)]
pub struct ResumeHead {
    pub principal: Actor,
    pub turn: Option<Revision>,
    pub working_state: Option<Revision>,
    pub cursor: Option<Revision>,
    pub session: Option<Revision>,
    pub unread: u64,
    pub pending_effects: u64,
    pub through: Revision,
}
#[derive(Clone, Debug)]
pub struct CursorRecord {
    pub id: RecordId,
    pub agent: AgentId,
    pub purpose: String,
    pub value: Cursor,
    pub window: Window,
    pub expected: Expected,
}
#[derive(Clone, Debug)]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub cause: String,
    pub detail: StoreDetail,
    pub remedy: se_types::Remedy,
    pub retry: se_types::Retry,
}
#[derive(Clone, Debug)]
pub enum StoreDetail {
    None,
    Conflict {
        expected: Expected,
        observed: Option<Revision>,
    },
    Version {
        application_id: u32,
        found: u32,
        minimum: u32,
        maximum: u32,
    },
    Request {
        scope: Scope,
        actor: Actor,
        key: IdempotencyKey,
    },
    Entity {
        family: HistoryFamily,
        event: Option<EventId>,
        record: Option<RecordId>,
    },
    Source {
        path: NativePath,
        offset: Option<u64>,
        length: Option<u64>,
        sqlite_extended_code: Option<i32>,
    },
    Budget {
        allowed: u64,
        required: Option<u64>,
    },
    Maintenance {
        state: StoreState,
        operation: Option<RecordId>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCode {
    Absent,
    Unreadable,
    ApplicationMismatch,
    TooNew,
    VersionUnsupported,
    NotReady,
    GenerationChanged,
    LocationUnsafe,
    PragmaRefused,
    Busy,
    Backpressure,
    WriterClosed,
    CommitOutcomeUnknown,
    IdempotencyKeyReused,
    EventIdConflict,
    NaturalKeyConflict,
    RevisionConflict,
    InvalidTransition,
    ReferenceMissing,
    ScopeMismatch,
    CreatorControlRefused,
    EventInvalid,
    BodyTooLarge,
    ProjectionInconsistent,
    CursorInvalid,
    CursorStale,
    ReadBudgetTooSmall,
    ReadIncomplete,
    SourceChanged,
    MigrationFailed,
    BackupFailed,
    RecoveryIncomplete,
    ContentErased,
    ErasureIncomplete,
    ErasureExternalCopies,
    ErasurePhysicalGuaranteeUnavailable,
}
pub type StoreResult<T> = std::result::Result<T, Box<StoreError>>;
```

### crates/se-store/src/event.rs

```rust
use crate::{
    Actor, CursorRecord, Expected, ImportCheckpoint, ImportCounts, RecordId, Revision, Scope,
    StoreId,
};
use se_types::{
    AgentId, DecisionId, EventId, HumanId, IdempotencyKey, LifecycleId, MessageId, NativePath,
    ProcessInstance, ProjectId, SessionId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Door {
    Cli,
    Mcp,
    Hook,
    Host,
    Import,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Claude,
    Codex,
    SeCode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionProfile {
    ReadOnly,
    WorkspaceWrite,
    NamedFullBypass,
}
#[derive(Clone, Debug)]
pub struct Profile {
    pub provider: Provider,
    pub model: Option<String>,
    pub permission: PermissionProfile,
    pub named_profile: String,
    pub effort: Option<String>,
}
#[derive(Clone, Debug)]
pub struct Root {
    pub path: NativePath,
    pub canonical_key: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Human,
    Agent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Consent {
    Capture,
    Suppressed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionKind {
    Note,
    Decision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Reserved,
    Running,
    StopRequested,
    Exited,
    Lost,
    Historical,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    Bell,
    Packet,
    IntegrationWrite,
    ProcessStart,
    ProcessStop,
    RuntimeStart,
    RuntimeStop,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectOutcome {
    Witnessed,
    Failed,
    Abandoned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationState {
    Installed,
    Removed,
    Conflict,
}
#[derive(Clone, Debug)]
pub enum ConfigKey {
    DefaultProject,
    DaemonAutostart,
    McpPort,
    ClaudeCommand,
    ClaudeModel,
    ClaudePermission,
    CodexCommand,
    CodexModel,
    CodexPermission,
    AtlasEnabled,
    AgentCanCreate(AgentId),
}
#[derive(Clone, Debug)]
pub enum GrantKey {
    AgentCanCreate(AgentId),
}
#[derive(Clone, Debug)]
pub enum ConfigValue {
    Bool(bool),
    Integer(i64),
    Text(String),
    Project(ProjectId),
    Permission(PermissionProfile),
}
#[derive(Clone, Debug)]
pub struct SourceEvidence {
    pub path: NativePath,
    pub incarnation: Vec<u8>,
    pub offset: u64,
    pub length: u64,
    pub sha256: Option<[u8; 32]>,
}
#[derive(Clone, Debug)]
pub struct ProcessIdentityRecord {
    pub record: LifecycleId,
    pub principal: Actor,
    pub session: Option<SessionId>,
    pub instance: ProcessInstance,
    pub custody: Vec<u8>,
}
/// Created only by the future staging implementation from a bounded owned stream.
/// No public arbitrary-path constructor; not a credential or an event payload by itself.
#[derive(Debug)]
pub struct StagedText {
    _private: (),
}
pub enum InputText {
    Inline(String),
    Staged(StagedText),
}
#[derive(Clone)]
pub enum StoredText {
    Present(String),
    Erased { erasure: RecordId },
}
#[derive(Clone)]
pub struct LegacyBytes {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct EventHeader {
    pub event: EventId,
    pub scope: Scope,
    pub actor: Actor,
    pub session: Option<SessionId>,
    pub origin: StoreId,
    pub door: Door,
    pub occurred_at_us: i64,
    pub cause: Option<EventId>,
    pub supersedes: Option<EventId>,
}
pub struct NewEvent {
    pub header: EventHeader,
    pub body: EventBody<InputText>,
}
#[derive(Clone)]
pub struct StoredEvent {
    pub header: EventHeader,
    pub revision: Revision,
    pub recorded_at_us: i64,
    pub recorded_incarnation: u64,
    pub body: EventBody<StoredText>,
    pub erased_fields: Vec<(crate::EraseField, RecordId)>,
}
/// Closed version-1 persisted kind catalogue. Body text is supplied by T once.
#[derive(Clone)]
pub enum EventBody<T> {
    ProjectRegistered {
        project: ProjectId,
        name: String,
        roots: Vec<Root>,
        owner: HumanId,
        expected: Expected,
    },
    ProjectUpdated {
        project: ProjectId,
        name: String,
        roots: Vec<Root>,
        expected: Expected,
    },
    ProjectRemoved {
        project: ProjectId,
        expected: Expected,
        witnesses: Vec<EventId>,
        preserved: Vec<String>,
    },
    PrincipalRegistered {
        principal: Actor,
        kind: PrincipalKind,
        owner: HumanId,
        created_by: Option<Actor>,
        name: String,
        role: String,
        expected: Expected,
    },
    PrincipalRenamed {
        principal: Actor,
        name: String,
        expected: Expected,
    },
    AliasImported {
        alias: String,
        principal: Actor,
        source: EventId,
        expected: Expected,
    },
    ProfileSaved {
        agent: AgentId,
        profile: Profile,
        expected: Expected,
    },
    GrantRecorded {
        principal: Actor,
        key: GrantKey,
        active: bool,
        expected: Expected,
    },
    ConfigSet {
        key: ConfigKey,
        value: ConfigValue,
        expected: Expected,
    },
    SessionPrepared {
        session: SessionId,
        agent: AgentId,
        provider: Provider,
        native_ref: String,
        consent: Consent,
        generation: u64,
        expected: Expected,
    },
    SessionActivated {
        session: SessionId,
        expected: Expected,
        incumbent: Option<(SessionId, Revision)>,
        witnesses: Vec<EventId>,
    },
    SessionEnded {
        session: SessionId,
        expected: Expected,
        reason: T,
        final_turn: Option<EventId>,
        final_cursor: Option<EventId>,
    },
    SessionRevoked {
        session: SessionId,
        expected: Expected,
        reason: T,
    },
    CredentialIssued {
        credential: RecordId,
        session: SessionId,
        purpose: String,
        secret_sha256: [u8; 32],
        expires_at_us: i64,
        expected: Expected,
    },
    CredentialRevoked {
        credential: RecordId,
        expected: Expected,
        reason: T,
    },
    MessageSent {
        message: MessageId,
        recipient: Actor,
        kind: String,
        body: T,
        refs: Vec<EventId>,
        reply_to: Option<MessageId>,
    },
    MessageDelivered {
        message: MessageId,
        recipient: Actor,
        evidence: EventId,
    },
    MessageRead {
        message: MessageId,
        recipient: Actor,
    },
    MessageDismissed {
        message: MessageId,
        recipient: Actor,
    },
    MessageSuperseded {
        message: MessageId,
        replacement: MessageId,
        expected: Expected,
    },
    DecisionProposed {
        decision: DecisionId,
        key: String,
        statement: T,
        prior: Option<DecisionId>,
        kind: DecisionKind,
    },
    DecisionRatified {
        decision: DecisionId,
        expected: Expected,
        approval: EventId,
    },
    DecisionRejected {
        decision: DecisionId,
        expected: Expected,
        reason: T,
    },
    DecisionRetracted {
        decision: DecisionId,
        expected: Expected,
        reason: T,
    },
    DecisionSuperseded {
        prior: DecisionId,
        replacement: DecisionId,
        prior_expected: Revision,
        replacement_expected: Revision,
        approval: EventId,
    },
    TurnCaptured {
        turn: RecordId,
        agent: AgentId,
        session: SessionId,
        provider: Provider,
        vendor_ref: String,
        role: Role,
        text: T,
        evidence: SourceEvidence,
    },
    CaptureSource {
        source: RecordId,
        session: SessionId,
        consent: Consent,
        native_ref: String,
        incarnation: Vec<u8>,
        expected: Expected,
    },
    CaptureProgress {
        source: RecordId,
        expected: Expected,
        incarnation: Vec<u8>,
        old_offset: u64,
        new_offset: u64,
        last_turn: RecordId,
    },
    CaptureSuppressed {
        source: RecordId,
        session: SessionId,
        expected: Expected,
        reason: String,
        from_offset: u64,
        to_offset: u64,
        count: u64,
    },
    ProcessRegistered {
        identity: ProcessIdentityRecord,
        initial: ProcessState,
    },
    ProcessTransition {
        process: LifecycleId,
        expected: Expected,
        from: ProcessState,
        to: ProcessState,
        observation: EventId,
        outcome: String,
    },
    WorkingStateSet {
        agent: AgentId,
        text: T,
        expected: Expected,
    },
    CursorRecorded {
        cursor: Box<CursorRecord>,
    },
    CursorAcknowledged {
        cursor: RecordId,
        expected: Revision,
        evidence: EventId,
    },
    EffectRequested {
        effect: RecordId,
        kind: EffectKind,
        intent: EffectIntent,
        cause: EventId,
        request_key: IdempotencyKey,
    },
    EffectSettled {
        effect: RecordId,
        expected: Expected,
        outcome: EffectOutcome,
        evidence: Vec<EventId>,
        failure: Option<String>,
        attempts: u32,
    },
    IntegrationRecorded {
        integration: RecordId,
        path: NativePath,
        key: String,
        marker: String,
        prior_sha256: Option<[u8; 32]>,
        written_sha256: Option<[u8; 32]>,
        state: IntegrationState,
        witness: EventId,
        expected: Expected,
    },
    BackupRecorded {
        generation: RecordId,
        through: Revision,
        bytes: u64,
        sha256: [u8; 32],
        schema_version: u32,
        witness: EventId,
    },
    ImportStarted {
        import: RecordId,
        source: NativePath,
        source_sha256: [u8; 32],
        format: String,
        policy_version: u32,
    },
    ImportProgress {
        checkpoint: ImportCheckpoint,
        counts: ImportCounts,
    },
    ImportFinished {
        import: RecordId,
        expected: Expected,
        counts: ImportCounts,
        complete: bool,
        omissions: Vec<RecordId>,
    },
    ImportUnreadable {
        import: RecordId,
        family: String,
        evidence: SourceEvidence,
        code: String,
    },
    LegacyRetained {
        import: RecordId,
        family: String,
        format_version: u32,
        legacy_id: String,
        mapped_id: RecordId,
        source: SourceEvidence,
        bytes: Option<LegacyBytes>,
    },
    ErasureRequested {
        erasure: RecordId,
        targets: Vec<crate::EraseTarget>,
        residuals: Vec<crate::ResidualCopy>,
    },
    ErasureCompleted {
        erasure: RecordId,
        manifest_sha256: [u8; 32],
        incarnation: u64,
        witnesses: Vec<EventId>,
    },
    RecoveryRecorded {
        recovery: RecordId,
        source: StoreId,
        backup: Option<RecordId>,
        recovered: u64,
        gaps: Vec<crate::RecoveryGap>,
        schema_version: u32,
        witnesses: Vec<EventId>,
    },
}
/// Closed effect intent: safe references, never shell code, secret environment or arbitrary SQL.
#[derive(Clone, Debug)]
pub enum EffectIntent {
    Mail {
        message: MessageId,
        recipient: Actor,
    },
    Packet {
        session: SessionId,
        cursor: RecordId,
    },
    Integration {
        integration: RecordId,
        plan_sha256: [u8; 32],
    },
    Process {
        process: LifecycleId,
        plan_sha256: [u8; 32],
    },
    Runtime {
        generation: u64,
    },
}
pub struct AtomicBatch {
    pub admission: crate::Admission,
    pub request_key: IdempotencyKey,
    pub events: Vec<NewEvent>,
    pub import_checkpoint: Option<ImportCheckpoint>,
}
```

### crates/se-store/src/api.rs

```rust
use crate::*;
use se_types::{
    AgentId, DecisionId, EventId, IdempotencyKey, LifecycleId, MessageId, Page, ProjectId, Read,
    SessionId,
};
use std::{io::Read as ByteReader, time::Duration};

/// Host filesystem custody supplies the held per-user runtime lease. An in-process
/// caller is trusted; IPC callers cannot construct this object from request JSON.
pub trait RuntimeLease {
    fn identity(&self) -> StoreResult<LeaseIdentity>;
}
/// Constructors are declarations, not executable fallback/default implementations.
pub trait StoreFactory {
    type Reader: ReadStore;
    type Direct: DirectStore;
    type Host: HostStore;
    fn recovery_plan(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
        target_store: StoreId,
    ) -> StoreResult<SalvagePlan>;
    fn build_salvage(
        options: &StoreOptions,
        plan: SalvagePlan,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<SalvageReport>;
    fn adopt_salvage(
        options: &StoreOptions,
        report: SalvageReport,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Self::Host>;
    fn restore_backup(
        options: &StoreOptions,
        backup: BackupGeneration,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Self::Host>;
    fn open_reader(options: &StoreOptions) -> StoreResult<Read<Self::Reader>>;
    fn open_direct(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Read<Self::Direct>>;
    fn open_host(options: &StoreOptions, lease: &dyn RuntimeLease)
    -> StoreResult<Read<Self::Host>>;
    fn create(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
        store_id: StoreId,
    ) -> StoreResult<Self::Host>;
}
pub trait ReadStore {
    type Snapshot: Snapshot;
    fn info(&self) -> StoreResult<StoreInfo>;
    fn inspect_backups(&self, budget: ReadBudget) -> StoreResult<Page<Read<BackupGeneration>>>;
    fn snapshot(&self, scope: ReadScope) -> StoreResult<Self::Snapshot>;
    /// Bootstrap-only hash lookup used by the trusted capability verifier before
    /// constructing Admission; never an operation/tool or a principal fallback.
    fn credential(&self, secret_sha256: [u8; 32]) -> StoreResult<Read<CredentialRecord>>;
}
pub trait TextStaging {
    fn stage_text(
        &self,
        source: &mut dyn ByteReader,
        maximum_bytes: u64,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<StagedText>;
}
pub trait DirectStore: ReadStore + TextStaging {
    fn append(
        &mut self,
        batch: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt>;
    fn close(self) -> StoreResult<()>
    where
        Self: Sized;
}
pub trait HostStore: ReadStore + TextStaging {
    type Writer: WriterOwner;
    fn start_writer(
        &mut self,
        options: WriterOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Self::Writer>;
    fn migration_plan(&self, target_version: u32) -> StoreResult<MigrationPlan>;
    fn migrate(
        &mut self,
        plan: MigrationPlan,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<MigrationReport>;
    fn backup(&mut self, lease: &dyn RuntimeLease, deadline: Duration)
    -> StoreResult<BackupReport>;
    fn checkpoint(
        &mut self,
        mode: CheckpointMode,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CheckpointReport>;
    fn erasure_plan(
        &self,
        targets: Vec<EraseTarget>,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<ErasurePlan>;
    fn erase(
        &mut self,
        plan: ErasurePlan,
        approval: ErasureApproval,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<ErasureReport>;
    fn close_clean(self, lease: &dyn RuntimeLease, deadline: Duration) -> StoreResult<BackupReport>
    where
        Self: Sized;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointMode {
    Passive,
    Truncate,
}
pub trait WriterOwner {
    type Client: WriterClient;
    fn client(&self) -> Self::Client;
    fn flush(&mut self, deadline: Duration) -> StoreResult<FlushReport>;
    fn drain(self, deadline: Duration) -> StoreResult<FlushReport>
    where
        Self: Sized;
}
pub trait WriterClient: Clone + Send + Sync {
    type Completion: CommitWait;
    fn submit(&self, batch: AtomicBatch) -> StoreResult<Self::Completion>;
}
pub trait CommitWait: Send {
    fn wait(self, deadline: Duration) -> StoreResult<CommitReceipt>
    where
        Self: Sized;
}
/// Private implementation seam: both host group commit and direct append use
/// this exact transaction engine. SQL handles never appear in the public API.
#[allow(
    dead_code,
    reason = "Compile-only private transaction contract; implementation is not admitted."
)]
pub(crate) trait TransactionEngine {
    fn commit_group(
        &mut self,
        batches: Vec<AtomicBatch>,
    ) -> StoreResult<Vec<StoreResult<CommitReceipt>>>;
    fn append_atomic(&mut self, batch: AtomicBatch) -> StoreResult<PreparedReceipt>;
    fn apply(&mut self, event: &StoredEvent) -> StoreResult<()>;
}
/// Cannot be returned to a caller as a durable receipt before group COMMIT.
pub(crate) struct PreparedReceipt {
    _private: (),
}

#[derive(Clone, Debug)]
pub struct MessageQuery {
    pub recipient: Option<Actor>,
    pub sender: Option<Actor>,
    pub kind: Option<String>,
    pub unread_only: bool,
    pub full_body: bool,
}
#[derive(Clone, Debug)]
pub struct DecisionQuery {
    pub id: Option<DecisionId>,
    pub pending_only: bool,
    pub history: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryFamily {
    Identity,
    Configuration,
    Sessions,
    Messages,
    Decisions,
    Turns,
    Processes,
    WorkingState,
    Cursors,
    Effects,
    Import,
    Recovery,
}
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub agent: Option<AgentId>,
    pub families: Vec<HistoryFamily>,
    pub since: Option<Revision>,
}
#[derive(Clone, Debug)]
pub struct SearchQuery {
    pub text: String,
    pub history: HistoryQuery,
}
/// Internal storage record, not a frozen CLI/MCP wire DTO.
#[derive(Clone)]
pub struct MessageRecord {
    pub message: MessageId,
    pub event: EventId,
    pub sent: Revision,
    pub sender: Actor,
    pub recipient: Actor,
    pub kind: String,
    pub body: StoredText,
    pub refs: Vec<EventId>,
    pub reply_to: Option<MessageId>,
    pub delivered: Option<Revision>,
    pub read: Option<Revision>,
    pub dismissed: Option<Revision>,
    pub body_complete: bool,
}
#[derive(Clone, Debug)]
pub struct CredentialRecord {
    pub credential: RecordId,
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub purpose: String,
    pub expires_at_us: i64,
    pub revoked: bool,
    pub revision: Revision,
}
#[derive(Clone)]
pub struct SearchHit {
    pub event: EventId,
    pub revision: Revision,
    pub snippet: StoredText,
    pub body_complete: bool,
}
/// Current-head record; body is reconstructed from the owning immutable event.
#[derive(Clone)]
pub struct ProjectionRecord {
    pub original: Option<Box<StoredEvent>>,
    pub current: StoredEvent,
}
/// One finite read transaction. No method mutates a marker/cursor or repairs data.
pub trait Snapshot {
    type LegacyRegistry<'a>: se_types::LegacyIdRegistry
    where
        Self: 'a;
    /// Bound to this snapshot's admitted project and recorded import sources.
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>>;
    fn info(&self) -> StoreInfo;
    fn event(&mut self, id: EventId) -> StoreResult<Read<StoredEvent>>;
    fn history(
        &mut self,
        query: HistoryQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>>;
    fn search(&mut self, query: SearchQuery, budget: ReadBudget) -> StoreResult<Page<SearchHit>>;
    fn projects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn project(&mut self, id: ProjectId) -> StoreResult<Read<ProjectionRecord>>;
    fn principals(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn principal(&mut self, id: Actor) -> StoreResult<Read<ProjectionRecord>>;
    fn profile(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    fn configuration(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn config(&mut self, key: ConfigKey) -> StoreResult<Read<ProjectionRecord>>;
    fn grant(&mut self, principal: Actor, key: GrantKey) -> StoreResult<Read<ProjectionRecord>>;
    fn session(&mut self, id: SessionId) -> StoreResult<Read<ProjectionRecord>>;
    fn sessions(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn message(&mut self, id: MessageId) -> StoreResult<Read<MessageRecord>>;
    fn messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>>;
    fn decision(&mut self, id: DecisionId) -> StoreResult<Read<ProjectionRecord>>;
    fn decisions(
        &mut self,
        query: DecisionQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>>;
    fn turns(&mut self, agent: AgentId, budget: ReadBudget) -> StoreResult<Page<StoredEvent>>;
    fn capture_source(&mut self, source: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    fn process(&mut self, id: LifecycleId) -> StoreResult<Read<ProjectionRecord>>;
    fn processes(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn working_state(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    fn cursor(&mut self, agent: AgentId, purpose: String) -> StoreResult<Read<CursorRecord>>;
    fn resume_head(&mut self, principal: Actor) -> StoreResult<Read<ResumeHead>>;
    fn pending_effects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn effect(&mut self, id: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    fn integrations(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn operation_receipt(
        &mut self,
        actor: Actor,
        request_key: IdempotencyKey,
    ) -> StoreResult<Read<CommitReceipt>>;
    fn import_progress(
        &mut self,
        import: RecordId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>>;
    fn close(self) -> StoreResult<()>
    where
        Self: Sized;
}
```
