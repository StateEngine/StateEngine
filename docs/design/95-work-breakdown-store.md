# 95. Work breakdown — se-store

Planning input for the project maintainer against the reconciled design. This breakdown
grants no independent implementation or test authority; section 95 and Jimmy’s
ratified wave-1 decision govern admission.

The normative storage contract is [20-data-model.md](20-data-model.md), including
its compile-only APIs, **52 event kinds, 41 tables/30 triggers and six user-history
import families**. Sections 00, 30, 50, 70, 80 and 90 supply their named constraints;
OPS contains **58 operations and 24 MCP tools (19 core + 5 Atlas)**. This plan adds
no product operation, PostgreSQL backend, factory feature or author-owned suite.

Dependencies: **F** = accepted se-types and its owner's shared DTO/error changes;
**K** = se-core's verified Admission, canonical IntentDigest, authorization and
operation policy; **H** = se-host's runtime ownership, blocking executor, wake
consumer, capture/staging producers and maintenance orchestration; **P** =
se-proc/host filesystem custody, owner-only permissions, shared/exclusive OS
locks and exact process observations; **Q** = independent section-90 tests,
journeys and native/resource qualification. SQL, projection logic and store
paging stay here; authentication, process actions, provider readers and transport
stay with those owners. A missing consumer blocks its witness, not independent
work against an approved interface.

Paths below are proposed implementation paths inside `crates/se-store/` unless
fully qualified. The project maintainer assigns one author per task/file set. S01 alone owns
manifest/lib/API/model/event wiring; S03 owns schema/index files and their
version registry; S04 owns apply dispatch. Domain authors deliver disjoint
leaves and use those owners for integration. Estimates are approximate shipped
Rust/SQL lines, **including** the existing compile-only declarations in S01;
exclude docs, host/native/core implementations, third-party code and Q's tests.
They are planning estimates, not gates or reasons to cut behavior.

## Foundation and write path

**S01 — Store composition, open and bootstrap (~1,700 lines).** Files: `Cargo.toml`, `src/lib.rs`, `src/api.rs`, `src/model.rs`, `src/event.rs`, `src/backup_context.rs`, `src/open.rs`, `src/connection.rs`. Depends F/P and the frozen section-20 interfaces; final open/bootstrap joins S02 codecs and S03 schema bytes. Clauses: 20 “Public API and dependency direction” / “Migrations and version skew”, 00 §2.1, 70 §5, 80 B1/B2. Implement the shared store-bound backup pin/cancel context and role-bound factory objects, measured absent/unreadable/foreign/newer/older states, checked pragmas and connection limits, protected no-replace FULL schema/header publication/readback for explicit owner init (hostless shared or explicit exclusive create), never from embedded open. Missing embedded state returns setup-required with same-home se init. Implement automatic sole-host additive migration after a verified pre-migration backup before ready; reader/direct old-schema detection closes handles/releases shared custody and invokes private host bootstrap. Preserve typed error/remedy/detail and immutable public ID spelling; no rusqlite handle or SQL callback escapes. Witness: Q checks fresh init versus missing/truncated/foreign/old/new state, outside permission/publication readback, concurrent bootstrap and J1/J2; workspace/API consumers compile. File protection and native lock acquisition remain P, not new unsafe code here.

**S02 — Event, identity and payload codecs (~700).** Files: `src/codec/mod.rs`, `src/codec/event.rs`, `src/codec/identity.rs`, `src/codec/custody.rs`, `src/staging.rs`. Depends F, the frozen S01 interface/wiring and P/H's owned staging/source observations; not S01's completed bootstrap. Clauses: 20 “Event wire and storage formats” / “Public ID decoding and exact legacy preservation” / recorded custody contract, 30 persisted checkpoints, 70 secret boundaries. Encode all 52 closed versioned kinds with one owning text copy; canonical UUIDv7 keys need no dictionary rows, legacy UUIDv8 storage keys retain exact scoped wire spellings, and registered exceptions use the contextual resolver. Validate the landed nine-state checkpoint/containment codec including NoChildCreated, Unpublished, Identified and historical Unknown, lossless paths, staged length/hash and erased values; unknown versions refuse and payload types never gain Debug logging. Witness: Q's actual codec/store consumers cover malformed/foreign IDs, absent versus unreadable identity, exact text/native-path readback and erased capture dedup; no author test scaffolding or vendor-account reader.

**S03 — Initial DDL, indexes and trigger registry (~650).**

Files: `migrations/001.sql`, `src/schema.rs`, later approved versioned SQL files.

Depends the frozen S01/S02 data contracts and accepted section-20 DDL; schema authoring does not await bootstrap/codec implementation.

Clauses: 20 schema/immutability, mail-window/live-keyset index and erase-exemption definitions; 70 §6; 80 bounded SQLite. Embed all 41 application tables (including resume_heads) and 30 triggers, the schema/application/user version, explicit constraints/indexes, immutable authority triggers and narrowly gated payload/fingerprint erasure transitions. Keep canonical-ID dictionary elision, the single owning turn row, partial caller-key index, current-list indexes and current indexed mail access paths; no decision chain or non-mail version rows; no second JSON event envelope.

Witness: Q loads the exact schema, inspects FKs/index plans and independently exercises ordinary immutability and approved-versus-unapproved erase transitions; verify trusted_schema=OFF and audited innocuous guard registration. Query-plan failures return to this owner with S10, not a new ratchet or parallel schema fork.

**S04 — Canonical transaction, retry identity and stamps (~650).**

Files: `src/transaction.rs`, `src/idempotency.rs`, `src/writer_stamp.rs`, `src/apply/mod.rs`.

Depends S01–S03, K's pre-allocation IntentDigest; its dispatch integration and complete behavior witness join S05–S07 as they arrive.

Clauses: 20 “Atomic append, apply and idempotency” / “Writer ownership, batching and durability”, 00 G2/G3, 50 writer receipt contract. One commit_group/append_atomic/apply path, savepoint isolation, entity counters starting at 1 and incrementing by 1 per committed change, checked counter CAS/references, immutable operation membership, private writer construction, retained primary-event writer/durability/wakes and exact replay. FULL is selected only by the closed security set; ordinary NORMAL may lose several recent commits after OS/power loss, while process-crash recovery and indeterminate COMMIT remain distinct. Ratify/reject/retract/supersede are FULL. Map every internal cause through section 20’s complete public map; pre-COMMIT SQLITE_FULL rolls back definitely with store-disk-full, while uncertain COMMIT acknowledgment is commit-outcome-unknown with the original key. Implement the intent/no-op/replay contract owned by section 20 “Atomic append, apply and idempotency”.

Witness: Q's P1/P2 and outside event/receipt readback cover partial failures, key conflicts, no-op storage growth, host/direct replays and FULL revocation boundaries. No filesystem/process/network effect runs inside SQL.

Add the narrow pre-writer FirstBinding/FirstBindingReceipt maintenance contract: preserve registry-owner and project-session scope/actor/request identities, but use the private TransactionEngine::commit_first_binding all-or-nothing wrapper over the common append/apply path for one FULL outer transaction with whole-pair rollback and original-pair replay; the ordinary savepoint policy cannot commit only the owner. No unresolved transfer phase is merged into this pair.

**S05 — Registry, agent metadata, sessions and credentials (~550).**

Files: `src/apply/registry.rs`, `src/apply/session.rs`.

Depends S02–S04 and K/H admission/binding inputs.

Clauses: 20 catalogue/projection/state tables, OPS creator amendment, 70 §§2.2–2.3. Persist the explicit re-adoption history_from field and ASCII NOCASE name uniqueness. Apply immutable creator and current grant facts, project/root/profile/grant heads, with no general configuration table or mirrored setting events, prepared sessions plus standalone-only credential issuance (embedded binding emits no credential events), ten-minute first-use deadline, atomic activation/incumbent revocation and terminal revocation. Historical principals/bindings never become live authority and aliases stay import-only lookup data.

Witness: Q's T1–T5/T18/T22/T26 and P1/P2 through real CLI/MCP/linked-host consumers, including direct-child versus grandchild control and failed preparation preserving the incumbent; supports J2/J4/J5. K owns permission decisions, H owns proof/secret delivery; these leaves recheck committed preconditions rather than mint capabilities.

**S06 — Mail windows, live decision heads and resume counts (~550).**

Files: `src/apply/message.rs`, `src/apply/decision.rs`, `src/apply/mail_window.rs`, `src/apply/resume.rs`.

Depends S02–S05 and K's admitted operation plans.

Clauses: 20 mail/decision/projection rules and “Live mail and mutable lists”, 00 G2/G4/G5, 50 A.4/A.5/A.11/A.12. Persist optional proposal rationale separately from later transition reasons. Apply recipient-specific monotonic marks, supersession/history and human decision transitions, read current messages/marks in sent_seq ascending order; decisions update only current heads ordered by latest-transition last_seq, with no hash chain or temporal summaries, and maintain principal-bound unread/pending/resume counts from row changes. Store current views and live mail keysets without duplicating bodies or scanning history for a status count.

Witness: Q's T1/T5–T9/T12 and P1/P4 include another legitimate reader marking mail between pages with explicitly live membership/dispositions and stable sent-key order, ratification moving a labelled live decision list, independent recipient readback and source-versus-rebuilt projections; J4. Notify/deploy/ratify policy remains K/H.

**S07 — Capture, process and effect facts (~650).**

Files: `src/apply/capture.rs`, `src/apply/process.rs`, `src/apply/effect.rs`, `src/apply/integration.rs`.

Depends S02–S06 and H/P's capture/offer/native checkpoint producers.

Clauses: 20 catalogue/state/custody rules, 00 §2.6/§2.7, accepted 30, 40 §6.1 handover store record, 50 containment pair, 70 consent. Persist complete turn/progress or named capture.failed without cursor overrun; preserve the full section-30 transition matrix, no-child/unpublished cancellation and exit observations, immutable published root identity, recoverable Lost and the five landed containment causes. Persist/project ownership release under section 30’s contract; section 50 owns its command. Apply pending/offered/terminal effects, deterministic offer-attempt keys, principal debt and owned integration readback references.

Witness: Q's T13–T16/T23/T27/T28, P1/P8 and J2–J5 use actual provider output, outside native scope observations and recipient markers. An offer, root exit, saved process row or hook exit 0 cannot substitute for the requested witness; P/H still perform effects.

**S08 — Writer worker, direct path and completion (~450).** Files: `src/writer.rs`, `src/completion.rs`, `src/direct.rs`. Depends S04–S07 and H/P's runtime lease/scheduler. Clauses: 20 writer ownership and API contracts, 00 §2.1/§2.2, 80 §4/B2/B5/B6/B9. Host owns one blocking worker and Arc lease; direct clients hold shared runtime locks and call the identical transaction engine, while a host needs exclusive ownership. Ordinary embedded cold activation retains the unique maintenance store until S04 commits owner plus first session together; only then start the worker/admit ordinary writes. Standalone and live-transfer owner ordering stays as specified in 20/40. Drain only queued work, cap 256 requests/resident/group bytes, use no gather timer, return awaitable commit/flush/drain futures and yield the maintenance object only after join. Keep commit-driven checkpoints and synchronous direct appends; use S01's shared backup context to suppress backup-pinned checkpoints/backpressure and signal the 64 MiB backup abort without waiting on the reader. Witness: Q's T8/T17/P1/P2 plus writer-generation/history readback cover multiple direct writers, host takeover, dropped waiters, busy/indeterminate outcomes and no idle polling; H measures event-loop responsiveness and B5/B6. Async: futures only at the writer boundary. Synchronous core returns OpStep::Commit { batch, then }; the host awaits Completion on its async task, while planning and the typed continuation each run as bounded blocking-pool jobs with finite snapshots. The direct CLI uses synchronous DirectStore::append and passes its receipt to that same continuation; CommitWait has no blocking-wait API. No write closure/FnOnce transaction API, second write implementation or runtime is introduced.

## Read path and maintenance

**S09 — Snapshots, cursor windows and scoped resolver (~400).** Files: `src/read/mod.rs`, `src/read/snapshot.rs`, `src/read/page.rs`, `src/read/cursor.rs`, `src/read/legacy_registry.rs`. Depends S01–S04/S06 and F's Read/Page/Window types; K supplies scope/visibility. Clauses: 20 bounded reads and ID resolver, 00 G4/G5, 50 page/error families. Bind store/incarnation/query/H/order to a bounded opaque cursor, use finite SQL snapshots, enforce bytes/deadline/eligible lookahead and preserve absent/unreadable/unknown. Only immutable history uses a fixed H; every mutable list uses current heads and label concurrent movement; budget exhaustion cannot fabricate a complete empty page. Legacy exception membership borrows the admitted snapshot and preserves errors rather than answering false. Witness: Q's T6/T9/T10/P3/P4 and J3/J4 concatenate fixed immutable-history windows and explicitly live mutable pages, including intervening changes, cursor scope/incarnation mismatch and first-item byte refusal. No transaction survives an external await/CLI page request.

**S10 — Typed indexed query consumers (~750).** Files: `src/read/message.rs`, `src/read/registry.rs`, `src/read/decision.rs`, `src/read/history.rs`, `src/read/runtime.rs`, `src/read/capture.rs`, `src/read/maintenance.rs`. Depends S02/S03/S05–S07/S09 and K's admitted query shapes. Clauses: every section-20 Snapshot/credential/backup-inspection method, 50 full-message/JSON families, 80 B7. Implement owner and sender/recipient streams, complete-body/preview reads without markers, current unread mail and current pending queries in section-50 order (messages by sent_seq ASC, live decisions by current last_seq ASC), exact decisions/keys, event-to-operation/history lookup, turns, internal recorded custody for status/agent control, counts, effects, agent profile/grants and import progress. Keep backend SQL/cursor arithmetic confined; fixed current/original event joins do not walk revision chains. Witness: Q drives the public consumers plus EXPLAIN on the named scoped indexes, T6/T9–T13/P3/P4 and latest/old-window 1M measurements. Provider account/private context access remains outside these readers, and a type/tenant mismatch never becomes a string-only match.

**S11 — Automatic additive migration and compatibility (~300).** Files: `src/migration.rs`. Depends S01–S04, S12 backup and H’s exclusive startup orchestration. S03 owns SQL/version registrations. Clauses: 20 migration/skew, 40 startup and 50 store-migration-required. The sole host verifies a protected pre-migration backup, applies supported additive DDL/backfills and publishes user_version under FULL before ready. A hostless old-schema read/direct command releases its handles/shared lease, invokes private host bootstrap, then retries. A running old host requires se down first; there is no MigrationApproval, plan fingerprint, manual migration command or doctor repair migration. Recreate only fixed immutable triggers within the exclusive transaction and validate before COMMIT. Unsupported old/new/foreign/corrupt stores retain distinct refusals and preserve source/backup. Witness: Q’s P5/P7/T25 and outside header/readback cover startup upgrade, rollback/crash points and old/new binary skew through J1/J3.

**S12 — Online backup and two-generation rotation (~300).**

Files: `src/backup.rs`.

Depends S01/S03/S04/S09 and H/P's read-pool/background scheduling/file custody.

Clauses: 20 backup contract, 70 secret/file limits, 80 B2/§4. Precheck pending-snapshot space while retaining both generations, and recheck before publication. Factory backup uses one independent read transaction for the entire stable-H copy in 64-page steps after ready; the S01/S08 context defers checkpoints instead of write backpressure and aborts/releases at 64 MiB WAL, with automatic retry next start-of-day. It never holds the writer or first-session gate, validates/syncs/no-replace publishes and retains two good generations until rotation is witnessed. Failures/deadlines expose pending/failed state and prior generations; shutdown cannot call a failed copy clean.

Witness: Q's T25/P7 and independent reopening/checksums/captured-position readback exercise stable-H convergence during writes, WAL-limit/deadline abort and reader release without write refusal, publication/rotation crashes and preserved originals; measure first bound session within B2 despite a large slow backup. H owns scheduling/status and native sync bounds, not another store polling worker.

**S13 — Explicit automatic-backup restore (~250).**

Files: `src/recovery.rs`.

Depends S01–S04/S09/S12 and H/P’s owner presence, quiescence and guarded replacement.

Clauses: 20 “Automatic backups and explicit restore”, 00 G2/G3/G8 and 50 restore receipt. Precheck staged-image/retained-source/WAL space and recheck before publication; mid-copy SQLITE_FULL cannot publish an incomplete output. Inspect backups without opening a corrupt live store; select/recheck the newest independently valid generation, print known/unknown loss and stop/revocation consequences, preserve source/WAL, then adopt only after explicit owner confirmation. Retain original valid events/stamps; change incarnation and end copied credentials/sessions rather than restoring live custody. An unreadable source StoreId stays None with exact artifact provenance and a fresh target. No valid backup refuses without empty replacement. Event salvage, manual backup and arbitrary event-group recovery are deferred.

Witness: Q’s P1/P5/P7/T25/J3 independently reopens restored/source images, checks loss and credential ending, no-valid-backup refusal, insufficient space and interrupted publication. Implement section 20 “Automatic backups and explicit restore”, which owns the staged witness, publication and verbatim receipt-replay contract; Q checks the original receipt across lost acknowledgment and later writes/rotation.

**S14 — In-place body erasure and cleanup (~400).**

Files: `src/erasure.rs`, `src/erase_guard.rs`.

Depends S01–S04/S08–S10, S12 backup inventory and H/K/P's owner approval, buffer/staging readback and quiescence.

Clauses: 20 narrow forget/guard contract, the in-place erasure decision, 70 §6, 50 ErasureReceipt. Inventory captured turn/message targets before drain; recheck revisions, secure-delete in one FULL content transaction with exact connection-local exemptions, retain identity/vendor refs/byte lengths and erase body-derived hashes/fingerprints. Finish actual WAL/render/search-buffer cleanup (version 1 has no FTS) and outside raw-byte/query readback before completion; failed/busy cleanup keeps ordinary admission frozen and remains pending; retained backups/provider/Node/media copies remain named residuals.

Witness: Q's T24/P1/P7 through real forget and catch-up ingestion proves no resurrection, no unauthorized target/metadata update, truthful partial cleanup and exact residual receipt. No whole-DB rebuild, arbitrary decision/config erasure or foreign-copy deletion.

**S15 — Accounted user-history import (~500).** Files: `src/import/mod.rs`, `src/import/registry.rs`, `src/import/ledger.rs`, `src/import/message.rs`, `src/import/capture.rs`, `src/import/artifact.rs`. Depends S01–S07/S09/S10 and H/K's explicit owner/source/consent/export adapters. Clauses: the six rows of section-20 “User-history import”, its exact ID matrix/checkpoints, OPS store.import_node, 70 provider-secret limits. Import supported identity/mail/decision/conversation/working history through the same atomic batches, preserve source/forward references and exception registrations, commit source checkpoint with its chunk, account for unreadable/rejected/excluded data and leave originals intact. Secrets, active tokens/locks/PIDs and factory authority never become new grants or product behavior; PostgreSQL contributes a separately authorized export, not a client dependency here. Witness: Q's T25/P1/P2/P7 and outside source-versus-query checks cover interrupted/resumed chunks, changed source, exact legacy round-trip, each of the six user-state family dispositions and actual J3 resume binding where available. Missing native references remain explicit; no Node rollback exporter or optional fleet importer.

## Joins and completion

S01/S03/S04 own the shared seams. The compile-only interfaces already freeze
their contract: after F/P approval, S01 wires those interfaces first, S02 codecs
and S03 DDL can progress together, and S01 then joins bootstrap/open. S04
implements the transaction seam before domain leaves and integrates their
dispatch as they arrive. S05–S07 own disjoint domain leaves and S09/S10
implement readers against those layouts. S08 joins the canonical transaction
and H's owner protocol. Backup/automatic startup migration, explicit restore, forget and import
remain separate file sets with the dependencies above; a blocked OS witness does
not stop an independent leaf. Changes to a seam go through its named owner,
without inventing a competing type, apply path, SQL schema or cursor format.

**Q-S — Integrated store acceptance (0 new production lines).** Files: none newly
owned; corrections return to S01–S15 and independent tests remain Q's. Depends
all admitted store tasks plus F/K/H/P consumers and Q's actual release images.
Clauses/witness: section-90 P1–P8 where applicable; T1–T28 at the relevant
CLI/MCP/linked-host consumers; J1–J5 with real Claude/Codex, host/direct mirrors,
outside committed event/receipt/recipient/file/native witnesses and schema skew.
Measure B1/B2/B5/B6/B7/B9 shares, first-session readiness, current and historical
1M windows, write tails and body-inclusive DB/WAL/backup footprint. Schema sizing,
EXPLAIN and three-target Clippy are evidence for this design, never native crash,
security, power-loss or journey passes. Native Mac compatibility remains an
explicit external witness; cross-compilation does not discharge it. No new
ratchet, flake hunt, test suite or author process document is assigned here.

Production estimate: **~8,800 lines total: ~8,150 Rust (including the existing
compile-only declaration lines) + ~650 embedded SQL**, with broad uncertainty until
implementation. Core policy/DTOs, host transports/producers, native filesystem
and process code, release work and independent tests are excluded. The current
schema-only measurements are not implementation sizing or budget qualification;
the approved behavior and resource bounds still decide completion.

Per-unit estimate check (including declarations; Q-S contributes zero):

| Unit | Rust + SQL lines |
| --- | ---: |
| S01 | 1,700 |
| S02 | 700 |
| S03 | 650 |
| S04 | 650 |
| S05 | 550 |
| S06 | 550 |
| S07 | 650 |
| S08 | 450 |
| S09 | 400 |
| S10 | 750 |
| S11 | 300 |
| S12 | 300 |
| S13 | 250 |
| S14 | 400 |
| S15 | 500 |
| **Total** | **8,800** |

Wave 0 lost-ACK slice owner: Nell, with Q observing one committed mutation retried through CLI, MCP, IPC and linked API; each returns the same receipt after a later head change and adds no second operation. Wave 1 uses the minimal S01/S03/S04/S06/S08 production subset through the installed CLI and authenticated hosted path. Its exit is J1 plus hosted E3 with NORMAL/FULL traffic and separate queue/transaction/sync/checkpoint timings; prototype W2 remains diagnostic and section 80 owns budgets.
