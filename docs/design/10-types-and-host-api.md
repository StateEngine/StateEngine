# 10. Foundation and linked API index

Design, 2026-10-30. This chapter indexes the actual declarations and assigns their
contracts to the sections below. Source listings are not copied into this index.
The Rust repository is the shipped product; the Node repository keeps its private
factory engine and history. User-state import is a product operation; factory
cutover is outside this product plan.

## 1. Sources and responsibilities

| Contract | Exact source | Design |
| --- | --- | --- |
| Internal identity, values and codecs | [id.rs](../../crates/se-types/src/id.rs) | [20 — data model](20-data-model.md) |
| Process and host identity values | [process.rs](../../crates/se-types/src/process.rs) | [30 — process ownership](30-process-ownership.md) |
| Read, page, window and omission facts | [read.rs](../../crates/se-types/src/read.rs) | 20; [50 — surfaces](50-surface-and-errors.md) |
| Commit, replay, pending and refusal values | [receipt.rs](../../crates/se-types/src/receipt.rs) | 20 and 50 |
| Protected byte values | [sensitive.rs](../../crates/se-types/src/sensitive.rs) | [70 — security](70-security.md) |
| Error classes, typed detail and remedies | [error.rs](../../crates/se-types/src/error.rs), [catalog.rs](../../crates/se-types/src/error/catalog.rs) | 50 §6 |
| Atlas query/result values and text validation | [code.rs](../../crates/se-types/src/code.rs) | [60 — Atlas](60-atlas.md); core uses these without a se-atlas dependency |
| Shared limits and internal framing identity | [lib.rs](../../crates/se-types/src/lib.rs) | 50 §1 and §2 |
| Proposed permissive SE Code API | [secode-stateengine-api.rs](secode-stateengine-api.rs) | [40 — host](40-host-runtime-and-harnesses.md) |
| Proprietary embedded constructor signature | [commercial-factory.rs](commercial-factory.rs) | 40 |
| Synchronous core commit step and read port | [commit.rs](../../crates/se-core/src/commit.rs), [compile-only consumer](commit-bridge-consumer.rs) | 50 §1; AtomicBatch/Snapshot/CommitReceipt belong to se-store, with no reverse dependency from se-types |
| Operation inputs, outputs and exposure | [OPS.md](../OPS.md), 50 | Synchronous `se-core` registry; async custody execution in `se-host` |

The foundation has no I/O, environment/ambient principal, runtime, random source,
clock, task, process handle or database owner. Constructors validate representation;
they cannot prove a commit, possession, native idleness or ownership. Crate users
explicitly import `Read`, `Cursor` and `Result` to avoid standard-library collisions.

The foundation source has pure validation/codec implementations. Host API source
is traits, constants and data declarations only. A compiler check of these files
is representation evidence, not a running provider, store or handover result.

## 2. Identity and values

New public IDs use the type's declared prefix and canonical lowercase UUIDv7.
UUID construction takes caller-supplied time/random bytes; the foundation does
not obtain either. Kind mismatch, a malformed UUID-shaped suffix and a credential
in an ID field refuse. `from_legacy` accepts only the documented producer grammar
for that kind; registered custom legacy names require the explicit scoped resolver.
The importer preserves original spelling and provenance. Canonical v7 IDs bypass
the legacy dictionary; old credentials/PIDs never become live authority.

`Generation`, `Revision`, `Sequence` and time values retain their actual range and
zero/nonzero rules. Revision/sequence order comes from committed store facts;
wall-clock time is presentation evidence. Hashes bind bytes, not native effects.
`NativePath` preserves native encoding, validates the appropriate absolute grammar
and never normalizes a foreign-host path into local custody.

`ProcessInstance`/`HostEpoch` bind machine, PID, OS birth identity and required
native registration/generation. An observation, bare PID or readable command line
is not permission to stop a process. Section 30 owns reobservation, custody,
containment and outside stop witnesses on each OS.

## 3. Read and mutation contracts

`Read<T>` preserves Present, Absent, Unreadable and Unknown. A failed read cannot
become an empty list or an absence proof. `Window`/`Page<T>` disclose the selected
range, item/byte limits, omissions, unreadable sources and continuation.
Mail keeps its stable unread/message windows and counts. Non-mail lists use
labelled live keysets; following them does not promise a historical snapshot or
unchanging membership. Source-incomplete and newly arrived mail remain explicit.

`Receipt<T>` distinguishes committed, original-key replay, refusal and pending
follow-up. Writer stamps come from the store transaction and replay keeps the
original writer. Delivery, read, dismissal, reply and task completion are separate.
Ordinary refusals use the error channel without a history event.

Every public mutation carries an identity created before its first send. CLI
invocations generate/print it and accept `--key` for cross-invocation retry; MCP
mutation schemas require `idempotency_key`; IPC and linked calls preserve it.
For store-backed mutations, same key with changed input conflicts. File-only
general config set and uninstall follow section 40’s current-state
readback reconciliation rather than a separate receipt journal. Restore retry
semantics belong to section 20; section 50 defines its receipt.
Only capture and read/ack/dismiss marker families use their restricted natural identity, verified by the registry/store.
A retry cannot substitute a new key after an uncertain commit. Linked
`RequestIdentity` explicitly separates reads, keyed mutations and that natural-key
exception; selecting the wrong form refuses before effects.

The shared DTO limits are `MESSAGE_BODY_MAX_BYTES` (32 KiB) and
`WORKING_STATE_MAX_BYTES` (16 KiB), declared in `se-types`. CLI, MCP, core and store
admission use those same limits on UTF-8 bytes before any effect. They reject
oversize input, never silently truncate it. Bounded previews disclose omissions.

## 4. Exact linked API and separately versioned JSON

The statically linked API is the permissive SE Code-owned crate, licensed
MIT OR Apache-2.0. It has no proprietary dependency or Tokio dependency. The
proprietary `se-host` implements it and maps its DTOs into `se-types`.

Cargo package identity/version is the compatibility gate. `ApiVersion` is an
exact-equality sanity check against `API_VERSION = 2.0`; there is no minor/range
negotiation at factory open, hello, registration or tool call. The internal
CLI/IPC `se-types::API_VERSION` is a separate framing identity. A changed public
Rust field, enum variant, trait method or meaning requires a Cargo/API major
change; optional fields in a public Rust struct count. The current unshipped
major-2 design is revised together, not treated as an already released contract.

Linked entity revisions use nonzero `Revision`; event/read positions are opaque
`Cursor` values, never global sequence numbers. Internal WindowFields accounting
is not a public wire snapshot. HostConfig carries the trusted installed
`helper_executable` and typed `linux_delegation` agent-scope policy; the adapter
maps these to se-host/se-proc without deriving a helper from provider input or PATH.

Every JSON family retains its `schema` identifier and its own major. Those wire
versions do not imply Rust struct compatibility. There is no N-1 encoder or
schema-freeze tool in this first build. The actually consumed
`secode.session-context-v1`, `stateengine-init/v1` and `seat-stop/v1` adapter
contracts remain explicit in 40/50; a generic resume object cannot replace them.

## 5. Host lifecycle and callbacks

The commercial constructor is
`se_host::embedded_factory(tokio::runtime::Handle) -> Arc<dyn HostFactory>`.
SE Code passes its existing runtime handle. Construction stores the handle
without I/O or spawning; all async/blocking work uses that supplied runtime.
No ambient runtime discovery, nested runtime, `block_on` or per-call process is
introduced. Library dependencies use caret ranges; Tokio `1` resolves alongside
SE Code's lock, and bundled SQLite must resolve to the same `links = sqlite3`
version. The embedding target is SE Code's Rust `secode-server` binary in
`crates/secode-product`, not its old TypeScript predecessor.

Factory open is read-only preparation. The caller registers the handle/G and
fresh `HostServices`, then explicitly activates. At activation the sole owning host applies
supported additive migrations automatically after a verified pre-migration
backup; unsupported/too-new schemas refuse. An old running host produces
`run se down first`. There is no migration approval token or manual upgrade step.
Embedded creation/readback sets owner-only modes per file and never changes the
SE Code process umask. The writer/native resources and join rules belong to 20/30/40.

Post-open calls carry exact G; ordinary callbacks carry exact native epoch/G.
Cloning a handle or restarting the engine cannot rebind an old Arc. Per-call
cancellation/deadline controls grant no authority, and no native transaction or
lock spans an await. Native effects commit and are independently queried by their
original identity after a lost reply.

Embedded binding returns a generation-bound in-process session handle. It does
not issue a transport credential or append credential-issued/activated events.
External MCP/IPC/hook authentication still verifies actual credentials on every
call. Owner intent markers and callback objects are trusted same-process seams;
wire input, model tools and an invented actor string cannot manufacture them.

The factory supervisor retains actual resource handles independently of `Host`.
Writer/lease/shared-collector faults, activate/drain/close panics and migration
failure after resources start poison G. Restart closes/joins it independently,
resolves uncertain commits, then prepares a fresh G after proved closure. A live
unjoinable writer quarantines ownership and refuses a successor. Other API/session
faults fence their route; bounded task-restart policy is in 40. No destructor
blocks, runs cleanup futures or claims that catching unwind proved rollback.

## 6. Native input and live handover joins

SE Code owns its existing sole provider-input queue and binding registry. Human
holds, takeover holds and revocation remain distinct. Promotion/admission use
native atomic transactions and exact active-session point reads; an interrupt
acknowledgement alone proves neither idle nor process absence. Native mail carries
IDs/digests, preserves original notice admission and never writes read markers.

Live SE Code↔daemon handover is required before alpha. `HostFactory::handover` is
the generation-independent control entry; `HandoverServices` is separate from
ordinary callbacks. Its retained queue identity, original immutable plan and
request-key index survive native epochs and factory loss before Prepared.
`queue_state_for_request` performs bounded typed discovery before allocating a
replacement; changed fingerprints or unreadable evidence refuse. Discovery
cannot authorize ownership or settlement.

The factory verifies store phases, current ownership/lease, original plan and
fresh native adoption; the permissive adapter has no proprietary store reader.
Checkpoint owner records the original freezing epoch; a recovery settlement
records the actual settling epoch without rewriting plan peers/generations.
A competing plan cannot overwrite an open fence. Reverse transfer first settles
its predecessor through the factory, then starts a new explicit transfer.

Participating agents cancel immediately, not at natural turn completion. Exact
`active_session Present(None)` and the external harness witnesses precede
Prepared. The transfer fence protects human and native-mail admission/promotion
and retained input/adoption/dedupe/independent-hold state. Only the factory's
verified terminal resolution removes that fence; no timeout or bare owner event
can do so. Terminal reports contain settled queue state. A verified Aborted
receipt means the abort completed, not successful activation.

Sections 20/30/40 own the final crash-safe phase set, native custody/capture,
pre-Prepared abort and checked Recovered owner/completion proof. Source-resource
closure precedes settlement; ordinary old-G routing stays fenced afterward.
Dormant native routes report `WaitingForSecode`, preserving pending input/mail.
Default SE Code exit with live agents hands back to detached `se up`; its daemon
exits ten minutes after its last live agent. Ordinary `se down` stops its owned
agent scope and prints achieved witnesses plus original-conversation resume argv.

## 7. Qualification and next implementation boundaries

[80 — budgets](80-performance-budgets.md) owns the single numerical budget table;
[90 — strategy](90-test-strategy.md) owns the outside-agent-tree judge and missing
native/runtime proofs. First-bound and post-task memory measurements include the
actual FULL set, without embedded credential events. B3's embedded process count
is measured with no live agent; a handback daemon is counted in its actual mode.
The linked declarations do not establish any performance, crash or native result.

[95 — work breakdown](95-work-breakdown.md) owns the build order and generated
size table. Standalone Windows/Linux is an intermediate milestone; done includes
all five journeys, real Claude and Codex, standalone and embedded, plus borrowed-Mac
qualification before alpha release. Atlas is compiled only into the standalone `se`; it is disabled by default and enabled by `atlas.enabled = true` in config.toml; in embedded SE Code that setting returns feature-unavailable. Atlas is built after
the journeys and handover; it cannot hold a milestone. Forget remains before
release, after the journeys. No factory cutover or Rust implementation is admitted
by a compilation result or by this index.
