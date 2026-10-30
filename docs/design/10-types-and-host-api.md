# 10. Foundation types and the embedded host API

Design candidate, 2026-10-30. Owner: Iris. Assignment: msg-425dfde8ccb94a5a5019f64a;
API ownership/panic decision: msg-2d0497bcc528d95036d3d2a3. The subsequent Prime
foundation decision in msg-e32a731023bb474adec95653 expressly requires real,
constructible se-types implementations. That exception applies to pure foundation
values only. Host/API source remains trait/data declarations, with no host,
authentication, queue, store or panic-wrapper implementation.

Base: rust-se main 617d312, with the reviewed shared foundation and section 30
process declarations. The current OPS contract governs helper targeting and
scoped full-body listing. The small foundation delta here aligns credential/
observation namespace exclusions and registered exceptions with Nell's final
section 20 matrix; the host API remains declarations only.
The complete public source reference is in the appendix. Compiler/consumer checks
are representation checks, not a claim that a journey or runtime budget passes.

## 1. Purpose, authority and boundaries

`se-types` is the proprietary internal vocabulary used by the store, core,
process layer, host and CLI. SE Code does not compile against it. The host-facing
traits and DTOs belong to a small permissive crate owned by SE Code; our host
implements that external contract and maps into these internal types. Its compiled dependency on another workspace crate
is zero. It has no filesystem, environment, network, process, clock, random-source,
runtime, background task, database handle or global current actor. It cannot
create a Tokio runtime, own a thread, signal a PID, settle a message, or claim that
a write committed. It implements representation validation, codecs, window consistency and total
error-to-remedy mapping. Version negotiation and runtime policy are host logic.

The synthesized `rust-plan.html` and reviewed `docs/OPS.md` override the older
section drafts. In particular: the product has one SQLite registry store; public
operations are only the OPS rows; every writer uses the same store implementation;
notification is a post-commit nudge; no database polling watcher is introduced;
Atlas is optional and uses a separate database; live SE Code/daemon handover is
after alpha; aliases are static refusals; refusals are not an event-history family.
This chapter defines service seams, not new commands or tools. It does not revive
HTTP mail v1/v2, factory orchestration, a generic extension loader or an old alias.

Responsibilities remain separate:

| Owner | Responsibility |
| --- | --- |
| se-types | Representations, versioned contracts, pure validation and codecs |
| se-store | Durable data, snapshot/cursor scope, migrations, transactions, idempotency and readback |
| se-core | The operation registry, authentication/authorization rules, identity and message/decision semantics |
| se-proc | Native observation, pinned handles, process custody and outside stop witnesses |
| se-host | Runtime composition, session tasks, bounded subscriptions, delivery debt and generation lifecycle |
| SE Code API crate (MIT OR Apache-2.0, Alpha's tree) | Trait and DTO definitions only, API versions, public not-included stub contract; no proprietary dependency or runtime logic |
| SE Code adapter (Alpha's tree) | Panic-catching call boundary, durable holds, native target registry, the one provider-input queue, notice admission/promotion and active-state observation |
| CLI/MCP adapters | Decode and render the same operation inputs/outputs; neither supplies authority through an actor argument |

A value's constructor proves representation only. Public in-process authority
sealing is permitted for the trusted host implementation, never as a wire decoder
or model operation. This follows the project's in-process trust boundary: a
malicious same-process caller is not a defended boundary. Mistakes, stale handles,
wrong sessions and changed generations still refuse at every operation boundary.

## 2. Normative Rust and implementation boundaries

The appendix copies the actual foundation source and the separate permissive API
proposal. Foundation is implemented and compiler-checked under Rust 1.97.1;
its constructors and serde readers enforce representation invariants. API source
is checked independently as a crate root and contains only traits, data and
constants. There are no placeholder bodies, author tests, runtime wiring or
in-process test substitutes. The API file has no dependency on se-types.

Concrete values use inherent methods rather than one-trait-per-value shells:
IDs provide PREFIX/from_parts/from_bytes/from_legacy/from_registered_legacy/as_str
and Display/FromStr;
opaque values provide new/as_str and Display/FromStr; counters provide new/get;
generations add successor; Sha256 provides from_bytes/parse_hex/as_bytes/hex.
NativePath, ProcessInstance, Window and Page have validating constructors.
Read provides map/as_ref and presentation helpers. Receipt provides validate and
committed_value. Code/Detail/ErrorBody own error metadata and rendering.

The remaining foundation traits express genuine cross-crate seams:
LegacyIdRegistry resolves exact historical registrations in a scoped authorized
source snapshot, without a global registry or name heuristic. OperationCommand converts a core generated operation input to literal argv;
RemedyCommands asks that same core registry for the operation remedy. Standard
serde/JsonSchema traits describe wire values. No separate runtime operation table
is maintained in this crate. Explicitly import Read/Cursor/Result to avoid names
colliding with std::io and standard Result.

Wire identities are strings, not derived byte arrays. Invariant-bearing private
values use validated Deserialize implementations; ordinary public DTO fields are
claims, not custody or proof of a commit. Serializing a Receipt directly does not
make its fields true: its producer must obtain them from the store and call its
validator. Credential buffers and local Error causes never enter ordinary JSON.
The only arbitrary JSON payloads are registry-validated tool data, schemas and
outputs; Value is never an actor, process handle or raw SQL operation.

## 3. IDs, process identity and primitive formats

### 3.1 Domain IDs and legacy history

New domain IDs are distinct kind-prefixed, lowercase canonical UUIDv7 strings
with the RFC variant. FromStr is strict: a wrong prefix, other UUID version,
uppercase/noncanonical suffix or malformed value returns UsageInvalidValue.
Debug and Display both print canonical ID text, never an internal byte array.
Each type is Eq/Ord/Hash/Clone with string serde and JsonSchema.

| Type | Prefix | Design source / meaning |
| --- | --- | --- |
| ProjectId | prj_ | Registered project, overview/data |
| AgentId | ag_ | Registered agent, overview/data |
| HumanId | hu_ | Human actor distinguished from Agent in data actors |
| SessionId | ses_ | Durable launched/bound conversation |
| MessageId | msg_ | Durable message |
| DecisionId | dec_ | Durable decision |
| EventId | ev_ | Append-only event |
| LaunchId | lch_ | Launch attempt referenced by LaunchInFlight |
| ObservationId | obs_ | Caller-scoped process observation referenced by process errors |
| StoreId | store_ | Durable registry/store identity used for source/cursor scope |
| LifecycleId | life_ | Process/runtime lifecycle identity retained across observations |
| AtlasRootId | aroot_ | Cache root provenance, Prime's approved Atlas addition |
| IndexEpochId | aidx_ | Optional cache index epoch, never history authority |

from_parts takes a supplied 48-bit millisecond timestamp and 80 random bits;
UUID version/variant consume six of those bits. It acquires no clock or entropy.
The caller supplies unique time/entropy combinations and handles clock rollback;
repeating identical inputs repeats the ID. from_bytes requires UUIDv7/RFC bytes.
No rowid, display label or raw PID becomes a domain identity through formatting.

Imported Node IDs retain their original spelling, per section 50 and Prime's
review decision msg-76bbe9679112584038aea3cb. The producer matrix agreed with
Nell in msg-dad7f38d5c079b0992ff4e87 supplements strict UUIDv7 decoding:

| Type | State-free supported legacy wire form |
| --- | --- |
| AgentId | agt- plus three four-character Crockford-base32 groups separated by hyphens |
| HumanId | The same serial under hum- |
| ProjectId | Node registry project grammar: 1..128 ASCII letters/digits/dot/underscore/hyphen, alphanumeric first, no trailing dot or Windows device-name stem; reject other known ID namespaces and bare UUID shapes |
| MessageId | msg- plus at least eight lowercase hex digits, within the 512-byte ID cap |
| SessionId | se-session-sha256- plus 64 lowercase hex; canonical UUIDv4 from a recorded provider/session; se- plus canonical UUIDv4 from identity-session-adapter |
| DecisionId / LaunchId / LifecycleId | Bare canonical RFC-variant UUIDv4 from their documented Node producers |
| EventId | evt- plus 64 lowercase hex |
| ObservationId | semantic-observation: plus 64 lowercase hex |
| StoreId / AtlasRootId / IndexEpochId | No Node producer grammar; canonical new IDs only |

Sources are Node agent-registry.mjs/generateAgentId, humans-registry.mjs,
msg-id.mjs/MSG_ID_RE, validation.mjs/validateProjectId, identity-session-adapter.mjs/
mintSessionId, session-loop.mjs and process-lifecycle.mjs, plus Nell's complete
source-pinned import matrix in section 20 (Node source a1b09788ef79fcbcd3bca7f6cdd9535d80afcf3d). The independent local Node source inspected is 0e47c3c0. Bare UUIDv4 deliberately overlaps only
its documented producing families; spelling alone never proves kind or existence.

Ordinary serde/TryFrom<String> accepts a type's canonical new spelling or precisely
its producer grammar. from_legacy uses that same grammar; it is not a generic
arbitrary-string escape. New-ID FromStr remains UUIDv7-only. New prefixes, including the reserved cred_ namespace, cannot
be used as a malformed-UUID legacy bypass. A raw selp- bearer is never a public
ID; it refuses even at the registered-exception constructor. Known observation
namespaces are excluded from broad project decoding; a truly registered old
project spelling overlapping a legacy namespace uses the contextual exception
route instead. A wrong canonical prefix is never that exception. JSON Schema includes the supported
own-kind alternatives and excludes an arbitrary string for AgentId.

Custom historical agent names or supplied session/decision/process IDs require
from_registered_legacy and an explicit LegacyIdRegistry snapshot that verifies
exact kind, project and source. This is an import/core boundary, not authority
acquired by constructing an ID. The constructor has no registry I/O or ambient
fallback; registered custom wire values must use that contextual decoder on the
receiving side, never the state-free serde path. That distinction permits old
registered names without hard-coded operator defaults or accepting every string
as every ID type. Core still resolves project/permissions before any action.

### 3.2 Opaque values, counters, Secret and Body

Opaque values are ASCII graphic strings without whitespace, controls or NUL.
The originating subsystem owns any narrower grammar and scope validation.
Cursor <=4096 bytes; MachineId/BootId <=256; native session/event/pending/provider
IDs <=512; IdempotencyKey <=128; NoticeId <=256. Native SE Code IDs keep their
existing opaque spellings. Opaque Debug/Display is diagnostic, not a credential.

Sequence, UnixMillis and UnixMicros accept 0..=i64::MAX. Sequence::ZERO is an
empty snapshot boundary. Recorded observation timestamps use UTC UnixMicros;
UUID timestamp construction alone uses milliseconds. Generation and
HostGeneration are distinct nonzero u64 values with checked successor; an engine
restart does not itself replace the host process epoch or durable SessionId.
A store may impose a narrower encoding at its own boundary without truncation.
Sha256 is 32 bytes with exactly 64 lowercase hex digits on the wire.

Secret owns 1..65536 bytes, has no Clone/Display/serde, prints only [redacted] in
Debug and zeroizes its allocation on drop. expose provides a borrowed protected
slice only at the intentional transport/storage seam. Copies made by a caller
are that caller's custody; this wrapper cannot erase someone else's allocation.
Body validates UTF-8 text up to 1 MiB, hashes its bytes once, serializes as a string
and prints only byte count/hash prefix in Debug. Body is ordinary authorized
content, not Secret. Core applies operation-specific smaller limits and consent.
Oversize data raises InputTooLarge with bytes/limit rather than silent truncation.

### 3.3 Cursor and source ownership

Cursor is an opaque bounded token. It exposes no sequence-extraction, MAC or
scope constructor. se-store owns its versioned codec, key custody, canonical
encoding, MAC verification, retained upper snapshot and principal scope (owner
or authenticated agent). CursorScope is intentionally absent from se-types.
Store/project/principal/query mismatches and foreign-origin tokens raise
CursorInvalid; unavailable retained history raises CursorExpired. A cursor
narrows an authorized query; it never grants access. No reader guesses another
subsystem's cursor layout. Durable mail traversal can survive engine generations;
generation-sensitive callbacks still validate the current handle separately.

Source distinguishes authoritative Store, native Host, Configuration and optional
Atlas cache. Source::Atlas carries project, typed AtlasRootId and optional
IndexEpochId; no populated epoch means no epoch was verified, not index zero.
Atlas provenance labels atlas.db and never substitutes for history or store
truth. Read absence diagnostics and Window snapshot metadata retain source.

### 3.4 ProcessInstance and NativePath

ProcessInstance is a serializable observation tuple: machine, boot, nonzero PID,
platform start identity, native executable path and SHA-256 of full literal argv.
from_observation is a pure representation validator; it checks OS/path pairing
and valid Mac microseconds. compare returns Same only for full tuple equality.
It cannot observe an OS, pin custody or authorize a signal. se-proc alone issues
OwnedProcess custody after a fresh outside read/pin. Thus allowing construction
or decoding of an observation DTO does not let a caller construct OwnedProcess.

| OS | StartIdentity | Outside behavior owned by se-proc |
| --- | --- | --- |
| Windows | Nonzero creation FILETIME | Match machine/boot/PID/start/image/argv; pinned handle/job witnesses stop |
| Linux | /proc start ticks plus boot identity | Match full identity; pidfd and group/session custody witness stop |
| macOS | proc_pidinfo seconds/microseconds, micros < 1,000,000 | Match full identity; process/kqueue/group witness |

NativePath preserves Unix bytes or Windows UTF-16 units including non-UTF-8 bytes
and unpaired surrogates. Tagged wire form is unix_bytes/windows_utf16; max32768
units, nonempty, absolute in originating grammar, no NUL. from_local/to_local use
OS string conversion without filesystem I/O; foreign encoding to_local refuses
UsageInvalidValue. History may retain a foreign observation without signalling it.
Equality is exact. Symlinks, canonicalization, ACLs, synced/network storage and
executable normalization require external observation, never lexical guessing.

## 4. Error and remedy model

One codes! table in error/catalog.rs defines the current section 50 catalog:
**163 codes**, including message-scope-denied. The macro generates Code, wire
names, Class, one typed details struct per code, the Detail tagged enum, message
and remedy matches. Adding a row requires all metadata at compile time. There is
no generic Detail::None or arbitrary exception-string substitute for the catalog's
arrays, IDs, counts and reason fields. Code is non_exhaustive for consumers;
the generated internal metadata matches are exhaustive. Catalog evolution must
update section 50 and this table together.

ErrorBody is Clone/Eq/serde/JsonSchema and owns Detail plus Retry. Code and Class
are computed from that Detail, so an independent contradictory code is impossible.
SeError adds an optional local Box<dyn Error + Send + Sync> cause and implements
Display/std::error::Error. It is deliberately not Clone or serializable. Read,
Receipt and failed effects carry ErrorBody, never the local source exception.
Retry is Never/AfterReread/After(Duration)/WhenRuntimeReady and is chosen by core
semantics; a default Never is not an automatic retry policy for all operations.
After serializes as a u64 whole-millisecond value, not Duration's seconds/nanos
object. Sub-millisecond or overflowing durations fail serialization explicitly
rather than round/truncate a retry deadline.

Code.message/remedy require the matching Detail; a mismatch refuses rather than
rendering another error's fields. Detail supplies typed values, RenderCx supplies
authorized optional project/agent and an optional RemedyCommands resolver. Missing
context is shown as AGENT/PROJECT/DIR in human templates, never guessed from cwd.
Array placeholders name their source, e.g. {stopped.len}; unrelated arrays
cannot change a count. Arrays render joined with comma/space and UnixMicros
renders UTC calendar time with six fractional digits, while its serde remains
an exact integer. Detail braces are data, not recursively expanded templates.
Human template text is display-only. An executable Cmd::Se contains literal Argv
constructed through Argv::from_op on a canonical core OperationCommand. There is
no public raw argv constructor, shell program or placeholder execution. Decoding
Argv only validates transport representation; it does not authorize an operation.
Cmd::Tool uses an owned String and registry-validated arguments; Cmd::Manual
provides explicit human work. RemedyCommands lets core choose an actual typed
operation without introducing a reverse dependency or a second operation table.
Without that resolver, rendering yields actionable text and command=None, not a
fabricated command. CLI/MCP composition must provide the resolver where the
catalog's remedy supports an admitted operation.

Wire se.error/v1 is schema, code, class, exit, message, detail, remedy and retry.
ErrorEnvelope derives class/exit from ErrorBody and renders its message with
explicit RenderCx scope. Decoding refuses contradictory class/exit/schema or
empty messages; it does not reconstruct a contextual human string from a body
that deliberately lacks the renderer's context. Output detail tolerates additive unknown fields in its
serde DTOs. Closed operation inputs remain core's responsibility. Source
exceptions, credentials, captured bodies and unredacted raw argv are never error
fields. Human failures use stderr; JSON uses stdout; MCP sets isError and retains
the same structured facts. Refusals are not an event-history family.

| Raised situation | Existing Code / class | Legal remedy |
| --- | --- | --- |
| ID/counter/digest/path or inconsistent Window/Page | UsageInvalidValue / Usage | Correct the named field; no guessing |
| Oversized opaque value/body | InputTooLarge / Usage | Shorten/split within named byte limit |
| Wrong cursor scope/MAC or expired snapshot | CursorInvalid / Usage; CursorExpired / Incomplete | Open an authorized bounded traversal |
| Foreign store identity/read failure/newer schema | StoreUnreadable / Unreadable; StoreTooNew / Refused | Preserve data; doctor or use compatible product |
| Measured absent required store | StoreAbsent / Refused | se init |
| No API range intersection | ApiVersionUnsupported / Refused | Upgrade incompatible side |
| Wrong bound project, invalid/revoked credential, missing grant | ProjectConflictsSession / Usage; CapabilityInvalid/Revoked/GrantRequired / Unauthorized | Legitimate rebind/grant, no owner fallback |
| Stale engine generation | SessionGenerationMismatch / Conflict | Refresh binding from authoritative state |
| Lost once-returned binding credential | SessionBindingUnproven / Unauthorized | Authorized new-key rebind/revocation, preserve conversation |
| Same key or NoticeId, changed payload | IdempotencyKeyReused / Conflict | Recover original or issue an explicitly new request |
| Target CAS changed | RevisionConflict / Conflict | Reread, no unconditional overwrite |
| Changed/unreadable live process | ProcessIdentityChanged / Refused; ProcessIdentityUnreadable / Unreadable | Do not signal; re-observe custody |
| No runtime / incomplete drain | RuntimeNotRunning / Unavailable; RuntimeDrainTimeout / Incomplete | Start runtime or inspect/retry named obligations |
| Callback uncertain at deadline / cancellation | DeadlineExceeded / Unavailable; Cancelled / Cancelled | Read back original keyed effect before retry |
| Capture lacks consent | CaptureConsentMissing / Refused | Obtain consent |
| Engine panic / invariant fault | TaskFailed or Internal / Internal | Poison this generation; preserve nonsecret diagnostics |

Native Held is NoticeAdmission::Held, not a revoked-capability error or invented
Code. Public ApiFailure includes NotIncluded/EnginePanicked/GenerationPoisoned;
the permissive error retains precise engine code text and remedy without depending
on proprietary Code. Unknown edge errors remain errors. Class exits are Usage64,
Unknown4, Unreadable3, Incomplete2 and all other errors including Cancelled1.
Measured absence/zero is success0. Failure is never converted to Absent/empty.

## 5. Read, Page and Window

Read<T> is Present{value}, Absent{checked:String},
Unreadable{source:String,reason:String,error:Option<Box<ErrorBody>>}, or
Unknown{what:String}. Those checked/reason strings match section 50 wire shapes;
the optional structured error is additive. Checked is a typed helper used to form
an absence diagnostic containing source, snapshot and supplied UnixMicros time.
Read::map/as_ref preserve all non-present facts. Absent requires an actual
successful authorized lookup; Unknown says that proof does not exist.

WindowFields retains typed Source, exclusive from/inclusive to sequences,
start/end opaque cursors, returned/item limit, encoded bytes/max_bytes,
omitted-before/after, unreadable count and stop reason. from==to permits only an
empty page. Filtered-out rows outside the requested predicate and rows before an
explicit starting cursor are not omissions unless the operation promised them.
Matching unreadable rows are counted, never silently skipped.

Omission is None, Known{positive count,reason}, or Unknown{reason}. Wire reasons
are exactly limit, budget, unreadable and source-incomplete. Combining unknown
counts retains unknown; checked count addition refuses overflow. If unreadable
rows overlap another omission, the combined count is unknown rather than double-
counted. Precedence is unreadable > source-incomplete > budget > limit.
Window::new validates bounds/items/bytes and demands a stated omission for any
non-exhausted stop. complete is derived: no omissions, no unreadables, Exhausted.
StopReason preserves diagnostic ItemLimit/ByteLimit/Unreadable/Cancelled/Deadline/
Unsupported without changing the canonical omission vocabulary.

Window wire fields are from/to opaque cursors, limit, complete and omitted;
an optional additive snapshot object retains typed producer source/accounting.
A minimal A.0 Window without that object decodes without inventing a source,
sequence, byte count or returned count: fields() is None. When metadata exists,
decoding reconstructs and checks every duplicated summary field. Page<T> validates
count<=limit, the producer returned count when supplied, no continuation on a
complete page, a continuation for known omitted-after rows, and continuation
different from start. A minimal limit/budget wire Window also requires next.
Page does not serialize/recount items: producers own body/encoded byte accounting
and enforce their advertised cap; treating a body-byte count as JSON size would
reject valid escaped/quoted values. Store verifies the
MAC, fixed upper snapshot, predicate and actual continuation progression; a
foundation comparison cannot infer order from opaque token text.

Generic limit/budget pagination exits0, unreadable/source-incomplete exits2.
Inbox's require_all flag maps any incomplete window to2. Read itself exits0 for
Present/Absent,3 for Unreadable,4 for Unknown. An empty incomplete page proves
neither absence nor zero unread messages. A reader cannot report complete after
silently excluding an oversized first item; it returns the explicit too-small-
budget failure/remedy rather than an endlessly identical cursor.

PageRequest has after and nonzero limit/max_bytes. Core applies negotiated policy
maxima before scanning. Byte budgets are encoded UTF-8 bytes; the host includes
outer envelope overhead in its response cap, beyond item-array accounting.
JSON syntax is never cut to fit. BoundedText is used only for explicitly partial
text with original/omitted facts. Both CLI/MCP and sync/async readers preserve
these completeness/error states.

## 6. Receipts and effect state

Receipt<T> has Committed, Replayed, Refused and Pending states. Committed flattens
event_id, nonzero sequence, idempotency_key, value and EffectStatus into the wire
receipt. Replayed contains that original commit, not a second event. Refused
carries ErrorBody with no value/event claim. Pending carries Queued/AwaitingWitness/
Recovering, the key and optional actual intent event_id, never a speculative value.
Decoded receipts validate nonzero commit sequences and outside witness order;
public in-process producers must also call validate before exposing their DTO.
A constructor/serde roundtrip is never evidence of a real store commit.

EffectStatus is NotRequired/Pending/Witnessed{EventRef}/Failed{ErrorBody},
independent of commit state. Witness sequence must follow the commit sequence.
A send may be committed with effect Pending. A queued notice is not recipient
read, and recipient read is not task completion. committed_value returns a value
only for Committed/Replayed. Local OS causes never block equality or wire codecs.

| Existing state | Input / outside fact | Result |
| --- | --- | --- |
| Request | Rejected before durable work | Refused or outer Err for transport/validation failure, no commit claim |
| Request | Durable intent, work unfinished | Pending with actual intent event_id if present |
| Request/Pending | Store COMMIT succeeds | Committed with original key/value/event |
| Committed | Same key and canonical request hash | Replayed with original commit |
| Committed | Same key, different request hash | IdempotencyKeyReused, original untouched |
| Pending effect | Outside witness succeeds | Witnessed with a later event |
| Pending effect | Outside effect fails | Failed with preserved ErrorBody; original commit remains |
| Any committed result | Reply lost/cancelled | Recover by original key; never relabel as uncommitted |

Err is for failure to produce the operation outcome (including pre-dispatch
validation); Receipt::Refused records a domain refusal in an outcome/lookup that
needs the full state machine. Neither adds a persistent refusal-event family.
Only se-store produces actual committed receipts after its chosen durability
barrier. This chapter does not choose a weaker SQLite sync/flush mode.
WriterMode belongs to se-store per section 50's writer-stamp decision: the store's
Committed wrapper and family dispatcher add the host/direct writer stamp. A bare
generic se-types receipt cannot mint or attest that writer identity.

## 7. Versioned service boundary owned by SE Code

### 7.0 Repository and licensing split

Prime's ownership decision supersedes the earlier idea of placing the linked host
API in se-types. Proposed crate name: `secode-stateengine-api`, in rust-secode,
licensed MIT OR Apache-2.0, trait/data only. Alpha owns its name, Cargo version,
API versions, DTO evolution and the public not-included implementation. The public
SE Code build depends only on that permissive crate and its stub; it never pulls
in proprietary se-types, se-core or se-host. The commercial build links our
implementation behind Alpha's feature/composition boundary. The stub returns an
explicit ApiFailure::NotIncluded for engine-dependent calls, never empty history,
a fake binding, a running daemon or a successful no-op hold/notice admission.

`docs/design/secode-stateengine-api.rs` is proposed permissive source checked separately as a standalone crate root
solely to make this design reviewable now; it imports no crate-local type.
It carries the proposed permissive SPDX notice and is NOT a published API or an
implementation in Alpha's tree. After Alpha accepts/lands the API crate, remove
this proposal copy and depend on Alpha's exact reviewed revision; never maintain
two authoritative copies or publish our own competing API version. The standalone
compile check treats this file as its own crate root, proving it needs no se-types
code. No change to SE Code 0.1 is authorized by this candidate.

The proprietary se-host adapter is the sole translation boundary. Public DTOs
contain raw, typed wrappers/fields; their construction grants no authority. Every
incoming value is checked, and every outgoing completeness/receipt is derived
from the actual internal result. There is no duplicate operation executor or
second message queue hidden in this mapping.

| Permissive API representation | Proprietary internal mapping |
| --- | --- |
| ID wrapper around String | Own-kind canonical/legacy decode; custom names require the scoped registry resolver; core verifies kind/project |
| Cursor(String) | Validate bounded opaque syntax, then let se-store verify origin/MAC/audience/query |
| u64-based Sequence/Generation/HostGeneration/UnixMicros wrappers | Check ranges/nonzero; retain distinct host/engine epochs |
| ProcessInstance DTO with current native PathBuf | Convert to ProcessFields/NativePath, validate OS/start/time/path/hash; never create OwnedProcess |
| ApiError(kind,code,message,remedy,retry) | Code/Class/Detail/Remedy mapping, explicit NotIncluded/EnginePanicked/GenerationPoisoned; unknown codes retained as unsupported/error, never absence |
| Raw Read/Page/Window/Receipt containers | Validate all accounting and scope before internal use; outgoing containers preserve every non-present/pending/omission fact |
| OwnerProof / credential bytes | Core/proc authenticate protected presentation; no credential in argv/debug/ordinary JSON |
| OwnerAuthority / BoundSession opaque grant | Engine-issued in-process handle, validated against this instance, generation and durable scope on every call; raw identity claims do not authenticate it |
| MailNotice / NoticeAdmission / HostSessionTarget | Validate stable digest/target/epoch, route through existing core debt and SE Code native queue only |
| HostFactory / Host / HostServices | se-host implements the engine-facing traits; SE Code implements callbacks and catches the entire asynchronous API edge |

ApiError is deliberately a small public transport vocabulary, not a dependency
on our Code enum. ApiFailure maps Usage/Refused/Unauthorized/Unknown/Unreadable/
Conflict/Incomplete/Unavailable/Cancelled/Internal plus NotIncluded, EnginePanicked
and GenerationPoisoned; the precise stable engine code is retained as text with
its remedy. Public code/schema ownership remains Alpha's. The data crate has no
validation or negotiation implementation, catch_unwind, runtime, I/O or store.

### 7.1 Negotiation and call rules

The proposed SE Code-owned API_VERSION is 1.0, independently of the internal
CLI/IPC se-types::API_VERSION (also initially 1.0). Neither version may be used
to infer compatibility of the other. ApiRange represents one major and inclusive minor interval.
Reject min>max; require equal major; choose the highest minor in the intersection;
otherwise ApiVersionUnsupported with both ranges. Features are closed NativeMail,
LocalListener and optional Atlas, intersected with compiled/allowed host features;
a required unsupported feature refuses. Every response uses the negotiated
schema; new required fields, changed meanings, changed existing error/tag behavior
or removal require a major bump. Additive optional inputs are sent only after
negotiating the minor that supports them. Unknown operation inputs refuse.
Decoders retain the raw failure for an unknown required tag/code; they never map
it to success, an empty page or a generic absent value.

StoreVersion is independent: application_id and schema. Host open refuses a
foreign application_id (StoreUnreadable) or newer schema (StoreTooNew) before
any write; only the host performs
a supported forward migration. An existing project attach is a cheap lookup with no migration/adoption/setup
commit. HostFactory runtime ownership may require its own durable lease metadata;
that cost must count in startup, not be hidden past first bound readiness. HostFactory is configured with the embedding
runtime before open: the API data crate and se-types never accept/create a Tokio runtime. This public
SE Code API requires HostIntegration::Secode and HostKind::EmbeddedSecode.
Standalone composition uses the same proprietary core/host internals with real
harness/proc adapters; it does not invent a no-op SE Code HostServices. The API
crate is not an additional standalone daemon protocol.

Every host operation uses HostFuture (boxed Send future with explicit borrow
lifetime) and CallOptions (expected engine generation, timeout and caller cancellation). Host and HostServices
are object safe. No mutex/store transaction survives an await. Timeouts apply to
a call, not an authority lifetime. Cancellation before commit may refuse; after
commit it preserves receipt and durable debt. Futures are dropped without assuming
that the remote/native operation did not commit. Secrets, authority and database
connections are never deserialized from tool arguments. Public credential DTOs have no
Debug/Clone/Serialize/Deserialize; receiving protected bytes does not authenticate them. The trait/data crate
cannot itself promise buffer erasure on drop; SE Code and proprietary protected-
storage owners must retire/erase their own allocations without logging them.

### 7.2 Host methods and authority

| Method | Contract and definitive result |
| --- | --- |
| HostFactory::open | Negotiate, open/validate store, establish usable services; Read::Absent if store is measured missing, Unreadable for failed access; never implicitly init; Present returns one shared host plus truthful recovery state |
| negotiated | Return selected API/store/generation/features/limits, no I/O |
| poison | Mark the exact current generation faulted, gate its admissions and preserve durable obligations; does not undo committed native transitions or release human holds |
| authenticate_owner | Verify machine credential and presenting process/OS-user authority through core/proc; typed OwnerProof alone is not evidence; agents cannot obtain human-only approval by this call |
| verify_capability | Per-call credential/session/revocation validation, no ambient fallback; yields a generation-bound handle |
| open_project | Authorized existing lookup, no implicit initialization, root selection or adoption |
| bind_session | Owner or one-use launch proof; validate project/agent/conversation/consent/target and expected generation; commit one binding; return capability only through protected output, once; retry cannot return a newly minted secret or duplicate session |
| revoke_session | Owner-selected or bound-self scope only, generation CAS; retire native target and credentials through durable intent/recovery, never fabricate process stop |
| tools | Registry-generated input/output schema catalogue, session permissions/features and bounded page; no unknown-name backdoor |
| call_tool | Registry-only MCP operation by bound identity, no project/actor overrides; core validates closed inputs and returns its versioned output/error |
| continuity | Read-only pre-provider barrier; context retains secode.session-context-v1 identity/provider/model/packet/model input/UTF-8 size/truncation/window/warnings; packet acknowledgment verifies digest and authenticated binding |
| capture_turn | Consent and conversation/source validation, bounded content, natural vendor-turn/idempotency dedupe; records capture, not task success |
| subscribe_mail | Atomic snapshot/subscription at durable cursor, bounded stream and exact binding; no notification before send COMMIT |
| settle_mail | Records a verified native notice admission/replay/hold/refusal result, not Read/Dismissed markers; core message.read/ack/dismiss own those markers |
| adoption_status | Owner inspection page with pending/reattached/held/revoked/absent/unreadable, never an empty success on recovery failure |
| drain | Gate admissions for expected generation, cancel/join its work, persist delivery cursors/debt and flush writer; report unresolved effects honestly |
| reopen | Require a completed drain of the actual current instance, reopen store and publish checked successor; stale supplied receipts do not override internal state |
| close | Idempotently finish the drained instance; retain durable sessions/holds/debt, release resources after join; no new generation |

One real Host is opened per runtime owner, shared by Arc; the public stub opens
only an explicit not-included result. The HostFactory implementation
must detect duplicate opens for the same runtime scope; it does not create another
writer/listener per project or session. A state-home lock/native ownership is
se-host's job, not an authorization granted by a HostConfig path. Canonical
state-home/store identity scopes an exclusive runtime owner; concurrent opens
serialize before migrations or publication. Existing verified same-process opens
share that owner; a different live daemon/SE Code owner returns
RuntimeOwnedElsewhere, since live handover is after alpha. Stale owner records
require an exact process-identity outside witness before takeover. Unreadable
ownership is not stale/absent, and a lease timeout alone cannot authorize stealing
a running writer. Lock/lease acquisition cost counts toward open readiness.

SessionIdentity is the durable project/agent/session tuple. BoundSession adds the
current engine Generation, binding revision and protected grant. HostEpoch is the SE Code
owner ProcessInstance plus HostGeneration. HostSessionTarget binds that epoch,
SE Code's native session ID, durable SessionIdentity and binding fingerprint.
The three concepts must not be conflated. Current generation is rechecked at
execution, not only at decode. Opaque API grants are issued by the implementation only after credential/grant
resolution, and revalidated before dispatch; a DTO carrying claimed IDs is not
such a resolution. Invalid/revoked capabilities never fall back to Owner or Anonymous.

IssuedSession contains a capability exactly once plus a committed binding receipt.
A replay whose once-returned secret is no longer in the original protected
custody returns SessionBindingUnproven, retaining the committed binding fact; it
must not return an empty/alternate secret with a successful receipt. Recovery is
an explicitly authorized rebind with a new idempotency key, expected current
binding revision, prior capability revocation and new capability issuance in one
core transaction, preserving the provider conversation. The trusted integration
must complete that recovery before provider admission, not silently start fresh.
BindingRequest.expected_binding_revision=None means first binding only; Some(r)
requires the current authoritative revision r. IssuedSession and BoundSession
return that revision; owner adoption_status exposes it for lost-credential
recovery. A stale revision refuses before issuing a new secret. ProviderSessionId and ModelIdentity retain the real
conversation/provider/model; Harness distinguishes ClaudeCode, CodexAppServer and
Secode. Harness::Secode is an embedding integration, not a new CLI provider or a
permission to reinterpret an existing Claude/Codex conversation.

### 7.3 Continuity and capture compatibility mapping

The linked SessionContext is a new typed API DTO, not a claim to be the old JSON
object. A compatibility renderer, if retained by SE Code, must explicitly emit
secode.session-context-v1 with schema_version=1. Its source contract is the
existing src/session-context-provider.mjs, not an invented generic resume map.
This does not add the old session-context CLI verb back to OPS.

| Existing context field | Linked source / validation |
| --- | --- |
| contract / schema_version | Constant secode.session-context-v1 / 1 only when using that renderer, independent of linked API_VERSION |
| project_id / agent_id / session_id | SessionContext.identity; equality with bound session required |
| packet_id | Present Packet.digest in lowercase hex; missing packet remains an explicit Read failure, never a made-up verified digest |
| source_cli / generated_at | Explicit source_cli / supplied UTC generated_at, rendered ISO8601 |
| identity.agent_id / display_name / role / neutral | display_identity; agent must match bound identity, neutral context cannot pass first-bound readiness |
| assembled_model_input / byte_size / truncated | model_input.text / its actual UTF-8 bytes / !complete; omitted_bytes remains explicit in linked DTO |
| continuity.rows / latest_ts | continuity_summary; full typed continuity Window remains available to new readers |
| warnings | Original bounded strings; structured failures are separate ApiErrors and cannot disappear as an empty warning array |
| provider / model / conversation | Explicit linked ModelIdentity/ProviderSessionId; no display label used as authority |

The old turn input's ts/agent_id/session_id/source_cli/role/content/event_id/
turn_id/machine_id/source_ref/nesting map to occurred_at, the authenticated
BoundSession assertions, source_cli, TurnRole, content, vendor_event/vendor_turn,
machine_id, source_ref and TurnNesting. Event names from a provider are not
StateEngine EventId authority. A legacy adapter supports only User/Assistant;
Tool requires the new typed path, not a changed v1 meaning. Partial content cannot
be reported as a complete captured turn: reject an oversized first body or retain
an explicit partial outcome with its original size. Capture verifies source hash,
conversation, consent, UTF-8 budget and natural vendor dedupe before a store write.
Schema additions/removals follow Alpha's API negotiation; an old decoder receives
only a contract it supports. These field mappings require reviewer consumer
witnesses before compatibility is claimed operational.

## 8. SE Code callbacks, one queue, holds and settlement

Input authority is Alpha's msg-45a1e58b4b70ef181371bbf1 and Gamma's source review
msg-9b84ed3c402f78ca89fe7c93. Source independently read through git transport at
SE Code f4cf8f6d8386accefeef706ddb9a4970e1f12ebb, notably
`crates/secode-inbox/src/admission/{native_mail,native_mail_state}.rs` and
`crates/secode-product/src/dogfood/interrupt_pending.rs`.

Current `interrupt_pending.rs` signals execution before `hold_native_mail_wakes`,
then acknowledges only after the hold succeeds. It already retains the session
hold and native pending rows durably. The takeover callback ordering below is
stronger: hold must commit BEFORE any interrupt invocation, including a wake that
lands between the calls. The design does not claim the current combined HTTP
handler already offers that ordering. Alpha's adapter must expose the split
callback or an atomic stronger operation; reusing the HTTP call unchanged fails
this contract.

### 8.1 Callback contracts (proposed to Alpha for review)

| HostServices method | Required semantics |
| --- | --- |
| hold(target, reason, key) | Recheck exact current target/epoch; commit the session-wide hold even with zero pending native notices, plus necessary per-input holds; preserve pending input; return HostEventRef only after durable commit; exact retry returns original receipt |
| interrupt(held) | Validate receipt against the durable held target and current epoch before signalling; never release hold; success means interruption requested, not idle/absent |
| active_sessions(epoch,page) | Successful bounded snapshot from that exact service; unreadable/unknown remain explicit; absence proof requires exhausting all pages of the same complete snapshot |
| idle(target) | Authoritative Idle/Executing/Interrupting or Read failure; Idle alone does not mean a target was revoked or a TUI process exited |
| binding_state(target) | Read durable target/hold/revocation and activity under the supplied epoch; never infer from an empty process map |
| adopt_binding(previous,current_epoch,key) | Compare the persisted native binding/fingerprint and recorded old epoch, append a durable adoption/CAS to the current epoch, preserve holds/revocation/pending admissions; refuse if original protected custody or persisted mapping cannot be verified |
| update_mail_target(Select/Revoke,key) | One native registry transaction selects the new binding and revokes bounded predecessors, or revokes the exact target; selection preserves an existing human hold and cannot revive a revoked predecessor; under that same transaction every superseded target must still be held and not executing, otherwise conflict |
| deliver_notice(notice) | Authenticate exact live binding/target; admit IDs only into SE Code's existing synthetic pending input queue with stable notice/digest dedupe; commit before returning Admitted; retry returns Replayed with original admitted sequence |
| notice_status(target,id) | Recover committed admission after lost response without admitting again; Absent requires successful exact-key lookup, unreadable/unknown never mean retry under a new ID |

No callback transports message bodies or a session secret as notice text. MailNotice
contains IDs, exact target, stable NoticeId, durable through cursor and dedupe hash.
A store transaction reserves each (durable SessionId, MessageId) delivery debt
for one outstanding stable notice intent before any callback; batches cannot
overlap merely because a subscription/generation reopened. Settlement advances
notification debt only; unread markers remain unread. SE Code constructs its
existing synthetic prompt referencing those IDs. The model
uses its bound StateEngine read operation to fetch bodies. The callback cannot
ack/read/dismiss any message and cannot settle another session's mail.

The canonical notice digest uses a versioned encoding of store/project/agent,
durable SessionId, native HostSessionId, ordered distinct message IDs and the
durable source cursor. It excludes transient engine generation/service process
identity so a legitimate restart can recover the same admission. Host target
routing/epoch is checked separately against the durable binding/adoption map.
Reusing a NoticeId with a different stable tuple/digest is IdempotencyKeyReused, including
under a new generation. `Admission.committed_in` retains the original service
epoch; its target names the current verified routing after a recorded adoption.
The original event/sequence are never replaced by a second admission.

### 8.2 Single queue state machine

| State | Allowed transition | Durable fact / outcome |
| --- | --- | --- |
| Message committed, notice debt pending | Create stable bounded notice intent | No read marker; send remains committed with pending delivery |
| Notice intent pending | Native deliver_notice | Admitted -> one synthetic pending item with admitted sequence/digest; callback response loss -> recovery lookup |
| Native pending item | Exact retry | Replayed original item, no new admitted sequence |
| Native pending item | Next safe promotion boundary | Existing SE Code promotion event selects eligible steer first, ordinary queued input only at idle |
| Native pending, host session held | New mail/reconnect/synthetic input | Remains held/pending; no automatic promotion |
| Native pending, held, genuine human input promoted | Native human-resume transaction | Clear human hold in that transaction; retained eligible work may resume at the allowed boundary |
| Native pending, target revoked | Any human input or reconnect | Remains ineligible; human resume cannot restore a revoked binding |
| Notice admitted/promoted | Host::settle_mail admission report | Notification offer/debt recorded, not recipient read |
| Model performs bound message.read/ack/dismiss | Core operation commits | Only StateEngine updates the authenticated recipient's corresponding marker |

There is no second StateEngine provider-input queue. Subscription buffers are
bounded notification transport, not independent prompt schedulers. There is no
resume boolean a mail sender can set. An explicit resume flag, fresh mail,
synthetic input, reconnect and origin=seat-startup cannot clear the native human
hold. Actual human-origin validation and promotion live in SE Code; no tool or
public library function named release_hold exists here. Diagnostic UI notices
are not native-mail synthetic admissions and are never reused as provider work.

### 8.3 Hold/revocation state machine and takeover

Held and revoked are distinct dimensions: eligible, human-held, or target-revoked.
Hold moves eligible -> held and is idempotent. Genuine promoted human input can
move held -> eligible only while the native target still verifies. Revoke moves
either -> revoked; no human resume/reconnect transition leaves revoked. Selecting
a legitimate new target establishes a new binding, not a resurrection of the old
one, and carries forward any human hold on that native session. Native rows and
historical per-input holds remain retained rather than deleted as "cleanup".

Takeover sequence is precise: core commits reserved/CAS replacement intent;
HostServices::hold commits exact predecessor hold; only then interrupt; then a
successful same-epoch active-map snapshot proves predecessor execution absent;
se-proc independently proves owned predecessor client/descendants gone if client
custody applies; recheck replacement intent/generation; native target transition
revokes predecessor and selects successor; core commits/adopts the successor
binding and enables provider admission. Cross-store steps use durable keyed
intents, not a transaction held across callbacks. Before the final admission,
core must verify the intended native selection was read back. Any failed step
leaves a named pending/held obligation, never admits an overlapping successor.
The final native Select transaction rechecks that every predecessor is still
held and not executing while it revokes their targets. An earlier complete active
snapshot alone is insufficient: genuine human promotion may have happened since
that read. A changed hold/activity/target refuses Select and forces a new
authorized hold/observe sequence, rather than publishing an overlapping successor.

A complete empty active map proves only no matching native execution in that
snapshot. It does not prove client process absence or revoke a credential. An
interrupt acknowledgement proves none of these. Changed epoch, stale reservation,
unreadable map, unknown binding, timeout or failed outside stop witness refuses
admission and preserves the hold for recovery.

## 9. Open, crash adoption and generation lifecycle

### 9.1 Runtime states

| State | Trigger | Next state / rule |
| --- | --- | --- |
| Closed | HostFactory::open | Opening; negotiate and check store without private-state exposure on failure |
| Opening | Missing store / failed read / unsupported API | Closed with Read::Absent / Unreadable / SeError, no half-ready owner |
| Opening | Usable store/services with no recovery debt | Ready |
| Opening | Usable store/services with pending verified recovery | Recovering with bounded per-session status; no hidden work counted as ready binding |
| Recovering | Each custody/binding readback succeeds | Reattached or held/revoked per durable state; then Ready when all resolved |
| Ready or Recovering | API-edge panic | Poisoned: gate this engine generation, preserve native state and keyed obligations |
| Poisoned | Recovery supervisor | Drain/join or quarantine old generation; recover durable intents; create verified successor, never resume the poisoned instance |
| Ready or Recovering | drain(expected current generation) | Draining; gate admissions and detach/cancel old subscription work |
| Draining | Tasks joined and writer flushed | Drained with accurate unresolved debt/effects |
| Draining | Deadline/unreadable worker/effect | Remain Draining with named error/obligation; no successful close/reopen receipt |
| Drained | reopen(actual matching drain receipt) | Reopening; check successor without overflow, reopen/adopt, publish new negotiated generation |
| Reopening | Successful usable successor | Ready or Recovering; old generation cannot admit work |
| Reopening | Failure | Unavailable with explicit preserved debt; no fallback to old stale admission |
| Drained | close(actual matching receipt) | Closed after resources joined/released; idempotent close returns same facts |

Drain is not a human stop and must not manufacture a human hold, revoke a durable
session, or clear a pre-existing hold. Old in-memory futures/handles are cancelled;
store intents/cursors/debt survive. Neither successful drain nor process loss
means a recipient read a notice. Pending effects may be unresolved in a successful
Drained result only if tasks are joined, the writer is flushed and every obligation
is durable; unresolved running tasks prevent a successful drain.

### 9.2 Restart/adoption algorithm

On existing-store open, record recovery from committed session/effect rows using
bounded pages. For each session verify credentials are still valid, project/agent
scope, current generation lease, protected provider conversation reference and
recorded process/native target. A process row must be reobserved/pinned by se-proc;
identity absent -> Absent, mismatch -> revoked/lost refusal, read failure ->
Unreadable. It never becomes a running instance by import or a PID-only lookup.

For SE Code, first query durable native binding_state and the same-epoch active
snapshot. A held binding reattaches as held; a revoked binding remains revoked;
an unreadable binding blocks only that path. Logical StateEngine reopen preserves
the durable SessionId and native target epoch; verify_capability creates a handle
for the new engine Generation. Old handles fail SessionGenerationMismatch. No new agent
conversation, user prompt or notice ID is created merely to recover.

If the SE Code process itself restarted, its HostEpoch changes. The adapter must
use adopt_binding with the previous protected binding and a durable CAS into its
current epoch, retaining pending queue admissions, human holds and revocation.
No persisted mapping/secret custody -> explicit refusal, not owner fallback or
"new session" success. Only after this outside callback readback may se-host mark
the native route reattached. Restoring linked code still requires redeploying
SE Code; there is no dynamic ABI/hot library replacement promise.

Recover each stable notice intent with notice_status before offering it again.
Admitted/Replayed -> record delivery of the original admission; measured Absent ->
retry the same NoticeId and digest; Unreadable/Unknown -> retain pending debt and
report the source. A crash after native commit but before engine settlement must
not lose or double the pending input. A generation change after commit cannot
reclassify it as an uncommitted retry. On cross-store target-selection recovery,
read the keyed selection result and reconcile the original engine intent before
successor admission; never claim cross-database atomicity.

### 9.3 Subscription lifecycle

Opening subscribe_mail reads a bounded snapshot/high-water cursor and attaches
notifications without a gap (subscribe first then snapshot/reconcile, or one
serialized host lane). Notice is emitted only after its message transaction commits.
Every subscription has negotiated entry and byte caps. Overflow emits Lagged with
the last durable safe resume cursor, terminates that stream, and retains all debt;
it never evicts unseen messages silently. Close returns the last safe cursor.
Revocation produces Revoked then closes; drain produces Closed for the old engine
generation. Resubscription validates scope and reads the durable remaining debt.
No active sessions means no subscription timers/polls. Delivery timers, if required
by a live provider, belong to se-host and are armed only by actual work.

### 9.4 Panic containment is part of the API contract

SE Code owns a wrapper around every entry into a real engine implementation,
including synchronous factory/future construction and every poll of the returned
future, subscription next/close, and drop/cleanup paths it invokes. Catching only
future construction does not catch an async panic. Every post-open call supplies
Some(expected_generation) in CallOptions; open alone permits None. SE Code binds
the HostServices wrapper to that generation and checks its fence inside the same
native serialization lane/transaction as hold, selection or admission. Poison or
publication closes that fence before joining old calls; no late old-generation
callback may start a native mutation. A callback already inside its native commit
finishes atomically and is reconciled by its original key before successor
publication. These fences are owned by the runtime adapters, not the data crate. The implementation also guards
its spawned tasks and joins their outcomes into its generation supervisor; a
panic on a detached writer/session task cannot disappear behind an otherwise
healthy Host handle. The API crate itself contains no catch/policy logic.

On caught panic: mint a bounded nonsecret incident ID, mark the local API handle's
GenerationHealth Poisoned, gate calls through that generation immediately, and
report ApiFailure::EnginePanicked with possible-commit semantics. Request poison
on the matching engine generation and drain/join it; if poison/cleanup itself
panics or times out, keep the old handle quarantined and refuse that binding path.
Only publish the successor after ownership/tasks/writer safety is verified. A
counter change alone is not a restart witness. Ordinary SE Code sessions, the
product process, user work and unrelated generation-independent input stay alive.
No raw panic payload, credential or captured body is logged in the API error.

Native HostServices callbacks use their existing transactional authority: a
panic before native commit rolls back via the transaction guard; a panic after
commit loses at most the reply. A hold and its native per-input changes are one
native transaction, as are a synthetic admission/claim/dedupe projection and its
queue event. Neither transaction spans an engine await. A durable hold remains
held across engine poisoning; a committed pending input stays in the single
queue with its original admitted sequence/digest. The engine must never infer
that catch_unwind rolled back a completed commit, unhold to "repair" a panic, or
retry admission under a new NoticeId.

Recovery queries/replays the original keyed hold/selection/admission, restores the
safe binding and resumes from the last durable cursor. Until definitive readback,
provider admission for the affected StateEngine-bound session remains gated; this
temporary safety gate is distinct from a durable human hold and never clears one.
If a native callback panics, SE Code's boundary reports the same uncertain-outcome
failure and reconciles its own authoritative transaction; the engine does not
manufacture an empty active map or settled notice. A process abort/OOM/OS kill
cannot be caught by Rust unwinding; process-restart adoption applies instead.
The release panic strategy must remain unwind on this embedded boundary; an abort
profile cannot claim generation-only panic isolation.

## 10. Per-OS behavior and budget allocation

All value validation is identical on Windows/macOS/Linux except native path
encoding/absolute grammar and Process StartIdentity. This crate cannot call
PowerShell, /proc, proc_pidinfo, GetProcessTimes, OS random or a filesystem API.
A successful parse does not stand in for those calls. Native callback persistence
lives in SE Code's existing store transaction on each platform; no platform may
ack a hold before its durable commit. Store flush details remain store-owner
policy; no platform silently relaxes durability to meet the timing target.

The hard embedded ceilings remain 30,000,000 added RSS bytes, 100 ms added ready/
first-bound time, zero extra persistent processes, and idle below 0.1% of one CPU
with approximately zero wakeups; standalone CLI target remains <20 ms. These are
whole-product measurements by the independent journey runner, not sums of asserted
module numbers. Foundation's design share is zero threads/tasks/timers/processes,
no retained global cache and no startup I/O; small-page pure validation/negotiation
should use <=1 ms of the startup allowance, to be measured, not claimed proven.

Default page limits follow section 50: 20 items, hard max 200 (message tools may
cap at 100); 1 MiB request/response
payload including envelope; continuity model input 32 KiB default and max 1 MiB as section 50;
128 distinct IDs per notice; 256 entries and 1 MiB total per host's native-mail
subscription buffers (shared accounting, not 1 MiB per seat). Producers reject
oversized configurations/requests rather than granting an unbounded allocation.
These caps are reported in Negotiated; changing a default cannot weaken the
correctness invariant or erase unreadable/omitted counts. Session/queue storage
is bounded independently from transient transport; unserved durable debt remains
in the store and is fetched by indexed pages.

Prototype input is explicitly limited. S3 follow-up 0e47c3c0 had observed paired
p95 75.1 ms existing and 96.1 ms fresh-inline over 50 pairs, with all samples kept;
the separate fresh-store adopt-close-launch control missed at 246.6 ms (429.7 ms
including adoption). Maximum paired RSS was 2,056,192 bytes and binary delta
131,568 bytes. It used a minimal bootstrap, not production capabilities/mail or
crash adoption, and its earlier in-clock process-inspection latency figures were
withdrawn. Therefore none of this declaration/design candidate is performance-
qualified; no live-agent handover or input-loss result is inferred from that spike.

## 11. How the five journeys exercise these contracts

| Journey | Required real-consumer observations |
| --- | --- |
| J1 Install | Installed version/API provenance, missing store distinct from unreadable, supported schema negotiation, no external checkout/Node required for the embedded StateEngine path |
| J2 Adopt | Project/agent UUIDs retained across idempotent init, pre-provider session context identity verified, actual committed turn/task, user files survive, no display-name or ambient actor authority |
| J3 Come back | Same durable conversation/session mapping, bounded complete continuity, crash/generation adoption and capability revalidation, held input not automatically resumed, no duplicate notice admission |
| J4 Two agents | Message committed before notice, IDs-only single-queue admission at a safe boundary, exact recipient bound body read and marker commit, replay after callback loss, final handoff/result visible |
| J5 Remove | Target holds/revocations, exact process/descendant outside witness, no unknown-as-empty cleanup, retained user work/history and explicit remaining obligations |

Both Claude/Codex and attended/autonomous surfaces use the same ID/error/read/
receipt contracts. CLI and MCP adapters share registry validation and outputs;
owner CLI inspection does not create an agent read marker. SE Code native input
queue/hold callbacks apply only to the embedded path; standalone uses its harness
and se-proc counterparts with the same external guarantees. Sync store reads and
async host futures carry the same Window and error facts, without a transaction
across await. Read/write symmetry includes committed message bodies and their
readback; a send receipt alone never qualifies J4.

Authors add no tests. Reviewers own targeted executable examples for UUID format,
wrong audience cursors, unknown/unreadable distinctions, window arithmetic,
typed remedy mapping, lost callback replies, held-session races and stale generation
refusal where journeys do not reach them. The independent journeys and budget
runner remain the acceptance oracle. Foundation checks reuse Otto's supplied external consumer (12 assertions, no
new author assertions), plus workspace compiler/Clippy/format checks. Its copied fixture corrects the retired launch_ ID prefix to lch_ and the
nonproducer agt-imported-legacy example to genuine agt-0000-0000-0000, retaining
the same 12 assertions. API declarations compile independently; none proves a runtime
guarantee above.

## 12. Decisions, open questions and implementation handoff

Only the explicitly authorized pure foundation implementation is present. No
host implementation may begin before its design approval. The following cross-area details must be reconciled during review:

1. **Store owner / Prime:** finalize the store application_id, schema progression,
   cursor MAC/key custody and durability policy; StoreVersion is explicit so this
   chapter does not pick another owner's migration/flush policy.
2. **Host owner / Alpha reviewer:** confirm the proposed callback methods and atomic
   native adoption/selection recovery can map to SE Code's persisted target registry
   without an alternative queue; hold-before-interrupt is a required stronger seam
   than the current combined handler, not an optional optimization.
3. **Core/API reviewer:** confirm the explicit SessionBindingUnproven/new-key
   authorized rebind policy in section 7.2; no silent secret regeneration on replay.
4. **API/SE Code reviewer:** validate the full existing secode.session-context-v1
   field mapping in the adapter; the DTO carries its identity/model/packet/window
   facts, but adapter fixtures must demonstrate N/N-1 decoding, not just schema
   strings. Any additional mandatory legacy field becomes a declared field here
   before implementation, not an untyped catch-all.
5. **Critic/Prime:** proposed page/continuity/notice caps and required feature
   negotiation are shared allocation policy; adjust centrally, not per surface.
6. **Alpha:** accept the exact permissive-crate signatures/version and panic
   wrapper placement, then land that crate in SE Code; our temporary proposal
   module is removed when replaced by the reviewed dependency. Stub behavior and
   panic-after-commit recovery need SE Code reviewer witnesses before adoption.

Live daemon/SE Code handover remains after alpha. Crash adoption of the same
supported host and logical engine generation drain/reopen are covered here, not
a new launch/handover command. macOS runtime validation and signing infrastructure
remain project acceptance dependencies; pure type compilation is not that witness.

Review the implemented foundation and have reviewers exercise its real values;
after design approval, se-store/core/host owners implement against these exact
internal contracts and Alpha's accepted permissive API. Any changed signature/state transition goes back through design review
before dependent implementation, rather than growing a second mirror API.

## Appendix: complete compiling public source

Foundation implementations are the explicit exception authorized by Prime.
The complete source includes validating bodies so every public signature below
is real Rust, with no declaration-only inherent methods. Macro input is included
because it defines public Code, Detail and per-code detail structs. The separate
SE Code proposal is trait/data only and checked independently as a crate root
with serde_json. Source files are the compilation authority; these copies must
be refreshed together after review corrections. There is no second generated
runtime API or behavior implementation in this appendix.

### crates/se-types/src/lib.rs

```rust
//! Shared product values. No I/O, ambient identity, runtime, clock or random source.
//! Prefer explicit imports for Read, Cursor and Result to avoid std name collisions.
//! Public host-facing contracts are owned by SE Code, not this proprietary crate.
mod error;
mod id;
mod process;
mod read;
mod receipt;
mod sensitive;
pub use error::*;
pub use id::*;
pub use process::*;
pub use read::*;
pub use receipt::*;
pub use sensitive::*;
pub type Result<T> = std::result::Result<T, SeError>;
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}
/// Internal CLI/IPC version, distinct from Alpha's linked API version ownership.
pub const API_VERSION: ApiVersion = ApiVersion { major: 1, minor: 0 };
```

### crates/se-types/src/id.rs

```rust
use crate::{Result, SeError};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt, num::NonZeroU64, str::FromStr};
use uuid::{Builder, Uuid, Variant, Version};

macro_rules! ids {
    ($($name:ident => $prefix:literal),+ $(,)?) => {
        #[derive(Clone,Copy,Debug,Eq,PartialEq,Hash)]
        pub enum IdKind { $($name,)+ }
        $ (
        #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub const PREFIX: &'static str = $prefix;
            /// No clock or RNG: uniqueness of the supplied inputs is caller-owned.
            pub fn from_parts(unix_millis: u64, random: [u8; 10]) -> Result<Self> {
                if unix_millis > 0xffff_ffff_ffff { return Err(SeError::invalid("unix_millis", "a 48-bit UUIDv7 timestamp")); }
                let id=Builder::from_unix_timestamp_millis(unix_millis,&random).into_uuid();
                Ok(Self(format!("{}{}", Self::PREFIX,id)))
            }
            pub fn from_bytes(bytes: [u8;16]) -> Result<Self> {
                let id=Uuid::from_bytes(bytes);
                if id.get_version()!=Some(Version::SortRand) || id.get_variant()!=Variant::RFC4122 {
                    return Err(SeError::invalid(stringify!($name), "UUIDv7 bytes with RFC variant"));
                }
                Ok(Self(format!("{}{}", Self::PREFIX,id)))
            }
            pub fn as_str(&self) -> &str { &self.0 }
            /// Explicit importer entrypoint: legacy text is data, never authority.
            /// A UUID-shaped suffix must be canonical new-format, not a legacy bypass.
            pub fn from_legacy(value: impl Into<String>) -> Result<Self> {
                let value=value.into();
                validate_opaque(&value,512,stringify!($name))?;
                if value.starts_with("selp-") { return Err(SeError::invalid(stringify!($name),"a public ID, never a bearer credential")); }
                if known_id_prefix(&value).is_some() { return value.parse(); }
                if !legacy_matches(IdKind::$name,&value) {
                    return Err(SeError::invalid(stringify!($name),"this kind's documented legacy grammar"));
                }
                Ok(Self(value))
            }
            /// Only a contextual, source/project-scoped registry may accept a
            /// historical custom spelling. No ambient registry is used by serde.
            pub fn from_registered_legacy(value:impl Into<String>,registry:&dyn LegacyIdRegistry)->Result<Self> {
                let value=value.into();
                validate_opaque(&value,512,stringify!($name))?;
                if value.starts_with("selp-") { return Err(SeError::invalid(stringify!($name),"a public ID, never a bearer credential")); }
                if known_id_prefix(&value).is_some() { return value.parse(); }
                if !registry.contains(IdKind::$name,&value)? {
                    return Err(SeError::invalid(stringify!($name),"an exact kind/project/source registration"));
                }
                Ok(Self(value))
            }
        }
        impl FromStr for $name {
            type Err=SeError;
            fn from_str(value:&str)->Result<Self> {
                let suffix=value.strip_prefix(Self::PREFIX).ok_or_else(||SeError::invalid(stringify!($name),Self::PREFIX))?;
                let uuid=Uuid::parse_str(suffix).map_err(|_|SeError::invalid(stringify!($name),"kind prefix plus canonical UUIDv7"))?;
                if uuid.get_version()!=Some(Version::SortRand) || uuid.get_variant()!=Variant::RFC4122 || uuid.to_string()!=suffix {
                    return Err(SeError::invalid(stringify!($name),"kind prefix plus lowercase canonical UUIDv7"));
                }
                Ok(Self(value.into()))
            }
        }
        impl TryFrom<String> for $name { type Error=SeError; fn try_from(value:String)->Result<Self> {
            // Only the own-kind historical producer grammar supplements strict UUIDv7.
            Self::from_legacy(value)
        } }
        impl From<$name> for String { fn from(value:$name)->String {value.0} }
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl fmt::Debug for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl JsonSchema for $name {
            fn schema_name()->Cow<'static,str>{stringify!($name).into()}
            fn json_schema(_: &mut SchemaGenerator)->Schema {json_schema!({"type":"string","minLength":1,"maxLength":512,"anyOf":[{"pattern":format!("^{}[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$",Self::PREFIX)},{"pattern":legacy_pattern(IdKind::$name)}]})}
        }
    )+
        fn known_id_prefix(value:&str)->Option<&'static str>{["cred_",$($prefix),+].into_iter().find(|prefix|value.starts_with(prefix))}
    };
}
ids!(ProjectId=>"prj_",AgentId=>"ag_",HumanId=>"hu_",SessionId=>"ses_",MessageId=>"msg_",DecisionId=>"dec_",EventId=>"ev_",LaunchId=>"lch_",ObservationId=>"obs_",StoreId=>"store_",LifecycleId=>"life_",AtlasRootId=>"aroot_",IndexEpochId=>"aidx_");

/// An already-authorized registry snapshot scoped to the import project/source.
/// Implemented by the store/import boundary, never a global or a name heuristic.
/// The result permits representing history, not launching or authenticating it.
pub trait LegacyIdRegistry {
    fn contains(&self, kind: IdKind, text: &str) -> Result<bool>;
}
fn hex(value: &str, count: Option<usize>) -> bool {
    count.is_none_or(|count| value.len() == count)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn serial(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    let groups: Vec<_> = suffix.split('-').collect();
    groups.len() == 3
        && groups.iter().all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
        })
}
fn uuid_v4(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| {
        id.get_version() == Some(Version::Random)
            && id.get_variant() == Variant::RFC4122
            && id.to_string() == value
    })
}
fn known_legacy_kind(value: &str) -> Option<IdKind> {
    [
        ("agt-", IdKind::AgentId),
        ("hum-", IdKind::HumanId),
        ("msg-", IdKind::MessageId),
        ("evt-", IdKind::EventId),
        ("se-", IdKind::SessionId),
        ("semantic-observation:", IdKind::ObservationId),
        ("observation-", IdKind::ObservationId),
        ("health-terminal-lineage-", IdKind::ObservationId),
    ]
    .into_iter()
    .find_map(|(prefix, kind)| value.starts_with(prefix).then_some(kind))
}
fn legacy_project(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || known_id_prefix(value).is_some()
        || known_legacy_kind(value).is_some()
        || (value.len() == 36 && Uuid::parse_str(value).is_ok())
    {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || value.ends_with('.')
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or("").to_ascii_lowercase();
    !matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        && !((stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.len() == 4
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
}
fn legacy_matches(kind: IdKind, value: &str) -> bool {
    match kind {
        IdKind::ProjectId => legacy_project(value),
        IdKind::AgentId => serial(value, "agt-"),
        IdKind::HumanId => serial(value, "hum-"),
        IdKind::SessionId => {
            value
                .strip_prefix("se-session-sha256-")
                .is_some_and(|s| hex(s, Some(64)))
                || value.strip_prefix("se-").is_some_and(uuid_v4)
                || uuid_v4(value)
        }
        IdKind::MessageId => value
            .strip_prefix("msg-")
            .is_some_and(|s| s.len() >= 8 && hex(s, None)),
        IdKind::EventId => value.strip_prefix("evt-").is_some_and(|s| hex(s, Some(64))),
        IdKind::DecisionId | IdKind::LaunchId | IdKind::LifecycleId => uuid_v4(value),
        IdKind::ObservationId => value
            .strip_prefix("semantic-observation:")
            .is_some_and(|s| hex(s, Some(64))),
        IdKind::StoreId | IdKind::AtlasRootId | IdKind::IndexEpochId => false,
    }
}
fn legacy_pattern(kind: IdKind) -> &'static str {
    match kind {
        IdKind::ProjectId => {
            r"^(?!(?:prj_|ag_|hu_|ses_|msg_|dec_|ev_|lch_|obs_|store_|life_|aroot_|aidx_|agt-|hum-|msg-|evt-|se-|semantic-observation:|observation-|health-terminal-lineage-|selp-|cred_))(?!(?:[cC][oO][nN]|[pP][rR][nN]|[aA][uU][xX]|[nN][uU][lL]|[cC][oO][mM][1-9]|[lL][pP][tT][1-9])(?:\..*)?$)(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$"
        }
        IdKind::AgentId => {
            r"^agt-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}$"
        }
        IdKind::HumanId => {
            r"^hum-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}$"
        }
        IdKind::SessionId => {
            r"^(?:se-session-sha256-[0-9a-f]{64}|(?:se-)?[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
        }
        IdKind::MessageId => r"^msg-[0-9a-f]{8,}$",
        IdKind::EventId => r"^evt-[0-9a-f]{64}$",
        IdKind::DecisionId | IdKind::LaunchId | IdKind::LifecycleId => {
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        }
        IdKind::ObservationId => r"^semantic-observation:[0-9a-f]{64}$",
        IdKind::StoreId | IdKind::AtlasRootId | IdKind::IndexEpochId => r"^$",
    }
}

pub(crate) fn validate_opaque(value: &str, max: usize, field: &str) -> Result<()> {
    if value.len() > max {
        return Err(SeError::too_large(field, max, value.len()));
    }
    if value.is_empty() || value.len() > max || value.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err(SeError::invalid(
            field,
            "bounded nonempty ASCII without whitespace or controls",
        ));
    }
    Ok(())
}
macro_rules! opaque {
    ($($name:ident => $max:literal),+ $(,)?) => {$ (
        #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash,Serialize,Deserialize,JsonSchema)]
        #[serde(try_from="String",into="String")]
        #[schemars(with="String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value:impl Into<String>)->Result<Self>{let value=value.into();validate_opaque(&value,$max,stringify!($name))?;Ok(Self(value))}
            pub fn as_str(&self)->&str{&self.0}
        }
        impl FromStr for $name {type Err=SeError;fn from_str(value:&str)->Result<Self>{Self::new(value)}}
        impl TryFrom<String> for $name {type Error=SeError;fn try_from(value:String)->Result<Self>{Self::new(value)}}
        impl From<$name> for String {fn from(value:$name)->String{value.0}}
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str(&self.0)}}
    )+};
}
opaque!(Cursor=>4096,MachineId=>256,BootId=>256,HostSessionId=>512,HostEventId=>512,HostPendingId=>512,ProviderSessionId=>512,IdempotencyKey=>128,NoticeId=>256);

macro_rules! counter {
    ($name:ident,$zero:expr) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
            JsonSchema,
        )]
        #[serde(try_from = "u64", into = "u64")]
        #[schemars(with = "u64")]
        pub struct $name(u64);
        impl $name {
            pub fn new(value: u64) -> Result<Self> {
                if value > i64::MAX as u64 || (!$zero && value == 0) {
                    return Err(SeError::invalid(
                        stringify!($name),
                        "a supported nonnegative/nonzero signed-store integer",
                    ));
                }
                Ok(Self(value))
            }
            pub const fn get(self) -> u64 {
                self.0
            }
        }
        impl TryFrom<u64> for $name {
            type Error = SeError;
            fn try_from(value: u64) -> Result<Self> {
                Self::new(value)
            }
        }
        impl From<$name> for u64 {
            fn from(value: $name) -> u64 {
                value.0
            }
        }
    };
}
counter!(Sequence, true);
counter!(UnixMillis, true);
counter!(UnixMicros, true);
impl Sequence {
    pub const ZERO: Self = Self(0);
}
macro_rules! generation {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
            JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);
        impl $name {
            pub fn new(value: u64) -> Result<Self> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or_else(|| SeError::invalid(stringify!($name), "a nonzero generation"))
            }
            pub const fn get(self) -> u64 {
                self.0.get()
            }
            pub fn successor(self) -> Result<Self> {
                self.get()
                    .checked_add(1)
                    .ok_or_else(|| SeError::invalid(stringify!($name), "an unexhausted generation"))
                    .and_then(Self::new)
            }
        }
    };
}
generation!(Generation);
generation!(HostGeneration);
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Sha256([u8; 32]);
impl Sha256 {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SeError::invalid(
                "sha256",
                "64 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        Ok(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
impl TryFrom<String> for Sha256 {
    type Error = SeError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse_hex(&value)
    }
}
impl From<Sha256> for String {
    fn from(value: Sha256) -> String {
        value.hex()
    }
}
impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// UTC calendar text for human messages; serde remains exact Unix microseconds.
impl fmt::Display for UnixMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.get() / 1_000_000;
        let days = (seconds / 86_400) as i64;
        // Gregorian 400-year eras, with March as month zero to handle leap days.
        let z = days + 719_468;
        let era = z / 146_097;
        let day_of_era = z - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let march_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * march_month + 2) / 5 + 1;
        let month = march_month + if march_month < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        let hour = seconds % 86_400 / 3_600;
        let minute = seconds % 3_600 / 60;
        let second = seconds % 60;
        write!(
            f,
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{:06} UTC",
            self.get() % 1_000_000
        )
    }
}
```

### crates/se-types/src/sensitive.rs

```rust
use crate::{Result, SeError, Sha256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Hasher};
use std::fmt;
use zeroize::Zeroize;

/// Protected transport material. No Display, Clone, Serialize or Deserialize.
pub struct Secret(Vec<u8>);
impl Secret {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let mut secret = Self(bytes);
        if secret.0.is_empty() || secret.0.len() > 65536 {
            secret.0.zeroize();
            return Err(SeError::invalid("secret", "1..65536 protected bytes"));
        }
        Ok(secret)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Body {
    text: String,
    digest: Sha256,
}
impl Body {
    pub const MAX_BYTES: usize = 1048576;
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.len() > Self::MAX_BYTES {
            return Err(SeError::too_large("body", Self::MAX_BYTES, text.len()));
        }
        let digest = Sha256::from_bytes(Hasher::digest(text.as_bytes()).into());
        Ok(Self { text, digest })
    }
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn len(&self) -> usize {
        self.text.len()
    }
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
    pub const fn digest(&self) -> Sha256 {
        self.digest
    }
}
impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Body {{ bytes: {}, sha256: {}… }}",
            self.len(),
            &self.digest.hex()[..12]
        )
    }
}
impl TryFrom<String> for Body {
    type Error = SeError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}
impl From<Body> for String {
    fn from(value: Body) -> String {
        value.text
    }
}
```

### crates/se-types/src/process.rs

```rust
use crate::{BootId, HostGeneration, MachineId, Result, SeError, Sha256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "encoding", content = "units", rename_all = "snake_case")]
pub enum PathEncoding {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "PathEncoding", into = "PathEncoding")]
pub struct NativePath(PathEncoding);
impl NativePath {
    pub fn from_encoded(path: PathEncoding) -> Result<Self> {
        let valid = match &path {
            PathEncoding::UnixBytes(bytes) => {
                !bytes.is_empty() && bytes.len() <= 32768 && bytes[0] == b'/' && !bytes.contains(&0)
            }
            PathEncoding::WindowsUtf16(units) => {
                let absolute = units.len() >= 3
                    && ((units[0] <= 127
                        && (units[0] as u8).is_ascii_alphabetic()
                        && units[1] == 58
                        && matches!(units[2], 47 | 92))
                        || (units[0] == 92 && units[1] == 92));
                absolute && units.len() <= 32768 && !units.contains(&0)
            }
        };
        if !valid {
            return Err(SeError::invalid(
                "path",
                "a bounded absolute native path without NUL",
            ));
        }
        Ok(Self(path))
    }
    pub fn encoded(&self) -> &PathEncoding {
        &self.0
    }
    pub fn from_local(path: PathBuf) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::from_encoded(PathEncoding::UnixBytes(
                path.as_os_str().as_bytes().to_vec(),
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Self::from_encoded(PathEncoding::WindowsUtf16(
                path.as_os_str().encode_wide().collect(),
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(SeError::invalid("platform", "Windows, Linux or macOS"))
        }
    }
    pub fn to_local(&self) -> Result<PathBuf> {
        match &self.0 {
            #[cfg(unix)]
            PathEncoding::UnixBytes(bytes) => {
                use std::os::unix::ffi::OsStringExt;
                Ok(std::ffi::OsString::from_vec(bytes.clone()).into())
            }
            #[cfg(windows)]
            PathEncoding::WindowsUtf16(units) => {
                use std::os::windows::ffi::OsStringExt;
                Ok(std::ffi::OsString::from_wide(units).into())
            }
            _ => Err(SeError::invalid(
                "path encoding",
                "the current platform's native encoding",
            )),
        }
    }
}
impl TryFrom<PathEncoding> for NativePath {
    type Error = SeError;
    fn try_from(path: PathEncoding) -> Result<Self> {
        Self::from_encoded(path)
    }
}
impl From<NativePath> for PathEncoding {
    fn from(path: NativePath) -> Self {
        path.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum StartIdentity {
    Windows {
        creation_filetime: NonZeroU64,
    },
    Linux {
        start_ticks: u64,
    },
    Macos {
        start_seconds: u64,
        start_micros: u32,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessFields {
    pub machine: MachineId,
    pub boot: BootId,
    pub pid: NonZeroU32,
    pub started: StartIdentity,
    pub executable: NativePath,
    pub argv_sha256: Sha256,
}
/// Representation of an observation, not the se-proc owned/pinned custody handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ProcessFields", into = "ProcessFields")]
pub struct ProcessInstance(ProcessFields);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMatch {
    Same,
    Different,
}
impl ProcessInstance {
    pub fn from_observation(fields: ProcessFields) -> Result<Self> {
        let valid = match (&fields.started, fields.executable.encoded()) {
            (StartIdentity::Windows { .. }, PathEncoding::WindowsUtf16(_)) => true,
            (StartIdentity::Linux { .. }, PathEncoding::UnixBytes(_)) => true,
            (StartIdentity::Macos { start_micros, .. }, PathEncoding::UnixBytes(_)) => {
                *start_micros < 1000000
            }
            _ => false,
        };
        if !valid {
            return Err(SeError::invalid(
                "process identity",
                "matching OS/path and valid native start identity",
            ));
        }
        Ok(Self(fields))
    }
    pub fn fields(&self) -> &ProcessFields {
        &self.0
    }
    pub fn compare(&self, other: &Self) -> IdentityMatch {
        if self == other {
            IdentityMatch::Same
        } else {
            IdentityMatch::Different
        }
    }
}
impl TryFrom<ProcessFields> for ProcessInstance {
    type Error = SeError;
    fn try_from(value: ProcessFields) -> Result<Self> {
        Self::from_observation(value)
    }
}
impl From<ProcessInstance> for ProcessFields {
    fn from(value: ProcessInstance) -> Self {
        value.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
```

### crates/se-types/src/read.rs

```rust
use crate::{
    AtlasRootId, Cursor, ErrorBody, HostEpoch, IndexEpochId, ProjectId, Result, SeError, Sequence,
    StoreId, UnixMicros,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroU64};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Store {
        store: StoreId,
        project: Option<ProjectId>,
    },
    Host {
        epoch: HostEpoch,
    },
    /// Rebuildable code cache, never the authority for history.
    Atlas {
        project: ProjectId,
        root: AtlasRootId,
        epoch: Option<IndexEpochId>,
    },
    Configuration {
        location: String,
    },
}
impl Source {
    pub fn describe(&self) -> String {
        match self {
            Self::Store { store, project } => format!(
                "store {store}, project {}",
                project
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "all".into())
            ),
            Self::Host { epoch } => format!(
                "host pid {}, epoch {}",
                epoch.owner.fields().pid,
                epoch.generation.get()
            ),
            Self::Configuration { location } => location.clone(),
            Self::Atlas {
                project,
                root,
                epoch,
            } => format!(
                "atlas.db project {project}, root {root}, epoch {}",
                epoch
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unverified".into())
            ),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Checked {
    pub source: Source,
    pub snapshot_to: Option<Sequence>,
    pub observed_at: UnixMicros,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Read<T> {
    Present {
        value: T,
    },
    Absent {
        checked: String,
    },
    Unreadable {
        source: String,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<Box<ErrorBody>>,
    },
    Unknown {
        what: String,
    },
}
impl<T> Read<T> {
    pub fn absent(checked: Checked) -> Self {
        Self::Absent {
            checked: format!(
                "{} at {}, snapshot {}",
                checked.source.describe(),
                checked.observed_at,
                checked
                    .snapshot_to
                    .map(|seq| seq.get().to_string())
                    .unwrap_or_else(|| "unverified".into())
            ),
        }
    }
    pub fn unreadable(source: Source, error: ErrorBody) -> Self {
        Self::Unreadable {
            source: source.describe(),
            reason: error.message(),
            error: Some(Box::new(error)),
        }
    }
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Read<U> {
        match self {
            Self::Present { value } => Read::Present { value: f(value) },
            Self::Absent { checked } => Read::Absent { checked },
            Self::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source,
                reason,
                error,
            },
            Self::Unknown { what } => Read::Unknown { what },
        }
    }
    pub fn as_ref(&self) -> Read<&T> {
        match self {
            Self::Present { value } => Read::Present { value },
            Self::Absent { checked } => Read::Absent {
                checked: checked.clone(),
            },
            Self::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source: source.clone(),
                reason: reason.clone(),
                error: error.clone(),
            },
            Self::Unknown { what } => Read::Unknown { what: what.clone() },
        }
    }
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Present { .. } | Self::Absent { .. } => 0,
            Self::Unreadable { .. } => 3,
            Self::Unknown { .. } => 4,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OmissionReason {
    Limit,
    Budget,
    Unreadable,
    SourceIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Omission {
    None,
    Known {
        count: NonZeroU64,
        reason: OmissionReason,
    },
    Unknown {
        reason: OmissionReason,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Omitted {
    pub count: Option<u64>,
    pub reason: Option<OmissionReason>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Exhausted,
    ItemLimit,
    ByteLimit,
    Unreadable,
    Cancelled,
    Deadline,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Store snapshot bounds are (from, to]: exclusive from, inclusive to.
/// bytes is producer accounting; foundation does not serialize items to recount it.
pub struct WindowFields {
    pub source: Source,
    pub from: Sequence,
    pub to: Sequence,
    pub start_cursor: Option<Cursor>,
    pub end_cursor: Option<Cursor>,
    pub returned: u64,
    pub limit: NonZeroU32,
    pub bytes: u64,
    pub max_bytes: NonZeroU32,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "WindowWire", into = "WindowWire")]
pub struct Window {
    fields: Option<WindowFields>,
    from: Option<Cursor>,
    to: Option<Cursor>,
    limit: NonZeroU32,
    complete: bool,
    omitted: Omitted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
struct WindowWire {
    from: Option<Cursor>,
    to: Option<Cursor>,
    limit: u32,
    complete: bool,
    omitted: Omitted,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<WindowFields>,
}
fn omission_rank(reason: OmissionReason) -> u8 {
    match reason {
        OmissionReason::Limit => 0,
        OmissionReason::Budget => 1,
        OmissionReason::SourceIncomplete => 2,
        OmissionReason::Unreadable => 3,
    }
}
fn combine(before: &Omission, after: &Omission) -> Result<Omitted> {
    let mut count = Some(0u64);
    let mut reason = None;
    for omission in [before, after] {
        let (n, r) = match omission {
            Omission::None => continue,
            Omission::Known { count, reason } => (Some(count.get()), *reason),
            Omission::Unknown { reason } => (None, *reason),
        };
        count = match (count, n) {
            (Some(a), Some(b)) => Some(
                a.checked_add(b)
                    .ok_or_else(|| SeError::invalid("omitted", "a nonoverflowing count"))?,
            ),
            _ => None,
        };
        if reason.is_none_or(|current| omission_rank(r) > omission_rank(current)) {
            reason = Some(r);
        }
    }
    Ok(Omitted { count, reason })
}
impl Window {
    pub fn new(fields: WindowFields) -> Result<Self> {
        if fields.from > fields.to
            || fields.returned > u64::from(fields.limit.get())
            || fields.bytes > u64::from(fields.max_bytes.get())
            || (fields.from == fields.to && fields.returned != 0)
        {
            return Err(SeError::invalid(
                "window",
                "ordered snapshot bounds, item and byte limits",
            ));
        }
        let mut omitted = combine(&fields.omitted_before, &fields.omitted_after)?;
        if fields.unreadable > 0 {
            omitted.count = if omitted.count == Some(0) {
                Some(fields.unreadable)
            } else {
                None
            };
            omitted.reason = Some(OmissionReason::Unreadable);
        }
        if fields.stop_reason != StopReason::Exhausted && omitted.reason.is_none() {
            return Err(SeError::invalid(
                "window omitted",
                "a stated omission for a non-exhausted read",
            ));
        }
        let complete = omitted.reason.is_none()
            && fields.unreadable == 0
            && fields.stop_reason == StopReason::Exhausted;
        Ok(Self {
            from: fields.start_cursor.clone(),
            to: fields.end_cursor.clone(),
            limit: fields.limit,
            fields: Some(fields),
            complete,
            omitted,
        })
    }
    /// Detailed producer accounting is absent in a minimal public wire Window.
    pub fn fields(&self) -> Option<&WindowFields> {
        self.fields.as_ref()
    }
    pub const fn complete(&self) -> bool {
        self.complete
    }
    pub fn omitted(&self) -> &Omitted {
        &self.omitted
    }
    pub fn exit_code(&self, require_all: bool) -> u8 {
        if (require_all && !self.complete)
            || matches!(
                self.omitted.reason,
                Some(OmissionReason::Unreadable | OmissionReason::SourceIncomplete)
            )
        {
            2
        } else {
            0
        }
    }
}
impl From<Window> for WindowWire {
    fn from(value: Window) -> Self {
        Self {
            from: value.from,
            to: value.to,
            limit: value.limit.get(),
            complete: value.complete,
            omitted: value.omitted,
            snapshot: value.fields,
        }
    }
}
impl TryFrom<WindowWire> for Window {
    type Error = SeError;
    fn try_from(value: WindowWire) -> Result<Self> {
        let limit = NonZeroU32::new(value.limit)
            .ok_or_else(|| SeError::invalid("window limit", "nonzero"))?;
        if (value.complete && (value.omitted.count != Some(0) || value.omitted.reason.is_some()))
            || (!value.complete
                && (value.omitted.reason.is_none() || value.omitted.count == Some(0)))
        {
            return Err(SeError::invalid(
                "window omitted",
                "consistent complete/count/reason",
            ));
        }
        let Some(snapshot) = value.snapshot else {
            return Ok(Self {
                fields: None,
                from: value.from,
                to: value.to,
                limit,
                complete: value.complete,
                omitted: value.omitted,
            });
        };
        let window = Self::new(snapshot)?;
        if value.from != window.from
            || value.to != window.to
            || limit != window.limit
            || value.complete != window.complete
            || value.omitted != window.omitted
        {
            return Err(SeError::invalid(
                "window envelope",
                "facts matching its snapshot",
            ));
        }
        Ok(window)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "PageWire<T>", bound(deserialize = "T: Deserialize<'de>"))]
pub struct Page<T> {
    items: Vec<T>,
    window: Window,
    next: Option<Cursor>,
}
#[derive(Deserialize, JsonSchema)]
struct PageWire<T> {
    items: Vec<T>,
    window: Window,
    next: Option<Cursor>,
}
impl<T> Page<T> {
    pub fn new(items: Vec<T>, window: Window, next: Option<Cursor>) -> Result<Self> {
        let known_after = window
            .fields
            .as_ref()
            .is_some_and(|fields| matches!(fields.omitted_after, Omission::Known { .. }));
        let wire_more = window.fields.is_none()
            && matches!(
                window.omitted.reason,
                Some(OmissionReason::Limit | OmissionReason::Budget)
            );
        if items.len() > window.limit.get() as usize
            || window
                .fields
                .as_ref()
                .is_some_and(|fields| items.len() as u64 != fields.returned)
            || (window.complete && next.is_some())
            || (next.is_none() && (known_after || wire_more))
            || (next.is_some() && next == window.from)
        {
            return Err(SeError::invalid(
                "page",
                "matching count and a progressing continuation for remaining rows",
            ));
        }
        Ok(Self {
            items,
            window,
            next,
        })
    }
}
impl<T> Page<T> {
    pub fn items(&self) -> &[T] {
        &self.items
    }
    pub fn window(&self) -> &Window {
        &self.window
    }
    pub fn next(&self) -> Option<&Cursor> {
        self.next.as_ref()
    }
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}
impl<T> TryFrom<PageWire<T>> for Page<T> {
    type Error = SeError;
    fn try_from(value: PageWire<T>) -> Result<Self> {
        Self::new(value.items, value.window, value.next)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: NonZeroU32,
    pub max_bytes: NonZeroU32,
}
```

### crates/se-types/src/receipt.rs

```rust
use crate::{ErrorBody, EventId, IdempotencyKey, Result, SeError, Sequence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EventRef {
    pub id: EventId,
    pub sequence: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: Box<ErrorBody> },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Commit<T> {
    pub event_id: EventId,
    pub sequence: Sequence,
    pub idempotency_key: IdempotencyKey,
    pub value: T,
    pub effects: EffectStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingReason {
    Queued,
    AwaitingWitness,
    Recovering,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    try_from = "ReceiptWire<T>",
    bound(deserialize = "T: Deserialize<'de>")
)]
pub enum Receipt<T> {
    Committed {
        #[serde(flatten)]
        commit: Commit<T>,
    },
    Replayed {
        #[serde(flatten)]
        original: Commit<T>,
    },
    Refused {
        error: Box<ErrorBody>,
    },
    Pending {
        cause: PendingReason,
        event_id: Option<EventId>,
        idempotency_key: IdempotencyKey,
    },
}
impl<T> Receipt<T> {
    pub fn committed_value(&self) -> Option<&T> {
        match self {
            Self::Committed { commit } | Self::Replayed { original: commit } => Some(&commit.value),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Committed { commit } | Self::Replayed { original: commit } => {
                if commit.sequence == Sequence::ZERO {
                    return Err(SeError::invalid(
                        "receipt sequence",
                        "a committed nonzero sequence",
                    ));
                }
                if let EffectStatus::Witnessed { witness } = &commit.effects
                    && witness.sequence <= commit.sequence
                {
                    return Err(SeError::invalid(
                        "effect witness",
                        "an outside event after the commit",
                    ));
                }
            }
            Self::Pending { .. } | Self::Refused { .. } => (),
        }
        Ok(())
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ReceiptWire<T> {
    Committed {
        #[serde(flatten)]
        commit: Commit<T>,
    },
    Replayed {
        #[serde(flatten)]
        original: Commit<T>,
    },
    Refused {
        error: Box<ErrorBody>,
    },
    Pending {
        cause: PendingReason,
        event_id: Option<EventId>,
        idempotency_key: IdempotencyKey,
    },
}
impl<T> TryFrom<ReceiptWire<T>> for Receipt<T> {
    type Error = SeError;
    fn try_from(value: ReceiptWire<T>) -> Result<Self> {
        let receipt = match value {
            ReceiptWire::Committed { commit } => Self::Committed { commit },
            ReceiptWire::Replayed { original } => Self::Replayed { original },
            ReceiptWire::Refused { error } => Self::Refused { error },
            ReceiptWire::Pending {
                cause,
                event_id,
                idempotency_key,
            } => Self::Pending {
                cause,
                event_id,
                idempotency_key,
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }
}
```

### crates/se-types/src/error.rs

```rust
use crate::{
    AgentId, DecisionId, EventId, Generation, LaunchId, MessageId, ObservationId, ProjectId,
    SessionId, UnixMicros,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Internal,
    Cancelled,
}
impl Class {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::Unknown => 4,
            Self::Unreadable => 3,
            Self::Incomplete => 2,
            Self::Refused
            | Self::Unauthorized
            | Self::Conflict
            | Self::Unavailable
            | Self::Internal
            | Self::Cancelled => 1,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectChoice {
    pub name: String,
    pub id: ProjectId,
    pub root: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImportFamilyIssue {
    pub name: String,
    pub rejected: u64,
    pub unreadable: u64,
}

macro_rules! codes {
    ($($variant:ident => ($wire:literal,$class:ident) { $($field:ident:$ty:ty),* $(,)? } => $message:literal,$remedy:literal;)+) => {
        $(const _: [();1] = [();($wire.len()>0 && $message.len()>0 && $remedy.len()>1) as usize];)+
        #[non_exhaustive]
        #[derive(Clone,Copy,Debug,Eq,PartialEq,Hash,Serialize,Deserialize,JsonSchema)]
        pub enum Code{$(#[serde(rename=$wire)] $variant,)+}
        pub mod details{use super::*;$(
            #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize,JsonSchema)]
            pub struct $variant{$(pub $field:$ty,)*}
        )+}
        #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize,JsonSchema)]
        #[serde(tag="code",content="detail")]
        pub enum Detail{$(#[serde(rename=$wire)] $variant(details::$variant),)+}
        impl Code{
            pub const fn as_str(self)->&'static str{match self{$(Self::$variant=>$wire,)+}}
            pub const fn class(self)->Class{match self{$(Self::$variant=>Class::$class,)+}}
            pub fn message(self,detail:&Detail)->crate::Result<String>{
                if self!=detail.code(){return Err(SeError::invalid("detail","detail matching the error code"));}
                Ok(detail.message())
            }
            pub fn remedy(self,detail:&Detail,cx:&RenderCx<'_>)->crate::Result<Remedy>{
                if self!=detail.code(){return Err(SeError::invalid("detail","detail matching the error code"));}
                let text=match self{$(Self::$variant=>render($remedy,detail,Some(cx)),)+};
                let command=match cx.commands{Some(commands)=>commands.for_error(&ErrorBody::new(detail.clone()))?,None=>None};
                Ok(Remedy{text,command})
            }
        }
        impl Detail{
            pub const fn code(&self)->Code{match self{$(Self::$variant(_)=>Code::$variant,)+}}
            pub fn message(&self)->String{match self{$(Self::$variant(_)=>render($message,self,None),)+}}
            fn message_in(&self,cx:&RenderCx<'_>)->String{match self{$(Self::$variant(_)=>render($message,self,Some(cx)),)+}}
            fn fields(&self)->Vec<(&'static str,String,Option<usize>)>{match self{$(Self::$variant(value)=>vec![$((stringify!($field),value.$field.human(),value.$field.count()),)*],)+}}
        }
    };
}
include!("error/catalog.rs");

trait HumanValue {
    fn human(&self) -> String;
    fn count(&self) -> Option<usize> {
        None
    }
}
macro_rules! display_values {
    ($($ty:ty),+ $(,)?) => {$(impl HumanValue for $ty {fn human(&self)->String {self.to_string()}})+};
}
display_values!(
    String,
    u16,
    u32,
    u64,
    i32,
    AgentId,
    DecisionId,
    EventId,
    LaunchId,
    MessageId,
    ObservationId,
    ProjectId,
    SessionId,
    UnixMicros
);
impl HumanValue for Generation {
    fn human(&self) -> String {
        self.get().to_string()
    }
}
impl<T: HumanValue> HumanValue for Option<T> {
    fn human(&self) -> String {
        self.as_ref()
            .map(HumanValue::human)
            .unwrap_or_else(|| "unknown".into())
    }
}
impl<T: HumanValue> HumanValue for Vec<T> {
    fn human(&self) -> String {
        self.iter()
            .map(HumanValue::human)
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn count(&self) -> Option<usize> {
        Some(self.len())
    }
}
impl HumanValue for ProjectChoice {
    fn human(&self) -> String {
        format!("{} ({}, {})", self.name, self.id, self.root)
    }
}
impl HumanValue for ImportFamilyIssue {
    fn human(&self) -> String {
        format!(
            "{}: {} rejected, {} unreadable",
            self.name, self.rejected, self.unreadable
        )
    }
}
fn render(template: &str, detail: &Detail, cx: Option<&RenderCx<'_>>) -> String {
    let fields = detail.fields();
    let mut output = String::new();
    let mut rest = template;
    // Single pass: braces inside a detail string are data, never another template.
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let token = &rest[start..];
        let Some(end) = token.find('}') else {
            output.push_str(token);
            return output;
        };
        let name = &token[1..end];
        if let Some(field) = name.strip_suffix(".len") {
            match fields
                .iter()
                .find(|(key, _, _)| *key == field)
                .and_then(|(_, _, count)| *count)
            {
                Some(count) => output.push_str(&count.to_string()),
                None => output.push_str(&token[..=end]),
            }
        } else if let Some((_, value, _)) = fields.iter().find(|(key, _, _)| *key == name) {
            output.push_str(value);
        } else {
            match name {
                "project" => output.push_str(
                    &cx.and_then(|cx| cx.project)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "PROJECT".into()),
                ),
                "agent" => output.push_str(
                    &cx.and_then(|cx| cx.agent)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "AGENT".into()),
                ),
                "root" => output.push_str("DIR"),
                _ => output.push_str(&token[..=end]),
            }
        }
        rest = &token[end + 1..];
    }
    output.push_str(rest);
    output
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if !value.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(serde::ser::Error::custom(
                "retry duration must be whole milliseconds",
            ));
        }
        let millis = u64::try_from(value.as_millis()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(millis)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Retry {
    #[default]
    Never,
    AfterReread,
    After(
        #[serde(with = "duration_millis")]
        #[schemars(with = "u64")]
        Duration,
    ),
    WhenRuntimeReady,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {
    #[serde(flatten)]
    detail: Detail,
    #[serde(default)]
    retry: Retry,
}
impl ErrorBody {
    pub fn new(detail: Detail) -> Self {
        Self {
            detail,
            retry: Retry::Never,
        }
    }
    pub fn with_retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }
    pub fn code(&self) -> Code {
        self.detail.code()
    }
    pub fn class(&self) -> Class {
        self.code().class()
    }
    pub fn detail(&self) -> &Detail {
        &self.detail
    }
    pub fn retry(&self) -> &Retry {
        &self.retry
    }
    pub fn message(&self) -> String {
        self.detail.message()
    }
    pub fn remedy(&self, cx: &RenderCx<'_>) -> crate::Result<Remedy> {
        self.code().remedy(&self.detail, cx)
    }
}
impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code().as_str(), self.message())
    }
}
#[derive(Debug)]
pub struct SeError {
    pub body: ErrorBody,
    pub cause: Option<Box<dyn Error + Send + Sync>>,
}
impl SeError {
    pub fn new(detail: Detail) -> Self {
        Self {
            body: ErrorBody::new(detail),
            cause: None,
        }
    }
    pub fn invalid(field: &str, expected: &str) -> Self {
        Self::new(Detail::UsageInvalidValue(details::UsageInvalidValue {
            argument: field.into(),
            got: "[redacted]".into(),
            expected: expected.into(),
        }))
    }
    pub fn too_large(field: &str, limit: usize, got: usize) -> Self {
        Self::new(Detail::InputTooLarge(details::InputTooLarge {
            field: field.into(),
            limit_bytes: limit as u64,
            got_bytes: got as u64,
        }))
    }
    pub fn with_cause(mut self, cause: impl Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }
    pub fn code(&self) -> Code {
        self.body.code()
    }
    pub fn class(&self) -> Class {
        self.body.class()
    }
    pub fn into_body(self) -> ErrorBody {
        self.body
    }
}
impl From<ErrorBody> for SeError {
    fn from(body: ErrorBody) -> Self {
        Self { body, cause: None }
    }
}
impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.body.fmt(f)
    }
}
impl Error for SeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| &**cause as &(dyn Error + 'static))
    }
}

/// Only generated typed operation inputs implement this; no raw argv constructor.
pub trait OperationCommand {
    fn cli_argv(&self) -> Vec<String>;
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(with = "Vec<String>")]
pub struct Argv(Vec<String>);
impl Argv {
    pub fn from_op(operation: &impl OperationCommand) -> crate::Result<Self> {
        Self::validate(operation.cli_argv())
    }
    fn validate(args: Vec<String>) -> crate::Result<Self> {
        if args.is_empty()
            || args.len() > 256
            || args.iter().any(|a| a.contains('\0') || a.len() > 32768)
        {
            return Err(SeError::invalid(
                "remedy argv",
                "1..256 bounded literal arguments without NUL",
            ));
        }
        Ok(Self(args))
    }
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Argv {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let args = Vec::<String>::deserialize(deserializer)?;
        Self::validate(args).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Cmd {
    Se { argv: Argv },
    Tool { name: String, args: Value },
    Manual,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Remedy {
    pub text: String,
    pub command: Option<Cmd>,
}
pub trait RemedyCommands {
    /// Resolve to the canonical registry input, then use Argv::from_op.
    fn for_error(&self, error: &ErrorBody) -> crate::Result<Option<Cmd>>;
}
#[derive(Default)]
pub struct RenderCx<'a> {
    pub project: Option<&'a ProjectId>,
    pub agent: Option<&'a AgentId>,
    pub commands: Option<&'a dyn RemedyCommands>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ErrorEnvelopeWire", into = "ErrorEnvelopeWire")]
pub struct ErrorEnvelope {
    body: ErrorBody,
    message: String,
    remedy: Remedy,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
struct ErrorEnvelopeWire {
    schema: String,
    #[serde(flatten)]
    body: ErrorBody,
    class: Class,
    exit: u8,
    message: String,
    remedy: Remedy,
}
impl ErrorEnvelope {
    pub fn new(body: ErrorBody, cx: &RenderCx<'_>) -> crate::Result<Self> {
        let message = body.detail.message_in(cx);
        let remedy = body.remedy(cx)?;
        Ok(Self {
            body,
            message,
            remedy,
        })
    }
    pub fn body(&self) -> &ErrorBody {
        &self.body
    }
}
impl From<ErrorEnvelope> for ErrorEnvelopeWire {
    fn from(value: ErrorEnvelope) -> Self {
        Self {
            schema: "se.error/v1".into(),
            class: value.body.class(),
            exit: value.body.class().exit_code(),
            body: value.body,
            message: value.message,
            remedy: value.remedy,
        }
    }
}
impl TryFrom<ErrorEnvelopeWire> for ErrorEnvelope {
    type Error = SeError;
    fn try_from(value: ErrorEnvelopeWire) -> crate::Result<Self> {
        if value.schema != "se.error/v1"
            || value.class != value.body.class()
            || value.exit != value.body.class().exit_code()
            || value.message.is_empty()
            || value.remedy.text.is_empty()
        {
            return Err(SeError::invalid(
                "error envelope",
                "consistent se.error/v1 code, class, exit and message",
            ));
        }
        Ok(Self {
            body: value.body,
            message: value.message,
            remedy: value.remedy,
        })
    }
}
```

### crates/se-types/src/error/catalog.rs

```rust
// One canonical table: typed detail, code, class, message and remedy.
// Section 50 catalog; no executable catalog generator or tests are shipped.
codes! {
    UsageUnknownCommand => ("usage-unknown-command", Usage) { got: String, suggestion: Option<String> } => "unknown command `{got}`", "Use `se help`";
    UsageUnknownFlag => ("usage-unknown-flag", Usage) { flag: String, command: String, suggestion: Option<String> } => "`{command}` has no flag `{flag}`", "Use `se help {command}`";
    UsageMissingArgument => ("usage-missing-argument", Usage) { command: String, argument: String } => "`{command}` needs {argument}", "Use `se help {command}`";
    UsageInvalidValue => ("usage-invalid-value", Usage) { argument: String, got: String, expected: String } => "{argument}: `{got}` is not {expected}", "correct the value";
    UsageConflictingFlags => ("usage-conflicting-flags", Usage) { flags: Vec<String> } => "{flags} cannot be used together", "pick one";
    FlagNotApplicable => ("flag-not-applicable", Usage) { flag: String, command: String } => "`{flag}` has no meaning for `{command}`", "drop the flag";
    InputUnknownField => ("input-unknown-field", Usage) { op: String, field: String } => "`{field}` is not an input of {op}", "Use `se schema {op}` / tools/list";
    InputTooLarge => ("input-too-large", Usage) { field: String, limit_bytes: u64, got_bytes: u64 } => "{field} is {got_bytes} bytes; limit {limit_bytes}", "shorten or split it";
    Renamed => ("renamed", Usage) { old: String, replacement: String } => "`{old}` was renamed", "Use `{replacement}` (template; fill placeholders)";
    CommandRetired => ("command-retired", Usage) { old: String, reason: String, workflow: String } => "`{old}` was retired: {reason}", "{workflow}";
    LegacyRootFlag => ("legacy-root-flag", Usage) { flag: String } => "`{flag}` was removed; projects come from the registry", "Use `se init --repo DIR` or `-p P`";
    FeatureDisabled => ("feature-disabled", Refused) { feature: String } => "{feature} is turned off", "Use `se config set {feature}.enabled true`";
    FeatureNotBuilt => ("feature-not-built", Refused) { feature: String } => "this build of se does not include {feature}", "install the standard build from stateengine.ai";
    JsonVersionUnsupported => ("json-version-unsupported", Usage) { family: String, requested: u16, served: Vec<u16> } => "{family} v{requested} is not served (have {served})", "Use `--json`";
    ToolUnknown => ("tool-unknown", Usage) { name: String } => "no tool `{name}`", "use tools/list";
    ToolNotAvailable => ("tool-not-available", Unauthorized) { name: String, reason: String } => "`{name}` is not available to this session ({reason})", "ask the owner, or use tools/list";
    SecretToTerminalRefused => ("secret-to-terminal-refused", Refused) { what: String } => "refusing to print {what} to a terminal", "run it through a pipe (integrations only)";
    StdinRequired => ("stdin-required", Usage) { what: String } => "{what} is read from stdin, which is a terminal", "pipe the input";
    OwnerRequired => ("owner-required", Unauthorized) { op: String } => "`{op}` is an owner command; agent sessions can't run it", "run it in your own terminal (unset `SE_SESSION`)";
    HumanTerminalRequired => ("human-terminal-required", Unauthorized) { op: String, reason: String } => "`{op}` needs you at an interactive terminal not started by an agent", "run `se {op}` in a terminal you opened";
    SessionRequired => ("session-required", Unauthorized) { op: String } => "`{op}` acts as an agent and needs a launched session", "Use `se launch AGENT`";
    MachineCredentialMissing => ("machine-credential-missing", Refused) { path: String } => "no machine credential at {path}", "Use `se init`";
    MachineCredentialUnreadable => ("machine-credential-unreadable", Unreadable) { path: String, reason: String } => "can't read the machine credential: {reason}", "Use `se doctor`";
    OsUserMismatch => ("os-user-mismatch", Unauthorized) { expected: String, actual: String } => "this StateEngine home belongs to {expected}, you are {actual}", "use your own `SE_HOME`";
    CapabilityInvalid => ("capability-invalid", Unauthorized) { reason: String } => "the session credential is not valid ({reason})", "relaunch: → `se launch AGENT`";
    CapabilityRevoked => ("capability-revoked", Unauthorized) { session: SessionId, at: UnixMicros, reason: String } => "session {session} was ended at {at} ({reason})", "Use `se launch AGENT`";
    CapabilityExpired => ("capability-expired", Unauthorized) { session: SessionId, at: UnixMicros } => "the session token expired at {at}", "the helper renews it; if not → `se launch AGENT`";
    ProjectConflictsSession => ("project-conflicts-session", Usage) { flag_project: String, session_project: String } => "`-p {flag_project}` conflicts with this session's project {session_project}", "drop `-p`";
    GrantRequired => ("grant-required", Unauthorized) { grant: String } => "this session lacks permission `{grant}`", "owner: → `se config set agent.{agent}.can-create true -p P`";
    NotRecipient => ("not-recipient", Unauthorized) { message: MessageId, recipient: String } => "only {recipient} can mark {message} read or dismissed", "read it with `se msg read` as that agent, or leave it";
    SelfApprovalRefused => ("self-approval-refused", Unauthorized) { decision: DecisionId } => "agents can propose decisions but not approve them", "owner: → `se decision ratify {decision}`";
    ListenerAdmissionRefused => ("listener-admission-refused", Unauthorized) { reason: String } => "local server refused the request: {reason}", "reconnect through `se mcp token`; non-loopback access is not supported";
    ProjectRequired => ("project-required", Usage) { choices: Vec<ProjectChoice> } => "which project? none registered here", "Use `se init` (none) or `se … -p NAME`";
    ProjectUnknown => ("project-unknown", Unknown) { selector: String } => "no project `{selector}`", "Use `se status --all`";
    ProjectAmbiguous => ("project-ambiguous", Usage) { selector: String, matches: Vec<String> } => "`{selector}` names {matches.len} projects", "use the id: `-p prj_…`";
    ProjectRemoved => ("project-removed", Refused) { project: ProjectId, at: UnixMicros } => "project {project} was removed at {at}", "re-adopt: → `se init --repo {root}`";
    RegistrationUnreadable => ("registration-unreadable", Unreadable) { path: String, reason: String } => "can't read project registrations: {reason}", "Use `se doctor`";
    CwdRegistrationAmbiguous => ("cwd-registration-ambiguous", Usage) { cwd: String, candidates: Vec<String> } => "{cwd} is registered twice", "Use `-p P`, then `se doctor --fix`";
    HomeUnreadable => ("home-unreadable", Unreadable) { home: String, reason: String } => "can't read StateEngine home {home}: {reason}", "Use `se doctor`";
    HomeUnsupportedLocation => ("home-unsupported-location", Refused) { home: String, kind: String } => "{home} is on a {kind} location; the store needs a local disk", "set `SE_HOME` to a local folder";
    ConfigUnreadable => ("config-unreadable", Unreadable) { path: String, reason: String } => "can't read {path}: {reason}", "fix permissions or → `se doctor`";
    ConfigInvalid => ("config-invalid", Refused) { path: String, line: u64, column: u64, problem: String } => "{path}:{line}:{column}: {problem}", "edit the file";
    ConfigKeyUnknown => ("config-key-unknown", Usage) { key: String, suggestion: Option<String> } => "no setting `{key}`", "Use `se config list`";
    ConfigValueInvalid => ("config-value-invalid", Usage) { key: String, got: String, expected: String } => "{key}: `{got}` is not {expected}", "Use `se config get {key} --origin`";
    ConfigScopeInvalid => ("config-scope-invalid", Usage) { key: String, scope: String } => "`{key}` is a {scope} setting", "drop or add `-p`";
    ConfigVersionUnsupported => ("config-version-unsupported", Refused) { path: String, version: u32, supported: u32 } => "{path} is format v{version}; this se reads v{supported}", "upgrade se";
    ProfileUnknown => ("profile-unknown", Refused) { profile: String } => "no permission profile `{profile}`", "Use `se config list`; define `[profiles.{profile}]`";
    BypassNotOptedIn => ("bypass-not-opted-in", Refused) { profile: String } => "full bypass is only allowed through a saved, named profile", "add `bypass = true` under `[profiles.NAME]`, then → `se config set agent.A.profile NAME`";
    RepoNotFound => ("repo-not-found", Refused) { path: String } => "{path} does not exist", "Use `se init --repo DIR` with an existing folder";
    RepoNotDirectory => ("repo-not-directory", Refused) { path: String } => "{path} is not a folder", "pick the repository folder";
    RepoInsideProject => ("repo-inside-project", Conflict) { path: String, project: ProjectId, root: String } => "{path} is inside project {project} ({root})", "use it: → `se status -p {project}`";
    RepoNameMismatch => ("repo-name-mismatch", Conflict) { root: String, project: ProjectId, requested: String } => "{root} is already project {project}", "rerun without `--name`";
    IntegrationConflict => ("integration-conflict", Conflict) { path: String, entry: String } => "you changed {entry} in {path}; StateEngine won't overwrite it", "keep it, or delete the entry and → `se doctor --fix`";
    IntegrationWriteFailed => ("integration-write-failed", Refused) { path: String, reason: String } => "couldn't write {path}: {reason}", "Use `se doctor`";
    IntegrationReadbackMismatch => ("integration-readback-mismatch", Refused) { path: String, entry: String } => "wrote {entry} in {path} but read back something else", "Use `se doctor --fix`";
    RemoveTargetRequired => ("remove-target-required", Usage) { choices: Vec<ProjectChoice> } => "name the project to remove", "Use `se remove -p P` or `se remove --all`";
    RemoveIncomplete => ("remove-incomplete", Incomplete) { stopped: Vec<String>, unwitnessed: Vec<String>, remaining: Vec<String> } => "removal partly done: {remaining}", "Use `se remove -p P` (idempotent)";
    StoreAbsent => ("store-absent", Refused) { home: String } => "no StateEngine data in {home}", "Use `se init`";
    StoreUnreadable => ("store-unreadable", Unreadable) { path: String, reason: String } => "can't read the store: {reason}", "Use `se doctor`";
    StoreCorrupt => ("store-corrupt", Unreadable) { path: String, check: String } => "the store failed its integrity check ({check})", "Use `se doctor --fix` (restores from the newest good backup + salvage)";
    StoreTooNew => ("store-too-new", Refused) { store_version: u64, supported: u64 } => "the store was written by a newer se (schema {store_version})", "upgrade se";
    StoreMigrationRequired => ("store-migration-required", Unavailable) { from: u64, to: u64 } => "the store needs an upgrade that only the runtime performs", "Use `se up`";
    StoreMigrationFailed => ("store-migration-failed", Refused) { from: u64, to: u64, step: String, rollback_copy: String } => "upgrade {from}→{to} failed at {step}; old copy kept at {rollback_copy}", "Use `se doctor`";
    StoreBusy => ("store-busy", Unavailable) { waited_ms: u64 } => "the store stayed locked for {waited_ms} ms", "retry (`Retry::After`)";
    StoreDiskFull => ("store-disk-full", Unavailable) { path: String, free_bytes: u64 } => "not enough disk space at {path}", "free space and retry";
    StoreReadOnly => ("store-read-only", Refused) { path: String } => "{path} is read-only", "fix permissions or `SE_HOME`";
    RevisionConflict => ("revision-conflict", Conflict) { entity: String, expected: String, current: String } => "{entity} changed (you had revision {expected}, now {current})", "reread: → `se working-state` / `se decision show ID`";
    IdempotencyKeyReused => ("idempotency-key-reused", Conflict) { key: String, original_event: EventId } => "key `{key}` was used for a different request", "use a new key";
    EventUnknown => ("event-unknown", Unknown) { event: EventId } => "no event {event} in this project", "Use `se search QUERY`";
    EventUnreadable => ("event-unreadable", Unreadable) { event: EventId, reason: String } => "event {event} exists but can't be decoded: {reason}", "Use `se doctor`";
    CursorInvalid => ("cursor-invalid", Usage) { reason: String } => "this cursor isn't valid here ({reason})", "rerun without `--since`";
    CursorExpired => ("cursor-expired", Incomplete) { oldest_available: u64 } => "the cursor is older than retained history", "rerun without `--since`";
    BackupDestinationExists => ("backup-destination-exists", Refused) { path: String } => "{path} already exists", "choose another path";
    BackupFailed => ("backup-failed", Refused) { path: String, step: String, reason: String } => "backup failed at {step}: {reason}", "Use `se doctor`";
    BackupReadbackMismatch => ("backup-readback-mismatch", Refused) { path: String } => "the backup at {path} didn't verify", "Use `se backup` to a new path";
    ImportSourceUnreadable => ("import-source-unreadable", Unreadable) { path: String, reason: String } => "can't read Node state at {path}: {reason}", "check the path";
    ImportFormatUnsupported => ("import-format-unsupported", Refused) { path: String, found: String, supported: Vec<String> } => "{path} is format {found}; supported: {supported}", "upgrade Node StateEngine first, then import";
    ImportSourceActive => ("import-source-active", Refused) { path: String, pid: Option<u32> } => "the old StateEngine is still running on {path}", "stop it with the old `se down`, then retry";
    ImportIncomplete => ("import-incomplete", Incomplete) { families: Vec<ImportFamilyIssue> } => "import finished with rejected rows", "rerun (idempotent); see the receipt";
    ForgetConfirmationRequired => ("forget-confirmation-required", Refused) { events: Vec<EventId> } => "erasure needs typed confirmation", "rerun in a terminal and type the first id";
    ForgetNotCapturedRecord => ("forget-not-captured-record", Refused) { event: EventId, kind: String } => "only captured turns and messages can be erased; {event} is a {kind}", "pick a captured record";
    ForgetIncomplete => ("forget-incomplete", Incomplete) { erased: Vec<String>, residual: Vec<String> } => "erased in the store; copies remain in {residual}", "delete or let backups expire; provider transcripts belong to Claude/Codex";
    RuntimeNotRunning => ("runtime-not-running", Unavailable) { op: String } => "`{op}` needs the StateEngine runtime", "Use `se up`";
    RuntimeStartFailed => ("runtime-start-failed", Unavailable) { reason: String, log: String } => "the runtime didn't start: {reason}", "see {log}; → `se doctor`";
    RuntimeStartPending => ("runtime-start-pending", Incomplete) { waited_ms: u64 } => "the runtime is still starting after {waited_ms} ms", "Use `se status`";
    RuntimeOwnedElsewhere => ("runtime-owned-elsewhere", Refused) { host: String, pid: u32, version: String } => "the runtime is hosted by {host}", "quit SE Code to stop it";
    RuntimeVersionMismatch => ("runtime-version-mismatch", Refused) { running: String, this: String } => "runtime {running} is running; this se is {this}", "Use `se down`, then retry";
    LegacyRuntimeRunning => ("legacy-runtime-running", Refused) { pid: Option<u32> } => "the old Node StateEngine is running on this home", "stop it with the old `se down`";
    RuntimeHandoverInProgress => ("runtime-handover-in-progress", Unavailable) { generation: String } => "the runtime is changing hosts", "retry (`WhenRuntimeReady`)";
    RuntimeDrainTimeout => ("runtime-drain-timeout", Incomplete) { deadline_ms: u64, pending: Vec<String> } => "shutdown didn't finish in time: {pending}", "Use `se down`";
    RuntimeStopUnwitnessed => ("runtime-stop-unwitnessed", Incomplete) { pid: u32, reason: String } => "stop requested but exit not confirmed: {reason}", "Use `se status`";
    ListenerPortInUse => ("listener-port-in-use", Refused) { port: u64, holder: Option<String> } => "port {port} is in use", "Use `se config set runtime.listen_port N`";
    ListenerNonLoopback => ("listener-non-loopback", Refused) { address: String } => "`{address}` is not loopback; only 127.0.0.1 is allowed", "fix `runtime.listen_address`";
    IpcUnavailable => ("ipc-unavailable", Unavailable) { endpoint: String, reason: String } => "can't reach the runtime: {reason}", "Use `se status`";
    ApiVersionUnsupported => ("api-version-unsupported", Refused) { client: String, host: String } => "client API {client} vs runtime {host}", "upgrade the older side";
    CustodyUnavailableHostless => ("custody-unavailable-hostless", Unavailable) { op: String } => "this stdio server has no runtime; `{op}` can't act", "Use `se up`";
    AgentUnknown => ("agent-unknown", Unknown) { selector: String, suggestion: Option<String> } => "no agent `{selector}` in {project}", "Use `se agent list`";
    AgentAmbiguous => ("agent-ambiguous", Usage) { selector: String, matches: Vec<String> } => "`{selector}` matches {matches.len} agents", "use the id";
    AgentNameTaken => ("agent-name-taken", Conflict) { name: String, agent: AgentId } => "`{name}` is already agent {agent}", "Use `se launch {name}` or pick another name";
    AgentNameInvalid => ("agent-name-invalid", Usage) { name: String, rule: String } => "`{name}`: {rule}", "choose another name";
    ProviderUnsupported => ("provider-unsupported", Usage) { got: String } => "`{got}` isn't a provider (claude, codex)", "Inspect the reported cause and correct it before retrying.";
    ProviderCliNotFound => ("provider-cli-not-found", Refused) { provider: String, searched: Vec<String> } => "can't find the {provider} CLI", "install it (`Cmd::Manual`), or → `se config set providers.{provider}.command PATH`";
    ProviderCliTooOld => ("provider-cli-too-old", Refused) { provider: String, found: String, minimum: String } => "{provider} {found} is older than {minimum}", "upgrade {provider}";
    ProviderCliUnrecognized => ("provider-cli-unrecognized", Refused) { provider: String, output: String } => "couldn't read the {provider} version", "Use `se doctor`";
    ProviderProtocolUnsupported => ("provider-protocol-unsupported", Refused) { provider: String, version: String, needed: String } => "{provider} {version} lacks {needed}", "upgrade {provider}";
    ProviderChangeBreaksResume => ("provider-change-breaks-resume", Refused) { agent: AgentId, saved: String, requested: String } => "{agent}'s conversation is a {saved} conversation", "Use `se launch {agent} --new --provider {requested}`";
    ResumeReferenceMissing => ("resume-reference-missing", Refused) { agent: AgentId } => "{agent} has no saved conversation to resume", "Use `se launch {agent} --new`";
    ResumeReferenceUnverifiable => ("resume-reference-unverifiable", Unreadable) { agent: AgentId, conversation: String, reason: String } => "can't verify conversation {conversation}: {reason}", "Use `se launch {agent} --new` (starts fresh, explicitly)";
    AgentAlreadyRunning => ("agent-already-running", Conflict) { agent: AgentId, pid: u32, since: String } => "{agent} is already running (since {since})", "message it, or → `se stop {agent}`";
    LaunchInFlight => ("launch-in-flight", Conflict) { agent: AgentId, launch_id: LaunchId } => "{agent} is already being launched", "retry";
    LaunchReadinessTimeout => ("launch-readiness-timeout", Incomplete) { agent: AgentId, waited_ms: u64, last_observed: String } => "{agent} started but wasn't ready after {waited_ms} ms", "Use `se agent show {agent}`";
    LaunchFailed => ("launch-failed", Refused) { agent: AgentId, provider: String, exit_code: Option<i32>, stderr_tail: String } => "{provider} exited during launch: {stderr_tail}", "fix the provider error, then → `se launch {agent}`";
    WindowUnavailable => ("window-unavailable", Refused) { tried: Vec<String> } => "no terminal window could be opened ({tried})", "Use `se launch AGENT --detach`, or set `launch.terminal`";
    JobBreakawayRefused => ("job-breakaway-refused", Refused) { parent: String } => "Windows won't let the agent outlive {parent}", "Use `se up` first, then launch";
    CgroupDelegationMissing => ("cgroup-delegation-missing", Refused) { path: String } => "Linux cgroup delegation is off ({path})", "enable systemd user delegation (`Cmd::Manual`, exact text in doctor)";
    CodexAppServerFailed => ("codex-app-server-failed", Refused) { phase: String, reason: String } => "Codex app-server failed at {phase}: {reason}", "Use `se doctor`";
    WakeNotRunning => ("wake-not-running", Refused) { agent: AgentId } => "{agent} isn't running, so there is nothing to wake", "Use `se launch {agent}`";
    StopUnwitnessed => ("stop-unwitnessed", Incomplete) { agent: AgentId, pid: u32, reason: String } => "stop sent but {agent}'s exit isn't confirmed", "Use `se agent show {agent}`, then `se stop {agent}`";
    StopPartial => ("stop-partial", Incomplete) { stopped: Vec<String>, failed: Vec<String> } => "stopped {stopped.len}; not confirmed: {failed}", "Use `se stop AGENT` for each";
    SessionUnknown => ("session-unknown", Unknown) { session: SessionId } => "no session {session}", "Use `se agent show AGENT`";
    SessionBindingUnproven => ("session-binding-unproven", Unauthorized) { reason: String } => "a session id alone can't bind ({reason})", "launch through se, or → `se doctor --fix` for your integration";
    SessionGenerationMismatch => ("session-generation-mismatch", Conflict) { expected: Generation, current: Generation } => "session generation is {current}, not {expected}", "reread and retry";
    SessionAlreadyEnded => ("session-already-ended", Refused) { session: SessionId, at: UnixMicros } => "session {session} ended at {at}", "Use `se launch AGENT`";
    CaptureConsentMissing => ("capture-consent-missing", Refused) { session: SessionId } => "capture is off for this session", "relaunch without `--incognito`";
    TurnInvalid => ("turn-invalid", Usage) { field: String, problem: String } => "turn {field}: {problem}", "fix the integration (→ `se doctor`)";
    TranscriptUnreadable => ("transcript-unreadable", Unreadable) { path: String, reason: String } => "can't read the transcript {path}: {reason}", "Use `se doctor`";
    TranscriptTruncated => ("transcript-truncated", Incomplete) { path: String, offset: u64, size: u64 } => "{path} shrank below the read offset", "captured turns stay; → `se status`";
    HookPayloadInvalid => ("hook-payload-invalid", Usage) { event: EventId, problem: String } => "Claude `{event}` payload: {problem}", "Use `se doctor` (hook exits 0 anyway)";
    MessageScopeDenied => ("message-scope-denied", Unauthorized) { filter: String, agent: AgentId } => "as an agent, {agent} can list only messages it sent or received; `{filter}` names others' mail", "Drop the filter, or the owner runs `se msg list` from their own terminal.";
    RecipientUnknown => ("recipient-unknown", Unknown) { to: String, suggestion: Option<String> } => "no agent `{to}` to send to", "Use `se agent list`";
    RecipientOtherProject => ("recipient-other-project", Refused) { to: String, project: ProjectId } => "{to} is in project {project}", "send from that project";
    MessageUnknown => ("message-unknown", Unknown) { id: String } => "no message {id}", "Use `se msg list --all`";
    ReplyTargetUnknown => ("reply-target-unknown", Unknown) { id: String } => "can't reply to {id}: not found", "drop `--reply-to`";
    DecisionUnknown => ("decision-unknown", Unknown) { id: String } => "no decision {id}", "Use `se decision list`";
    DecisionKeyInvalid => ("decision-key-invalid", Usage) { key: String } => "`{key}` isn't a valid decision key", "use lowercase letters, digits, `.`, `_`, `-`";
    DecisionStateInvalid => ("decision-state-invalid", Refused) { id: String, state: String, action: String } => "can't {action} {id}: it is {state}", "Use `se decision show {id}`";
    SupersedeInvalid => ("supersede-invalid", Refused) { prior: DecisionId, replacement: DecisionId, reason: String } => "can't supersede: {reason}", "Use `se decision list --history`";
    ObservationUnknown => ("observation-unknown", Unknown) { observation: ObservationId } => "no observation {observation}", "Use `se process list`";
    ObservationNotYours => ("observation-not-yours", Unauthorized) { observation: ObservationId } => "{observation} belongs to another caller", "use your own handle";
    BarePidRefused => ("bare-pid-refused", Usage) { got: String } => "processes are selected by observation, not pid", "Use `se process list`";
    ProcessIdentityChanged => ("process-identity-changed", Refused) { pid: u32, expected_start: String, found_start: String } => "pid {pid} now belongs to a different process", "nothing to stop; → `se process inspect --observation O`";
    ProcessIdentityUnreadable => ("process-identity-unreadable", Unreadable) { pid: u32, reason: String } => "can't read pid {pid}'s identity: {reason}", "retry; → `se doctor`";
    CommandNotFound => ("command-not-found", Refused) { program: String } => "`{program}` not found on PATH", "give a full path";
    SpawnFailed => ("spawn-failed", Refused) { program: String, reason: String } => "couldn't start {program}: {reason}", "Inspect the reported cause and correct it before retrying.";
    CwdOutsideWorkspace => ("cwd-outside-workspace", Refused) { cwd: String, workspace: String } => "{cwd} is outside the project folder {workspace}", "use a path inside the project";
    EnvKeyNotAllowed => ("env-key-not-allowed", Usage) { key: String } => "`{key}` can't be set for a managed process", "drop it";
    StopDeadlineExceeded => ("stop-deadline-exceeded", Incomplete) { observation: ObservationId, deadline_ms: u64, remaining: Vec<String> } => "{remaining.len} processes still alive after {deadline_ms} ms", "retry with a longer `--deadline`";
    AtlasIndexAbsent => ("atlas-index-absent", Refused) { project: ProjectId } => "no code index for {project} yet", "Use `se config set atlas.enabled true -p P` (indexes in the background; `se status` shows progress)";
    AtlasIndexing => ("atlas-indexing", Incomplete) { indexed: u64, total: u64 } => "index is {indexed}/{total} files; results may be partial", "retry later";
    AtlasUnreadable => ("atlas-unreadable", Unreadable) { path: String, reason: String } => "can't read atlas.db: {reason}", "Use `se doctor --fix` (rebuilds the index)";
    AtlasPathOutsideRoot => ("atlas-path-outside-root", Refused) { path: String, root: String } => "{path} is outside {root}", "use a project-relative path";
    AtlasPathUnknown => ("atlas-path-unknown", Unknown) { path: String } => "{path} isn't indexed", "Use `se atlas find PATH --kind path`";
    AtlasSymbolUnknown => ("atlas-symbol-unknown", Unknown) { symbol: String } => "no symbol `{symbol}`", "Use `se atlas find {symbol}`";
    AtlasSymbolAmbiguous => ("atlas-symbol-ambiguous", Usage) { symbol: String, candidates: Vec<String> } => "`{symbol}` names {candidates.len} symbols", "add `--path`";
    AtlasLanguageUnsupported => ("atlas-language-unsupported", Refused) { path: String, language: Option<String> } => "{language} files aren't parsed", "text search: `--kind text`";
    AtlasFileOverBudget => ("atlas-file-over-budget", Refused) { path: String, size: u64, budget: u64 } => "{path} ({size}) exceeds the parse budget", "none; the file stays text-searchable";
    RepairNotSupported => ("repair-not-supported", Refused) { check: String } => "`doctor --fix` can't repair {check}", "follow the check's own fix line";
    RepairWouldWeakenDefaults => ("repair-would-weaken-defaults", Refused) { change: String } => "refusing to {change}: it weakens safety defaults", "change it yourself by named profile";
    BundleDestinationInvalid => ("bundle-destination-invalid", Usage) { path: String, reason: String } => "can't write the bundle to {path}: {reason}", "Use `se doctor --bundle PATH`";
    DeadlineExceeded => ("deadline-exceeded", Unavailable) { op: String, deadline_ms: u64 } => "`{op}` didn't finish in {deadline_ms} ms", "retry";
    Cancelled => ("cancelled", Cancelled) { op: String } => "`{op}` was interrupted", "rerun; writes are all-or-nothing";
    TaskFailed => ("task-failed", Internal) { task: String, report_id: String } => "internal task {task} failed ({report_id})", "Use `se doctor --bundle` and send it";
    Internal => ("internal", Internal) { report_id: String, location: String } => "StateEngine hit a bug ({report_id})", "Use `se doctor --bundle` and send it";
}
```

### Proposed SE Code permissive crate root

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proposal for Alpha's MIT/Apache secode-stateengine-api crate, not an engine API.
//! Standalone trait/data declarations: deliberately no dependency on se-types.
//! Checked independently as a crate root for design review, not published or wired.
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiFailure {
    NotIncluded,
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Cancelled,
    EnginePanicked,
    GenerationPoisoned,
    Internal,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiCommand {
    Se {
        argv: Vec<String>,
    },
    Tool {
        name: String,
        args: serde_json::Value,
    },
    Manual,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiRemedy {
    pub text: String,
    pub command: Option<ApiCommand>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiRetry {
    Never,
    AfterMillis(u64),
    AfterRefresh,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    pub kind: ApiFailure,
    pub code: String,
    pub message: String,
    pub remedy: ApiRemedy,
    pub retry: ApiRetry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasRootId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexEpochId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPendingId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyKey(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoticeId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cursor(pub String);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostGeneration(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sequence(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixMicros(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256(pub [u8; 32]);
pub type NativePath = PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartIdentity {
    Windows {
        creation_filetime: u64,
    },
    Linux {
        start_ticks: u64,
    },
    Macos {
        start_seconds: u64,
        start_micros: u32,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInstance {
    pub machine: String,
    pub boot: String,
    pub pid: u32,
    pub started: StartIdentity,
    pub executable: PathBuf,
    pub argv_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    Store {
        store: StoreId,
        project: Option<ProjectId>,
    },
    Host {
        epoch: HostEpoch,
    },
    Atlas {
        project: ProjectId,
        root: AtlasRootId,
        epoch: Option<IndexEpochId>,
    },
    Configuration {
        location: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Read<T> {
    Present {
        value: T,
    },
    Absent {
        checked: String,
    },
    Unreadable {
        source: String,
        reason: String,
        error: Option<ApiError>,
    },
    Unknown {
        what: String,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    Limit,
    Budget,
    Unreadable,
    SourceIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Omission {
    None,
    Known { count: u64, reason: OmissionReason },
    Unknown { reason: OmissionReason },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    Exhausted,
    ItemLimit,
    ByteLimit,
    Unreadable,
    Cancelled,
    Deadline,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    pub source: Source,
    pub from: Sequence,
    pub to: Sequence,
    pub start_cursor: Option<Cursor>,
    pub end_cursor: Option<Cursor>,
    pub returned: u64,
    pub limit: u32,
    pub bytes: u64,
    pub max_bytes: u32,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
    pub complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub window: Window,
    pub next: Option<Cursor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: u32,
    pub max_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    pub id: EventId,
    pub sequence: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: ApiError },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit<T> {
    pub event: EventRef,
    pub idempotency_key: IdempotencyKey,
    pub value: T,
    pub effects: EffectStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingReason {
    Queued,
    AwaitingWitness,
    Recovering,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Receipt<T> {
    Committed {
        commit: Commit<T>,
    },
    Replayed {
        original: Commit<T>,
    },
    Refused {
        error: ApiError,
    },
    Pending {
        cause: PendingReason,
        event: Option<EventRef>,
        idempotency_key: IdempotencyKey,
    },
}
use serde_json::Value;
use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}
pub const API_VERSION: ApiVersion = ApiVersion { major: 1, minor: 0 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiRange {
    pub major: u16,
    pub min_minor: u16,
    pub max_minor: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreVersion {
    pub application_id: u32,
    pub schema: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKind {
    EmbeddedSecode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feature {
    NativeMail,
    LocalListener,
    Atlas,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    pub api: ApiVersion,
    pub store: StoreVersion,
    pub generation: Generation,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub page_items: NonZeroU32,
    pub payload_bytes: NonZeroU32,
    pub notice_ids: NonZeroU32,
    pub subscription_entries: NonZeroU32,
    pub subscription_bytes: NonZeroU32,
}
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub state_home: NativePath,
    pub api: ApiRange,
    pub kind: HostKind,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
pub trait Cancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
pub struct CallOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}

// No Debug, Clone or Deserialize on protected material or authority.
pub struct MachineCredential(pub Vec<u8>);
pub struct SessionCapability(pub Vec<u8>);
pub struct LaunchCredential(pub Vec<u8>);
pub struct OwnerProof {
    pub credential: MachineCredential,
    pub presenting_process: ProcessInstance,
}
/// Opaque issued handles; the implementation validates every handle and generation.
/// Public bytes are protected transport data, not deserialized authority claims.
pub struct OwnerAuthority {
    pub grant: Vec<u8>,
}
pub struct BoundSession {
    pub grant: Vec<u8>,
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Sequence,
}
pub enum Authority {
    Owner(OwnerAuthority),
    Session(BoundSession),
    Anonymous,
}
pub enum BindingAuthority {
    Owner(OwnerAuthority),
    Launch(LaunchCredential),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Harness {
    ClaudeCode,
    CodexAppServer,
    Secode,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelIdentity {
    pub provider: String,
    pub model: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInfo {
    pub id: ProjectId,
    pub name: String,
    pub root: NativePath,
    pub revision: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreInfo {
    pub id: StoreId,
    pub version: StoreVersion,
    pub head: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequest {
    pub project: ProjectId,
    pub agent: AgentId,
    pub harness: Harness,
    pub model: ModelIdentity,
    pub conversation: ProviderSessionId,
    pub target: Option<HostSessionTarget>,
    pub expected_generation: Generation,
    pub expected_binding_revision: Option<Sequence>,
    pub capture_consent: bool,
    pub idempotency_key: IdempotencyKey,
}
pub struct IssuedSession {
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Sequence,
    pub capability: SessionCapability,
    pub receipt: Receipt<SessionIdentity>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndReason {
    UserStopped,
    SessionEnded,
    Replaced,
    Removed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeRequest {
    pub session: SessionId,
    pub reason: EndReason,
    pub key: IdempotencyKey,
}

#[derive(Clone, Debug)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
}
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
    pub idempotency_key: Option<IdempotencyKey>,
}
#[derive(Clone, Debug)]
pub struct ToolOutput {
    pub schema: String,
    pub content: Value,
    pub window: Option<Window>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityRequest {
    pub page: PageRequest,
    pub acknowledge_packet: Option<Sha256>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedText {
    pub text: String,
    pub utf8_bytes: u64,
    pub complete: bool,
    pub omitted_bytes: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub digest: Sha256,
    pub content: BoundedText,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextDisplayIdentity {
    pub agent: AgentId,
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub neutral: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuitySummary {
    pub rows: u64,
    pub latest_at: Option<UnixMicros>,
}
/// Linked DTO; an explicitly versioned adapter retains legacy context fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionContext {
    pub schema: String,
    pub identity: SessionIdentity,
    pub display_identity: ContextDisplayIdentity,
    pub generated_at: UnixMicros,
    pub source_cli: String,
    pub harness: Harness,
    pub model: ModelIdentity,
    pub conversation: ProviderSessionId,
    pub packet: Read<Packet>,
    pub model_input: BoundedText,
    pub continuity: Window,
    pub continuity_summary: ContinuitySummary,
    pub warnings: Vec<String>,
    pub failures: Vec<ApiError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnRole {
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnNesting {
    pub parent_session: Option<ProviderSessionId>,
    pub nested_agent: Option<AgentId>,
    pub depth: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTurn {
    pub conversation: ProviderSessionId,
    pub vendor_turn: String,
    pub vendor_event: Option<String>,
    pub machine_id: Option<String>,
    pub source_ref: Option<String>,
    pub source_cli: String,
    pub nesting: Option<TurnNesting>,
    pub role: TurnRole,
    pub occurred_at: UnixMicros,
    pub content: BoundedText,
    pub source_sha256: Sha256,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSessionTarget {
    pub epoch: HostEpoch,
    pub session: HostSessionId,
    pub binding: SessionIdentity,
    pub binding_fingerprint: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventRef {
    pub id: HostEventId,
    pub sequence: NonZeroU64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    HumanStop,
    Takeover,
    Revocation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldReceipt {
    pub target: HostSessionTarget,
    pub committed: HostEventRef,
    pub retained_pending: u64,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterruptReceipt {
    pub target: HostSessionTarget,
    pub requested: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionActivity {
    Idle,
    Executing,
    Interrupting,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSession {
    pub target: HostSessionTarget,
    pub activity: SessionActivity,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetStatus {
    Eligible,
    Held,
    Revoked,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptBinding {
    pub previous: HostSessionTarget,
    pub current_epoch: HostEpoch,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingObservation {
    pub target: HostSessionTarget,
    pub status: TargetStatus,
    pub last_transition: HostEventRef,
    pub activity: Read<SessionActivity>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetTransition {
    Select {
        target: HostSessionTarget,
        superseded: Vec<HostSessionTarget>,
    },
    Revoke {
        target: HostSessionTarget,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetReceipt {
    pub target: HostSessionTarget,
    pub committed: HostEventRef,
    pub status: TargetStatus,
}
/// Contains IDs only: the model obtains bodies using the bound read operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailNotice {
    pub id: NoticeId,
    pub target: HostSessionTarget,
    pub messages: Vec<MessageId>,
    pub through: Cursor,
    pub dedupe_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    pub committed_in: HostEpoch,
    pub notice: NoticeId,
    pub target: HostSessionTarget,
    pub pending: HostPendingId,
    pub admitted_sequence: NonZeroU64,
    pub dedupe_sha256: Sha256,
    pub committed: HostEventRef,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoticeAdmission {
    Admitted(Admission),
    Replayed(Admission),
    Held(HoldReceipt),
    Refused(ApiError),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailSubscriptionRequest {
    pub from: Option<Cursor>,
    pub page: PageRequest,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailEvent {
    Notice(MailNotice),
    Lagged {
        resume_from: Cursor,
        window: Window,
    },
    Held {
        hold: HoldReceipt,
        resume_from: Cursor,
    },
    Revoked {
        identity: SessionIdentity,
    },
    Closed {
        generation: Generation,
        resume_from: Cursor,
    },
}
/// No read/dismiss action here: this settles notice delivery only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailSettlement {
    pub notice: NoticeId,
    pub admission: NoticeAdmission,
    pub idempotency_key: IdempotencyKey,
}
pub trait MailSubscription: Send {
    fn next<'a>(&'a mut self, options: CallOptions) -> HostFuture<'a, MailEvent>;
    fn close<'a>(&'a mut self, options: CallOptions) -> HostFuture<'a, Cursor>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdoptionState {
    Pending,
    Reattached,
    Held,
    Revoked,
    Absent,
    Unreadable(ApiError),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adoption {
    pub identity: SessionIdentity,
    pub binding_revision: Sequence,
    pub state: AdoptionState,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    Recovering { adoptions: Box<Page<Adoption>> },
}
pub struct OpenedHost {
    pub host: Arc<dyn Host>,
    pub negotiated: Negotiated,
    pub store: StoreInfo,
    pub readiness: Readiness,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainReceipt {
    pub generation: Generation,
    pub pending_notices: u64,
    pub unresolved_effects: u64,
    pub writer_flushed: bool,
}

/// The implementation/factory is configured with the embedding host's runtime.
/// No Tokio dependency or runtime creation belongs to se-types.
pub enum HostIntegration {
    Secode(Arc<dyn HostServices>),
}

pub trait HostFactory: Send + Sync {
    fn open<'a>(
        &'a self,
        config: HostConfig,
        integration: HostIntegration,
        options: CallOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationHealth {
    Ready,
    Recovering,
    Draining,
    Drained,
    Poisoned,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReport {
    pub generation: Generation,
    pub incident: String,
}

pub trait Host: Send + Sync {
    fn poison<'a>(
        &'a self,
        report: FaultReport,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;

    fn negotiated(&self) -> Negotiated;
    fn authenticate_owner<'a>(
        &'a self,
        proof: OwnerProof,
        options: CallOptions,
    ) -> HostFuture<'a, OwnerAuthority>;
    fn verify_capability<'a>(
        &'a self,
        capability: &'a SessionCapability,
        options: CallOptions,
    ) -> HostFuture<'a, BoundSession>;
    fn open_project<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        project: ProjectId,
        options: CallOptions,
    ) -> HostFuture<'a, Read<ProjectInfo>>;
    fn bind_session<'a>(
        &'a self,
        authority: &'a BindingAuthority,
        request: BindingRequest,
        options: CallOptions,
    ) -> HostFuture<'a, IssuedSession>;
    fn revoke_session<'a>(
        &'a self,
        authority: &'a Authority,
        request: RevokeRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<SessionIdentity>>;
    fn tools<'a>(
        &'a self,
        session: &'a BoundSession,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<ToolDefinition>>;
    fn call_tool<'a>(
        &'a self,
        session: &'a BoundSession,
        call: ToolCall,
        options: CallOptions,
    ) -> HostFuture<'a, ToolOutput>;
    fn continuity<'a>(
        &'a self,
        session: &'a BoundSession,
        request: ContinuityRequest,
        options: CallOptions,
    ) -> HostFuture<'a, SessionContext>;
    fn capture_turn<'a>(
        &'a self,
        session: &'a BoundSession,
        turn: CapturedTurn,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<EventRef>>;
    fn subscribe_mail<'a>(
        &'a self,
        session: &'a BoundSession,
        request: MailSubscriptionRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Box<dyn MailSubscription>>;
    fn settle_mail<'a>(
        &'a self,
        session: &'a BoundSession,
        settlement: MailSettlement,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<NoticeId>>;
    fn adoption_status<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<Adoption>>;
    fn drain<'a>(
        &'a self,
        expected: Generation,
        options: CallOptions,
    ) -> HostFuture<'a, DrainReceipt>;
    fn reopen<'a>(
        &'a self,
        drained: DrainReceipt,
        options: CallOptions,
    ) -> HostFuture<'a, Negotiated>;
    fn close<'a>(
        &'a self,
        drained: DrainReceipt,
        options: CallOptions,
    ) -> HostFuture<'a, DrainReceipt>;
}
/// SE Code owns admission and promotion of its one input queue.
/// StateEngine owns message bodies, recipient read/dismiss markers and debt.
pub trait HostServices: Send + Sync {
    fn hold<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        reason: HoldReason,
        key: IdempotencyKey,
        options: CallOptions,
    ) -> HostFuture<'a, HoldReceipt>;
    fn interrupt<'a>(
        &'a self,
        held: &'a HoldReceipt,
        options: CallOptions,
    ) -> HostFuture<'a, InterruptReceipt>;
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a HostEpoch,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Read<Page<ActiveSession>>>;
    fn idle<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: CallOptions,
    ) -> HostFuture<'a, Read<SessionActivity>>;
    fn binding_state<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: CallOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn adopt_binding<'a>(
        &'a self,
        request: AdoptBinding,
        options: CallOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn update_mail_target<'a>(
        &'a self,
        transition: TargetTransition,
        key: IdempotencyKey,
        options: CallOptions,
    ) -> HostFuture<'a, TargetReceipt>;
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a MailNotice,
        options: CallOptions,
    ) -> HostFuture<'a, NoticeAdmission>;
    fn notice_status<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        notice: &'a NoticeId,
        options: CallOptions,
    ) -> HostFuture<'a, Read<NoticeAdmission>>;
}
```
