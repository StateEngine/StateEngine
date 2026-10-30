# 10. Foundation types and the embedded host API

Design candidate, 2026-10-30. Owner: Iris. Assignment: msg-425dfde8ccb94a5a5019f64a;
API ownership/panic decision: msg-2d0497bcc528d95036d3d2a3. The subsequent Prime
foundation decision in msg-e32a731023bb474adec95653 expressly requires real,
constructible se-types implementations. That exception applies to pure foundation
values only. Host/API source remains trait/data declarations, with no host,
authentication, queue, store or panic-wrapper implementation.

This alpha handover amendment uses the accepted store ownership and native
process handover contracts. It corrects all prior handover exclusions, adds the
retained coordinator/native queue fence below and follows the section-00/40
fault-domain and lifecycle-recovery policy. Linked API major 2 is required for the added
traits/methods; the internal CLI/IPC foundation version is unchanged.
The reviewed 165-code shared foundation and section 30 process declarations remain.
The current OPS contract governs helper targeting and
scoped full-body listing. Revision includes Prime/Opus msg-dd929f207d5f7645ecb8a21b and Gamma
msg-a7821f5080b58b8ecb6742c6: preparation before activation, mandatory generations,
push-only delivery and factory-owned recovery. The small foundation delta here aligns credential/
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
in alpha under sections 20/30/40's durable ownership barrier; aliases are static
refusals; refusals are not an event-history family.
This chapter defines service seams, not new commands or tools. It does not revive
HTTP mail v1/v2, factory orchestration, a generic extension loader or an old alias.

Responsibilities remain separate:

| Owner | Responsibility |
| --- | --- |
| se-types | Representations, versioned contracts, pure validation and codecs |
| se-store | Durable data, snapshot/cursor scope, migrations, transactions, idempotency and readback |
| se-core | The operation registry, authentication/authorization rules, identity and message/decision semantics |
| se-proc | Native observation, pinned handles, process custody and outside stop witnesses |
| se-host | Runtime composition, session tasks, push delivery debt and generation lifecycle |
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
**165 codes**, including message-scope-denied and the three distinct Atlas
resource/parser/source failures; cgroup delegation absence is not an error. The macro generates Code, wire
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
| Linked API version mismatch | ApiVersionUnsupported / Refused | Upgrade incompatible side |
| Wrong bound project, invalid/revoked credential, missing grant | ProjectConflictsSession / Usage; CapabilityInvalid/Revoked/GrantRequired / Unauthorized | Legitimate rebind/grant, no owner fallback |
| Stale engine generation | SessionGenerationMismatch / Conflict | Refresh binding from authoritative state |
| Lost once-returned binding credential | SessionBindingUnproven / Unauthorized | Authorized new-key rebind/revocation, preserve conversation |
| Same key or NoticeId, changed payload | IdempotencyKeyReused / Conflict | Recover original or issue an explicitly new request |
| Target CAS changed | RevisionConflict / Conflict | Reread, no unconditional overwrite |
| Changed/unreadable live process | ProcessIdentityChanged / Refused; ProcessIdentityUnreadable / Unreadable | Do not signal; re-observe custody |
| No runtime / incomplete drain | RuntimeNotRunning / Unavailable; RuntimeDrainTimeout / Incomplete | Start runtime or inspect/retry named obligations |
| Callback uncertain at deadline / cancellation | DeadlineExceeded / Unavailable; Cancelled / Cancelled | Read back original keyed effect before retry |
| Capture lacks consent | CaptureConsentMissing / Refused | Obtain consent |
| Engine panic / invariant fault | TaskFailed or Internal / Internal | Preserve nonsecret diagnostics; fence affected route, and poison G for writer/lease/shared collector faults, lifecycle-call panics or migration failure after resource start |

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

### 7.0 Repository, licensing and trust boundary

The linked API belongs in SE Code's small MIT OR Apache-2.0 crate, proposed name
secode-stateengine-api. Alpha owns its package/API versions, traits, DTOs and
public stub. Public SE Code depends only on that crate/stub; proprietary se-host
implements it. docs/design/secode-stateengine-api.rs is a self-contained proposal,
not a published dependency or a write to Alpha's tree. Once Alpha lands the API,
replace this temporary copy with that reviewed dependency. There is no second
operation executor or provider-input queue in the translation.

The stub factory returns ApiFailure::NotIncluded immediately. Its remedy is
Manual/plain text describing the unavailable integration, with no instruction to
run a proprietary CLI. All engine-dependent operations refuse visibly; ordinary
SE Code remains usable. The permissive crate contains no Atlas/HumanId types or
ApiCommand::Se. Embedded composition has no Atlas worker or feature. Atlas stays
an optional standalone component and its types remain proprietary in se-types.
ApiError.code is opaque diagnostic text; SE Code does not match proprietary Code.

OwnerAuthority is a marker constructed by SE Code's trusted native control plane,
not a model argument, serde field or reauthentication protocol. This follows the
in-process trust ruling: the same process already owns the integration. Native
SE Code establishes human/creator intent and permissions before selecting an
owner path; generated model tool calls always use BoundSession and cannot select
OwnerAuthority. Process/machine boundaries (CLI, MCP, credentials) still require
the proprietary authentication rules. SessionCapability/LaunchCredential bytes
remain protected transport, without Debug/Clone/serde; every issued session grant
is checked against current core scope, revocation, revision and generation.

| Public representation | Proprietary mapping / boundary |
| --- | --- |
| String ID wrappers | Validate matching new/legacy grammar; custom names use the scoped registry resolver; resolve project/kind before use |
| Cursor | Bounded opaque token; origin/MAC/audience/query checked by its actual owner |
| Counters/time/digest | Check range/nonzero/length and preserve UTC microseconds |
| Native ProcessInstance/HostEpoch | Validate full tuple through se-proc; observation is not custody or signal authority |
| Read/Page/Window/Receipt | Validate counts/completeness/metadata and preserve non-present/uncertain states; a minimal presentation Window is not a native active-state witness |
| OwnerAuthority | Trusted embedding intent marker, never reconstructed from wire claims |
| BoundSession | Engine-issued grant, identity and revision, revalidated at each dispatch |
| ApiError/ApiRemedy | Preserve stable opaque code, class, text, retry and Tool/Manual remedy; unknown errors remain errors |
| MailNotice/NoticeAdmission | IDs-only keyed native admission; no body or read/dismiss markers |

### 7.1 Version, runtime channel and call options

This is a statically linked Rust API. Cargo package identity/version is the
compatibility gate, and ApiVersion is an exact equality sanity check against
API_VERSION (2.0 for the handover amendment). HostConfig.features is a required closed set;
unsupported/disallowed entries refuse rather than silently disappearing. Limits
are checked against host policy before work. ApiRange and minor-range negotiation are removed.
Every addition/removal/change of a public field, enum variant, trait method or
its meaning requires a Cargo/API major version bump, including an optional field
in a public Rust struct. A minor may change documentation or implementation
without changing that surface/meaning. Opaque engine error-code text can evolve
without adding an ApiFailure variant. This closed-surface policy is the deliberate
alternative to non_exhaustive plus constructor logic in the data crate.

The proprietary commercial constructor is explicitly
se_host::embedded_factory(runtime: tokio::runtime::Handle) -> Arc<dyn HostFactory>.
Its exact function-pointer signature is compiled in
`docs/design/commercial-factory.rs` as EmbeddedFactoryBuilder. SE Code passes a
clone of its existing runtime Handle. The constructor stores it without I/O or
spawning. Every async spawn and spawn_blocking uses that supplied Handle; no
ambient tokio::spawn, Handle::current, new runtime or block_on is permitted.
Tokio is a proprietary composition dependency and never enters the permissive
API crate. Composition uses the same Tokio crate version as SE Code. The one
se-writer OS thread and native process collector remain their section 20/30
owners, started only at explicit activation and counted in the shared budget.

StoreVersion (application_id/schema) is independent. Foreign identity/newer
schema refuses before mutation; supported migrations happen during activation,
not during read-only factory preparation. Existing project attach is a lookup,
not a new adoption/setup commit. Live daemon/SE Code handover is an alpha
requirement; read-only preparation and activation do not replace its section-40
ownership, native-custody and input/delivery barrier.

Only factory open uses OpenOptions with an optional expected generation. Every
post-open Host call uses CallOptions.generation; every HostServices call uses
ServiceOptions.generation, which cannot be omitted. Both options are Clone/Debug;
cloning never changes the generation. Timeout and cancellation are bounded call
controls, not authority. Cancellation Debug exposes no credential. Host and
HostServices remain object-safe boxed Send futures. No store transaction or mutex
is held across await. Cancellation after commit preserves keyed readback/debt.

negotiated(), health() and Cancellation::is_cancelled are non-blocking snapshots:
no I/O, joins, blocking channel receives or blocking-lock waits. Drop never joins,
flushes, waits, block_on's or releases a live writer's custody. Explicit async
close invokes the store writer's close routine and waits for its join using the
passed blocking pool. Factory restart uses that same close routine through its
independent supervisor. Dropping a caller handle only releases its reference and
may signal cancellation/fence atomics; the supervisor retains ownership until
close completes. SE Code must explicitly close before shutting down its runtime.
An incomplete close keeps ownership visible; dropping a handle is no success
witness and never makes a still-live thread's home available to another writer.

### 7.2 Factory, preparation, activation and Host methods

Factory open creates a Prepared handle. Before returning it, open may perform
bounded read-only configuration/store validation and acquire an RAII ownership
lease, but it cannot start se-writer, migrate/persist a generation or binding,
invoke HostServices, adopt a native target or enqueue input. It does not start
engine background loops. A bounded in-flight blocking read may finish after
cancellation but has no callback/write channel. Unwinding a failed preparation
cannot leave a late writer, native adoption or queue mutation. A preparation lease
remains under the factory's cleanup custody until released, never an orphaned
success. A missing store is Read::Absent, a failed read Read::Unreadable; neither
implicitly initializes or starts a runtime.

SE Code first receives and registers the Arc<dyn Host> and its generation with
its panic wrapper/control plane. It then creates a HostServices wrapper bound to
that exact generation, and only then calls Host::activate(integration, options).
HostIntegration also carries the exact native HostEpoch. Repeated activation
for the same G/epoch returns its actual current readiness; it cannot replace the
registered native source under an already active generation. Wrong epoch or
generation refuses, with no source swap. That is the first ordinary Host operation allowed to start writer/tasks, migrate,
adopt or mutate native state. Explicit factory handover is the separate retained
coordinator protocol in section 8.4, never an implicit side effect of open. A panic in activate is now attributable to a known handle/
generation. If open panics before publication, there is no engine generation with
mutating resources to fence: it is an opening failure with an incident reference,
not a successful bind. A Prepared handle dropped without activate has no writer
or native work. This closes Gamma's pre-return opening window.

Each HostServices wrapper records one immutable expected generation plus the
SE Code-owned current-generation fence. Every call checks both ServiceOptions
and that fence inside the native serialized transition. Activation/restart always
gets a fresh wrapper; old Arc callbacks cannot silently become a successor's
services. SE Code closes the old fence before restart or explicit drain and
publishes the new routing fence only under the activation/adoption protocol.
Already-entered atomic native transactions finish wholly and are reconciled by
key; queued old calls fail before mutation once fenced.

| Method | Contract / definitive result |
| --- | --- |
| HostFactory::open | Read-only preparation; return Prepared, Absent or Unreadable; duplicate opens on the same factory may share an already registered healthy owner, never return a poisoned handle as successful readiness |
| HostFactory::restart | Independent supervisor closes the exact Drained/Poisoned old generation without invoking its Host object, then returns a fresh Prepared handle; no new writer/native callbacks before caller registers and activates it |
| HostFactory::handover | Retained coordinator stages a keyed live transfer using section 20/30/40 barriers and the separate native queue fence; pending/aborted is not activation, and ordinary close cannot replace this protocol |
| activate | Required known generation plus fresh services wrapper; start resources/migrate/adopt, return Ready or Recovering only after truthful validation |
| negotiated / health | Non-blocking metadata/current state of this specific handle, never another generation |
| wait_health(after) | Notification-driven lifecycle change, not mail pull/polling; reports Prepared/Activating/Ready/Recovering/Draining/Drained/Poisoned/Closed or an explicit timeout/cancel error |
| poison | Gate the current generation and preserve durable obligations; report known fault, never undo native commits or human holds |
| verify_capability | Validate protected credential, scope, revocation and generation; no owner fallback |
| open_project | Authorized existing lookup, no implicit init/root/adoption |
| bind_session | Trusted owner/one-use launch path; validate conversation/target/consent and binding revision, commit once and issue protected capability once |
| revoke_session | Owner-selected or bound-self scope; durable target/capability revocation intent, never invented process stop |
| tools / call_tool | Core registry only; bound identity and closed arguments, same operation implementation as CLI/MCP |
| continuity | Bound pre-provider context/packet/model/UTF-8/window facts, no cross-agent private fallback |
| capture_turn | Consent/conversation/source/hash and natural vendor-turn dedupe; capture receipt is not task success |
| native_state_changed | Native control-plane nudge after a committed eligibility/target change; re-read actual binding/status before retry, no body pull, admission settlement or hold release |
| adoption_status | Bounded owner inspection of every pending/reattached/held/revoked/absent/unreadable route |
| drain | Generation comes only from CallOptions; gate admissions, join generation tasks, persist debt and flush writer; return named unresolved facts |
| close | Actual matching drained state, explicit writer close/join and resource release; idempotent readback, no new generation |

One factory/supervisor owns a canonical state-home/store scope. Duplicate opens
share only its registered healthy owner. A different live daemon/factory owner
returns RuntimeOwnedElsewhere even if its PID happens to match; timeout alone
cannot steal a lease. Poisoned open returns GenerationPoisoned with the restart
route. The independent supervisor outlives an individual Host object and holds
the writer/tasks/lease needed to close it safely. It must not be implemented as a
call back through a quarantined Host::drain or Host::close.

SessionIdentity is durable project/agent/session. BoundSession adds engine
Generation, binding revision and issued grant. HostEpoch identifies the native
SE Code service separately from the engine generation, and HostSessionTarget
binds native session, epoch, durable identity and fingerprint. No tuple alone
proves custody or permission. A capability returned once is not regenerated on
replay; lost custody yields SessionBindingUnproven and a trusted new-key CAS
rebind that revokes the prior capability while retaining the conversation.
expected_binding_revision=None means first binding only; Some(r) must match.
Owner adoption_status supplies the revision for legitimate recovery.

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

## 8. Push mail, native queue, holds and admission debt

Authority is Alpha's msg-45a1e58b4b70ef181371bbf1, Gamma's source assessment and
review msg-a7821f5080b58b8ecb6742c6, and Prime's push-only decision. Source read is
SE Code f4cf8f6d, especially native_mail/native_mail_state and interrupt_pending.
The existing combined interrupt handler signals before committing its hold;
takeover requires the stronger split ordering below. No unchanged HTTP handler
is claimed to satisfy it.

### 8.1 HostServices contracts

Every method requires ServiceOptions.generation and the exact target/epoch. The
wrapper checks its expected generation and current native fence in the same
serialized lane as any mutation; a late old-generation call refuses. No lock or
transaction spans an engine await.

| Method | Definitive semantics |
| --- | --- |
| hold(target, reason, key) | Durably commit session-wide/per-input hold even with zero pending notices; retain pending input; exact retry returns original event |
| interrupt(held) | Verify that exact hold is still active before signalling; return requested, never an idle/exit witness |
| active_session(target) | One authoritative point lookup: Present(Some(active)) means observed execution, Present(None) proves no active execution for this exact target/epoch at that read; Absent/Unreadable/Unknown do not prove no execution |
| active_sessions(epoch,page) | Bounded diagnostics only; pages are not a snapshot-bound absence proof |
| idle(target) | Native activity observation, not revoked binding or client process exit |
| binding_state(target) | Durable target/hold/revocation and activity, never inferred from an empty process map |
| adopt_binding(previous,current_epoch,key) | Exact persisted old binding/fingerprint CAS into new epoch; preserve holds, revocation and original admissions; missing custody refuses |
| update_mail_target(Select/Revoke,key) | Atomic selection/revocation; every superseded target must still be held and not executing inside that transaction; retain human holds and refuse changed activity/target |
| deliver_notice(notice) | IDs-only push into the existing native queue; stable NoticeId/digest; Admitted only after commit, exact retry Replayed with original sequence |
| notice_status(target,id) | Exact-key recovery after uncertain callback outcome; no mutation or fresh admission; unreadable/unknown never become absence |

No subscribe_mail, MailSubscription, MailEvent, MailSettlement or settle_mail
exists. StateEngine's host reads its indexed durable delivery debt internally and
pushes through deliver_notice. SE Code never pulls a second mail stream. The only
queue is SE Code's existing pending-input queue. Lifecycle wait_health transports
no mail, body, admission or cursor.

Before a callback, one core/store transaction reserves each (SessionId, MessageId)
for a stable notice intent, preventing overlapping reopened batches. MailNotice
contains IDs, exact native target, through cursor and digest, never body/secrets.
The digest versioned encoding covers store/project/agent, durable SessionId,
native HostSessionId, ordered distinct message IDs and durable cursor; it excludes
transient engine/service process generations. Epoch routing is checked separately.
Changed payload under the same NoticeId is IdempotencyKeyReused. On adoption,
Admission.committed_in and original event/sequence stay original; current target
is only updated through the verified native adoption map.

### 8.2 Notice debt and single-queue state machine

| Existing state | Observation / action | Durable result and retry trigger |
| --- | --- | --- |
| Message committed, unoffered debt | Reserve stable bounded notice intent | Intent/key/body-ID set durable before callback; recipient remains unread |
| Intent pending | Admitted or Replayed with verified target/id/digest/event | Record original native queue admission in StateEngine debt, once; this is the only success that acknowledges queue admission |
| Intent pending | Held before admission | Keep the same intent and full unoffered debt; no native pending item is presumed; record held reason/observation only |
| Intent pending | Refused before admission | Keep intent/debt plus explicit cause; do not advance offer cursor, mark read, or claim a native pending item |
| Intent pending | Callback reply lost/deadline/panic | Outcome uncertain; notice_status on the same target/ID before any retry; never mint a new NoticeId |
| Uncertain | Verified status Admitted/Replayed | Record original admission; no second pending input |
| Uncertain | Successful exact-key Absent | Retry the same intent only after target is verified eligible; Read::Unreadable/Unknown retains uncertainty |
| Held debt | Genuine human promotion clears hold and native target remains eligible | An explicit native eligibility/control-plane event schedules retry with original intent; fresh mail, reconnect or engine restart is not a human resume |
| Refused debt, retryable cause | Explicit binding repair/re-authorization or bounded work-driven retry allowed by that cause | Read binding/status then retry original key; no idle polling and no retry by inventing a key |
| Refused debt, revoked/permanent target | Owner creates a legitimate new target or explicitly retires delivery obligation | Preserve original refused debt/history; a new target has a new explicit intent, never relabel old refusal as admitted |
| Native pending input | Safe promotion boundary | Existing native queue promotes eligible steer first, ordinary queue input only at idle |
| Native pending, held | Mail/reconnect/synthetic startup | Remains held; no promotion or read marker |
| Held, genuine human input promoted | Native human transaction | Clear hold only if target still verifies; revoked target never revives |
| Recipient performs bound message.read/ack/dismiss | Core commit | Only StateEngine changes that recipient's marker; admission is not read/task completion |

SE Code's adapter supplies the real human-eligibility event to its integration
control plane, which calls Host::native_state_changed(target, CallOptions).
This nudge means only reconciliation was accepted; it carries no mail IDs/bodies,
acknowledges no admission and grants no authority. The host validates target/G,
then reads actual binding_state/notice_status before eligible retry. It is an
internal embedding hook, not a new CLI/MCP operation or a provider-input queue. Activation and
explicit owner repair also schedule reconciliation, but first read native held/
revoked state and never clear a hold. Pending debt is visible through status and
adoption inspection until resolved. Held/Refused handling is internal keyed
host/store accounting, not a public settlement API that SE Code can call to
advance delivery. No response containing Held/Refused acknowledges admission.

### 8.3 Takeover and abort semantics

Takeover commits a replacement intent/reservation; hold predecessor durably;
interrupt only after that hold; active_session must return Present(None) for the
exact predecessor; se-proc proves any owned client/descendants exited; recheck
replacement/generation; final native Select transaction rechecks held/no execution,
revokes predecessors and selects successor; read back that target transition;
only then commit/enable the successor binding. Cross-store steps use keyed
intents, never a transaction held across callbacks. Point observation can go stale:
if a human resumed after it, final Select refuses rather than overlap execution.
Paged active_sessions is diagnostic and cannot replace the point read. Its
windows describe a single diagnostic observation; without an immutable cursor
snapshot, a multi-page changing source is marked source-incomplete, not advertised
as a complete concatenated census.

Held and revoked remain separate dimensions. Hold: eligible->held; genuine human
promotion: held->eligible only while target valid; revoke: either->revoked; no
human/reconnect transition leaves revoked. A new legitimate binding preserves any
native session human hold. A failed/aborted takeover does not automatically
release its hold. An intact takeover hold stays until a genuine human acts; UI
must say that the takeover stopped and the session awaits human input. There is
no engine abort_takeover/release_hold escape. If a human already changed the hold,
report that actual native state rather than inventing a held fact or re-holding
as cleanup. Pending takeover intent is visibly aborted/failed, never success.

Interrupt acknowledgement proves neither idle nor process absence. Unreadable/
unknown point query, changed epoch/reservation, failed outside stop or target CAS
keeps the successor gated and preserves each actual obligation. Windows breakaway
is owned by section 30/se-proc; SE Code's containing job must permit the required
breakaway. An OS refusal reports the named breakaway failure; this API cannot
weaken the job/profile or substitute an unowned PID. Linux uncontained process-
group evidence cannot prove absence of descendants that left that group; a
required outside witness remains incomplete rather than inventing total custody.

### 8.4 Alpha live handover and the native queue fence

Live SE Code↔daemon transfer is in alpha. Each participating agent is interrupted
**immediately**: a running turn is cancelled, not awaited to completion or a later
natural boundary. Before Prepared, exact active_session Present(None) proves idle
for every participating native target; the equivalent harness witness applies to
external agents. An interruption ACK is insufficient. B8 measures the subsequent
custody/capture cutover within 500 ms without lost/doubled input; quiescence time
is measured and reported separately. Runtime qualification is still outstanding.
Section 40 owns coordination; section 20 owns the FULL ownership CAS.

HostFactory::handover is the generation-independent control entry. Request.source
is the **current runtime owner's** full epoch, including when SE Code initiates a
request to a daemon; CallOptions names that source G, not the caller's process.
The retained factory verifies actual owner/lease/store before mutation, pins the
successor and binds a unique TransferId to one immutable HandoverPlan and original
request key. Both epochs/generations are fixed. Exact-key retry recovers that
transfer, not a second plan. Private authenticated IPC orchestrates the two
processes; no Rust Arc crosses it and no agent/model operation is added.

HandoverServices supplies nonblocking epoch()/queue() snapshots of the actual
SE Code adapter and retained native store/queue incarnation. The factory checks
these **before the first callback**. A new transfer uses the direction checks
below; predecessor-fence recovery instead verifies the fresh adapter's actual
epoch and adoption chain as specified after the table:

| Direction | Native adapter and checkpoint.owner | Freeze semantics |
| --- | --- | --- |
| SE Code → Standalone | native.epoch() == plan.source; checkpoint.owner is that SE Code source epoch | Fence participating live native routes, immediately interrupt them and prove exact idle; retain their original queue before SE Code exits |
| Standalone → SE Code | native.epoch() == plan.successor == destination.epoch; checkpoint.owner is that receiving SE Code epoch | Reopen the same durable dormant queue; the factory first settles any predecessor transfer's fence using its verified terminal outcome, then starts the new transfer and freezes its participating targets before any new-G admission/promotion or callbacks; do not pretend the daemon's epoch owns the native queue |

HandoverServices has no proprietary store reader and **does not verify runtime
ownership events or FULL phases**. Those checks belong exclusively to the factory,
which reads section-20 facts/head and fresh native/lease proof before issuing a
resolution. EventRef in a resolution identifies the factory-verified fact; it is
not an adapter-readable proof or permission from a caller-supplied number. The
native adapter checks exact TransferId/plan, queue incarnation, stored checkpoint
and its own current native epoch/adoption mapping. It cannot select an unrelated
target or become ordinary successor-G authority. Old HostServices Arcs remain
fenced; fresh ordinary callbacks require handle registration and activation.

The native fence is keyed by **TransferId in the retained queue**, not by the
lifetime of the adapter or its SE Code epoch. Checkpoint.owner records the epoch
that made the original freeze and never changes on recovery. A fresh adapter
may inspect/settle that predecessor's fence only when its queue() is exactly the
same NativeQueueId and the factory independently verifies the new epoch's native
store/binding adoption and ownership/recovery chain. This recovery check replaces
the original-attempt epoch equality in the direction table; it does not rewrite
checkpoint.owner or either plan epoch. NativeQueueSettlement records
the actual fresh settled_by epoch; no old Arc is rebound or resurrected.

| Control call | Required native result |
| --- | --- |
| freeze_queue(plan) | Commit a distinct transfer fence on both human and native-mail admission/promotion for the complete participating target set; drain entered transactions, immediately interrupt and prove exact idle, then seal/read back the complete queue checkpoint |
| queue_state(transfer) | Exact durable Frozen/Settled lookup by TransferId, including a predecessor epoch's record; preserve Absent/Unreadable/Unknown and original commit references after a lost reply |
| settle_queue(checkpoint,resolution) | After factory verification, match the retained transfer/checkpoint/queue and commit/read back removal of only that fence at Finished, verified Aborted or checked Recovered, preserving every independent human/takeover/revocation hold |

The complete participating set comes from SE Code's native binding registry,
not a caller-guessed list. Unrelated SE Code sessions continue and are never
interrupted. The manifest binds the exact target set; additions need a new checked
transfer after the current one ends. freeze_queue persists its initial fence
before awaiting cancellation; queue_state may therefore show Frozen with
quiescence_witnessed=false. That is not idle or Prepared authority. Same-plan
retry completes the cancellation/readback and seals quiescence_witnessed=true;
only this final checkpoint is immutable and may enter Prepared. Unknown activity
leaves the fence and original queue visible. Neither interruption nor await holds
a native transaction open.

NativeQueueId binds the retained store incarnation and its sole queue; the freeze
event sequence identifies the cut. The manifest digest is domain-bound to NativeQueueId and the frozen cut, not
just coincidentally equal payload bytes. The protected manifest includes original
pending-input IDs/bodies, NoticeId/digest, admission events/sequences, committed
epochs, adoption maps, claims/promotion dedupe and independent holds. The actual
queue is flushed and independently reopened/read before ownership advances.
Digests/counts or StateEngine debt alone cannot restore it. HoldReceipt values in
checkpoint.held identify transfer-fence events to interrupt; ordinary human or
takeover release paths ignore them. Only settle_queue with the full checkpoint
can remove this fence, and it never removes independent holds.

| Recovery state | Factory proof and native settlement |
| --- | --- |
| SE Code dies after freeze, before settlement | Fresh epoch reopens the same queue; queue_state(transfer) returns the original plan/checkpoint, including checkpoint.owner; factory verifies its actual epoch/queue and durable recovery chain, then settles its original fence using the verified Finished, pre-claim Aborted or Recovered outcome |
| Freeze exists before Prepared | Factory proves no Prepared fact, actual source ownership/lease and safe staged-copy closure; Aborted may cite that FULL source-owner fact, and the native settlement records the abort without inventing a skipped store phase; unreadable fact/peer state remains pending |
| Prepared/ReadyToClaim, no claim | Verified pre-claim abort/lease recovery commits FULL Aborted before native fence removal; deadline/cancellation alone never clears it |
| Claimed/Activated, receiver lost | One checked cold runtime.owner FULL event carries RuntimeRecoveredTransfer and atomically sets the owner head to the original transfer/Recovered, with fresh activated custody/capture and queue-cut proof; its own EventId is the completion reference, and old peers/generations stay immutable |
| Another plan/key while this fence exists | Ordinary freeze/handover refuses runtime-handover-in-progress and names the open TransferId; it does not overwrite, stack or steal the fence, even for a proposed reverse plan |

RuntimeHandoverInProgress keeps its catalog generation detail; the returned
ApiError.message must also name the exact open TransferId from the retained
fence, not the attempted request key. This is diagnostic identity, not authority
to settle the fence; the factory still verifies the persisted plan and outcome.

An ordinary second plan, including a reverse request, cannot bypass an open
native fence. Checked receiver-loss recovery first accounts for that original
transfer as Recovered in the same FULL owner transaction; the factory verifies
the one owner/completion EventId, its RuntimeRecoveredTransfer payload, the
atomic Recovered head and fresh activated custody/capture plus retained queue-cut
proof before settlement. An actual reverse transfer can then
start as a new explicit transfer after the old fence is settled. The old plan's
peers/generations are not rewritten to impersonate the cold owner. A cold owner
fact without that typed Recovered payload/head is not terminal permission.
HandoverResolution::Recovered.ownership names this FULL runtime.owner event,
not a fabricated old-plan phase append; the factory checks its exact old
handover-event reference and retained queue-cut digest against the checkpoint. Resolution
is Finished, Aborted or Recovered, never receiver absence or timeout alone.

Source gates ordinary work and completes accepted launch/capture/debt operations,
then freezes capture/debt/full-frame positions before inactive staging and FULL
Prepared. Writer drain/ReadyToClaim, exclusive lease transfer, FULL Claimed,
native activation and FULL Activated precede destination consumers. On the normal path, FULL Finished
plus verified source closure precedes native fence removal; the native transfer
fence still blocks promotion during the Activated→Finished interval. Factory
replays a lost Finished acknowledgement to finish native settlement with the same
key. Removing the transfer fence does not reopen an old ordinary-G routing fence.

After SE Code exits, the daemon continues custody/capture; native input/mail stay
intact and dormant. AdoptionState::WaitingForSecode{transfer} is the typed status
fact rendered “waiting for SE Code to reopen”, never fully active. Daemon-launched
agents are unaffected. Receiving SE Code proves original queue/admission adoption
under its fresh epoch/G before promotion; a daemon never promotes or reconstructs
native input. The version-2 HandoverReport contains only NativeQueueSettlement,
never a Frozen checkpoint. A verified abort returns Ok(Committed/Replayed) with
resolution Aborted, meaning the abort completed, **not** successful activation;
an unresolved transfer returns Pending or its precise error, never a terminal
report. No runtime or B8 result follows from these declarations.

## 9. Generation lifecycle, adoption and panic containment

### 9.1 States and observable signals

| State | Trigger | Next state / result |
| --- | --- | --- |
| Closed | Factory open, valid read-only scope | Prepared handle, no writer/native callbacks before return |
| Opening before publication | Missing/unreadable/version failure or panic | Explicit opening failure, no mutating generation to fence; retain factory cleanup custody over any preparation lease |
| Prepared | SE Code registers handle/G and activates fresh services | Activating; this is the first mutating stage |
| Prepared | Invalid activation arguments/source before resource start | Remain Prepared with explicit error, no native mutation |
| Activating | Valid ownership/store/services, no pending recovery | Ready |
| Activating | Actual routes still need reconciliation | Recovering with bounded truthful per-session states |
| Activating | Writer/lease/collector fault or migration failure after resource start | Gate this G, preserve exact partial facts, Poisoned and explicit factory-restart route |
| Activating/Ready/Recovering | Writer/lease/shared collector panic or invariant fault | Poisoned, gate G and report known generation/incident |
| Any published G | Panic or invariant fault in activate, drain or close | Poisoned, gate G and retain actual resources/obligations for independent factory restart |
| Activating/Ready/Recovering | Non-lifecycle API/session/capture/listener task panic | Return Internal/EnginePanicked and fence affected route; session task restarts at most three times in 60 s, then fails by name; unaffected routes continue |
| Prepared/Ready/Recovering | Explicit drain | Draining; SE Code closes native generation routing first, engine joins tasks/persists debt/flushes |
| Draining | Tasks joined, writer flushed, all unfinished effects durable | Drained with pending-effect counts; still owned until close |
| Draining | Deadline/unreadable/live task | Remain Draining with named blockers, never a successful drain |
| Drained | Host close | Explicit writer close/join, resources released, Closed; repeated drain/close returns the same observed result |
| Drained/Poisoned | Factory restart for actual current G | Supervisor closes old generation independently, then fresh Prepared G+1 after safe closure |
| Restart closure | Live/unjoinable writer/task or unreadable ownership | Unavailable with named blocker; old ownership quarantined, no fresh writer or fake successor |
| Fresh Prepared | Caller registers new handle/fresh services and activates | Ready or Recovering, old handles remain invalid |

health() and notification-driven wait_health expose these states without a mail
stream. API wrapper catches return EnginePanicked immediately with the known G;
writer/lease/shared collector faults, activate/drain/close panics, and migration
failure after resources start set Poisoned and wake wait_health.
SE Code gates that G for these ownership/lifecycle faults; other incidents fence the
affected route, preserving original-key recovery and named task status. Explicit drain returns Drained/Incomplete,
not a human hold. There is one host-level health wait, no per-seat poller/timer.
Timeout is an explicit error, not a health change. Old handle snapshots refer only
to old G; they can never start returning Ready for the new generation.

### 9.2 Factory recovery independent of a poisoned Host

The caller first fences G in its own native/API wrapper, then invokes factory
restart(Poisoned{incident}, stable_key, CallOptions{generation:G,...}). A normal restart uses
its actual Drained receipt instead. The factory's independently retained
supervisor validates G/state/lease, closes admissions and cancels/aborts/joins G's
owned tasks without invoking any method on the quarantined Host object. It calls
the store writer's explicit close routine, flushes/rolls back as appropriate and
joins the writer via the passed blocking pool. Native committed effects and human
holds are untouched; every uncertain commit is recovered by original key.

A completed writer join returning a panic still proves that thread terminated,
not that its transaction committed or rolled back. The supervisor validates the
store and resolves original in-flight keys against durable state before reusing
it. A writer that already panicked can therefore be replaced even though the old
Host cannot drain; no acknowledgement from that damaged object is required. Raw
panic payload is not exposed. Unreadable/corrupt store remains an explicit refusal.

Only after proved termination and ownership/store verification may the supervisor
prepare checked successor G+1 and publish its new handle. It retains/transfers
its exclusive home lease safely; it never releases a lease over a live old writer.
SE Code registers that handle and a newly fenced HostServices wrapper, then calls
activate. This path works even if old Host::drain/close panics or is unusable;
those methods are not the supervisor's resource handles. Restart is keyed by
the old generation and stable idempotency key; exact retries return the original
successor/result instead of creating G+2. A reused key with a changed request
refuses. If a caller loses a successful restart reply, it repeats that key or
uses read-only factory open to recover the already prepared/registered owner;
neither path starts native work before registration/activation. No Host::reopen method
or old integration Arc is reused for recovery.

A truly stuck native writer cannot safely be killed or abandoned portably inside
the process. In that case restart returns explicit Unavailable with the named
unjoined worker/ownership blocker and asks for a controlled SE Code process
restart after preserving its native work. It does not freeze ordinary SE Code
sessions or claim a fresh generation while the old writer might still commit.
Caught ownership/lifecycle panics have the closed supervisor path above; abort/OOM/OS kill
requires process-restart adoption instead. The whole embedded boundary uses
unwind; an abort release profile cannot promise generation-only panic isolation.

### 9.3 Adoption and push recovery

Activation reads committed session/effect state in bounded indexed pages. Verify
credential/revocation/project/agent/conversation/current generation and actual
process/native target. se-proc reobserves/pins process custody; absence, mismatch
and unreadable remain distinct. Imported process/history rows are not live custody.

Read binding_state and the exact active_session point query under this HostEpoch.
A held route adopts as held; a revoked route remains revoked; unreadable blocks
only that route. Same-process engine restart retains durable SessionId and native
host epoch, refreshes generation-bound handles and creates no conversation/prompt.
After SE Code service restart, adopt_binding verifies old protected mapping and
CASes it to the current epoch, retaining holds/revocation/original queue sequence.
Missing mapping/custody refuses, never falls back to owner/new-session success.

For each outstanding stable notice call notice_status first. Verified original
Admitted/Replayed records that exact admission; measured absence permits eligible
retry of the same intent. Held/Refused/Unreadable/Unknown retain unoffered or
uncertain debt with the triggers in 8.2. A crash after native commit but before
engine debt recording cannot lose or duplicate input. Activation/restart itself
cannot clear a human hold or pretend a notice was read.

### 9.4 Atomic native transactions and panic/drop rules

SE Code catches synchronous constructor/future-construction panics and every poll
of engine futures, including activate, health wait and explicit close. Constructor
is Handle-only/no I/O and cold open is nonmutating; after publication every fault
has a registered generation. Engine-owned task panics reach the supervisor with
their fault domain; they never disappear as successful work. Writer/runtime-lease/
shared-collector faults, activate/drain/close panics, and migration failure after
resources start poison G and use independent factory restart. Other non-lifecycle
public/API/session faults
return Internal/EnginePanicked and fence the affected route; a session task is
restarted at most three times in 60 seconds, then failed by name. Mutex poison is
Internal and retains actual resources. No raw panic payload/body/credential leaks.

Native hold plus per-input holds, target selection/revocation, and pending input
admission/claim/dedupe are each one existing SE Code transaction. Before commit,
panic rolls back; after commit, it may lose only the reply. Atomic changes remain
atomic across engine poison. Catching unwind never proves rollback of a completed
commit. Recovery queries/replays original keys; it never unholds, invents a new
NoticeId, erases pending input or acknowledges Held/Refused as admission.

Drop never runs arbitrary cleanup futures, blocks on writer joins or catches a
second destructor panic as if recovery succeeded. Resource shutdown is explicit
async close, with its result witnessed before runtime shutdown. SE Code's normal
work, native queue and durable holds survive a contained engine fault. Only the
affected binding/generation is gated until verified recovery; that temporary gate
is separate from the persistent human hold and cannot release one.

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
no retained global cache and no startup I/O; small-page pure validation/version checks
should use <=1 ms of the startup allowance, to be measured, not claimed proven.

Default page limits follow section 50: 20 items, hard max 200 (message tools may
cap at 100); 1 MiB request/response
payload including envelope; continuity model input 32 KiB default and max 1 MiB as section 50;
128 distinct IDs per notice. Callback request/response memory is bounded per
host; there is no mail subscription buffer or additional prompt queue. Producers reject
oversized configurations/requests rather than granting an unbounded allocation.
Page/payload/notice caps are reported in Negotiated; changing a default cannot weaken the
correctness invariant or erase unreadable/omitted counts. Session/queue storage
is bounded independently from transient transport; unserved durable debt remains
in the store and is fetched by indexed pages.

The runner must measure the entire first-bound sequence: commercial factory
construction, read-only open, registration/activate, open_project, bind_session,
verify_capability and continuity, including lease/migrations/recovery work. It
must fit the 100 ms whole-product ceiling before this shape is frozen as a
performance-qualified API. A fused bind/context operation is a possible reviewed
revision if measurement requires it, not a present speed claim. Owner marker
construction is local; no extra machine-credential round trip exists here.

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
| J1 Install | Installed version/API provenance, missing store distinct from unreadable, supported schema/version sanity, no external checkout/Node required for the embedded StateEngine path |
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
runner remain the acceptance oracle. Foundation checks reuse Otto's supplied external consumer unchanged (12 assertions
and all 165 typed error fixtures), plus workspace compiler/Clippy/format checks.
The public API and commercial constructor signature compile independently. None
proves a runtime guarantee above.

## 12. Decisions, open questions and implementation handoff

The eight Opus changes and Gamma's two owner clarifications are incorporated:
point active lookup; required service generations/fresh activation wrapper;
push-only mail; independent keyed factory restart and human-only takeover abort;
non-blocking Drop/snapshots with Clone/Debug options; no public Atlas/Human/CLI
command type; closed API major-bump rule and version sanity; named passed Handle
constructor. The handover correction adds transfer-keyed cross-epoch recovery,
factory-owned FULL phase verification, direction-specific native controls,
immediate cancellation and lifecycle/migration poison rules. Gamma's opening fence is achieved by forbidding mutating resources
before handle publication, and Held/Refused debt remains explicit/retryable.

Only the explicitly authorized pure foundation implementation is present. No
host implementation may begin before its design approval. The following cross-area details must be reconciled during review:

1. **Store owner / Prime:** finalize the store application_id, schema progression,
   cursor MAC/key custody and durability policy; StoreVersion is explicit so this
   chapter does not pick another owner's migration/flush policy.
2. **Host owner / Alpha reviewer:** confirm the point lookup, activation/fencing and callback methods plus atomic
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
5. **Critic/Prime:** proposed page/continuity/notice caps and linked version sanity are shared allocation policy; adjust centrally, not per surface.
6. **Alpha:** accept the exact permissive-crate signatures/version and panic
   wrapper placement, then land that crate in SE Code; our temporary proposal
   module is removed when replaced by the reviewed dependency. Stub behavior and
   panic-after-commit recovery need SE Code reviewer witnesses before adoption.

Live daemon/SE Code handover is in alpha, with B8 requiring custody/capture
re-adoption within 500 ms from post-quiescence cutover and no lost or doubled
input; quiescence is separately reported. Sections 20/30/40 own its
durable ownership, native custody and host barrier; same-host crash adoption and
logical generation drain/factory-restart remain distinct from that transfer.
No new public launch/handover command is introduced. macOS runtime validation and signing infrastructure
remain project acceptance dependencies; pure type compilation is not that witness.

Review the implemented foundation and have reviewers exercise its real values;
after design approval, se-store/core/host owners implement against these exact
internal contracts and Alpha's accepted permissive API. Any changed signature/state transition goes back through design review
before dependent implementation, rather than growing a second mirror API.

## Appendix: complete compiling public source

The pure foundation is the explicit implementation exception authorized by Prime.
Its exact source is included so public signatures and macro-generated details
remain reviewable. The SE Code proposal is a separate MIT/Apache trait/data crate
root with only serde_json. The commercial constructor signature is checked in a
third independent crate with Tokio and that public API; Tokio never enters the
permissive dependency graph. All three compile roots are declarations/values only,
with no host implementation, author tests or runtime qualification. Actual files
are the compilation authority and these copies must change together on returns.

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
    AtlasUnreadable => ("atlas-unreadable", Unreadable) { path: String, reason: String } => "can't read the index database atlas.db: {reason}", "Use `se doctor --fix` (rebuilds the index)";
    AtlasPathOutsideRoot => ("atlas-path-outside-root", Refused) { path: String, root: String } => "{path} is outside {root}", "use a project-relative path";
    AtlasPathUnknown => ("atlas-path-unknown", Unknown) { path: String } => "{path} isn't indexed", "Use `se atlas find PATH --kind path`";
    AtlasSymbolUnknown => ("atlas-symbol-unknown", Unknown) { symbol: String } => "no symbol `{symbol}`", "Use `se atlas find {symbol}`";
    AtlasSymbolAmbiguous => ("atlas-symbol-ambiguous", Usage) { symbol: String, candidates: Vec<String> } => "`{symbol}` names {candidates.len} symbols", "add `--path`";
    AtlasLanguageUnsupported => ("atlas-language-unsupported", Refused) { path: String, language: Option<String> } => "{language} files aren't parsed", "text search: `--kind text`";
    AtlasFileOverBudget => ("atlas-file-over-budget", Refused) { path: String, size: u64, budget: u64 } => "{path} ({size}) exceeds the per-file parse budget", "none; the file stays text-searchable";
    AtlasResourceBudget => ("atlas-resource-budget", Unavailable) { resource: String, requested: u64, available: u64 } => "Atlas can't index right now: {resource} needs {requested}, {available} available", "wait for memory pressure to ease, or use bounded text search → `se atlas find QUERY --kind text`";
    AtlasParseFailed => ("atlas-parse-failed", Incomplete) { path: String, language: String, reason: String } => "Atlas couldn't parse {path} ({language}): {reason}", "results for this file use bounded text search; → `se doctor --bundle` to report the diagnostic";
    AtlasSourceUnreadable => ("atlas-source-unreadable", Unreadable) { path: String, reason: String } => "Atlas can't read {path}: {reason}", "restore read access to the file";
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
//! Closed Rust API: adding/removing/changing any public field, enum variant,
//! trait method or its meaning requires a Cargo/API major version change.
//! No blocking or joining in Drop; resources close through explicit async calls.
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
pub struct SessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreId(pub String);
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
pub struct TransferId(pub String);
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
pub const API_VERSION: ApiVersion = ApiVersion { major: 2, minor: 0 };

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
}
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub state_home: NativePath,
    pub api: ApiVersion,
    pub kind: HostKind,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
pub trait Cancellation: Send + Sync + std::fmt::Debug {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct CallOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct ServiceOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}

// Protected byte buffers have no Debug, Clone or Deserialize.
pub struct SessionCapability(pub Vec<u8>);
pub struct LaunchCredential(pub Vec<u8>);
/// Trusted SE Code control-plane authority, never decoded from model/tool input.
#[derive(Clone, Copy, Debug)]
pub struct OwnerAuthority;
/// Engine-issued grant; every call revalidates its identity, revision and generation.
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
pub enum AdoptionState {
    Pending,
    Reattached,
    Held,
    Revoked,
    Absent,
    Unreadable(ApiError),
    WaitingForSecode { transfer: TransferId },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adoption {
    pub identity: SessionIdentity,
    pub binding_revision: Sequence,
    pub state: AdoptionState,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    Prepared,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoverDestination {
    Standalone,
    EmbeddedSecode { epoch: HostEpoch },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverRequest {
    pub source: HostEpoch,
    pub destination: HandoverDestination,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverPlan {
    pub transfer: TransferId,
    pub source: HostEpoch,
    pub successor: HostEpoch,
    pub source_generation: Generation,
    pub successor_generation: Generation,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug)]
pub struct HandoverOptions {
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueId(pub String);
/// Receipt for SE Code's own protected queue, never its input bodies or a second queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueCheckpoint {
    pub plan: HandoverPlan,
    pub owner: HostEpoch,
    pub queue: NativeQueueId,
    pub committed: HostEventRef,
    pub sha256: Sha256,
    pub pending: u64,
    pub held: Vec<HoldReceipt>,
    pub quiescence_witnessed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoverResolution {
    Finished { ownership: EventRef },
    Aborted { ownership: EventRef },
    Recovered { ownership: EventRef },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueSettlement {
    pub checkpoint: NativeQueueCheckpoint,
    pub resolution: HandoverResolution,
    pub committed: HostEventRef,
    pub settled_by: HostEpoch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeQueueHandoverState {
    Frozen(Box<NativeQueueCheckpoint>),
    Settled(Box<NativeQueueSettlement>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverReport {
    pub plan: HandoverPlan,
    pub queue: NativeQueueSettlement,
}
/// Native queue control retained independently of ordinary generation callbacks.
/// A fresh epoch may recover the same queue's transfer-keyed fence; ownership
/// phase verification belongs to the factory, not this permissive adapter.
pub trait HandoverServices: Send + Sync {
    /// Non-blocking snapshots of this adapter's actual epoch and queue incarnation.
    fn epoch(&self) -> HostEpoch;
    fn queue(&self) -> NativeQueueId;
    fn freeze_queue<'a>(
        &'a self,
        plan: &'a HandoverPlan,
        options: HandoverOptions,
    ) -> HostFuture<'a, NativeQueueCheckpoint>;
    fn queue_state<'a>(
        &'a self,
        transfer: &'a TransferId,
        options: HandoverOptions,
    ) -> HostFuture<'a, Read<NativeQueueHandoverState>>;
    fn settle_queue<'a>(
        &'a self,
        checkpoint: &'a NativeQueueCheckpoint,
        resolution: HandoverResolution,
        options: HandoverOptions,
    ) -> HostFuture<'a, NativeQueueSettlement>;
}

/// The implementation/factory is configured with the embedding host's runtime.
/// No Tokio dependency or runtime creation belongs to this permissive API crate.
pub enum HostIntegration {
    Secode {
        epoch: HostEpoch,
        services: Arc<dyn HostServices>,
    },
}

pub trait HostFactory: Send + Sync {
    /// Cold open is preparation only: no writer, native mutation or callbacks.
    fn open<'a>(
        &'a self,
        config: HostConfig,
        options: OpenOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
    /// Independent supervisor closes the old generation, then prepares a fresh one.
    fn restart<'a>(
        &'a self,
        reason: RestartReason,
        key: IdempotencyKey,
        options: CallOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
    /// Retained coordinator; does not invoke a drained or poisoned Host object.
    fn handover<'a>(
        &'a self,
        request: HandoverRequest,
        native: Arc<dyn HandoverServices>,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<HandoverReport>>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestartReason {
    Drained { receipt: DrainReceipt },
    Poisoned { incident: String },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationHealth {
    Prepared,
    Activating,
    Ready,
    Recovering,
    Draining,
    Drained,
    Poisoned,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReport {
    pub incident: String,
}

pub trait Host: Send + Sync {
    fn poison<'a>(
        &'a self,
        report: FaultReport,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;

    /// Non-blocking snapshots; no I/O or wait for worker threads.
    fn negotiated(&self) -> Negotiated;
    fn health(&self) -> GenerationHealth;
    fn wait_health<'a>(
        &'a self,
        after: GenerationHealth,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;
    /// Caller registers this handle/generation before this first mutating call.
    fn activate<'a>(
        &'a self,
        integration: HostIntegration,
        options: CallOptions,
    ) -> HostFuture<'a, Readiness>;
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
    /// Nudge only: re-read eligibility/debt; cannot acknowledge admission or clear holds.
    fn native_state_changed<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: CallOptions,
    ) -> HostFuture<'a, ()>;
    fn adoption_status<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<Adoption>>;
    fn drain<'a>(&'a self, options: CallOptions) -> HostFuture<'a, DrainReceipt>;
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
        options: ServiceOptions,
    ) -> HostFuture<'a, HoldReceipt>;
    fn interrupt<'a>(
        &'a self,
        held: &'a HoldReceipt,
        options: ServiceOptions,
    ) -> HostFuture<'a, InterruptReceipt>;
    /// Point observation; Present(None) proves no active execution at this read.
    fn active_session<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Option<ActiveSession>>>;
    /// Diagnostic pages cannot be combined into an absence proof.
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a HostEpoch,
        page: PageRequest,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Page<ActiveSession>>>;
    fn idle<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<SessionActivity>>;
    fn binding_state<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn adopt_binding<'a>(
        &'a self,
        request: AdoptBinding,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn update_mail_target<'a>(
        &'a self,
        transition: TargetTransition,
        key: IdempotencyKey,
        options: ServiceOptions,
    ) -> HostFuture<'a, TargetReceipt>;
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a MailNotice,
        options: ServiceOptions,
    ) -> HostFuture<'a, NoticeAdmission>;
    fn notice_status<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        notice: &'a NoticeId,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<NoticeAdmission>>;
}
```

### Proprietary commercial constructor signature

```rust
// SPDX-License-Identifier: LicenseRef-StateEngine-Proprietary
//! Constructor signature for se-host's commercial composition, not the public API.
//! The real se_host::embedded_factory function must have this exact type.
use secode_stateengine_api::HostFactory;
use std::sync::Arc;
use tokio::runtime::Handle;

pub type EmbeddedFactoryBuilder = fn(runtime: Handle) -> Arc<dyn HostFactory>;
```
