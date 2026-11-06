# 95. Work breakdown — se-core and CLI/MCP surfaces

Design reconciliation, 2026-10-30. Implementation awaits the operator's approval of the
assembled design. These tasks add no author tests, runtime stubs or gate tooling.
The registry has **58 operations and 24 MCP tools (19 core, 5 optional Atlas)**.
One closed input type per operation supplies CLI, MCP, IPC and linked validation;
authenticated authority never comes from that DTO.

`se-core` is synchronous validation, planning and receipt construction. A write
returns `OpStep::Commit { batch, then }`: `then` is a typed continuation, never a
closure holding a transaction. The host runs planning and continuation in separate
bounded blocking-pool jobs with owned/Arc readers, releasing the worker permit
and Snapshot around the executor-only CommitWait. Core never waits on a commit;
the hostless CLI uses synchronous DirectStore::append under its lease. Custody is
a typed plan executed by the host or hostless CLI file-custody adapter. No core
Tokio, filesystem/env access, process handle or network client is introduced. Refusals use the error channel without a history
write; a lost acknowledgement keeps the original identity and exposes uncertainty.

Dependencies: **F** = shared se-types, including limits/errors and `code` DTOs;
**S** = section 20 canonical reads, AtomicBatch, expected revisions, idempotency,
writer completions; **H** = section 40 authority, async
custody/IPC/bootstrap, capture and native/file readback adapters; **P** = section 30
exact-instance native custody; **A** = optional standalone CodeIndex adapter;
**Q** = section 90's independent runner/reviewer tests and release artifacts.
Store-domain causes map completely to the one public catalogue; no parallel error
protocol is added. An unavailable consumer blocks its witness, not independent
work on agreed declarations.

## Core units

Each unit names its complete production ownership, dependencies and outside
witness. K01 alone wires the core manifest/lib/modules; B01 alone wires the binary.
Others author disjoint leaves. Estimates exclude implementations owned by F/S/H/P,
release packaging and reviewer tests; they are planning estimates, not gates.

**K01 — Registry and synchronous dispatcher (900 lines).** Own
`crates/se-core/Cargo.toml`, `src/lib.rs`, `src/ops/mod.rs`, `src/registry.rs`,
`src/dispatch.rs`, `src/ports.rs`, `src/commit.rs`, `src/ops/meta.rs` (core-relative paths after the
manifest). Depends F and agreed S/H ports. Implement the one ops list, generated
CLI/MCP/schema metadata, closed input validation, typed Commit/Custody steps,
continuations, canonical error mapping and receipt construction from actual store
writer stamps. No waiting, writer closures, schema-freeze tool or second tool list.
Witness: generated help/schema/tools/list agree on all admitted rows; independent
history readback binds host/direct writer stamps; T4, P6 and J1.

**K02 — Authority and scope (650).** Own core `src/admission.rs`, `src/scope.rs`,
`src/ops/identity.rs`. Depends K01/F/H. Enforce bound actor/project, direct-created
target plus current creator grant, no private-read expansion, nearest registered
ancestor and explicit unreadable/ambiguous outcomes. Human policy is always,
never or per-config-key; security keys including agent can-create require the
verified outside-agent-tree owner terminal, with its same-user limitation stated.
Canonical path/native observations arrive from adapters. Witness: T1–T5/T26,
authenticated T21 prerequisite and CLI/MCP/linked J2/J4.

**K03 — Mail and recipient markers (650).** Own core `src/ops/message.rs`. Depends
K01/K02/S and H post-commit offers. Cover all six message rows, 32 KiB shared body
limit, required send key, natural recipient/message/marker keys, stable mail
windows and count/body completeness. Listing/owner inspection never marks mail
read; an offered notification is not a recipient read. Witness: T1/T6/T9/T12, P4,
real J4 handoff and independent marker/event readback, including a lost ACK.

**K04 — Decisions (450).** Own core `src/ops/decision.rs`. Depends K01/K02/S. Cover
seven decision rows, exact-ID selection, immutable expected-revision transitions,
required request keys and FULL ratify/reject/retract/supersede. No decision chain
or temporal decision-summary index. Human receipts disclose the mistake/drift
boundary; no bulk approval or typed-ID prompt. Witness: T5/T6/T7, decision/event
readback and J4; an agent-created PTY is not human presence.

**K05 — Continuity, history and working state (850).** Own core
`src/ops/continuity.rs`, `src/ops/history.rs`, `src/ops/working_state.rs`,
`src/context.rs`. Depends K01/K02/S and optional A through shared code DTOs only.
Cover resume, three history rows and two working-state rows: self-private context,
owner read-only preview, CAS, 16 KiB shared working-state limit, explicit omissions
and saved conversation references. Search is a bounded streamed scan, never FTS;
non-mail lists are labelled live keysets. Witness: T10/T13, P3/P8, A.14 outside
capture readback and J3 demonstrated recall. Disabled/unbuilt Atlas cannot block
resume or start indexing.

**K06 — Project/agent identity (650).** Own core `src/ops/project.rs`,
`src/ops/agent.rs`. Depends K01/K02/S/H. Cover project init/remove/status and agent
list/create/show/rename: idempotent adoption, immutable creator, safe named profiles,
required keys, accurate state/containment and stop/revoke before removal. Init
owns absent-store creation/FULL schema/header publication and readback through
S01 before completing owner/project/agent facts; retry reuses valid published
state and finishes missing setup. Embedded open never invokes init implicitly. Init
chooses/persists a per-user listener port in 20000–29999. H performs native/file
work and readbacks. Witness: T18/T26, J2/J5, unchanged user files/HEAD, refusal of
edited integrations and explicit incomplete obligations. Remove preserves history;
it does not imply forget or uninstall.

**K07 — Integration semantics (450).** Own core `src/ops/session.rs`,
`src/ops/hook.rs`. Depends K01/K02/K05/S/H. Cover session begin/context/turn/end and
hook.claude, with session_turn in MCP. Require proved binding, exact generation,
consent, stable capture identity before send and the frozen SE Code context
adapter. The first ordinary-cold embedded binding supplies S01/S04 and H with
separately admitted registry-owner/project-session batches for their single FULL
maintenance transaction before writer startup; both stable keys and the actual
activation revision survive retry. Embedded binding returns an in-process handle and issues no credentials;
external helpers remain authenticated. The public turn DTO uses 128 KiB content inside the existing 1 MiB frame, including worst-case escaping; trusted pinned-source capture streams its separate canonical turn into staging. Witness: T3/T13/T23/T24, real J2/J3 capture and
A.14; session-start is read-only and hook exit zero is not capture proof.

**K08 — Configuration policy (250).** Own core `src/ops/config.rs`,
`src/config_policy.rs`. Depends K01/K02/H plus S for explicit agent-record fields.
One file precedence is flag > env > config.toml > default, without project settings.
Saved profile/model/create-grant updates are domain records, not config overrides.
Closed key metadata marks security mutations human-only. Unneeded tuning knobs are
constants; general writes use H’s shared file adapter without starting a runtime.
File-only retries follow section 40’s readback reconciliation, without a journal.
Witness: T22, outside readback and J2 safe defaults; doctor cannot select bypass.

**K09 — Runtime/agent custody and MCP adapters (250).** Own core
`src/ops/runtime.rs`, `src/ops/custody.rs`, `src/ops/mcp.rs`. Depends K01/K02/S/H/P
and K05 resume references. Cover runtime up/down, agent launch/stop/wake and MCP
serve/token (seven rows), with current creator authorization, durable effect plans,
exact stop witnesses and original-conversation resume argv. No process.start,
process.control or process.list. Private bootstrap may start the host; core does
not execute it. Witness: applicable T14–T16/T26–T28 and J2/J3/J5. H owns supervision,
credentials, native effects and default SE Code handback.

**K10 — Diagnosis, owner recovery and uninstall (500).** Own core
`src/ops/doctor.rs`, `src/ops/store.rs`, `src/ops/installation.rs`. Depends
K01/K02/K08/S/H/P. Cover doctor inspect/repair/bundle, store restore/import/forget,
credential rotate and installation uninstall (eight rows). Repair selects exactly
one diagnosed CHECK-ID and never rotates/restores. Separate human-only restore and
rotate print consequences; import admits six user-state families and preserves its
source. Forget accounts for actual store/WAL/cache copies. Uninstall first invokes
ordinary graceful down, verifies owned-agent stops and saved resume references,
prints achieved facts, then removes owned installation/integrations and restores
managed PATH. Scripts/SE Code's installer call this operation. Witness: T18/T22–T25,
P7, independent store/artifact readback and J5 PATH restoration. No manual backup,
salvage, SQL console or second uninstall implementation.

## Binary units

**B01 — CLI bootstrap (700).** Own `crates/se/Cargo.toml`, `src/main.rs`,
`src/config.rs`, `src/bootstrap.rs` (binary-relative paths). Depends F/K01/K02/K08
and H/P. Resolve only admitted home/env/config inputs, native owner/session proof,
redacted origins, shared input limits and bounded stdin. Anonymous metadata and
static compatibility refusals precede store access. Witness: T2/T3/T22/T23,
J1/J2 and no fleet defaults; ordinary current-schema reads construct no runtime.
For non-init store-dependent routes requiring setup, preserve absence as
setup-required with resolved-home `se init --repo DIR` remedy. Bare se and
se status render not-set-up and exit 0 (T10/G4); metadata remains store-free.
No CLI/embedded open silently creates schema. The per-workspace pre-TUI
repository trust hook invokes explicit bundled owner init only after the
workspace is accepted, then re-prepares; a declined workspace is never registered.
Profile onboarding is separate and the public GitHub stub silently skips init.
Plain se init and se init --repo DIR are managed setup: no repository writes,
all setup in the per-user state home outside the repository, launch-flag wiring
for managed agents and no separate repository-write consent. Only --adopt
installs unmanaged Claude/Codex integration files, lists each file actually
written and records files_touched/integrations[]; plain human output ends with
the explicit se init --adopt invitation in section 50.

**B02 — Generated grammar (250).** Own binary `src/grammar.rs`, `src/compat.rs`.
Depends K01/B01. Consume the generated tree, map doctor/history selectors to the
same closed DTOs, reject unknown/inapplicable flags, and handle static renamed or
retired syntax before handler/state access. No process actions or executable
aliases survive. Witness: P6, help/schema and inert usage/rename readback; J1/J2.

**B03 — Routing and commit completion (550).** Own binary `src/route.rs`,
`src/ipc.rs`. Depends B01/B02/K01/K02/S/H/P. Current-schema WAL reads stay direct;
a supported older schema releases the reader lease and privately bootstraps the
sole migrating host, rather than asking a stranger to run an upgrade. Existing
host writes use authenticated IPC; hostless writes use the same batch transaction
engine under the lease through synchronous DirectStore::append. No future or background writer is added to that direct route. Preserve request identity,
uncertain commit outcomes and version-independent down routing. Route explicit
init through S01 create/open and its FULL publication/readback; a missing store
on a non-init store-dependent route requiring setup reports setup-required; bare
se/status keep their not-set-up exit-0 result. Witness:
T8/T17/T21, P2, lost-ACK CLI/IPC slice and writer/event readback; never fall back to
a different actor or second writer after endpoint/peer mismatch.

**B04 — Human and JSON output (550).** Own binary `src/render/mod.rs`,
`src/render/read.rs`, `src/render/write.rs`, `src/render/error.rs`. Depends
K01/B01/B02. Emit current schema-tagged families, separate stderr diagnostics,
readable next steps/remedies, precise exits/omissions and achieved stop facts.
Keep consumed init/stop/context adapters; no N-1 encoders or schema-freeze tooling.
Unknown commit output prints the original --key retry, not a fresh command identity.
Witness: T10–T13/T28, family/exit readback and J1–J5; no new golden-output suite.

**B05 — Integration wrappers (250).** Own binary `src/mcp_stdio.rs`, `src/hook.rs`,
`src/mcp_token.rs`. Depends K07/K09/B01/B03/H. Preserve native hook/header-helper
stdout, bounded escaped-JSON frames, per-call session authentication and generated
MCP results. H owns framing/execution/listeners; wrappers add no second dispatcher.
Cold hooks use private host bootstrap and the host writer (40 §9.3), as settled
by E8; no direct-write fallback or production cold-hook latency win is promised.
Witness: T3/T4/T19–T23, real-provider J2–J4 and outside capture readback; a failed
capture must remain visible even when provider protocol requires exit zero.

**B06 — Runtime/private entry and installer join (300).** Own binary
`src/runtime.rs`, `src/private_entry.rs`. Depends B01/B03/K09/K10/H/P. Wire public
up/down and the one uninstall operation to runtime/installer adapters, plus
protected private helper entries. Private bootstrap is not a public daemon verb.
Default SE Code exit with live agents hands back to detached se up; it exits ten
minutes after its last live agent. Ordinary down stops owned agents on every OS.
Witness: T16/T23, J1/J2/J3/J5, native instance/stop readbacks and installer invoking
the same uninstall path. No un-witnessed mass termination belongs in a script.

## Joins and completion

K01/K02 establish shared ports/admission; K03–K10 can proceed in their disjoint
leaves as S/H become available. A12 exclusively owns the optional
`se-core/src/ops/atlas.rs` bridge and its estimate, without a second core unit.
B01 joins K08, and B02/B03/B05/B06 join their named consumers. B04 proceeds
against agreed DTOs. A blocked dependency does not license taking over another owner's file or introducing a second implementation.

Q owns independent acceptance, with fixes staying in the responsible production
unit. It covers CLI/MCP/linked mirrors, required T1–T28 and store P1–P8, the lost-ACK
slice, security/build checks and all five journeys with real Claude and Codex.
Windows/Linux standalone is intermediate. Done includes clean Windows, Linux and
macOS, standalone and embedded; borrowed-Mac qualification happens before alpha
without delaying implementation. Unreached runtime/native cases are not passes.
Section 80 owns every performance threshold, including ordinary mixed host writes
and the separate FULL-write bound; this breakdown introduces no duplicate budget.

## Estimate arithmetic

Core K01–K10: **900 + 650 + 650 + 450 + 850 + 650 + 450 + 250 + 250 + 500
= 5,600 lines**. Binary B01–B06: **700 + 250 + 550 + 550 + 250 + 300 = 2,600**.
Combined production estimate: **8,200 lines across 16 units**. A12 counts the
optional 150-line Atlas bridge once within its own composition estimate. External
host, store, native custody, foundation DTO/catalogue, packaging and reviewer tests
are excluded. Per-unit estimates are the source for the generated overview table.
