# 95. Work breakdown — se-core and CLI/MCP surfaces

Planning input for Prime, 2026-10-30; base main `118044a`. **No code, tests or
build permission. Jimmy approves the full design before implementation.**

The current [OPS inventory](../OPS.md) wins: 59 operations, 26 MCP tools
(21 core, including session.turn, plus 5 optional Atlas); do not copy section
50's older 25-tool assertion. Section 00's synchronous kernel/ports boundary
also wins over section 50's illustrative async Op/CancellationToken signatures:
se-core acquires no Tokio runtime, native process, network, env or filesystem
I/O. Refusals return catalogued errors, not a new event-history family. Mac
native qualification is deferred to Prime's compatibility campaign; keep the
build and explicit platform bounds, without claiming a native Mac journey pass.

Dependencies: **F** = accepted se-types plus its owner's required common
operation/DTO/error contracts; **S** = section 20 store reads, transactions,
idempotency, writer stamp, scoped cursors and pending effects; **H** = section
40 verified authority, custody, runtime lock/IPC, capture, config/artifact
readbacks and sync/async adapters; **P** = accepted se-proc primitives; **A** =
section 60 CodeIndex adapter. **Q** = independent section 90 tests/journey runner
and release artifacts. A missing consumer blocks its behavior witness, not
independent authoring against the agreed interface.

Each task's named files have one author, assigned by Prime. K01 alone owns
se-core's manifest/lib/module wiring; B01 alone owns the binary's manifest/main
wiring, including later integrations. Other authors deliver disjoint leaf
files. Shared se-types, se-store, se-host, schemas/build tooling and the runner
stay with their existing owners. MCP framing/listeners/authentication are **H
work**, not a second server in se or se-core. Estimates below are production
Rust lines, approximate, excluding those external implementations and tests;
they are review signals, not gates or reasons to cut behavior.

## Core tasks, in build order

**K01 — Registry, contracts and dispatcher (~900 lines).** Files: `crates/se-core/Cargo.toml`, `src/lib.rs`, `src/ops/mod.rs`, `src/registry.rs`, `src/dispatch.rs`, `src/ports.rs`, `src/ops/meta.rs` (all paths after the manifest are inside se-core). Depends F and agreed S/H ports. Satisfies 50 §§1, 4.3 and OPS generation: one closed ops! list, three metadata ops, feature/auth/runtime/effect metadata, typed validation, optional CLI derive, generated parser/catalogue/schemas/remedy argv, canonical errors and store-issued writer stamp; no hand-maintained second tool list or forged commit fact. Witness: generated help/schema/tools/list agree, owner verbs absent (T4), literal argv (P6), host/direct writer readback via history; J1. Kernel logic stays synchronous; H owns async custody execution.

**K02 — Admission, project scope and whoami (~650).** Files: `crates/se-core/src/admission.rs`, `src/scope.rs`, `src/ops/identity.rs`. Depends K01, F's representation types and H's verified authority/native membership/TTY proof. Satisfies OPS scope, 50 §§1.5/2.2 and 70 §2: bound actor/project only, current creator grant/direct-child target checks, no owner fallback, no input-supplied authority, nearest registered ancestor with unreadable/ambiguous refusal, human-only policy. Canonical path observations are supplied by adapters, not read by the kernel. Witness: T1–T5/T26 through CLI/MCP and T21's authenticated transport prerequisite; J2/J4. Host-issued authority remains outside these files.

**K03 — Mail and recipient markers (~700).** Files: `crates/se-core/src/ops/message.rs`. Depends K01/K02 and S's atomic message/idempotency/marker/page APIs; H supplies post-commit offers. Satisfies all six message.* rows, 50 A.4/A.5 and G2/G4/G5: sender from authority, recipient-only read/ack/dismiss, owner inspection never marks read, full-body flag is effective, unread totals/continuations and unknown omissions remain honest. Witness: T1/T6/T9/T12, P4; J4 round trip and outside marker readback. Delivery pending/offered/read remain distinct; never notify before commit.

**K04 — Decisions and human transitions (~500).** Files: `crates/se-core/src/ops/decision.rs`. Depends K01/K02 and S's expected-revision/idempotent transitions. Satisfies all seven decision.* rows, 50 A.11/A.12 and 70 §2.3: proposal/list/show plus human-only ratify/reject/retract/supersede, exact-ID filtering, preserved history, no bulk/legacy approval execution. Witness: T5/T6/T7 plus decision/event readback; supports J4. A PTY inside a managed agent tree is not human proof.

**K05 — Resume, history and working state (~1,000).** Files: `crates/se-core/src/ops/continuity.rs`, `src/ops/history.rs`, `src/ops/working_state.rs`, `src/context.rs`. Depends K01/K02, S's principal-bound snapshots/cursors/FTS and optional A. Satisfies continuity.resume, three history.* and two working_state.* rows, 50 A.7 and G4/G5: revision CAS, bounded UTF-8 context, explicit omissions, self-only private continuity, read-only owner preview and real saved provider references. Witness: T10/T13, P3/P8; J3 recall and printed resume argv. The session-context adapter reuses this assembler; Atlas absence cannot block resume.

**K06 — Project and agent identities (~700).** Files: `crates/se-core/src/ops/project.rs`, `src/ops/agent.rs`. Depends K01/K02, S and H's integration/config/custody effect ports. Satisfies project.init/remove/status and agent.list/create/show/rename (seven rows), 50 A.1–A.3/A.8/A.9 and 70 §§2/5: idempotent adoption, stable IDs/creator, safe named profiles, accurate pending/unknown/containment status, stop/revoke before removal and exact owned-edit readbacks. Witness: T18/T26, J2/J5 with HEAD/user files unchanged, edited integrations refused and remaining obligations shown. H performs native/file effects; history preservation is not secret erasure.

**K07 — Session/capture integration semantics (~500).** Files: `crates/se-core/src/ops/session.rs`, `src/ops/hook.rs`. Depends K01/K02/K05, S and H's consent/binding/capture ports. Satisfies session.begin/context/turn/end and hook.claude, 50 §4.2 and 70 §§2.2/3: caller-proved binding, generation/capability checks, consented canonical turn ingestion, revocation and frozen secode.session-context-v1 mapping. Keep session.turn in the MCP catalogue. Witness: T3/T13/T23/T24; J2/J3. Session-start is read-only; hook exit 0 never proves capture, and a claimed session ID never grants private context.

**K08 — Configuration policy (~300).** Files: `crates/se-core/src/ops/config.rs`, `src/config_policy.rs`. Depends K01/K02, S project settings and H's atomic user-config writer/readback port. Satisfies config.get/set/list, 50 §7 and 70 §§2/5: closed keys/scopes, precedence/origins, named bypass only, human presence for security changes, validated readback rather than optimistic success. Witness: T22 and outside config reread; J2 safe defaults. File/env access stays in adapters; doctor repair cannot enable bypass.

**K09 — Runtime, agent and process custody adapters (~350).** Files: `crates/se-core/src/ops/runtime.rs`, `src/ops/custody.rs`, `src/ops/mcp.rs`. Depends K01/K02, S/H/P and K05's resume references. Satisfies runtime.up/down, agent.launch/stop/wake, process.start/control/list and mcp.serve/token (ten rows), 50 A.6/§6.11 and OPS runtime needs: typed literal requests, inspect never stops, no bare PID, creator control, durable pending effects, actual outside witnesses/remaining bounds and resume-by-default. Witness: T14–T16/T26–T28; J2/J3/J5. These are host-port adapters, not another supervisor, token issuer or native backend.

**K10 — Doctor, backup, import and forget adapters (~450).** Files: `crates/se-core/src/ops/doctor.rs`, `src/ops/store.rs`. Depends K01/K02/K08, S's backup/import/erasure and H's diagnostics/repair/artifact ports. Satisfies doctor.inspect/repair/bundle and store.backup/import_node/forget, 50 A.10/§6 and 70 §§5–6: measured/unmeasured checks, allowlisted repairs, source-preserving accounted import, explicit erasure consent and WAL/search/backup limitations. Witness: T18/T22/T24/T25, P7 and independent artifact/store readback; supports J3/J5. No SQL, arbitrary file writer, uploaded bundle or provider credential handling moves into core.

**K11 — Optional Atlas operation bridge (~200).** Files: `crates/se-core/src/ops/atlas.rs`. Depends K01/K02 and agreed A DTO/CodeIndex port. Satisfies the five atlas.* rows, 50 §3/§4 and 60: bounded typed queries, explicit coverage/confidence/index state, feature-disabled CLI refusal and no phantom tools when disabled. Witness: section 60's reviewer public-query cases, tools/list/schema checks and an optional real query; no Atlas T-number or journey prerequisite is invented. May proceed independently after the port; no se-atlas dependency or cold-index engine inside the kernel.

## Binary and MCP surface joins

**B01 — Native CLI bootstrap and configuration (~700).** Files: `crates/se/Cargo.toml`, `src/main.rs`, `src/config.rs`, `src/bootstrap.rs` (paths after the manifest are inside se). Depends F/K01/K02/K08 and H/P's sync config, protected-state and identity APIs. Satisfies 50 §§2/7, 70 §§2–3/5, 80 B7: only the approved env/config sources, redacted precedence, explicit home, no fleet defaults, session pin verification with no owner fallback, native host identity and bounded stdin. Witness: T2/T3/T22/T23 and J1/J2; discovery/rename fast paths precede config/state access, and cold read commands do not create an async runtime or a subprocess.

**B02 — Generated grammar and static compatibility refusals (~300).** Files: `crates/se/src/grammar.rs`, `src/compat.rs`. Depends K01 and B01's dispatch seam. Satisfies 50 §§1.3/2/7.5 and OPS old spellings: consume the generated command tree, bind doctor/history selectors and process.control actions, reject inapplicable/legacy flags, preserve literal argv after --, keep integrations hidden, and refuse renamed/retired syntax before handler/state access. Witness: P6, public help/schema and inert rename/usage calls; J1/J2. No executable aliases or separate handwritten operation tree.

**B03 — Direct reads and race-free write routing (~500).** Files: `crates/se/src/route.rs`, `src/ipc.rs`. Depends B01/B02, K01/K02, S and H/P's authenticated endpoint/lock protocols. Satisfies 00 §2.1/50 runtime needs/70 §4.4/80 B7–B9: WAL reads never start a host; host writes use IPC; hostless writes hold the shared runtime lock and call the same store implementation; migration/custody go to the host. Witness: T8/T17/T21, P2 and writer-generation/event readback; J2–J4. Endpoint PID/peer mismatch never falls back to a different actor or writer.

**B04 — Human/JSON/errors and compatibility encoders (~750).** Files: `crates/se/src/render/mod.rs`, `src/render/read.rs`, `src/render/write.rs`, `src/render/error.rs`. Depends K01's typed outputs/catalog and B01/B02; can start against the agreed DTOs. Satisfies 50 §§4–6/Appendix A and N/N-1: readable default, versioned JSON only on stdout, diagnostics on stderr, literal next/remedy argv, payload-derived exits, quiet/color, explicit incomplete/unreadable states and count-safe stop text. Preserve init/stop legacy profiles and frozen consumer contracts. Witness: T10–T13/T28, schema/exit readback and J1–J5. Inbox incompleteness remains exit 2 even when an ordinary limit-only page is exit 0; no golden-output suite is added.

**B05 — Stdio, hook and header-helper wrappers (~250).** Files: `crates/se/src/mcp_stdio.rs`, `src/hook.rs`, `src/mcp_token.rs`. Depends K07/K09, B01/B03 and H's MCP/IPC/token/capture consumers. Satisfies OPS mcp.serve/token/hook.claude, 50 §§3–5 and 70 §§2.2/3/4: bounded framing, per-call session capability, identical MCP structuredContent/JSON, correct hook stdout and token header-map protocols. Hostless stdio supports admitted logical operations and honestly refuses custody; hook failure is recorded with exit 0. Witness: T3/T4/T19–T23, J2–J4. H owns HTTP/JSON-RPC/stdio protocol execution and anonymous tools policy; the binary wrapper creates no second dispatcher or listener.

**B06 — Runtime and private image-entry dispatch (~300).** Files: `crates/se/src/runtime.rs`, `src/private_entry.rs`. Depends B01/B03, K09 and H/P's runtime-up, installed attach/bootstrap and shutdown APIs. Satisfies OPS up/down and private native helper plumbing, 70 security boundaries and 80 B2/B3: only explicit up/mcp build a runtime, one standalone owner, foreground/background behavior, protected helper entry dispatch and truthful readiness/stop results. Private entries add no OPS verb or bypass. Witness: T16/T23, J1/J2/J3/J5; outside PID/birth/helper inventory and native stop readback. H/P own runtime composition, process effects and handover policy.

## Joins, parallelism and completion

After K01's shared ports and K02 admission, K03–K11 can run on disjoint domain
files as their own S/H/A interfaces become ready. B01 joins K08 configuration;
B02/B03/B05/B06 join their named consumers. B04 can proceed alongside domain
work using frozen DTOs. K01/B01 owners alone register new modules/dependencies.
No domain author takes over se-types, store schemas, host transport or another
file to bypass a blocked dependency.

**Q01 — Integrated acceptance (0 new production lines).** Files: none newly
owned; fixes stay with the owners above, reviewer tests/runner maps stay with Q.
Depends all required core/binary/H/S/P joins, with Atlas optional. Witness:
section 90's CLI/MCP/linked-host mirrors, Windows/Linux J1–J5 with both real
providers, T1–T28 where applicable, store properties P1–P8 under their store
owner, current schemas and existing build/security checks. Unreached cases are
not passes. Measure B1/B2/B3/B4/B5/B6 integration shares, B7 reads (<20 ms p95,
30 runs per named command) and B9 host writes; preserve the first-Linux-launch
<=110 ms / warm <=50 ms and declared stop bounds. Deferred Mac native work is
reported separately. No new tests/tooling are authored by this planning lane.

Production estimate: **~6,250 core + ~2,800 binary = ~9,050 lines**, with broad
uncertainty until the approved interfaces are implemented. H's MCP transport,
store internals, native process code, foundation/catalog changes, packaging,
reviewer tests and the external runner are excluded, not silently assigned here.
