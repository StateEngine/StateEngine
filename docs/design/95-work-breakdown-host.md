# 95. Work breakdown — se-host

Planning input for Prime, 2026-10-30; base main `52dfe972`.
**No code, tests or build permission. Jimmy approves the full design before
implementation.** The accepted [section 40](40-host-runtime-and-harnesses.md)
and [OPS inventory](../OPS.md) govern; sections 80 and 90 are the shared budget
and acceptance chapters. These are planning tasks, not mandatory separate
landings or new assignments.

Dependencies: **F** = se-types identities, errors, receipts and checked codecs;
**S** = se-store snapshots, writer, leases, keyed transactions and runtime-owner
facts; **P** = se-proc identity/security, ProcessRuntime, evented stdio, transfer,
runtime bootstrap and shared file-watch service; **K** = se-core's synchronous
registry, authorization, session/mail/capture and continuity operations;
**E** = the SE Code API's HostFactory/Host implementation contract and the native
HostServices/HandoverServices supplied by SE Code. **Q** = independent section
90 reviewers, external journey runner/action map and packaged artifacts.
The native backend, native queue implementation, kernel/store internals and
permissive API stay with those owners; this chapter consumes them.

H01 alone owns the se-host manifest, lib/model facade and module registration.
Other authors own their listed leaf files; facade moves and Cargo.lock changes
are serialized with the relevant integrator. Paths below are inside
`crates/se-host/src/` unless stated otherwise. The proposed layout refines
40 §2.1, with no planned source file above 500 lines. Estimates are production
Rust lines excluding external implementations and reviewer tests. Agreed ports
permit parallel authoring; missing consumers block their behavior witnesses,
not unrelated work. Authors write no tests or runner changes (90 §1).

## Shared runtime and consumers

**H01 — Composition and shared wiring (~250 lines).** Files: `crates/se-host/Cargo.toml`, `lib.rs`, `model.rs`, directory `mod.rs` registrations and declaration re-exports. Depends F/S/P/K/E contracts. Satisfies 40 §§1–2/4, 80 B1/B3/B4 and 90 §5: supplied Tokio Handle only, concrete adapters, optional Tokio-free client, unified dependencies and no proprietary types in the permissive API. Witness: real SE Code linked open/bind plus standalone invocation, public-build dependency exclusion and outside helper/process inventory; Q checks the existing build/dependency rules. A compiling stub is not the linked behavior.

**H02 — Blocking bootstrap, wire and client proof (~750).** Files: `client/{endpoint,lease,wire,auth}.rs`. Depends H01, F/S/P and K's admitted operation DTOs. Satisfies 40 §§5/7.1–7.2, 80 B7 and 90 §3 T2/T3/T17/T21/T22: synchronous generation-free discovery/direct-lock acquisition, native server/peer verification, challenge MAC, bounded framing and original-key readback. Share wire/auth primitives with host consumers; never route an invalid session to owner or a failed IPC write to a competing direct writer. Witness: installed CLI with/without a host, foreign/squatting peers and revoked credentials, plus outside store/writer-stamp readback and B7's 30 samples per named command.

**H03 — Factory preparation and first activation (~400).** Files: `runtime/factory.rs`, `runtime/activation.rs`. Depends H01/H02 and F/S/P/K/E. Satisfies 40 §§4–5/10.2, 80 B1/B2/B3 and 90 §§2–3 T10/T17: read-only prepare, actual lease/endpoint/listener ownership, FULL runtime.owner before writer, registered G/services before activation and no implicit migration. First FULL binding and continuity belong inside B2; recovery, reconnect and backup wait until ready. Witness: actual SE Code first authenticated session response and independent owner/binding readback, existing/new-store A/B timing and J1/J2; absent/incompatible stores must refuse honestly before mutation.

**H04 — Evented process I/O and recovery adapter (~550).** Files: `process/{reactor,io,recovery}.rs`. Depends H01/H03, F/S/P and E's epoch/generation contracts. Satisfies 40 §§3.2–4/9.1, 80 B1/B4/B5/B6 and 90 §3 T16/T23: Unix native reactor integration, Windows safe create/attach_stdio ports on the existing collector, retained partial/cancelled completions, stdin half-close, exact All close/release and tagged arena recovery. No raw-handle conversion or second collector in host. Witness: public launch/close/restart with real provider output, independent PID/birth and stream/EOF readback; Q covers dropped-reply/cancel/import cases beyond T16 and inventories threads/helpers outside the process.

**H05 — Launch, stop and exit coordinator (~800).** Files: `process/{launch,stop,events}.rs`. Depends H03/H04, F/S/P/K and agreed harness contracts. Satisfies 40 §3, 80 §1 launch/stop targets and 90 §3 T14–T16/T23/T26/T28: reservation/checkpoint/CAS before native create/exec/stop, retained failed launches, native ExitSink readback and cleanup only after witnessed closure. Linux first-launch delegation is reported separately; uncontained is a real supported bound. Witness: CLI/MCP J2/J3/J5, outside root/scope observations and truthful containment/cause; Q drives PID reuse, surviving descendants and checkpoint crashes through public surfaces. Warm ≤50 ms/first Linux ≤110 ms exclude separately reported provider startup; stop retains its graceful/forced bounds.

**H06 — Binding, consent and takeover (~500).** Files: `session/{state,takeover}.rs`. Depends H03/H05, F/S/K and E/P's native target/control proof. Satisfies 40 §8, 80 B2/B8 and 90 §3 T3/T23/T26/T27: stable session/provider/lifecycle mapping, FULL activation/revocation, current creator control and hold → interrupt → exact Present(None) → checked stop/selection. Human resume races invalidate stale absence, and aborted takeover never clears independent holds. Witness: public linked-host takeover and CLI/MCP old-bearer refusal, real new-session task and outside target/binding readback; J2/J3/J4. T27's terse wording does not replace section 40's hold-before-interrupt order.

**H07 — Trusted capture and shared watches (~650).** Files: `capture/{pins,reader,watch}.rs`. Depends H04/H06, F/S/K and P's shared file-watch service; providers supply agreed source identities. Satisfies 40 §§4/9.2/10.1, 80 §§3.1/3.7/4 and 90 §3 T13/T24: trusted no-follow file pin, incremental bounded reads, canonical dedupe/cursor commit, rotation/oversize verdicts and no erased-content re-ingest. Share Windows 64 KiB root buffers/collector with section 60; watcher loss is visible and uses hooks/events/catch-up. Witness: real completed turns read through public history/resume, unchanged markers after bad capture, foreign-path/rotation/erase cases and outside memory/idle observations; J2/J3. A hook's claimed path or exit 0 is no capture witness.

**H08 — Durable mail debt and dispatch (~550).** Files: `session/mail.rs`. Depends H06, F/S/K and agreed provider/E admission contracts; H11–H13 join the real consumers. Satisfies 40 §8.1, 80 §§3.1/3.6–3.7 and 90 §3 T1/T6/T9/T12: reserve stable notices before callbacks, reconcile original-key uncertainty, preserve oldest unresolved debt and bound resident IDs/bytes without truncating mailboxes. Native admission is not promotion or recipient read; restart/mail cannot clear holds. Witness: J4's actual token/file/reply and independent recipient marker readback through CLI/MCP, stopped/held recipients and lost replies. No parallel SE Code queue or idle retry loop.

## Provider joins

**H09 — Common provider preparation (~250).** Files: `harness/{config,dispatch}.rs`. Depends H01/H05/H06 and F/S/P/K; E supplies embedded identity conventions. Satisfies 40 §§9.1/9.3–9.5, 80 B2/B3 and 90 §3 T18/T22/T23: bounded installed-version/feature probe before disturbing an incumbent, literal invocation, safe named profiles, protected launch files and actual conversation echo. Configuration produces a plan rather than a second arbitrary file writer. Witness: real attended/headless launch using the user's existing account, missing/old-provider refusal, provider argv/environment readback and J2; configuration effects join H20.

**H10 — Claude launch and command hooks (~500).** Files: `harness/{claude_launch,claude_hook}.rs`. Depends H05–H09, F/S/P/K and H18's MCP consumer. Satisfies 40 §§9.1–9.3, 80 §§3.6/4 and 90 §3 T3/T13/T23/T24: per-launch settings/MCP/plugin flags, original-session resume, fixed hook mappings, read-only session-start and pinned transcript capture. Headless stream-json reports activity/input correlation, not duplicate captured turns. Witness: J2/J3 with real Claude in both modes, new recall reply and independent captured-turn readback; rejected foreign pins, failed persistence and empty stop-hook stdout remain explicit. Hook availability exit 0 cannot conceal capture failure.

**H11 — Claude attended mail/mod (~300 Rust + 200–350 JS).** Files: `harness/claude_mail.rs`, `crates/se-host/integrations/claude/mod.js` and its adjacent provider manifest. Depends H08/H09/H10/H19 and F/S/K. Satisfies 40 §§7.3/8.1/9.3, 80 §§3.1/3.7 and 90 §§2–3 T3/T9/T19/T23: one authenticated ≤25 s wait, IDs-only notification, safe attributed prompt at idle and real human-stop cancellation. No Node process, secret prompt/query or manufactured user input. Witness: real attended Claude J4, outside prompt/reply/read markers and process inventory; measure 0.04/s renewal per attended session in idle/budget runs. The Linux headless prototype is not this mod witness.

**H12 — Codex protocol, input and capture (~600).** Files: `harness/{codex_rpc,codex_input,codex_capture}.rs`. Depends H04–H09, F/S/P/K and H18. Satisfies 40 §§9.1/9.4, 80 §§3.3/3.6–3.7 and 90 §§2–3 T3/T13/T16/T23: stock app-server initialize/start/resume, exact thread/turn steer/interrupt, canonical completed-item capture and original-key reconnect recovery. Preserve CODEX_HOME/login; headless Windows stdio is supported while attended private transport requires real qualification. Witness: J2/J3/J4 on actual Codex, printed resume run verbatim with recall, actual MCP discovery/tool call, no duplicate input and external capture/native readback. Refusal is not an attended-mode pass.

**H13 — SE Code linked/native translation (~250).** Files: `harness/secode.rs`. Depends H03/H06–H08, F/S/K and E's current public API/native callbacks. Satisfies 40 §§2/8.1/9.4, 80 B1/B2/B3/B8 and 90 §§2–3 T3/T27: checked shared/permissive IDs, immutable G wrappers, real native capture events, single-queue notice/status/adoption and UI-only owner/human presence. SE Code implements its native queue/fence; this adapter neither copies it nor rebinds an old Arc. Witness: real linked SE Code J2–J4, original admission/recipient readback, revoked old-G calls and public-build NotIncluded behavior; Q owns the link canary and API black-box checks.

## Supervision and explicit handover cost

**H14 — Fault containment and orderly shutdown (~450).** Files: `runtime/{generation,tasks,shutdown}.rs`. Depends H03–H08 and the selected H10/H12/H13 consumers, F/S/P/K/E. Satisfies 40 §§4–5/10.3, 80 §§3.2/3.7/4 and 90 §3 T8/T16/T17: retained supervisor resources, caught public/lifecycle faults, route-local restart ≤3/60 s, ownership/lifecycle poison and independent keyed factory restart. Join writer/backup, close_clean and exact native obligations before lease release; one background blocking slot leaves one foreground slot. Own the live 15-minute catch-up, ten-minute empty auto-start timer and saved-resume ordinary exit. Witness: public health/drain/restart plus outside store/native closure, real down/up J3 and idle/memory probes; unjoined work stays incomplete, not a new writer.

**H15 — Handover preparation and normal cutover (~400).** Files: `runtime/handover/{plan,cutover}.rs`. Depends H03–H08/H13/H14, F/S/P/K/E and their accepted runtime/queue contracts. Satisfies 40 §§6–6.1/10.2, 80 B8/§3.4 and 90 §§1–3 T16/T27's relevant boundaries: typed request-key discovery before replacement allocation, immediate turn cancellation/exact idle, final capture/debt/frame freeze, inactive native staging and immutable Prepared. Transfer lease, FULL Claimed/native activation/FULL Activated, verify source-resource closure/FULL Finished, settle queue, then allow final source exit. Witness: public SE Code↔daemon handover both ways, external PID/birth/stream/capture continuity, one pending-input promotion after reopen and native WaitingForSecode while absent. Report quiescence separately from ≤500 ms custody/capture cutover; no old-G input or zero-handle gap.

**H16 — Handover crash recovery and terminal proof (~300).** Files: `runtime/handover/{recovery,proof}.rs`. Depends H15/H07/H13 and F/S/P/K/E. Satisfies 40 §§6–6.2, 80 B8/B1/B4 and 90 §§1/3 T16 plus reviewer public-API crash cases: discover the original keyed plan after lost reply/pre-Prepared loss, verified source-owner Aborted with no invented phase, post-Claimed forward recovery and atomic owner/Recovered completion. Verify fresh native custody/capture and the retained queue cut, settle across epochs, then permit a new reverse plan; keep old peers/generations immutable. Witness: independently observed source/receiver loss, lost ACK and fresh-adapter settlement with exact original receipts/queue; missing proof remains pending. Stage/hash bounded attestations, never treat a digest or timeout as authority. H15+H16 expose ~700 host Rust lines of handover cost; native/store/SE Code work is external.

## Transports and owned integration effects

**H17 — Local HTTP server and common admission (~450).** Files: `http/{server,admission}.rs`. Depends H01–H03, F/S/P/K and agreed E runtime/credential contracts. Satisfies 40 §7, 80 §§3.1–3.2/4 and 90 §3 T2/T3/T5/T19–T23: verify SE Code server Cargo.lock and reuse its HTTP crate or the fixed-route HTTP/1.1 fallback, then enforce loopback/Host/Origin/Sec-Fetch-Site, caps and credential/binding/G checks. IPC and HTTP reuse authority policy; HTTP/stdio never accept Owner. Witness: public foreign-origin/peer/squatter/revocation calls, native ACL readback and secret scan of actual provider inputs; no headers/side effects on refusal. Unsafe peer/ACL code remains P-owned.

**H18 — One MCP protocol consumer (~350).** Files: `http/mcp.rs`, `mcp/stdio.rs`. Depends H02/H17, F/S/K and H03's admitted executor path. Satisfies 40 §7.3, 80 §§3.1/3.6 and 90 §3 T1/T3/T4/T6/T9/T12/T19: consume the generated registry, POST-only MCP/JSON response and the same bound-session execution through stdio. Budget final JSON-RPC text/structured/window/marker bytes, refuse an unfit first full item and keep listings read-only. Witness: real Claude/Codex tools/list/call plus CLI/HTTP/stdio result/marker mirrors and actual 8-agent latency; hostless stdio supports legal logical work and refuses custody. Binary wrappers stay with the CLI owner.

**H19 — Parked mail, liveness and server proof (~200).** Files: `http/{mail,proof,livez}.rs`. Depends H08/H17 and F/S/K; H11 consumes the wait. Satisfies 40 §7.3, 80 §§3.1/3.7 and 90 §3 T19/T20/T23: separate fixed GET mail/livez routes, anonymous bounded server-auth challenge, protected IPC-only token issuance and no HTTP token route. Keep 64 active slots separate from one parked wait/session, scaled to the negotiated session cap inside fixed byte budgets. Witness: actual mod wait/replacement, anonymous liveness contains no private data, squatting listener receives no bearer, and external idle/resource observation. Renew at 25 s, never promise a 25-minute vendor fetch.

**H20 — Owned configuration install/remove (~400).** Files: `integration/{install,remove,diagnostics}.rs`. Depends H06/H09/H14, F/S/P/K and E's native control where applicable. Satisfies 40 §9.5, 80 B3/B4 and 90 §3 T18/T22–T25: compare expected owned entries, atomic protected edits, outside readback, revoke/stop before unlink and preserve foreign/provider/repository work. Supply bounded native/config observations and allowlisted redacted artifact data to K's doctor/bundle ports; erasure remains S-owned. Hook plans use per-launch files; no arbitrary repair writer, global account replacement or bypass. Witness: J2/J5 with unchanged Git HEAD/user file, edited-entry refusal, byte-for-byte owned-entry removal and public bundle without body/secret markers. Remaining processes/files/secrets stay named obligations, never successful empty cleanup.

## Scheduling and completion

H01 freezes shared contracts/wiring first. H02/H04/H09 and the leaf transport
work can then proceed alongside their external owners; H03/H05/H06 join actual
custody, and H07/H08 join the provider/native producers. H10–H13 can run on
disjoint files once their ports agree. H14 joins safe supervision; H15/H16 join
both directions and every terminal fence path. One owner serializes each shared
file; source-module registration remains H01's job. A blocked native, SE Code or
store path does not stop unrelated leaves, and cannot be replaced by a fake
success. Prime assigns owners and assembles complete candidates.

**QH — Integrated host acceptance (0 new production lines).** Files: none newly owned; fixes remain with H01–H20, reviewer cases/runner with Q. Depends all required host joins, F/S/P/K/E and real artifacts. Satisfies 40 §§10–12, 80 B1–B9 and 90 §§1–3/5: same pinned runner/profile on Node and Rust, J1–J5 on Windows/Linux with real Claude and Codex, embedded/standalone and attended/headless mirrors, public-boundary cases where journeys cannot reach. Measure B1 ≤30 MB, B2 ≤100 ms through first authenticated bind/continuity, B3's 0/1/0 process counts, B4 ≤25 MB after real work, B5/B6 idle, B7's 30 actual samples/command, B8's separately timed quiescence/cutover and B9 host writes. Mac builds remain required; native Mac qualification follows section 90's Mac campaign and release matrix, never a cross-compile claim. Missing runner maps/probes or unreached modes remain unqualified; authors add no tests, gates or runner edits.

Production estimate: **~8,900 host Rust + 200–350 provider-native Claude JS
lines**, matching 40 §2.1. Allocation: composition 250; client 750; runtime
1,550 (including the 700-line handover pair); process adapters 1,350; sessions
1,050; capture 650; harnesses 1,900; HTTP/MCP 1,000; integration 400. These are
rough planning estimates, not correctness caps. Native backends/watching,
SQLite/kernel implementation, SE Code's queue/API, CLI wrappers, Atlas,
packaging and independent qualification are excluded, not silently reassigned.
