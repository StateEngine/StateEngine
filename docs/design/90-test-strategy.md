# 90 — Test strategy

Status: reconciled design, 2026-10-31. Implements the plan's "How we know it works"
and Jimmy's decisions: the five journeys are the judge; authors write no tests; reviewers add black-box
tests only where a journey can't reach or a bug was found; about 6–8 property tests for the store.

## 1. Policy

**Authors write no tests.** The design makes the type checker do the work tests used to do:
`Read<T>` instead of `Option` (G4); `Page<T>` with a `Window` on every read (G5); `ProcessInstance`
constructible only in se-proc (G6); `Authority` constructible only by se-host (G1); `SeError` whose
remedy match is exhaustive; `Secret` without `Clone`/`Display`; and one `ops!` registry that generates
the CLI and MCP, so the two cannot drift. "No tests" is not "unverified": authors drive their work
through the real `se` binary and run the journeys locally before review.

**Reviewers add black-box tests, for two reasons only:**
1. A guarantee the journeys cannot reach: pid reuse, a foreign actor, a revoked capability, a partial
   inbox, a crash after an acknowledged write.
2. A bug found in review; the reviewer shows the test failing before the fix, once, in the review report.

**Each test names what it protects** in its first doc line:
`/// Protects: G6 — stop refuses a reused pid` or `/// Bug: <short sha> — inbox skipped the last page`.
A test without that line is a review return. That is a review rule, not a CI gate.

**Black-box means public surfaces only:** the installed `se` binary (argv, JSON, exit codes, files),
MCP frames over HTTP and stdio, and the `se-host` API SE Code links. No private-function tests and no
internal mocks, so a refactor can't break a test that still describes correct behavior.

**Where the tests live:**
| Kind | Location |
| --- | --- |
| CLI and MCP black-box | `crates/se/tests/`, using `env!("CARGO_BIN_EXE_se")` |
| Host API black-box | `crates/se-host/tests/` |
| Store property tests | `crates/se-store/tests/`, against the store's public API |
| Fake provider fixture | `test-support/fake-provider`, `publish = false`, never shipped, excluded from the dependency-direction check |

**Expected size:** 40–60 black-box test functions and 8 property suites. Ordinary bounded checks
target under 2 s each and under 3 min per OS. The full table-driven native crash campaign (§3.1)
runs separately in wave 4 and reports its case count and elapsed time; its cases are not extra test
functions or a promise of a two-second campaign. Growth in functions is a review signal, not a gate.

**Test doubles match the real readers.** The fake provider replays frames recorded from real Claude
hooks and stock Codex 0.166 app-server runs (host prototype). Nightly journeys against the latest CLIs
catch drift; stale recordings are re-recorded, never hand-edited to fit our code.

## 2. The journeys are the acceptance oracle

### 2.1 Where they live and who owns them
- The independent judge lives in `journeys/` in the Node factory repository. Master
  `9fc45c7234faeb720bad37c4a1d13fab1dcec2bc` contains the accepted runner changes through
  `31df4e96c93b84ee6e61c2dd775a951e38ae7329`. The journey owner writes no product code.
  Product authors run the judge; independently reviewed runner changes remain the journey owner's work.
- The Rust product is judged with `--implementation rust` and a `journey-product/v1` descriptor
  selecting only the shipped `rust-v1` map. Node remains the private factory engine; passing its
  journeys is not a Rust acceptance prerequisite. No factory runtime migration or fleet import is planned.
- The judge uses its own Node 24+ on the test machine. Rust ships without Node. Public installer,
  `se`, SE Code and uninstaller argv come from the descriptor; product source is never imported.
  Record the exact product and runner commits and resolved map SHA with qualification results.
- Launch the judge from a human's non-agent shell or an OS scheduler/timer outside every managed
  agent process tree, with fleet/session variables absent. A PTY supplies terminal I/O; it does not
  change ancestry or confer human authority. A managed seat may prepare scripts and inspect results,
  but cannot run J5 from its own tree and claim the human-presence precondition passed.

### 2.2 What each journey asserts
| Journey | Assertions, all observed from outside the product |
| --- | --- |
| J1 Install | Unsigned archive with install and uninstall scripts for the first milestone; signed download for release; both commands found from a fresh terminal (fresh login shell on Unix; PATH rebuilt from the registry on Windows); `stateengine X.Y.Z` version format |
| J2 Adopt | Existing Git repo with committed work; `HEAD` unchanged by init; a real agent writes a file holding a random token and replies by message; the user's file unchanged |
| J3 Come back | Real task and reply; `stop` prints a resume command in its JSON; `down` then `up`; the printed command is run verbatim; a **new** reply recalls the token without being told it |
| J4 Two agents | Planner→Builder and Builder→Planner messages with the token; the file effect is real |
| J5 Remove | Host identity witnessed by pid + birth from outside; remove and uninstall; setup reported absent by a separate CLI; owned active records, credentials, integrations and commands gone; history retained; known and newly seen processes gone; user work and PATH restored |

Each journey runs in a fresh private home with fleet variables stripped, links (never copies) provider
credentials, never kills by name, and judges section 80's budgets in the same run.

**Required Linux qualification.** Linux launch is BestAvailable (00 §7.1), so a journey on Linux accepts either a
contained agent (`containment: "cgroup"`) or an explicitly uncontained one (`"uncontained"` with a
non-null `containment_cause`). Read the pair from the launch receipt and from `se status`,
report it per run in `results.json`, and fail the step when the field is missing or null for a running
agent, or when `uncontained` comes without a cause. Stop and J5's "processes gone" checks are judged
against the bound the receipt names: the cgroup when contained, the process group when uncontained
(70 §2.4).

### 2.3 Runner on master and qualification still missing
The runner on master has closed action and field maps for setup/status, create, launch, stop,
resume, down/up, send/list, decisions and removal. The Rust map uses OPS spellings: `init --repo`,
`status`, `agent add`, `agent list`, `launch`, `stop`, `up`, `down`, `msg send/list/inbox`,
`decide`, `decision list`, and `remove --all`, with explicit `--home` and project context.
It reads section 50's judged families, including message IDs and sender/recipient references,
`runtime.process.pid`, complete pages, and stop's exact resume argv. The descriptor selects the map
by name; embedded maps and legacy read overrides refuse. The descriptor cannot replace asserted
facts, thresholds or the independently selected Rust policy. Saved `command-map.json` bytes match the SHA in `results.json`.

On master, ordinary reads use 30 native CLI spawn-to-exit samples. Hosted message and decision
writes use 30 fresh samples each, retain every failure, and require exact committed IDs/bodies from
a separate public reader plus the observed writer generation. Linux no-session idle uses paired
10/70-second foreground hosts and a native child subreaper, including exited-thread/descendant
usage. One-session idle requires public kernel self-accounting with its stated helper and provider
bounds. macOS CPU applies the Mach timebase. None of these controls is a Rust product pass.

The following remain qualification work, not capabilities claimed for master: Linux receipt/status
containment and independent achieved-scope closure; live linked handover in both directions with
exact idle, queue/capture continuity, all crash phases and no doubled input; real Claude Stop-hook
writes with outside `history` readback; and embedded memory after resume, mail, tools and a real task.
The existing embedded S3 probe is bootstrap-only and explicitly provisional. Declaration-only Rust
or a fake provider cannot qualify these measurements. Missing access, API, field or native evidence
is unavailable/not reached, never zero. B8 and B9 use section 80's single budget table; quiescence is
reported separately from cutover, dormant SE Code input is not active adoption, and hook exit zero
is not capture evidence. Codex capture uses app-server, not a fabricated Claude hook.
With no host running, a real Claude hook must start one and commit with `writer.mode=host`, verified against outside history readback and the actual host generation.

### 2.4 Cadence
| When | Where | Agents |
| --- | --- | --- |
| Each product milestone | Windows and Linux clean user accounts, scheduled outside agent trees | Claude |
| Nightly | Same two machines, outside agent trees | Claude and Codex, against current supported upstream CLIs |
| Mac campaign | Borrowed Mac before alpha ships; the Windows/Linux build continues before access is available | Claude and Codex |
| Alpha release candidate | Clean Windows, Linux and macOS from the signed download | Real Claude and Codex, inside SE Code and standalone |

Partial runs (`--only`) are diagnostic and never qualify. `results.json` and `budgets.json` go to the
project's results directory, never the engine's. Pass counts are reported daily.

## 3. Reviewer black-box tests, mapped to guarantees

These are the tests the plan names, plus the boundary tests from section 70. Where both surfaces exist,
one test function runs against the CLI and against MCP (mirror coverage by construction). A test that
cannot reach its precondition on an OS reports **not reached**, which is never a pass.

| ID | Protects | Test | Surfaces | OS |
| --- | --- | --- | --- | --- |
| T1 | G1 foreign actor refused | Agent A's capability tries to read, ack and dismiss B's message, and to supply `from`/`agent_id` in input → `not-recipient` / usage refusal; B's markers unchanged | CLI, MCP | all |
| T2 | G1 label ≠ identity | `SE_PROJECT` or `-p` that conflicts with a bound session refuses; an agent named like the owner gains nothing | CLI | all |
| T3 | G1 revoked capability | After stop and after takeover, the old bearer and capability are refused over HTTP and IPC, with no fallback to owner | MCP, CLI | all |
| T4 | G1 owner verbs absent | Session `tools/list` contains no ratify, reject, retract, supersede, remove, forget or config tool | MCP | all |
| T5 | G1 human presence | `decision ratify` with piped stdin, and from inside a managed agent tree with an allocated PTY, refuses with its fix | CLI | all |
| T6 | G2 retries | Identity created before first send; drop the committed reply, retry the same key/body → original receipt and one event; changed body → `idempotency-key-reused`. Every MCP mutation requires its key; natural-key capture/dispositions retain their restricted path | CLI, IPC, MCP, linked API | all |
| T7 | G2 supersede keeps history | Supersede a decision; history lists both with the transition | CLI | all |
| T8 | G3 crash after acknowledged write | 100 sends through the host; force-kill after each acknowledged receipt; restart finds every commit once. One table-driven reviewer test also runs the storage crash cases in §3.1. Separately benchmark the real NORMAL/FULL mix including FULL decision ratify/reject/retract/supersede. Application-crash results do not claim OS-crash or power-loss durability; NORMAL may lose several recent ordinary commits there | CLI | all |
| T9 | G3 pending ≠ delivered | Send to a stopped agent → receipt says `delivery: pending`; never `delivered` until offered | CLI, MCP | all |
| T10 | G4 absent / unreadable / zero | Fresh home with no store: bare `se` or `se status --json` → measured absence (`setup.state: not-set-up`, `project.state: absent`), onboarding with `se init`, exit 0; store with a foreign `application_id` or bad bytes → Unreadable, exit 3; store unreadable by permission → Unreadable, not Absent; empty inbox → exit 0, zero; newer `user_version` → `store-too-new` | CLI | all |
| T11 | G4 unknown target | An unknown agent or message id → exit 4 naming the choices | CLI, MCP | all |
| T12 | G5 partial inbox | 150 unread, page 100 → exit 2, window shows 50 omitted plus a continuation; following it returns the rest; nothing marked read implicitly | CLI, MCP | all |
| T13 | G5 truncation is explicit | A 32 KiB message is accepted; one byte over is rejected before any effect on every surface, with no truncation. Page/body budgets remain explicit. Transcript truncation/rotation retains the committed cursor and reports its mismatch, with no silent re-ingest or duplicate | CLI, MCP | all |
| T14 | G6 pid reuse refuses | Linux: inside `unshare --user --pid --fork --map-root-user`, write `ns_last_pid` so a new process gets the recorded pid, then `stop AGENT` against the recorded managed lifecycle → `stop-unwitnessed` (native IdentityChanged mapped by section 30), with the PID and expected/found start identities in its reason; no signal reaches the impostor, which survives by outside OS readback. Windows: spawn short processes until the pid recycles (bounded; else not reached). macOS: in the Mac campaign | CLI | Linux, Windows |
| T15 | G6 + G8 orphan descendants | Launch a managed fake-provider fixture that double-forks and calls `setsid`. Windows, and Linux with `containment: "cgroup"`: `stop` → the descendant is gone by OS reread, and the receipt has an outside witness. macOS, and Linux with `containment: "uncontained"`: the bound is that every member still in the tracked process group is gone by OS reread and witnessed; a descendant that left the group with `setsid` is a stated limit (70 §1.2, §2.4), not a failure, and the test reports which bound it judged | CLI, MCP | all |
| T16 | G6 host restart | Default SE Code exit with live agents transfers to a detached standalone host; reopening transfers back with the original PID/birth/conversation and retained queue. One table-driven reviewer test exercises the transfer crash cases in §3.1, including source/successor death and lost ACK with the same key. Abrupt host death without a completed transfer is judged separately at the OS crash-policy bound, with saved-conversation recovery and no doubled input | CLI, host API | all |
| T17 | G7 hostless loop | No daemon: init, send, inbox, decide and resume use the same store implementation directly; custody auto-starts through private bootstrap; the next host start delivers pending effects | CLI | all |
| T18 | G8 integration readback | Adopt writes marked entries; the user edits one; `remove` refuses that entry by name and restores the others byte-for-byte | CLI | all |
| T19 | 70 §4.2 listener admission | Foreign `Host`, foreign or `null` `Origin`, cross-site `Sec-Fetch-Site`, `text/plain` POST, token in the query, `OPTIONS` → refused; no `Access-Control-*` header ever | HTTP | all |
| T20 | 70 §4.3 loopback and squatting | Non-loopback config → refusal before any socket opens; another listener on the port → `se mcp token` prints no header | CLI | all |
| T21 | 70 §4.4 IPC peer check | A client as another uid (`sudo -u nobody` in a CI container) is refused; Windows: pipe DACL read back as user-only | IPC | Linux, macOS; Windows readback |
| T22 | 70 §5 permissions | After init: mode 0600/0700 or a user-only DACL; loosen it → a named diagnosis and remedy. `doctor --fix CHECK-ID` prints the specific plan and consequences before applying that check; configuration repair never rotates credentials or restores history. Separate named owner actions for rotation/restore enforce the human-presence guard | CLI | all |
| T23 | 70 §3.2 no secret leaks | The fake provider dumps its argv and environment: no `sec1.`/`sels-` text, and `SE_SESSION` is a handle only; unbound child/tool processes receive no session handle unless explicitly admitted | CLI | all |
| T24 | 70 §6 forget erases | A captured turn with a unique marker; `forget` → the marker's bytes are absent from `state.db` and the WAL, the bounded streamed search and cache/readback find nothing, catch-up does not resurrect it, and the receipt names the backups and the provider transcript | CLI | all |
| T25 | 70 §6 bundle allowlist | Markers in a message, turn and decision; `doctor --bundle` → none of the markers in the zip bytes | CLI | all |
| T26 | G1 creator control is narrow | A with `can-create` launches, wakes and stops its direct helper via `target_agent_id`; a grandchild, another agent's helper, an imported agent with no recorded creator, and any target after the grant is revoked → refused; `stop --all` from a session refuses | MCP, CLI | all |
| T27 | SE Code takeover holds | Through the host API: interrupt, hold, absent from the active map; a later mail wake does not revive the old session or clear the independent human hold; the human-presence guard prevents mistakes/drift, not a determined same-account program | host API | all |
| T28 | G4 + G8 uncontained is reported, never silent | In a container or user namespace with no systemd user manager: `se launch AGENT` succeeds (no refusal); the launch receipt, `se status --json` and `se agent list --json` all show `containment: "uncontained"` with a non-null `containment_cause`; the human launch line says uncontained; `se doctor` reports `custody.linux-cgroup` as `warning`, not `ok`; `stop` witnesses with `pidfd-exit+pgid-empty`, or `start-identity-exit+pgid-empty` on a kernel without pidfd support, never `cgroup-empty`; the runner accepts either label only when it matches the kernel capability reported by `se doctor`. With a user manager present, the same test sees `cgroup` and a null cause (else that half is not reached) | CLI, MCP | Linux |
| T29 | G3 + G6 launch/stop recovery | Drive the launch/stop case table in §3.1 through real crash boundaries; recover the last durable lifecycle without duplicate launch, premature activation or release before exit proof. The case outcomes are owned by 30 | CLI, MCP, host API | all |
| T30 | G1 + G6 unwitnessed release | `se stop AGENT --release` from Running, LeaderExited or Lost → `IllegalTransition`; only StopUnproved after an ordinary stop admits the human-owner path on uncontained Linux/macOS. Trace every release branch for zero signals; the receipt never claims an exit witness. Remove then unblocks but reports possible survivors. CLI without human presence and all MCP invocation refuse; MCP lists no release form. Windows jobs and cgroups refuse. Contracts: 30 §4 and 50 A.6 | CLI, MCP | all (successful release: Linux/macOS uncontained) |

### 3.1 Table-driven crash campaigns

The 40–60 black-box test budget counts reviewer test functions, not the cases each function drives.
Use **one reviewer test per table below**: storage extends T8, transfer extends T16, and launch/stop is
T29. Each function iterates every applicable row, both sides of each listed boundary, and the declared
OS/surface variants. Transfer also covers both directions and death of either live peer. These are finite case tables, not separate
per-phase, per-OS or per-surface suites; property P1 supplements them rather than replacing them.

Each case starts from fresh state, kills a real process at an independently observed boundary, reopens
through the public consumer, and checks the named durable outcome plus outside native/file effects.
Use public store/host APIs and native tracing or controlled peers, never private production hooks.
Record the reached boundary and result for each case; an unavailable observation or unsupported
precondition is **not reached**, never coverage by inference. Continue independent cases after a
failure, retain every first result, and report case counts separately from function counts. The tables
reference the owning contracts below; their phases and legal recovery outcomes remain authoritative.

**Storage — one T8 test** (20: atomic append, first binding, migrations, backups, restore, forget and import):

| Case | Boundaries to cut | Required restart/readback |
| --- | --- | --- |
| Ordinary and FULL write groups | Savepoint failure, outer COMMIT, reply/notification | Definite rollback versus unknown commit stays distinct; original-key or natural-key resolution finds all-or-none members, original stamps and exactly one effect; acknowledged process-crash commits survive |
| Embedded first binding | Paired FULL owner/session commit, writer admission, first-bind deadline/fallback | Both receipts or neither; no speculative fallback after unknown outcome, no second owner/session after lost reply; ordinary work stays gated until the legal owner path completes |
| Creation and migration | Staged schema, protected publication, verified pre-migration backup, final FULL version publication/readback | No partial ready store or overwrite; old source/backup retained on failure; sole owner completes only a supported migration before admission |
| Automatic backup | Copy, independent validation, file/directory sync, generation publication and rotation | Partial copy never becomes a valid generation; prior valid generations survive failed publication; recovery selects only an independently validated published image |
| Explicit restore | Confirmed selection, staged recovery record, guarded publication, outside readback and lost reply | Same owner/key after a lost reply, later writes and backup rotation → byte-identical complete original `se.restore/v1` receipt (20 replay contract); changed explicit intent refuses. Absent record means no publication; unreadable record refuses; corrupt source/WAL stays retained |
| Forget | FULL erasure commit, WAL/cache cleanup, independent absence proof, FULL completion | Pre-commit rollback retains complete bodies; post-commit failure stays frozen/pending until finite cleanup; no early completion or re-ingestion; retained backups/provider copies remain named residuals |
| User-history import | Imported events plus source checkpoint commit, reply, interrupted resume | Original source unchanged; checkpoint advances only with accounted events; same-source retry neither skips nor duplicates; no imported process/session authority |

**Launch and stop — one T29 test** (30: launch commit grouping, durable recovery table and state transitions):

| Case | Boundaries to cut | Required restart/readback |
| --- | --- | --- |
| Launch | C1 reservation, native scope creation, C2 scope checkpoint, native exec/readiness, C3 activation | Recover exactly the last durable reservation/scope/root at the OS crash-policy bound; no fabricated root, launch-ready receipt or ordinary StateEngine admission before C3, and no duplicate launch on uncertain retry |
| Helper/terminal launch | Additional RootCheckpoint and exec authorization between C2 and C3 | Vendor cannot execute before its recoverable native identity commits; pre-authorization parent loss closes the helper; committed checkpoint remains recoverable |
| Cancellation and stop | StopRequested CAS, native dispatch, outside exit proof, Exited commit, native release and release acknowledgment | Failed CAS signals nothing; post-CAS uncertainty retains StopUnproved; proof precedes terminal release; an already released exact scope resolves without touching a replacement |

**Live transfer — one T16 test** (20: durable handover table; 40 §6/§6.1: native and store phase tables):

| Case | Boundaries to cut | Required restart/readback |
| --- | --- | --- |
| Preparation | Inactive native staging, writer/readers/backup drain, FULL Prepared seal | Before Prepared, staged copies have no authority; after it, no mutable source writer/manifest; only a legal claim or verified preclaim abort can settle the seal |
| Claim and activation | Source lease release, successor FULL Claimed, each native activation and source-closure/capture-debt/queue proof | Before claim, only proved Aborted may restore the source; after claim, source cannot resume, including on lost ACK; transient activation is not a durable phase |
| Completion | FULL Finished, ordinary destination admission and reply/ACK | Proofs precede Finished, consumers follow it; lost ACK replays the same transfer with exactly one queued input/effect; surviving native custody retains PID/birth/conversation, while actual host loss uses the declared OS crash-policy recovery |
| Abort and cold recovery | FULL Aborted; fresh custody proof plus FULL runtime.owner/Recovered | Prepared settles only by the legal abort path; a stranded Claimed transfer uses checked cold Recovered under fresh custody, never stale-successor Finished; required holds and capture debt survive |

Application-process kills establish only application-crash behavior. OS-crash/power-loss claims need
separate native campaigns at the stated NORMAL/FULL bounds; they cannot be inferred from these tests.
The full transfer/crash matrix remains wave 4 work; the earlier round-trip slice does not qualify it.

## 4. Property tests

Eight `proptest` suites over the store's public API. Each runs 256 cases per PR and 10,000 nightly on
the Linux workstation. Failing seeds are committed as `proptest-regressions` files (data, not tests).

| # | Name | Invariant |
| --- | --- | --- |
| P1 | `crash_points_are_atomic` | A child process runs random write batches and is killed at a random moment. After reopening, every batch is all or none, and the projections (inbox, marks, resume heads, effects) equal a fresh replay of the event log. |
| P2 | `retries_deduplicate` | Concurrent callers through CLI/IPC/MCP/linked API, with direct CLI writing only under a shared lease while no host owns the exclusive lease, retrying uncertain outcomes with the original idempotency keys produce exactly one event per key: same body gives the same receipt, a different body is refused. |
| P3 | `pages_concatenate_to_the_full_read` | For a quiescent event set, following cursors yields the full read in order without gaps/duplicates and with accurate omissions. Mail retains its snapshot window across appends. Other lists use labelled live keysets; concurrent changes remain explicitly live, never a fabricated historical snapshot. |
| P4 | `mail_markers_are_monotonic` | For any sequence of offer, deliver, read, ack, dismiss and retry, each recipient's marker only moves forward (unread → delivered → read; dismissed separate). Only the recipient's authority writes read marks. The unread count equals the unread markers. |
| P5 | `history_is_append_only` | For any operation sequence, the first n events are byte-identical before and after. `forget` changes only the body of the named turn events and keeps id, order and `vendor_turn_ref`. Supersession keeps both rows. |
| P6 | `argv_is_literal` | For any argument strings (`--k=value`, `--`, leading dashes, quotes, non-ASCII): parse → typed input → render → parse gives the same input; nothing after `--` is read as a flag; NUL is refused. |
| P7 | `import_is_idempotent_and_accounted` | For generated non-fleet Node user state (identities, agents/profiles, messages/marks, decisions, working state, turns and conversation references), including malformed lines, importing twice gives the same state; read = imported + duplicate + unreadable + dropped-by-policy; no source byte changes. |
| P8 | `resume_respects_its_budget` | For any history and byte budget, resume output fits the budget, is valid UTF-8 at the cut, and included plus omitted equals the total for each section. |

## 5. Build, review and release checks

Use Windows x86_64, Linux x86_64 and macOS arm64 for compilation and bounded black-box/property
checks without provider credentials. Real journeys run in clean signed-in accounts outside agent trees.
Windows/Linux is an intermediate milestone; macOS and embedded SE Code are required before alpha ships.

Each candidate runs formatting, workspace clippy with the agreed lints, the applicable black-box and
property tests, dependency/license checks and a release build. Review manifests for dependency direction,
unsafe placement and the synchronous se-core boundary: Tokio belongs in se-host, not the synchronous
core/store API. Print binary size and per-crate size as review signals using section 95's single size
table. Do not add schema-freeze tooling, N-1 encoders, or additional CI machinery. Every JSON output
retains its schema identifier; decoder behavior is exercised through the installed public surfaces.

Embedded qualification links the actual Rust `secode-server` in `crates/secode-product` from Alpha's
SE Code repository and its matching release source. It does not use the frozen TypeScript predecessor.
The statically linked API version must match exactly. Dependencies use compatible caret ranges and one
resolved SQLite linkage; the canary builds the real composition and runs a bound-session smoke and
post-task memory/startup probes. It also confirms the public SE Code build excludes commercial se-* crates.

Before the broad build, run E1-E9 and the lost-ACK slice from the coordinated build order. Prove the
Rust runner rejects a stub on Windows/Linux outside agent trees. Begin J1 from an unsigned archive
with install and uninstall scripts; then qualify Claude J2/J3/J5, both providers' five standalone
journeys, embedded/live handover in both directions and all crash phases, forget, and signed downloads.
Atlas stays disabled by default, is built after the journeys and live handover pass, and holds no
milestone. Forget stays before release. Non-fleet import is interrupted, rerun and checked by resuming
both providers' actual saved conversations. Supported additive migrations run automatically under the
sole owner after a verified backup; a still-running old host refuses with `se down first`. Do not
require an approval fingerprint or a manual stranger migration step.

Nightly use the same runner against current supported native providers and the larger property corpus.
For release verify the delivered signatures and run J1 from the signed download, then all five journeys
with real Claude and Codex on clean Windows, Linux and macOS, standalone and embedded. Failed tests are
not automatically retried or relabelled as passes; retain the original failure and fix its cause.

## 6. What we will not build

- **Mutation tooling:** no mutant runner, tiers, anchors or receipts. A test proves it can fail through
  the reviewer's one-time demonstration against the real bug.
- **Census and ratchet gates:** no test-count, coverage-percentage, line-count or kernel-size gates.
  Sizes are printed as review signals.
- **Golden-output sprawl:** no snapshots of human-readable output and no help goldens (help is
  generated from the registry). Machine output keeps a versioned schema identifier and documented family fields; journeys read JSON.
- **Unit tests of internals,** internal mocks, `#[cfg(test)]` hooks in production paths or test-only
  features. Crash tests kill real processes.
- **Per-surface suites, flake-hunt infrastructure,** automatic retries or quarantine lists.
- **Committed evidence packets** or per-slice reports; the commit message is the record.
- **A guard per incident.** A found bug gets one regression test, or a product change that removes the
  cause instead.
