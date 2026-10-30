# 90 — Test strategy

Status: deep design, 2026-10-30. Precedence as in 00. Implements the plan's "How we know it works"
and Jimmy's rulings: the five journeys are the judge; authors write no tests; reviewers add black-box
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

**Expected size:** 40–60 black-box tests and 8 property tests, each under 2 s, under 3 min per OS. More
is a review signal that the policy is slipping.

**Test doubles match the real readers.** The fake provider replays frames recorded from real Claude
hooks and stock Codex 0.166 app-server runs (Vera's prototype). Nightly journeys against the latest CLIs
catch drift; stale recordings are re-recorded, never hand-edited to fit our code.

## 2. The journeys are the acceptance oracle

### 2.1 Where they live and who owns them
- Today: `journeys/` on `seat-5d/five-user-journeys` (`c422d0b4d4f`), with the budget probes on
  `seat-5d/journey-runtime-budgets` (`32bbabfcde6`), in the Node repository.
- Target, per the plan: their own repository, owned by the journey seat (5d), which writes no product
  code. The Rust repo pins the runner commit it was judged by in `journeys.lock`; it never vendors or
  edits the runner. Changes to the runner get independent review, and **Node and Rust must pass the same
  runner commit**, so the judge cannot drift toward either implementation.
- The runner uses its own Node 24+ and reaches the product only through a `journey-product/v1`
  descriptor (public argv arrays, profile `node` or `rust`). Product authors may run it, never edit it.

### 2.2 What each journey asserts
| Journey | Assertions, all observed from outside the product |
| --- | --- |
| J1 Install | Real installer; both commands found from a fresh terminal (fresh login shell on Unix; PATH rebuilt from the registry on Windows); `stateengine X.Y.Z` version format |
| J2 Adopt | Existing Git repo with committed work; `HEAD` unchanged by init; a real agent writes a file holding a random token and replies by message; the user's file unchanged |
| J3 Come back | Real task and reply; `stop` prints a resume command in its JSON; `down` then `up`; the printed command is run verbatim; a **new** reply recalls the token without being told it |
| J4 Two agents | Planner→Builder and Builder→Planner messages with the token; the file effect is real |
| J5 Remove | Host identity witnessed by pid + birth from outside; remove and uninstall; setup reported absent by a separate CLI; records, keys and commands gone; known and newly seen processes gone; user work and PATH restored |

Each journey runs in a fresh private home with fleet variables stripped, links (never copies) provider
credentials, never kills by name, and judges section 80's budgets in the same run.

**Linux containment.** Linux launch is BestAvailable (00 §7.1), so a journey on Linux accepts either a
contained agent (`containment: "cgroup"`) or an explicitly uncontained one (`"uncontained"` with a
non-null `containment_cause`). The runner reads the pair from the launch receipt and from `se status`,
reports it per run in `results.json`, and fails the step when the field is missing or null for a running
agent, or when `uncontained` comes without a cause. Stop and J5's "processes gone" checks are judged
against the bound the receipt names: the cgroup when contained, the process group when uncontained
(70 §2.4).

### 2.3 Required runner change before Rust can be judged
The runner still drives Node spellings and fields: `init --status`, `init --remove`, `seat launch`,
`seat stop`, `seat create --human-actor`, `agents`, `--project-root`, `--registry-root`, `--user-id`,
`up --detach --no-follow`, and JSON fields `from_seat`, `to_seat`, `msg_id`, `engine_session.session_pid`.
OPS.md makes every one of those a `renamed` refusal or an unknown flag. Only `reads` is mapped by the
descriptor today. **Proposal for the runner owner:** extend `journey-product/v1` with a closed
**action map** (setup, status, agent create, launch, stop, down/up, send, list, remove) giving argv and
field paths per profile, written by the journey seat and independently reviewed. The Node profile must
still pass that commit. Product authors don't write the Rust profile's map.

### 2.4 Cadence
| When | Where | Agents |
| --- | --- | --- |
| Every landing batch | Windows (clean test account on the PC) and Linux (per-seat worktree on the workstation) | Claude |
| Nightly | Same two machines | Claude and Codex, against the latest upstream CLIs |
| Mac campaign | Borrowed Mac, once the repo is mostly built | Claude and Codex |
| Release candidate | All three OSes, from the signed download | Both, inside SE Code and standalone |

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
| T6 | G2 retries | Same idempotency key + same body → replayed receipt; different body → `idempotency-key-reused`; one event | CLI, MCP | all |
| T7 | G2 supersede keeps history | Supersede a decision; history lists both with the transition | CLI | all |
| T8 | G3 crash after acknowledged write | 100 sends through the host; the host is force-killed right after each receipt; on restart all 100 are present once (prototype: 0 of 100 lost) | CLI | all |
| T9 | G3 pending ≠ delivered | Send to a stopped agent → receipt says `delivery: pending`; never `delivered` until offered | CLI, MCP | all |
| T10 | G4 absent / unreadable / zero | No store → Absent, exit 1, "run `se init`"; store with a foreign `application_id` or bad bytes → Unreadable, exit 3; store unreadable by permission → Unreadable, not Absent; empty inbox → exit 0, zero; newer `user_version` → `store-too-new` | CLI | all |
| T11 | G4 unknown target | An unknown agent or message id → exit 4 naming the choices | CLI, MCP | all |
| T12 | G5 partial inbox | 150 unread, page 100 → exit 2, window shows 50 omitted plus a continuation; following it returns the rest; nothing marked read implicitly | CLI, MCP | all |
| T13 | G5 truncation is explicit | A body over budget → incomplete flag; a captured transcript truncated or rotated → a recorded verdict, with no silent re-ingest or duplicate | CLI | all |
| T14 | G6 pid reuse refuses | Linux: inside `unshare --user --pid --fork --map-root-user`, write `ns_last_pid` so a new process gets the recorded pid, then `process stop` → `process-identity-changed`, and the impostor survives. Windows: spawn short processes until the pid recycles (bounded; else not reached). macOS: in the Mac campaign | CLI | Linux, Windows |
| T15 | G6 + G8 orphan descendants | `process start` a command that double-forks and calls `setsid`. Windows, and Linux with `containment: "cgroup"`: `stop` → the descendant is gone by OS reread, and the receipt has an outside witness. macOS, and Linux with `containment: "uncontained"`: the bound is that every member still in the tracked process group is gone by OS reread and witnessed; a descendant that left the group with `setsid` is a stated limit (70 §1.2, §2.4), not a failure, and the test reports which bound it judged | CLI, MCP | all |
| T16 | G6 host restart | Kill the host; on Linux/macOS agents survive and are re-adopted with the same pid and birth; on Windows the tree stops and the relaunch resumes the conversation; no doubled input | CLI | all |
| T17 | G7 hostless loop | No daemon: init, send, inbox, decide, resume all work directly; the next host start delivers pending effects | CLI | all |
| T18 | G8 integration readback | Adopt writes marked entries; the user edits one; `remove` refuses that entry by name and restores the others byte-for-byte | CLI | all |
| T19 | 70 §4.2 listener admission | Foreign `Host`, foreign or `null` `Origin`, cross-site `Sec-Fetch-Site`, `text/plain` POST, token in the query, `OPTIONS` → refused; no `Access-Control-*` header ever | HTTP | all |
| T20 | 70 §4.3 loopback and squatting | Non-loopback config → refusal before any socket opens; another listener on the port → `se mcp token` prints no header | CLI | all |
| T21 | 70 §4.4 IPC peer check | A client as another uid (`sudo -u nobody` in a CI container) is refused; Windows: pipe DACL read back as user-only | IPC | Linux, macOS; Windows readback |
| T22 | 70 §5 permissions | After init: mode 0600/0700 or a user-only DACL; loosen it → `status` refuses with the `doctor --fix` fix; `doctor --fix` tightens and rotates | CLI | all |
| T23 | 70 §3.2 no secret leaks | The fake provider dumps its argv and environment: no `sec1.`/`sels-` text, and `SE_SESSION` is a handle only; `process start` children have no `SE_SESSION` | CLI | all |
| T24 | 70 §6 forget erases | A captured turn with a unique marker; `forget` → the marker's bytes are absent from `state.db` and the WAL, search finds nothing, a catch-up sweep does not re-ingest it, and the receipt names the backups and the provider transcript | CLI | all |
| T25 | 70 §6 bundle allowlist | Markers in a message, turn and decision; `doctor --bundle` → none of the markers in the zip bytes | CLI | all |
| T26 | G1 creator control is narrow | A with `can-create` launches, wakes and stops its direct helper via `target_agent_id`; a grandchild, another agent's helper, an imported agent with no recorded creator, and any target after the grant is revoked → refused; `stop --all` from a session refuses | MCP, CLI | all |
| T27 | SE Code takeover holds | Through the host API: interrupt, hold, absent from the active map; a later mail wake does not revive the old session | host API | all |
| T28 | G4 + G8 uncontained is reported, never silent | In a container or user namespace with no systemd user manager: `se launch` succeeds (no refusal); the launch receipt, `se status --json` and `se agent list --json` all show `containment: "uncontained"` with a non-null `containment_cause`; the human launch line says uncontained; `se doctor` reports `custody.linux-cgroup` as `warning`, not `ok`; `stop` witnesses with `pidfd-exit+pgid-empty`, or `start-identity-exit+pgid-empty` on a kernel without pidfd support, never `cgroup-empty`; the runner accepts either label only when it matches the kernel capability reported by `se doctor`. With a user manager present, the same test sees `cgroup` and a null cause (else that half is not reached) | CLI, MCP | Linux |

## 4. Property tests

Eight `proptest` suites over the store's public API. Each runs 256 cases per PR and 10,000 nightly on
the Linux workstation. Failing seeds are committed as `proptest-regressions` files (data, not tests).

| # | Name | Invariant |
| --- | --- | --- |
| P1 | `crash_points_are_atomic` | A child process runs random write batches and is killed at a random moment. After reopening, every batch is all or none, and the projections (inbox, marks, resume heads, effects) equal a fresh replay of the event log. |
| P2 | `retries_deduplicate` | Concurrent writers (direct CLI under the shared lock, plus the host writer) retrying any interleaving of idempotency keys produce exactly one event per key: same body gives the same receipt, a different body is refused. |
| P3 | `pages_concatenate_to_the_full_read` | For any event set, page size and body budget, following cursors yields the full read in order with no gap or duplicate. Every page but the last says incomplete with correct omitted counts. Appends made while paging appear after the cursor, never inside earlier pages. |
| P4 | `mail_markers_are_monotonic` | For any sequence of offer, deliver, read, ack, dismiss and retry, each recipient's marker only moves forward (unread → delivered → read; dismissed separate). Only the recipient's authority writes read marks. The unread count equals the unread markers. |
| P5 | `history_is_append_only` | For any operation sequence, the first n events are byte-identical before and after. `forget` changes only the body of the named turn events and keeps id, order and `vendor_turn_ref`. Supersession keeps both rows. |
| P6 | `argv_is_literal` | For any argument strings (`--k=value`, `--`, leading dashes, quotes, non-ASCII): parse → typed input → render → parse gives the same input; nothing after `--` is read as a flag; NUL is refused. |
| P7 | `import_is_idempotent_and_accounted` | For any generated Node-format corpus with malformed lines, importing twice gives the same state; read = imported + duplicate + unreadable + dropped-by-policy; no source byte changes. |
| P8 | `resume_respects_its_budget` | For any history and byte budget, resume output fits the budget, is valid UTF-8 at the cut, and included plus omitted equals the total for each section. |

## 5. CI matrix and checks

Hosted runners for Windows (x86_64), macOS (arm64) and Linux (x86_64), with no provider credentials on
them. Journeys run on self-hosted clean accounts (§2.4), because they need signed-in agents.

**Every PR and landing batch, on all three OSes:**
1. `cargo fmt --check`.
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`, with the workspace lints
   (`unwrap_used`/`expect_used` denied; `unsafe_code` forbidden) and clippy config disallowing
   unbounded channels and `std::env::var*` outside `se::config` (00 §5.5–5.6).
3. **Dependency direction:** an `xtask` (about 60 lines over `cargo metadata`) checks that each crate's
   edges match 00 §3.1, and that the kernel crates (se-types, se-store, se-core) depend on no tokio
   networking, hyper, notify, harness or surface crate.
4. **Unsafe location:** the same xtask fails if any crate other than se-proc overrides `unsafe_code`.
   In se-proc, `clippy::undocumented_unsafe_blocks` is denied, so every block carries `// SAFETY:`.
5. **Schema freeze:** `cargo xtask schema --check` compares the generated MCP input and output schemas,
   the `se.<family>/vN` output families and the store DDL against committed `schemas/`. A non-additive
   change without a version bump fails. Store migrations must be additive in alpha (no drop, no rename).
6. `cargo deny check` (licenses, advisories, bans, sources; 70 §7).
7. **No outbound network:** `cargo tree -i` for TLS and HTTP-client crates is empty for the shipped
   binary.
8. Black-box tests and property tests (256 cases).
9. Release build; binary size and per-crate line counts printed as review signals, not gates.

**Nightly:**
- **SE Code link canary:** build `secode-server` from its mirrored source (offline) with the
  `stateengine` feature against our head. `cargo tree -d` must show no duplicate tokio, hyper, rusqlite
  or libsqlite3-sys. Run one bound-session smoke. Also build SE Code's public configuration and confirm
  that no `se-*` crate appears in its dependency graph (the licensing rule). A failure goes to Alpha's
  seat and ours as one message.
- Journeys with Claude and Codex (§2.4).
- Property tests at 10,000 cases.
- `cargo deny check advisories` against a fresh advisory database, since new advisories arrive without
  any code change.

**Release:** verify signatures (`signtool verify /pa`, `spctl --assess`, minisign), then run J1 from the
signed download. CI never retries a failed test; a flaky test is fixed or deleted with a reason.

## 6. What we will not build

- **Mutation tooling:** no mutant runner, tiers, anchors or receipts. A test proves it can fail through
  the reviewer's one-time demonstration against the real bug.
- **Census and ratchet gates:** no test-count, coverage-percentage, line-count or kernel-size gates.
  Sizes are printed as review signals.
- **Golden-output sprawl:** no snapshots of human-readable output and no help goldens (help is
  generated from the registry). Machine output is pinned once per family by the schema files; journeys
  read JSON.
- **Unit tests of internals,** internal mocks, `#[cfg(test)]` hooks in production paths or test-only
  features. Crash tests kill real processes.
- **Per-surface suites, flake-hunt infrastructure,** automatic retries or quarantine lists.
- **Committed evidence packets** or per-slice reports; the commit message is the record.
- **A guard per incident.** A found bug gets one regression test, or a product change that removes the
  cause instead.
