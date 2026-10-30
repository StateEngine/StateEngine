# 95. Work breakdown — assembled plan

Status: reconciled 2026-10-30 after Jimmy declined the first version and two whole-design reviews
(Opus and Sol) plus two outside reviews found cross-section contradictions and scope no journey
needed. Building starts only when Jimmy approves this revision. Estimates are review signals, not
caps; no schedule is promised until the early proofs below settle.

Per-crate plans (files, dependencies, clauses, outside witness and estimate per task):
`95-work-breakdown-store.md`, `-se-proc.md`, `-core-cli.md`, `-host.md`, `-atlas.md`, `-release.md`.

## Size (one table; owners' parts are the source)

| Part | Before reconciliation | Reconciled estimate | Main change |
| --- | ---: | ---: | --- |
| Shared types (se-types) | ~2,000 | ~2,000 | — |
| Store (se-store) | ~9,250 | ~7,900–8,300 | no decision chain, live keysets for non-mail lists, user-state import families only, salvage deferred, automatic migration without approval machinery |
| Process ownership (se-proc) | ~10,950 | ~10,600 | three launch barriers (four on Unix terminal, macOS and uncontained helpers); process.* operations removed |
| Core and CLI/MCP surface | ~9,050 | ~8,300–8,500 | process tools removed, error catalogue merged, simpler config layers, no N-1 encoders or schema-freeze tooling |
| Host runtime and harnesses | ~8,900 + 200–350 JS | ~8,700 + 200–350 JS | no embedded credential events; handover durable phases 7 → 5 |
| Release and packaging | 920–1,540 | 960–1,600 | uninstall and early unsigned archives added |
| **Core product (alpha critical path)** | | **~38,500–39,700** | |
| Atlas (after journeys and handover; Jimmy) | 6,000–9,300 | 6,000–9,300 | disabled by default; never holds a milestone |
| macOS backends (Mac campaign) | ~1,350 | ~1,350 | qualified on Jimmy's borrowed Mac before alpha ships |
| **Everything** | 47,000–51,000 | **~45,800–50,300** | |

Live handover stays in before alpha (Jimmy): about 2,500–3,000 lines across se-proc, se-host and
se-store, plus SE Code's side. `forget` stays in alpha (Jimmy), about 600 lines.

## Early proofs (before the broad build)

| Proof | What it settles | Status |
| --- | --- | --- |
| E1 Windows handover primitives | named-pipe completion-port replacement across hosts; job re-association; abort; 100 loops | **PARTIAL**: pipe transfer PASS 3/3 on the PC and 3/3 on Linux; job re-association, abort and the 100-loop run open |
| E1b Real-provider handover | Codex 0.166 and Claude 2.1.314 keep the same process and conversation across A→B→A and answer a follow-up | **PASS** Windows 2/2 (Prime, on the PC, 2026-10-30), Linux 2/2 |
| E2 Embedded startup | B2 ≤ 100 ms with the real FULL commits, new and existing store, Windows with Defender; memory after a real task | Running (Iris) |
| E3 Write latency | B9 p95 ≤ 20 ms for `msg send`, `working-state set` and `hook claude stop` through a running host; FULL commands p95 ≤ 75 ms on Windows with Defender; the 37/67 ms rehearsal is in commit time; checkpoint-in-commit is a hypothesis. Keep the failed baseline, decompose commit time, optionally compare an off-path checkpoint variant, through a host on NTFS and ext4 | Running (Nell, 5p) |
| E4 Attended Claude mail | 25 s renewal under Claude's 30 s fetch limit; mail held during a busy turn; 100 sends with zero missed wakes | **PARTIAL**: renewal and busy-turn hold PASS on Linux; the 100-send run is open; stop/revocation bound stated (Claude's fetch has no caller abort) |
| E5 Windowed Codex | stock Codex through the private-socket app-server with a viewable TUI; headless and `--listen` paths | **PARTIAL**: Linux windowed PASS (0.163); headless, `--listen` and Windows open |
| E6 History import | real history imports; interrupted retries reproduce the same events; resumed conversation recalls | **PASS** for Codex on a factory slice; non-fleet history and Claude continuation pending |
| E7 Linux containment | what ssh, Docker and WSL2 hosts actually get | Pending |
| E8 Cold hook start | host-start versus direct write on Windows with Defender | Pending |
| Lost-ACK slice | one message after a dropped reply, through CLI, IPC, MCP and the linked API | Pending |
| E9 SE Code real server | the integration target is SE Code's Rust server, not the frozen TypeScript one | **DONE** (Alpha): `E:ust-secode` branch dev, `crates/secode-product`, caret pins, axum `=0.8.9` |
| Runner | the journey runner judges Rust from a Rust-only map, launched outside agent trees | Section 90 revised; red-against-stub run pending |

## Build order

Authors write production code only; reviewers write the tests that judge it (Jimmy 2026-10-29).
Each wave ends at an outside witness, not a green unit suite.

| Wave | Work | Done when |
| --- | --- | --- |
| 0 | The early proofs above; the runner red against a stub on Windows and Linux; this reconciliation applied and re-reviewed as one design | every proof has a result and the design is accepted as a whole |
| 1 | se-types, se-store, sync core registry and hostless CLI, se-proc Windows and Linux backends with the stop witness | J1 from an unsigned archive with install and uninstall scripts |
| 2 | Host, HTTP/MCP, Claude headless with hooks and capture, launch/stop, remove and uninstall | J2, J3 and J5 with Claude on Linux, then Windows |
| 3 | Codex, push mail and the attended Claude mod, windowed launch, `doctor --fix CHECK-ID` with printed plans, history import | all five journeys, both providers, Windows and Linux, standalone |
| 4 | Embedded SE Code and live handover (both directions, every crash phase), `forget`, signing | B1, B2 and B8 on Windows and Linux; J1 from the signed download |
| 5 | Atlas; macOS campaign; release | the five journeys pass from the real downloads on Windows, Linux and macOS |

## Proposed owners

| Owner | Work |
| --- | --- |
| 5p | se-proc |
| Nell | se-store and import |
| Vera | se-host and harnesses |
| Iris | se-types, the SE Code API, SE Code integration with Gamma |
| 5b, 5e | se-core and the `se` binary; 5e then Atlas |
| Milo | release, packaging, install and uninstall |
| 5d | journey runner and per-wave witnesses |
| 5c, Otto, Opus (Prime) | reviews and the tests that judge each wave |

## What "done" means

The five scripted journeys (Install, Adopt, Come back, Two agents, Remove) pass on clean Windows,
Linux and macOS with real Claude and Codex, standalone and inside SE Code, within section 80's
budgets, from the real release artifacts (Jimmy 2026-10-29).
