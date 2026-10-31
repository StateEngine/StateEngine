# 95. Work breakdown — assembled plan

Status: reconciled 2026-10-30 after Jimmy declined the first version and two whole-design reviews
(Opus and Sol) plus two outside reviews found cross-section contradictions and scope no journey
needed. Jimmy approved wave 1 on 2026-10-31 after two more outside reviews (Astra 6, Opus 5.5),
on condition that the round-4 fixes pass one cross-section check; later waves wait on wave 1's
results. Estimates are review signals, not caps; no schedule is promised until the early proofs
below settle.

Per-crate plans (files, dependencies, clauses, outside witness and estimate per task):
`95-work-breakdown-store.md`, `-se-proc.md`, `-core-cli.md`, `-host.md`, `-atlas.md`, `-release.md`.

## Size (one table, summed from the owners' per-task estimates)

Every row is the sum of its part's per-task estimates; the part file shows the arithmetic.
se-types has no separate breakdown and keeps its earlier estimate.

| Part | Before reconciliation | Reconciled (per-task sum) | Source | Main change |
| --- | ---: | ---: | --- | --- |
| Shared types (se-types) | ~2,000 | ~2,000 | earlier estimate | Atlas DTOs moved in from se-atlas (counted once) |
| Store (se-store) | ~9,250 | 8,800 | 95-store S01–S15 | no decision chain, no general settings in the store, live keysets for non-mail lists, six import families, no salvage, automatic migration without approval |
| Process ownership (se-proc) | ~10,950 | 11,400 | 95-se-proc P00–P09 | three launch barriers (four on Unix terminal, macOS, uncontained); five handover outcomes; process.* operations removed; +450 for the Linux scoped helper and D-Bus scope adapter (E7) |
| Core and CLI/MCP surface | ~9,050 | 8,200 | 95-core-cli K01–K10, B01–B06 | process tools, N-1 encoders, FTS and project settings removed; owner actions added; the Atlas bridge (`ops/atlas.rs`) is owned and counted once, by Atlas A12 |
| Host runtime and harnesses | ~8,900 + 200–350 JS | 9,050 + 200–350 JS | 95-host H01–H20 | automatic migration, readback-reconciled file operations, async commit join, version-independent stop |
| Release and packaging | 920–1,600 | 960–1,600 | 95-release R01–R07 | one `se uninstall` path; early unsigned archives |
| **Core product (alpha critical path)** | | **40,410–41,050 + 200–350 JS** | | |
| Atlas (after journeys and handover; Jimmy) | 6,000–9,300 | 6,000–9,300 | 95-atlas A01–A13 (A12 owns the core bridge) | standalone only, disabled by default |
| macOS backends (Mac campaign) | ~1,350 | 1,350 | 95-se-proc P03-M, P07-M | qualified on Jimmy's borrowed Mac before alpha ships |
| **Everything** | 48,420–52,400 | **47,760–51,700 + 200–350 JS** | | |

The first reconciled overview claimed a core of ~38,500–39,700 without per-task sums behind it.
The summed figure is about 900–1,400 lines higher: se-proc's native scope did not shrink, and the
host gained the async commit join and stop-across-versions work. Estimates are review signals, not caps.

Live handover stays in before alpha (Jimmy): about 2,500–3,000 lines across se-proc, se-host and
se-store, plus SE Code's side. `forget` stays in alpha (Jimmy), about 600 lines.

## Early proofs (before the broad build)

| Proof | What it settles | Status |
| --- | --- | --- |
| E1 Windows handover primitives | named-pipe completion-port replacement across hosts; job re-association; abort; 100 loops | **PARTIAL**: pipe transfer PASS 3/3 on the PC and 3/3 on Linux; job re-association, abort and the 100-loop run open |
| E1b Real-provider handover | Codex 0.166 and Claude 2.1.314 keep the same process and conversation across A→B→A and answer a follow-up | **PASS** Windows 2/2 (native PC, 2026-10-30), Linux 2/2 |
| E2 Embedded startup | B2 ≤ 100 ms: the in-window first bind as one combined check, and the late path as two independent checks (startup alone, and bind to first visible assistant response, against no StateEngine bound) | **PARTIAL** with the store created at `se init` plus one FULL owner+first-session commit (20, 40). In-window: Windows with Defender 38.7 / 46.6 ms p95, 0/100 over; Linux 70.7 / 63.5 ms at load 7–8, 1/100 over (diagnostic: the box idles at load 6–8). Late path, Windows: startup 26.4 ms and bind-to-response 43.7 ms p95, 0/50 over each (an earlier run missed startup at 158.7 ms on a busy PC; retained). Late path, Linux: startup 90.1 ms p95 at load 9.5, 0/50 over; bind-to-response still to run. Linux `se init` itself is about 79 ms p95. The Windows FULL budget for init is not yet measured. Memory after a real task is not yet measured |
| E3 Write latency | B9: serial plus eight agents, each ordinary command p95 ≤ 20 ms spawn to exit through a running host; twenty-agent burst worst case ≤ 100 ms with no lost writes; FULL commands p95 ≤ 75 ms on Windows with Defender | **OPEN RISK (Linux)**. Database layer: Windows with Defender 3.9 / 10.5 ms p95 (serial / twenty at once). Linux NVMe at load 7–9: serial 16.9 ms, eight at once 44.4 ms, twenty at once 87.9 ms. Three isolated levers each made eight-at-once worse: separate FULL groups 57.8 ms, index removal 58.5, checkpoint off the commit path 66.9. Rerun on a quiet box (load ≤ 10) comparing 4 KiB with 16 KiB pages and with and without `list_versions`, then measured on the real Rust host and CLI in wave 1. If the hosted result still misses, Jimmy's fallback applies (2026-10-31): one agent writing alone keeps p95 ≤ 20 ms, eight at once p95 ≤ 50 ms, and the write path is not redesigned |
| E4 Attended Claude mail | 25 s renewal under Claude's 30 s fetch limit; mail held during a busy turn; 100 sends with zero missed wakes | **PARTIAL**: renewal and busy-turn hold PASS on Linux; the 100-send run is open; stop/revocation bound stated (Claude's fetch has no caller abort) |
| E5 Windowed and headless Codex | stock Codex through the private-socket app-server with a viewable TUI; headless and `--listen` paths | **PASS (headless)**: Windows stdio 16/16 plus a real-turn outside-write denial 17/17, Windows local socket 26/26, Linux both transports 43/43 (0.163). The safe headless policy comes from the saved profile; Windows avoids Store PowerShell (40 §9.4). Linux windowed PASS. Attended Windows and macOS stay open |
| E6 History import | real history imports; interrupted retries reproduce the same events; resumed conversation recalls | **PASS** for Codex on a factory slice; non-fleet history and Claude continuation pending |
| E7 Linux containment | what ssh, Docker and WSL2 hosts actually get | **PASS**, 20/20 native cases. Desktop, real SSH, rootless Podman and WSL2 (Ubuntu 26.04 with systemd) are contained where a user manager exists. SSH needs the short helper inside a fresh per-launch scope over D-Bus (30 §5.2). Scopes ship in wave 4 (Jimmy 2026-10-31); waves 1–3 use the process-group path on Linux, as macOS does. Docker without systemd, ordinary or privileged, is honestly uncontained with cause no-user-manager. A systemd-enabled container is not tested |
| E8 Cold hook start | host-start versus direct write on Windows with Defender | **PASS, settled**: 100 pairs with Defender on; host-start p95 82.5 ms, direct p95 88.1 ms. A hook with no host starts the host privately and never writes directly (40 §9.3). Routing is settled; production hook latency is measured in wave 2 |
| Lost-ACK slice | one message after a dropped reply, through CLI, IPC, MCP and the linked API | Pending |
| E9 SE Code real server | the integration target is SE Code's Rust server, not the frozen TypeScript one | **DONE** (SE Code): `E:\rust-secode` branch dev, `crates/secode-product`, caret pins, axum `=0.8.9` |
| Runner | the journey runner judges Rust from a Rust-only map, launched outside agent trees | **PASS**: the pinned judge rejects a zero-exit native stub, launched outside the agent tree, on Linux and on Windows (2026-10-31) |

## Build order

Authors write production code only; reviewers write the tests that judge it (Jimmy 2026-10-29).
Each wave ends at an outside witness, not a green unit suite.

| Wave | Work | Done when |
| --- | --- | --- |
| 0 | The early proofs above; the runner red against a stub on Windows and Linux; the lost-ACK slice; this reconciliation applied and re-reviewed as one design | every proof has a result and the design is accepted as a whole |
| 1 | se-types, se-store, sync core registry and hostless CLI, se-proc Windows backend and the Linux process-group backend with the stop witness, and a minimal hosted write path (installed CLI, authenticated IPC, host, production writer, mixed NORMAL and FULL traffic) | J1 from an unsigned archive with install and uninstall scripts, and the hosted E3 result with queue, transaction, sync and checkpoint time reported separately |
| 2 | Host, HTTP/MCP, Claude headless with hooks and capture, launch/stop, remove and uninstall; a thin real SE Code slice (link, bind, task, capture through `crates/secode-product`) | J2, J3 and J5 with Claude on Linux, then Windows; the SE Code slice works end to end; memory measured after a real task |
| 3 | Codex, push mail and the attended Claude mod, windowed launch, `doctor --fix CHECK-ID` with printed plans, history import; one SE Code process handover round trip once E1's primitives pass | all five journeys, both providers, Windows and Linux, standalone |
| 4 | Embedded SE Code and live handover (both directions, every crash phase), `forget`, Linux cgroup scopes (zbus first), signing | B1, B2 and B8 on Windows and Linux; J1 from the signed download |
| 5 | Atlas; macOS campaign; release | the five journeys pass from the real downloads on Windows, Linux and macOS |

## Work ownership

The project maintainer assigns authors to the module work in the breakdown:
process containment, store/import, host/harnesses, shared types and SE Code API,
core/CLI, Atlas, release/packaging and journey witnesses. SE Code integration
also requires the host project's interface review. Independent correctness and
craft reviewers assess each complete candidate before integration. This plan
contains no named-seat assignments or permission to start implementation.

## What "done" means

The five scripted journeys (Install, Adopt, Come back, Two agents, Remove) pass on clean Windows,
Linux and macOS with real Claude and Codex, standalone and inside SE Code, within section 80's
budgets, from the real release artifacts (Jimmy 2026-10-29).
