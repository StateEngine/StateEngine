# 95. Work breakdown — assembled plan

Status: design complete, all sections accepted by both Opus and Sol reviews on 2026-10-30.
Build start waits for Jimmy's approval of the whole design. Estimates are review signals,
not caps (Jimmy 2026-10-30): never weaken a contract to hit a number.

Per-crate plans, each with files, dependencies, clauses satisfied, outside witness and
line estimate per task:

| Part | Plan | Estimated production lines (alpha: Windows + Linux) |
| --- | --- | ---: |
| Shared types (se-types) | already declared on main | ~2,000 (1,867 exist) |
| Store (se-store) | `95-work-breakdown-store.md` | ~9,250 |
| Process ownership (se-proc) | `95-work-breakdown-se-proc.md` | ~10,950 (+~1,350 macOS, deferred) |
| Core and CLI/MCP surface (se-core, se) | `95-work-breakdown-core-cli.md` | ~9,050 |
| Host runtime and harnesses (se-host) | `95-work-breakdown-host.md` | ~8,900 Rust + 200–350 JS |
| Atlas (se-atlas) | `95-work-breakdown-atlas.md` | 6,000–9,300 |
| Release and packaging | `95-work-breakdown-release.md` | 920–1,540 |
| **Total** | | **~47,000–51,000** |

Two scope items are separable and carry their own cost:
- **Live handover** (SE Code ↔ daemon without killing agents): ~2,550 lines (host H15/H16
  ~700; se-proc P07-W/P07-L/P08 ~1,850), plus the SE Code side owned by Gamma. In alpha per
  Jimmy's 10-30 plan. Without it, an SE Code restart stops its agents and the user resumes.
- **Atlas** (code index): 6,000–9,300 lines, off by default in embedded SE Code.
Excluding both gives ~38,000–42,000.

## Build order

Authors write production code only; reviewers (Opus via Prime, Sol via 5c/Otto) write the
tests that judge it (Jimmy 2026-10-29). Each wave ends at an outside witness, not a green
unit suite. A missing interface blocks only its consumer.

| Wave | Work | Done when |
| --- | --- | --- |
| 0 | se-types complete; store schema, writer, readers; se-proc P00/P01 ports; core registry/dispatcher (K01) | store writes and reads back from outside the writer; `se --version` and help generated from the registry |
| 1 | se-proc Windows and Linux backends (P02/P03-W/P03-L/P04/P05); host composition, client and factory (H01–H03); core operations | a launched process is owned, observed, stopped and witnessed gone on both OSes |
| 2 | Host launch/stop, sessions, capture, mail (H04–H09); HTTP + one MCP consumer (H17–H19); CLI and MCP surfaces | Install and Adopt journeys pass on Linux with a stub-free product |
| 3 | Claude and Codex harnesses (H10–H12), SE Code integration (H13, with Gamma), supervision (H14), config install/remove (H20) | all five journeys pass on Linux and Windows with real Claude and Codex |
| 4 | Live handover (P06–P08, H15/H16, SE Code side); Atlas | B8 handover probe passes; Atlas index/query witnessed within its budgets |
| 5 | Release: native builds, Windows signing, bundle in SE Code, stateengine.ai staging | the five journeys pass from the real downloads on clean Windows and Linux |

macOS work (P03-M, P07-M, macOS release) waits for the Mac compatibility campaign.

## Proposed owners

| Owner | Work |
| --- | --- |
| 5p | se-proc |
| Nell | se-store |
| Vera | se-host |
| Iris | se-types, SE Code API, SE Code integration with Gamma |
| 5b, 5e | se-core and the `se` binary; 5e then Atlas |
| Milo | release and packaging |
| 5d | journey runner and per-wave journey witnesses |
| 5c, Otto, Opus (Prime) | reviews and the tests that judge each wave |

## What "done" means

The five scripted user journeys (Install, Adopt, Come back, Two agents, Remove) pass on clean
Windows and Linux with real Claude and Codex, inside section 80's budgets, from the real
release artifacts (Jimmy 2026-10-29). macOS follows in its own campaign.
