# StateEngine (Rust)

The StateEngine product, rebuilt in Rust. One `se` binary; library crates that SE Code links.
Plan: https://claude.ai/artifact/F82qoYRSPSaVZfXevnWU5D (ledger: rust-redesign-planned-before-rebuild-2026-10-30).

| Crate | Holds |
| --- | --- |
| se-types | IDs, errors with remedies, Read/Window types, host API types |
| se-store | SQLite event log, projections, migrations, backup and salvage |
| se-core | kernel operations and the operation registry (CLI + MCP generated from it) |
| se-proc | owned processes per OS; the only crate allowed `unsafe` |
| se-host | session tasks, batched writer, mail, Claude/Codex/SE Code integrations, MCP, listener |
| se-atlas | code-only index with its own database |
| se | the binary: CLI, hooks, doctor, import |

Dependency direction: se-types <- se-store <- se-core <- se-host <- se; se-proc depends on se-types only;
se-atlas depends on se-types and se-store. Authors write no tests; reviewers add black-box tests;
the five journey scripts are the acceptance judge. Line counts are estimates, never caps.
