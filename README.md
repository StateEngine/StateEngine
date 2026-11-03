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

To import existing Node user history, first preserve a source copy containing its
`.stateengine/projects.jsonl`, named project history, and saved profiles. Initialize
a Rust data home with `se init`, then run `se import --from-node PATH` as its owner.
The source must have a single human matching the importing owner. For a different
source owner or multiple historical humans, pass `--source-owner <human_id>` to
explicitly adopt that source owner; copies containing projects from other owners
are refused. Historical actors retain their original IDs.
The command keeps source files intact and reports imported, duplicate, unreadable,
excluded and deferred source rows (individual entries for profile documents). Retry the same retained copy to continue committed
progress. A malformed final row is recorded as unreadable; preserve a repaired
export as a separate copy rather than rewriting its consumed prefix. `--json` returns the accounted receipt. An already registered root must be
released explicitly before its historical project ID can adopt it. `se init` only
offers this import; it never starts one automatically.

Imported agents without a usable saved profile adopt the current owner's safe default
provider profile after source configuration is processed. This is current configuration,
not a claim about their historical provider or permissions. Floor broadcasts and messages
with floor or unmapped human senders retain their recorded sender, audience and text in history;
they do not create a sender identity or a new native recipient-read fact.

Imported conversations remain ended. Saved Claude and Codex references are retained
in history only; launching an imported agent starts a fresh conversation. Missing
or unsupported references are reported explicitly. Provider
account files, credentials, running processes and factory authority are not imported.
