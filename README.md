# StateEngine (Rust)

The StateEngine product, rebuilt in Rust. One `se` binary; library crates that SE Code links.
Plan: https://claude.ai/artifact/F82qoYRSPSaVZfXevnWU5D (ledger: rust-redesign-planned-before-rebuild-2026-10-30).

## Your first agent

StateEngine is one command, `se`. A **home** is its data directory (Linux default
`~/.local/state/stateengine`; macOS/Windows differ); a **project** is a folder it tracks,
usually a git repo; an **agent** is one saved coding assistant (Claude Code or Codex) in a
project; the **floor** is the append-only message log between you and your agents.

1. Install the release: extract the release archive for your platform and, from the
   extracted folder, run `sh ./install.sh` (Linux, macOS) or `install.ps1` (Windows),
   or build one from this tree on the target platform with `python3
   scripts/release/build.py --target <target> --out <new-dir>` and `python3
   scripts/release/assemble.py --build <new-dir> --out <archive-dir>`. Verify:

       $ se --version
       stateengine 0.0.1

2. First install and log in to the agent you will use: a Codex agent needs the Codex CLI
   (0.152.0 or newer) and `codex login`; the default Claude Code is installed and logged
   in the same way. Then, in an existing git repo, register the project and create your
   first agent. `--provider codex` makes it a Codex agent.

       $ se init --provider codex
       Project repo registered at /path/to/repo
       State home: /home/you/.local/state/stateengine
       Agent main uses Codex
       Permission profile default: workspace-write, approval on-request, network false, bypass false
         registered the home owner / registered the project / registered the project owner
         created the initial saved agent / persisted the initial listener port
       Launch your first agent: se --home /home/you/.local/state/stateengine --project prj_... launch ag_... --detach

   `State home` above is the Linux default; macOS: `~/Library/Application Support/StateEngine`,
   Windows: `%LOCALAPPDATA%\StateEngine`. The profile line says what the agent may do; init
   prints the exact `se config set` command (run it in your own terminal) to change it.

3. Launch the agent headless with a one-line task:

       $ se launch main --task "Create a file called notes.md with one sentence describing what this repo is for." --detach
       Agent main: running (Codex, headless)

4. Check on it:

       $ se status
       Project: repo (/path/to/repo)
       Runtime: running
         main: running — unread 0

5. Read what it did: a plain task launch reports in its conversation and in your folder, not by floor mail:

       $ se msg list
       Unread messages: 0
       $ se history --agent main
       session.turn — repo
         text: Created [notes.md](/path/to/repo/notes.md) with: "This repository is a small demo for the StateEngine quickstart."

6. Resume it: `se resume --preview AGENT` reads the saved context without restarting
   the agent; `se stop AGENT` ends a running session; `se launch AGENT --detach`
   restarts the same saved conversation.

       $ se resume --preview main
       Who am I?
       main in repo — ready (owner preview; nothing acknowledged)
       $ se stop main
       Stop agent: stopped (complete: true)
       Resume ready: se --home /home/you/.local/state/stateengine --project prj_... launch ag_... --detach

7. When you are done, stop the runtime; the next launch starts it again.

       $ se down
       Runtime stop complete
         witnessed via authenticated shutdown stages and outside native completion readback: Achieved: [AgentsStopped, ResumeSaved, WriterJoined, CaptureFlushed, DebtFlushed, ResourcesClosed, LeaseReleased]

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

Before upgrading, run `se down` for each running data home (use the same `--home`
as its host), then install the new release and run `se up`. An existing Windows
host keeps the pipe name chosen by its original executable until restarted.

To import existing Node user history, first preserve a source copy containing its
`.stateengine/projects.jsonl`, named project history, and saved profiles. Initialize
a Rust data home with `se init`, then run `se import --from-node PATH` as its owner.
The source must have a single human matching the importing owner. For a different
source owner or multiple historical humans, pass `--source-owner <human_id>` to
explicitly adopt that source owner; copies containing projects from other owners
are refused. Historical humans keep their recorded IDs and display names as project
members, without becoming owners of the Rust data home. To explicitly associate a
source human with an existing target human, repeat `--map-human SOURCE_ID=TARGET_ID`.
The target must already be registered in each imported project; explicit mapping onto
the importing owner is also supported, because adoption registers that owner there.
Missing targets are refused before adopting an import run. The source ID and name remain in history, and
names alone never imply a correspondence. Changing a correspondence after importing
that human is refused; use a fresh target data home for a different mapping.
The command keeps source files intact and reports imported, duplicate, unreadable,
excluded and deferred source rows (individual entries for profile documents). Retry the same retained copy to continue committed
progress. A malformed final row is recorded as unreadable; preserve a repaired
export as a separate copy rather than rewriting its consumed prefix. `--json` returns the accounted receipt. An already registered root must be
released explicitly before its historical project ID can adopt it. `se init` only
offers this import; it never starts one automatically. Historical humans with colliding display names keep distinct IDs. The lowest source ID keeps the plain name; other IDs receive a stable ` (historical ID-SUFFIX)` suffix derived from their exact ID. Source row order does not change these names. The original name remains in provenance with a counted import note.

Imported agents without a usable saved profile adopt the current owner's safe default
provider profile after source configuration is processed. This is current configuration,
not a claim about their historical provider or permissions. Floor broadcasts and messages
with floor or unmapped human senders retain their recorded sender, audience and text in history;
replies and replacements referencing retained mail keep their recorded links without native message identities;
they do not create a sender identity or a new native recipient-read fact.

Imported conversations remain ended. Saved Claude and Codex references are retained
in history only; launching an imported agent starts a fresh conversation. Missing
or unsupported references are reported explicitly. Provider
account files, credentials, running processes and factory authority are not imported.
