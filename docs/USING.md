# Using StateEngine

This guide expands the README quickstart: what each step reports, how to tell a
finished task from a running one, and how adoption, Atlas and the MCP tools behave.

## Words StateEngine uses

- An **agent** is one saved coding assistant in a **project**, the folder containing
  your work. A **session** is one running instance of a saved agent.
- The **state home** is the directory where StateEngine keeps its settings and saved
  conversations, separate from your project. See
  [INSTALL.md](INSTALL.md#state-homes) for default locations.
- The **runtime** is StateEngine's background service. Its listener port is its
  local connection address.
- An **event** identifies a saved change; a **request key** lets a retry refer to that
  same change.
- A **cursor** is a bookmark for later reads. Copy the full `Continue` command a run
  prints rather than constructing one.

## Your first agent, step by step

### 1. Register the project

```sh
cd "/path/to/your/repo"
se init --provider codex          # or --provider claude
```

In PowerShell, for example, use `cd "C:\path\to\your\repo"`. If the folder is not a
Git repository yet, run `git init` there first. Init registers the folder and creates
the saved agent named `main`. It writes no files into your working tree and does not
change Git history; it records the project's identity in `.git/stateengine/` so the
project can be found again if the folder moves. It ends by printing the exact
first-launch command for your project and state home. If you chose a custom home with
`--home` or `SE_HOME`, keep using it, because the default commands select a different
home. Init also prints the permission profile it saved; see
[HARNESSES.md](HARNESSES.md#permission-profiles).

### 2. Give it a task

From the same project folder:

```sh
se launch main --task "Create a file called notes.md with one sentence describing what this repo is for." --detach
se status
se history --agent main
```

`--detach` runs the assistant in the background. **Running does not mean the task has
finished.** Read history again until there is an assistant reply, then open `notes.md`
(`cat notes.md`, or `Get-Content .\notes.md` in PowerShell) and check its contents.
Success means both a reply and the requested file exist and the file says what you
asked for. An empty message inbox is normal: task replies go into conversation
history, not project mail.

If there is no assistant reply or file, run `se agent show main`, read
`se history --agent main` for errors, and recheck `codex login status` or
`claude auth status`. Finish sign-in if it is still pending. To retry after correcting
the cause, stop the agent with `se stop main` and repeat the launch.

### 3. Read what status reports

`Not counted` and `not checked` mean that information was not inspected, not that it
was proved empty or broken. An unknown code-index status likewise does not establish
that no index exists.

Launch may report `Containment: uncontained`. Containment is the OS process boundary
used to track and stop an agent's jobs; uncontained means the OS did not supply that
boundary. It does not mean provider sandbox permissions were bypassed.

Before the first conversation turn is saved, status can say that no conversation
cursor is established yet. That means there is nothing saved to reopen yet: keep the
agent running and read its history after it replies. It does not establish that the
task failed or succeeded.

### 4. Stop and come back

```sh
se stop main
se launch main --resume --detach
```

The second command reopens the saved provider conversation. Stop prints the exact
resume command for the selected home and project; use it if yours differ from these
defaults. `--resume SESSION` selects a specific saved session.

If launch refuses because the old session or its jobs (processes it started) are still
running, launch shows the sessions and managed jobs it would stop. An interactive owner
terminal asks for confirmation; scripts and agents must supply `--force`, which is not
needed for an ordinary stop and reopen. See [Reference](#reference) for the details.

### 5. Inspect saved context

```sh
se resume --preview main
```

This is an **owner preview**: you, the current OS user, read the agent's saved
context without restarting it or marking messages read. A snapshot is what was
available at that read. Working state is a saved note about ongoing work
(`se working-state`). **Saved context available (JSON `ready`) and context complete
describe this read only; provider sign-in and task completion are not checked.**
Missing information, unreadable sources and clipped results are reported separately
with follow-up commands.

### 6. Finish for now

```sh
se down
```

This stops the runtime and its active agents while keeping saved work. The next launch
starts the runtime again.

## Adopting sessions you start yourself

On Linux and Windows, capture sessions you start directly in a provider with
`se init --adopt --provider claude` (Claude Code 2.1.295 or newer) or
`se init --adopt --provider codex` (Codex 0.166.0 or newer).

StateEngine adds its hooks to the provider's user settings and preserves existing
hooks, models, permissions and settings text. Codex adoption installs its hooks in
`config.toml` and trusts only those exact definitions through the provider's discovery
hashes. For Claude, review and trust the new hooks in the provider's own prompt.
Status keeps capture and mail unconfirmed until an authenticated hook runs.
Running `se init --adopt` again on an existing adoption preserves any edits or
removals you made to hooks StateEngine already installed, and adds newly
introduced hooks (such as the Atlas context hook) when enabled. If the provider
settings file is unreadable or malformed, setup refuses without changing it.

Only explicitly registered project roots participate. Adopted sessions appear with the
`observed` surface in status. Incoming mail uses the provider's native wake or input
queue; an offer is not a recipient read receipt. StateEngine does not own or stop these
user-started processes. Uninstall removes unchanged integration entries, preserves
later user edits and revokes project adoption.

## Atlas code navigation

Atlas is the code index. Its background indexer runs on Linux, Windows and macOS and
is enabled by default. If you disabled it, edit the `config.toml` in the data home
printed by `se status` (or the file selected by `SE_CONFIG`), set `enabled = true` in
`[atlas]`, then run `se down` and `se up` with the same `--home` you normally use.
`se config set` changes saved agent settings only.

Agents get two Atlas tools. `stateengine_atlas_inspect` takes one target before an
edit and returns, in one call, the defining file's declarations, callers and other
references, dependents within two hops with possible covering tests and linked
records, and edits Atlas observed to that file in the last seven days. Each section
keeps its own coverage and continuation. `stateengine_atlas_find` locates code, text,
recent edits and messages by query. From a shell, `se atlas inspect TARGET` and
`se atlas find QUERY` are the same calls; `se atlas outline`, `refs`, `impact` and
`changes` page one section further. They start the host if it is not running, and
`se status` reports preparation and partial coverage. `se atlas changes` takes
`--since` with a duration (`10m`), an ISO UTC time, a commit SHA, a cursor or Unix
milliseconds.
Answers are compact pointers: a line range and byte count show how much source a target
contains before you read it. JSON retains the full span and byte offsets. An extent
that was not measured shows no byte count; stale revisions stay labelled.

An agent's resume and its first-turn context carry a small orientation: the largest
areas of the indexed tree, the files most others import with their first declarations,
and the open assignments the agent holds. It fits in the space the packet has left, says
when the index is not ready or not current, and is left out rather than delaying the
resume. `se resume` in an agent session shows it when a host is running.

Launched agents are told to inspect a file or symbol with Atlas before editing it. With `hooks = true`
in `[atlas]` (the default), managed Claude Code and Codex sessions, and sessions first
adopted with `se init --adopt`, run a hook before a search or single-file read. When
Atlas has a confident answer for that lookup, the agent receives a few lines of indexed
context first. ACP protocol agents don't get this hook; re-run `se init --adopt`
on an existing adoption to add it. A hook with no confident answer within its deadline
(75 ms, or 100 ms on Windows) adds nothing and never blocks the tool call. Set
`hooks = false` to turn this off.

## Messages, captain and assignments

Direct messages go to one agent. A `question`, `blocker` or `done` message with no
recipient goes to the project's current captain (`se captain set`, shown by
`se captain show`). Project work is recorded with `se assignment write`, whose
`--action` is `open`, `accept`, `done`, `block` or `hand-back`, and listed with
`se assignment list`. Listing or resuming does not mark messages read; reading and
acknowledging do, while dismissal does not. A committed message is not evidence of
delivery, reading or task completion.

## MCP tool arguments

Managed Claude and Codex sessions discover the same compact MCP tool catalogue. It
advertises argument shapes, required fields, enums and defaults; the runtime still
checks complete value grammars, bounds and permissions. For full input and output
schemas, run `se schema OP --json`, for example `se schema message.send --json` or `se
schema atlas.inspect --json`; without `--json` it prints only the operation names. The
[operation reference](OPS.md) lists operation names.

- Omit `agent_id` and `project_id` in a managed session. If supplied, they must match
  its authenticated caller; they never select another caller. Use `target_agent_id`
  only where advertised to select a controlled agent.
- Copy IDs and opaque cursors from results rather than constructing them. For a
  mutation, retain its `idempotency_key`; retry an uncertain result with the same
  arguments and key. Remote mail also pins the same target and expected session.
- Direct messages use `to`; floor messages additionally require `work.action` and
  explicit `work.addressees`. `quiet` leaves mail unread but suppresses its
  notification.
- `working_state_set.expect` is the revision just read, or `absent` on first write.
  Launch starts fresh with StateEngine context. `resume: true` reopens the latest saved
  provider conversation; `resume: "session-id"` selects a saved session. `force`
  explicitly consents to stopping the existing lifecycle and jobs.
- An Atlas `target` is a plain path, `path:line` or symbol name, such as
  `"src/auth.rs"` or `"authenticate"`. The tagged forms
  `{"Symbol":{"Name":{"name":"authenticate"}}}` and `{"File":"src/auth.rs"}` narrow a
  symbol or force a file. Its `root` selects a registered worktree, and `regex` searches live source with a
  case-sensitive expression (`(?i)` ignores case). Remote watch's `measure` reports
  producer age at release, not a guaranteed delivery-latency bound.

## Getting help

Run `se --help`, then a command's own help, such as `se launch --help` or
`se history --help`, for the commands implemented by your installed version. For
workflow guidance, run `se guide` to list short topics, then `se guide TOPIC` to read
one. Agents use `stateengine_help` with no topic for the same index, or with `topic`
set to one exact name. The CLI guide works before project setup and without a running
host. `se doctor` checks an installation and names exact supported repairs, and
`se diagnostic-bundle` saves a private redacted file to share for support.

The [operation reference](OPS.md) describes the operation design; some listed paths
are not shipped.

## Reference

- **Forced relaunch.** `--force` closes the selected old scopes before starting one
  replacement and preserves captured history. Repeating the same request key rejoins
  that replacement. `--override-live` remains an alias for `--force`.
- **SE Code bindings.** Stopping an embedded SE Code binding retires only that engine
  binding and reports that jobs in its externally owned service were not stopped.
- **Decision ledger.** Decision-ledger commands are retired. Previously stored events
  remain readable through `se history`; retirement does not delete their recorded
  payloads.
- **Linked worktrees.** `se worktree remove PATH` safely removes a linked Git worktree
  after checking for symlinks, junctions and unreadable entries (use `--force` to remove
  a dirty worktree after those safety checks pass).
- **External seats.** To let an external MCP client join a project without StateEngine
  launching its process, register the agent with `se agent add NAME --external`, connect
  the client through `se mcp --as NAME`, and approve the printed claim out of band with
  Owner authority outside any StateEngine-managed agent tree (a human terminal or your own
  standalone agent; StateEngine child seats are refused) using `se external list` and
  `se external approve CLAIM_ID`. Revoke at any time with `se external revoke NAME`.
  Destructive operations (`forget`, `restore`, `remove`, `uninstall` without `--yes`, and
  `doctor --fix`) still require a human terminal. External seats enforce per-agent exclusivity against
  managed launches, expire after 8 hours or on bridge disconnect/host restart, and use
  `se msg wait [--as NAME] [--after CURSOR] [--timeout SECS]` for zero-polling blocking
  mail waits on a separate CLI channel (keeping MCP stdio pipes non-blocking). A runner
  that drives the client reports turns with `se msg activity busy|idle --as NAME` so waits
  never wake a busy agent; see [Waking external agents](HARNESSES.md#waking-external-agents). Run
  `se guide external-seats` for the full walkthrough.
- **Published turns.** A harness that runs its own conversations can record each completed
  turn with the `stateengine_session_publish_turn` tool, or from an Owner terminal with
  `se session publish-turn TURN_JSON --key KEY`: a summary, reported token usage, diff
  counts and a decision. A session publishes only its own turns. History shows them,
  `se status` uses the reported usage of the latest turn for context fill until a live
  runtime reports its own, and `se atlas find --kind turn` and `se atlas inspect` show a
  turn's decision and changed paths. `se forget --event ID` erases the summary, decision,
  paths and content digest, and removes the turn from Atlas, while keeping the counts.
