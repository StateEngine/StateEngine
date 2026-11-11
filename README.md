# StateEngine

Run a coding assistant in your project, save its conversation, and pick up where you
left off. StateEngine launches **Claude Code** or **Codex**, records their work, and
lets assistants exchange project messages. The `se` command manages those assistants.

## Before you install

The first-agent workflow below is for **Linux x86_64** and **Windows x86_64**.
**macOS cannot run the background service or launch managed agents in this alpha**;
those commands refuse. macOS packages support installation and saved-state inspection,
but are not a working first-agent path. Native macOS qualification is still pending.

**Release download URL: not published yet; the publishing location is undecided.**
Until that is settled, obtain the unsigned archive and its checksum from the
maintainer. There is no public download command to copy here yet. Archive names use
`stateengine-VERSION-TARGET-unsigned` with these endings:

| Your machine | TARGET | Archive ending |
| --- | --- | --- |
| Linux, Intel/AMD 64-bit | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Windows, Intel/AMD 64-bit | `x86_64-pc-windows-msvc` | `.zip` |
| macOS, Apple silicon (limited as above) | `aarch64-apple-darwin` | `.tar.gz` |
| macOS, Intel (limited as above) | `x86_64-apple-darwin` | `.tar.gz` |

Install [Git](https://git-scm.com/downloads) and **one** provider before continuing.
Use the provider's official installation instructions for your OS:

- [Install Codex CLI](https://developers.openai.com/codex/cli/) (version 0.152.0 or newer),
  then run `codex login`, finish browser sign-in, and run `codex login status`.
- [Install Claude Code](https://code.claude.com/docs/en/setup), then run
  `claude auth login`, finish sign-in, and run `claude auth status`.

Continue only when your chosen provider reports that you are signed in. Run the
provider and StateEngine as the same OS user, on the same machine. An open sign-in
page is not a completed login. Provider access and billing belong to your provider
account; StateEngine does not supply a provider account.

## Your first agent

An **agent** is one saved coding assistant in a **project** (the folder containing
your work). A **state home** is the directory where StateEngine keeps its settings
and saved conversations; it is separate from your project. These commands assume
one default state home and a terminal you opened yourself.

### 1. Install and verify in this terminal

Put the archive and its adjacent `.sha256` file in the same folder, then open a
terminal there. Replace `VERSION` below with the downloaded version. A checksum
checks that the archive matches the supplied file; it does not authenticate an
unsigned release. Do not extract or install if verification fails.

**Linux:**

```sh
archive="stateengine-VERSION-x86_64-unknown-linux-gnu-unsigned.tar.gz"
sha256sum -c "$archive.sha256" && tar -xzf "$archive" && cd "${archive%.tar.gz}"
```

**Windows PowerShell:**

```powershell
$archive = "stateengine-VERSION-x86_64-pc-windows-msvc-unsigned.zip"
$expected = ((Get-Content -LiteralPath "$archive.sha256" -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or $actual -ne $expected) { throw "Archive checksum mismatch; do not install." }
Expand-Archive -LiteralPath $archive -DestinationPath . -ErrorAction Stop
Set-Location -LiteralPath ([IO.Path]::GetFileNameWithoutExtension($archive))
```

**macOS (installation and saved-state inspection only):**

Use `x86_64-apple-darwin` instead of `aarch64-apple-darwin` on Intel Macs.

```sh
archive="stateengine-VERSION-aarch64-apple-darwin-unsigned.tar.gz"
shasum -a 256 -c "$archive.sha256" && tar -xzf "$archive" && cd "${archive%.tar.gz}"
```

After a successful check and extraction, run the installer from that extracted
folder as your normal user. On macOS, `sh ./install.sh` installs the limited
package; do not continue to the managed-agent steps below.

**Linux, sh/bash/zsh:**

```sh
sh ./install.sh
export PATH="$HOME/.local/bin:$PATH"
se --version
```

The installer also prints a quoted absolute `se --version` command that works
immediately, even before changing PATH. PATH is the list of folders your terminal
searches for commands. The `export` above adds StateEngine for this terminal;
future login terminals load the installer's saved change. In **fish**, replace
that `export` line with `set -gx PATH "$HOME/.local/bin" $PATH`.

**Windows PowerShell:**

```powershell
.\install.ps1
$env:Path = "$env:LOCALAPPDATA\StateEngine\bin;$env:Path"
se --version
```

The installer prints an absolute PowerShell command that also works immediately.
A successful version check prints `stateengine` and a version number. If `se` is
not found, copy that exact printed command; do not continue with an unverified
installation. Keep the extracted archive for upgrades and removal.

### 2. Open your project and create an agent

Change into the folder you want the assistant to work in; replace the example path
with your own:

```sh
cd "/path/to/your/repo"
se init --provider codex
```

In PowerShell, for example, use `cd "C:\path\to\your\repo"`. If the folder is
not a Git repository yet, run `git init` there first. For Claude Code, use
`se init --provider claude` instead. Init registers the folder and creates the
saved agent named `main`; it does not change your repository files or Git history.
It ends by printing the exact first-launch command for your project and state home.

Default state homes are:

| OS | Default state home |
| --- | --- |
| Linux | `~/.local/state/stateengine` (or `$XDG_STATE_HOME/stateengine` when set) |
| Windows | `%LOCALAPPDATA%\StateEngine` |
| macOS | `~/Library/Application Support/StateEngine` |

Init prints the actual path. Use that path if you chose a custom home with
`--home` or `SE_HOME`; the default examples below will otherwise select a different
home. A permission profile is the saved set of rules for what the assistant may do.
For the default Codex profile, `workspace-write` allows edits in its permitted
workspace and scratch locations; `approval never` means no interactive requests
for tool approval; `network false` disables tool network access; and `bypass false`
keeps sandbox bypass disabled. These are provider tool permissions, not a provider
sign-in check. Init describes the selected provider's rules and how to edit a
named profile in the state home's `config.toml`; relaunch to apply changes.
`se config` changes saved agent settings, not permission profiles.

### 3. Give it a task

From the same project folder:

```sh
se launch main --task "Create a file called notes.md with one sentence describing what this repo is for." --detach
se status
se history --agent main
```

`--detach` runs the assistant in the background. **Running does not mean the task
has finished.** Read history again until there is an assistant reply, then open
`notes.md` and check its contents:

```sh
cat notes.md
```

In PowerShell, use `Get-Content .\notes.md`. Success means both a reply and the
requested file exist and the file says what you asked for. An empty message inbox
is normal: task replies go into conversation history, not project mail.

Status calls StateEngine's background service the **runtime**; its listener port
is its local connection address. `Not counted` and `not checked` mean that
information was not inspected, not proved empty or broken. An unknown code-index
status likewise does not establish that no index exists. An event identifies
a saved change; a request key lets a retry refer to that same change.

Launch may report `Containment: uncontained`. Containment is the OS process
boundary used to track and stop an agent's jobs; uncontained means the OS did
not supply that boundary. It does not mean provider sandbox permissions were
bypassed.

If there is no assistant reply or file, run `se agent show main`, read
`se history --agent main` for errors, and recheck `codex login status` or
`claude auth status` before moving on. Finish sign-in if it is still pending.
To retry after correcting the cause, stop the agent with `se stop main` and
repeat the task launch above.

Before the first conversation turn is saved, status can say that no conversation
cursor is established yet. That means there is nothing saved to reopen yet;
keep the current agent running and read its history after it replies. It does
not establish that the task failed or succeeded.

### 4. Stop and come back

```sh
se stop main
se launch main --detach
```

The second command reopens the saved provider conversation. Stop prints the exact
resume command for the selected home and project; use it if yours differ from
these defaults. A session is one running instance of a saved agent. If launch
refuses because the old session or its jobs (processes it started) are still
running, launch shows the sessions and managed jobs it would stop. An interactive
owner terminal asks for confirmation; scripts and agents must supply `--force`.
Force closes the selected old scopes before starting one replacement and preserves
captured history. Repeating the same request key rejoins that replacement.
`--override-live` remains an alias; neither option is needed for ordinary stop and
reopen. An embedded SE Code binding retires only that engine binding and reports
that jobs in its externally owned service were not stopped.

Decision-ledger commands are retired. Previously stored events remain readable
through `se history`; retirement does not delete their recorded payloads.

To inspect saved context without restarting or marking messages read:

```sh
se resume --preview main
```

This is an **owner preview**: you, the current OS user, read the agent's saved
information. A snapshot is what was available at that read. Working state is a
saved note about ongoing work. A cursor is a bookmark for later reads: copy the full
`Continue` command printed by your run rather than inventing one.
**Saved context available (JSON `ready`) and context complete describe this read
only; provider sign-in and task completion are not checked.** Missing information, unreadable sources and clipped
results are reported separately with follow-up commands.

### 5. Finish for now

```sh
se down
```

This stops StateEngine's background service and its active agents while retaining
saved work. The next launch starts the service again.

## Optional protocol agents

An ACP agent is a separately installed assistant that speaks Agent Client Protocol
version 1 over standard input and output. Configure its executable and arguments
in your state home's `config.toml`; StateEngine does not run a shell to interpret
those arguments. The agent must support authenticated HTTP MCP connections. Resuming also requires
loading saved sessions; agents without that capability can start with `--new`. Sign in and select a model using that agent's own setup.

**This harness provides no execution sandbox in protocol mode.** It requires an
explicitly named profile with `bypass = true` and `network = true`; choose it only
for work where you accept unsandboxed execution with network access. The saved
`approval = "never"` setting allows protocol
permission requests. Other approval settings refuse each such tool request with
a reason: a human approval interface is not implemented yet. A provider's own
rules still apply; a protocol mode does not establish OS containment or sandboxing.

After installing and configuring a protocol agent, add these sections to the
existing configuration. Replace `protocol-agent` with its native executable and
replace `YOUR_MODEL` with your configured model. Use the agent's documented
protocol arguments in `acp.arguments`:

```toml
[providers.acp]
command = "protocol-agent"
model = "YOUR_MODEL"
profile = "protocol-work"

[profiles.protocol-work]
bypass = true
network = true
approval = "never"

[acp]
arguments = ["--acp", "--model", "{model}"]
```

`{model}` expands only the saved model inside each argument. If you set
`acp.mode`, it must match the mode the agent reports before receiving work.
Omit it to use the agent's announced default, including agents without modes.
For a script, including a package-manager script launcher on Windows, select its
native interpreter as `command` and put the script's absolute path first in
`arguments`. StateEngine does not execute `.cmd`, `.ps1` or shell shims as native
images. If the provider needs additional environment
variables, list their names in `acp.environment`; keep account credentials in the
provider's own configuration.

```sh
se init --provider acp
se launch main --task "Read the README and explain what this project does." --detach
se agent show main
se history --agent main
se stop main
se launch main --detach
```

Launch and status disclose the unsandboxed policy. Status shows current activity
and any permission refusal; streamed text is explicitly provisional until the
completed turn appears in saved history. Resume loads the same conversation and
compares its complete text with captured history before offering new input. A
missing, changed, erased or oversized history refuses resume instead of silently
starting over. If capture was disabled, use `--new` for a new conversation.

## Help, upgrade and removal

Run `se --help`, then a command's own help, such as `se launch --help` or
`se history --help`, for the commands implemented by your installed version.
For workflow guidance, run `se guide` to list short topics, then `se guide TOPIC`
to read just one. Agents use `stateengine_help` with no topic for the same index,
or with `topic` set to one exact name. The CLI guide works before project setup
and without a running host.
[OPS](docs/OPS.md) describes the operation design; some listed paths are not shipped.

For one default Linux installation, stop its service and remove the installed
program from a terminal you opened yourself:

```sh
se down
se --home "$HOME/.local/state/stateengine" uninstall
```

If you set `XDG_STATE_HOME`, use `"$XDG_STATE_HOME/stateengine"` instead. On Windows,
run `se down`, then the old extracted archive's `uninstall.ps1` in PowerShell and
wait for its final successful completion. The installation home is the directory
containing `standalone-install.json`; it is the path selected during installation,
which may differ from a custom data home used later. Removal keeps history,
conversations, identity, credentials, configuration and repository files.

To upgrade, first run `se --home HOME down` for every running data home. As the
same OS owner, run the current release archive's `install.sh` on Linux/macOS or
`install.ps1` on Windows. For a custom installation data home, set `SE_HOME` to
its original absolute path before running the installer. The installer can
replace a stopped installation whose recorded files and native ownership still
match, preserving history, conversations, identity, credentials, configuration
and repository files. A live runtime or changed/foreign installation files cause
a refusal with its reason; resolve that refusal before retrying. After successful
installation, run `se --home HOME up` for each home.

Older binaries refuse data written with a newer unsupported schema. If trying an
older release leaves it unable to start or uninstall, run the current archive's
installer again with the same installation data home; recovery does not require
the older binary to open or alter the newer data. Ordinary compatible uninstall
followed by installation remains an option: in your own terminal, run the installed
`se --home INSTALL_HOME uninstall`, or on Windows the matching old release
archive's `uninstall.ps1`, and wait for successful completion before installing.
Use each home's original path throughout; an old Windows host keeps the pipe name
chosen by its executable until restarted.

## Connect to another machine

From your own terminal, use an SSH destination that already works with your
normal SSH configuration and host-key verification:

```sh
se remote add my-server --name build
se remote list --host build
se remote watch --host build --target PROJECT_ID/AGENT_ID
```

The first command stages the matching native executable and starts or reuses
your remote host. A compatible running host and its agents keep running.
If the saved host has shut down while idle, the next remote operation starts
it again over SSH and waits for that cold startup.
Use the project, agent and current session IDs from `remote list` when sending:

```sh
se remote send --host build --target PROJECT_ID/AGENT_ID --session SESSION_ID --key request-1 "Check the failing test"
```

Reuse the same key and request when retrying an uncertain send. Launched agents
use the configured MCP remote tools, which preserve their own sending identity.
Agent sandboxes keep their existing permissions; a sandboxed CLI that cannot
prove native ownership directs the agent to MCP.

`se remote disconnect --name build` closes the connection while the remote
host and agents continue. Run `remote add` again to reconnect. `remote forget
--name build` also removes the saved local connection. Neither command stops
remote work. Ordinary return-mail routing and independent agent revocation
are planned separately.

Attach, pending echo, live output and reconnect timings are not yet measured.

## Optional migration from the older Node implementation

New users can skip this section. `se import` is only present in builds compiled with the opt-in `import` cargo feature (off by default); `se import --help` lists the migration options.
For source-owner selection, read `owner_human_id` in the retained source copy's
`.stateengine/projects.jsonl` and match it to `human_id` in
`.stateengine/humans.jsonl`; a display name is not an identity. Target human IDs
must already be registered in the target project. Run
`se --json history --kind principal.registered` in that project; for a human entry,
`payload.principal.kind` is `owner` or `human`, and `payload.principal.id` is the ID
to use. Follow returned page cursors if needed; `se history --help` describes
paging. Do not create or guess IDs to make an import pass.

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

## Optional code navigation (Atlas)

Atlas is the optional code index. Its background indexer currently runs on Linux.
It is enabled by default. If you disabled it, edit the `config.toml` in the data home printed by `se status` (or
the file selected by `SE_CONFIG`), set `enabled = true` in `[atlas]`, then run
`se down` and `se up` with the same `--home` you normally use. `se config set`
changes saved agent settings only. Run `se atlas` for find, references, impact,
changes and outline commands; `se status` reports preparation and partial coverage.
Answers are compact pointers: a line range and byte count show how much source a
target contains before you read it. JSON retains the full span and byte offsets.
Unverified or unavailable extents say `size unavailable`; stale revisions stay labelled.

## Assistant tool arguments

Managed Claude and Codex sessions discover the same compact MCP tool catalogue.
It advertises argument shapes, required fields, enums and defaults; the runtime
still checks complete value grammars, bounds and permissions. For full input and
output schemas, run `se schema OP`, for example `se schema message.send` or
`se schema atlas.refs`. The [operation reference](docs/OPS.md) lists operation names.

- Omit `agent_id` and `project_id` in a managed session. If supplied, they must
  match its authenticated caller; they never select another caller. Use
  `target_agent_id` only where advertised to select a controlled agent.
- Copy IDs and opaque cursors from results rather than constructing them. For a
  mutation, retain its `idempotency_key`; retry an uncertain result with the same
  arguments and key. Remote mail also pins the same target and expected session.
  A committed message is not evidence of delivery, reading or task completion.
- Direct messages use `to`; floor messages additionally require `work.action`
  and explicit `work.addressees`. `quiet` leaves mail unread but suppresses its
  notification. Listing or resuming does not mark messages read; reading and
  acknowledging do, while dismissal does not.
- `working_state_set.expect` is the revision just read, or `absent` on first
  write. Launch normally resumes the saved conversation; `new` starts another.
  `force` explicitly consents to stopping the existing lifecycle and jobs.
- Atlas targets retain their tagged JSON shape, such as
  `{"Symbol":{"Name":{"name":"authenticate"}}}` or `{"File":"src/auth.rs"}`.
  Its `root` selects a registered worktree, and `regex` searches live source with
  a case-sensitive expression (`(?i)` ignores case). Remote watch's `measure`
  reports producer age at release, not a guaranteed delivery-latency bound.

## For developers

The Rust workspace provides one `se` binary and libraries linked by the SE Code
application. The [operation reference](docs/OPS.md) describes the command surface.

To build an unsigned archive from a clean, committed source checkout, install Git,
Python 3.11+, and rustup with the toolchain pinned in `rust-toolchain.toml`
(currently Rust 1.97.1, including rust-docs). Use a native machine matching the target:
Linux needs a C compiler/linker and binutils; Windows needs Visual Studio Build
Tools with the MSVC C++ workload and Windows SDK; macOS needs Xcode Command Line
Tools and has the runtime limits stated above. SQLite's C source is bundled;
Node.js is not needed by the installed product. The build downloads lockfile-pinned
Cargo inputs unless `--offline` is selected with an already populated cache.

For example, on Linux x86_64, choose new output paths outside the source tree:

```sh
rustup component add rust-docs
python3 scripts/release/build.py --target x86_64-unknown-linux-gnu --out /absolute/path/new-build
python3 scripts/release/assemble.py --build /absolute/path/new-build \
  --remote-build /absolute/path/windows-build \
  --remote-build /absolute/path/macos-arm-build \
  --remote-build /absolute/path/macos-intel-build \
  --out /absolute/path/new-archive
```

The release builder removes symbol tables and debug sections with the pinned
compiler's `rust-objcopy`, then checks the resulting executable and hashes those
final bytes. Linux keeps a separate `.debug` file; an emitted Windows PDB is
retained when available. Assembly writes retained diagnostics beside the archive
in its `.symbols` directory, bound to the source commit and executable hash.
These files stay out of the installer payload. macOS archives are stripped too;
a separate native symbol bundle is not produced by this build.

Build each companion on its matching native platform from the same commit and
release inputs. Remote-enabled archives include every supported destination's
executable and notices; assembly refuses missing or mismatched companion builds.
Use the matching target from the platform table for other native builds. Building
or cross-checking a target does not qualify its runtime behavior on that OS.
