# StateEngine

> **Experimental pre-alpha.** StateEngine is in early development and is not recommended
> for real work yet. Commands, saved data and behaviour can change without notice or a
> migration path, and some flows are unfinished. Try it only on projects you have backed up.

Run a coding assistant in your project, save its conversation, and pick up where you
left off. StateEngine launches **Claude Code** or **Codex**, records their work, and
lets assistants exchange project messages. The `se` command manages those assistants.

## Before you install

The first-agent workflow below is for **Linux x86_64** and **Windows x86_64**.
**macOS cannot run the background service or launch managed agents in this pre-alpha**;
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

On Linux and Windows, capture sessions you start directly with
`se init --adopt --provider claude` for Claude Code 2.1.295 or newer, or
`se init --adopt --provider codex` for Codex 0.166.0 or newer. StateEngine adds
its hooks to the provider's user settings and preserves existing hooks, models,
permissions and settings text. Codex adoption installs its hooks in `config.toml`
and trusts only those exact definitions through the provider's discovery hashes.
Status keeps capture and mail unconfirmed until an authenticated hook runs.
For Claude, review and trust the new hooks in the provider's own prompt.
Only explicitly registered project roots participate. Adopted sessions appear
with the `observed` surface in status. Incoming mail uses the provider's native
wake or input queue; an offer is not a recipient read receipt. StateEngine does
not own or stop these user-started processes. Uninstall removes unchanged
integration entries, preserves later user edits and revokes project adoption.

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

The native agent owns its permissions and sandboxing. StateEngine does not add
an execution sandbox or network restriction to the protocol. Choose the agent's
native permission level explicitly. The saved `approval = "never"` setting allows
protocol permission requests; other approval settings refuse them with a reason
because a headless approval interface is not implemented yet. A protocol mode or
saved StateEngine profile does not establish OS containment.

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

Launch and status disclose that the native agent owns its policy. Status shows current activity
and any permission refusal; streamed text is explicitly provisional until the
completed turn appears in saved history. Resume loads the same conversation and
compares its complete text with captured history before offering new input. A
missing, changed, erased or oversized history refuses resume instead of silently
starting over. If capture was disabled, use `--new` for a new conversation.

### Named harness descriptors

Several installed protocol agents can share the same adapter. Give each one a
named entry in `config.toml`, with an explicit mapping for every launch profile
it uses. This example maps `protocol-work` to the agent's announced native mode;
replace the command and arguments with the installed agent's documented values:

```toml
[harnesses.my-agent]
driver = "acp-stdio"
command = "protocol-agent"
arguments = ["--acp", "--model", "{model}"]
environment = []

[harnesses.my-agent.permissions.protocol-work]
arguments = []
mode = ""
```

Use `se init --harness my-agent`, or `se agent add helper --harness my-agent`.
Selecting a harness implies the ACP provider; a conflicting explicit provider
refuses. The `[providers.acp].profile` setting selects an existing launch
profile, such as `protocol-work` above. Permission entries can supply additional native
arguments, native mode environment values in `environment`, and an expected
`mode` that the agent must report before work starts. They do not override
capabilities reported by the running agent.

Descriptor `environment` lists inherited variable names, never account secrets.
For a model selected through a native environment variable, set
`model_environment = "NATIVE_MODEL_VARIABLE"` instead of an argv `{model}` slot.
The saved agent retains its harness selection across configuration default
changes and resumes. Existing agents without a saved selection keep the legacy
`[providers.acp]` and `[acp]` configuration. Restore a missing descriptor before
launching its saved agents; there is no fallback to a different agent.
Descriptor-bound profiles use event schema version 2, so older binaries refuse
them instead of losing the saved selection.

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

For unattended removal, add `--yes` to `se uninstall`. This confirms removal
without a terminal; OS ownership, managed-session and agent ancestry checks still
apply. Retained history and provider login remain preserved.

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

Remote launch requires a separate Owner decision. At the end of pairing choose
**launch**, or run `se remote permissions --name build --launch` in a terminal.
Choose an existing destination agent and allow or revoke future launches. The
review shows its saved provider and permission profile. Existing machine grants
keep their list, watch and send verbs; they do not gain launch permission.

A launched lead can call `stateengine_remote_launch`, and the CLI uses
`se remote launch --host build --target PROJECT/AGENT --key start-1` with IDs
from remote list. The destination starts that agent headlessly with its saved
profile and conversation. It does not create an identity, override its model,
or stop existing work. A start receipt confirms the original launch; replaying it does not claim the
agent is still running. Use its returned session for remote send, which refuses
a stopped or replaced session. A pending launch retains its key; repeat the same launch
with that key to observe its result. Revoking launch consent blocks future
reservations; already admitted launches and running agents continue.

The Linux nightly includes a separate remote journey over real SSH: connect,
launch on the destination, observe live assistant output, exchange a message,
and reconnect to the original session. Its reports retain attach, pending echo,
live output and reconnect samples with their measurement boundaries. Live output
uses an explicitly unqualified monotonic clock estimate across the connection;
these samples do not certify a latency budget or a physical network topology.
Windows source/destination coverage and hands-on qualification remain separate.

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
Tools and has the runtime limits stated above. SQLite's C source is bundled.
The build downloads lockfile-pinned
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

To bundle the native runtime inside another application's package, add
`--payload-out /absolute/path/new-payload` to the assembly command. This publishes
the same verified executable, build receipt and original license and notice
bytes, with an exact file inventory in `native-payload.json`. The assembly result
reports the manifest digest, version and source commit for the consumer's pin.
The directory includes remote bootstrap images when the archive does. The consumer remains responsible for exercising its installed
launcher on each native platform.
The payload output path must be absolute and new. Assembly prepares the archive,
checksum, payload and diagnostics before publishing their final paths; a refused
publication rolls back its newly published paths so the same command can retry.

## License and contributions

The Rust workspace is licensed under the [GNU Affero General Public License, version 3 only](LICENSE).
Third-party components retain their own licenses.

Outside pull requests require a signed [contributor agreement](CONTRIBUTING.md) before merge.
The agreement preserves your ownership and permits StateEngine LLC to offer your contribution
under additional licenses while continuing to offer it under the submission-date license.
