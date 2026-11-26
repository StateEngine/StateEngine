# StateEngine

**Keep your coding agents' work.** StateEngine runs Claude Code, Codex and other coding
agents in your repository, saves every conversation, and lets you stop today and resume
tomorrow, hand work between agents, and run a small crew that messages each other.
It ships as one native `se` binary for Linux, macOS and Windows.

> **Early alpha.** StateEngine is pre-1.0: commands and saved data can still change
> between releases. Try it on a repository you have backed up, and
> [tell us](https://github.com/StateEngine/StateEngine/issues) what breaks.

## What you get

- **Conversations that survive.** Every agent's work is saved. `se stop main` today,
  `se launch main --resume` tomorrow, and the same provider conversation continues.
- **Any agent, one workflow.** Claude Code and Codex out of the box, plus Qwen Code,
  Goose, Hermes, OpenCode, Gemini, Kimi, Auggie, Cline or any agent that speaks the
  Agent Client Protocol (ACP).
- **One-line MCP server.** `se mcp` gives any MCP-capable tool StateEngine's tools
  over stdio: status, mail, resume, assignments, Atlas code navigation and more.
- **A crew, not a single chat.** Saved agents send each other mail, a captain receives
  questions and blockers, assignments track who is doing what, and `se status` shows
  the whole crew at a glance.
- **Atlas code navigation.** A built-in index answers find, references, impact,
  outline and recent-changes queries with compact pointers instead of whole files.
- **Remote machines over SSH.** Watch, message and launch agents on another machine
  using your existing SSH configuration.
- **Bring your existing sessions.** `se init --adopt` captures Claude Code or Codex
  sessions you start yourself (Linux and Windows).

## Install

**Linux and macOS**

```sh
curl --proto '=https' --proto-redir '=https' -fsSL https://github.com/StateEngine/StateEngine/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/StateEngine/StateEngine/releases/latest/download/install.ps1 | iex
```

**npm** (Node 18 or newer, any supported platform)

```sh
npm install -g @stateengine/cli      # or try it first: npx @stateengine/cli --version
```

The install script prints an absolute `se --version` command: run it, then add the
printed folder to PATH or open a fresh login terminal before continuing, so plain `se
--version` prints `stateengine` and a version number. The installer runs as your normal
user, needs no administrator rights, and starts nothing in the background. Supported
platforms: Linux x86_64 (glibc), macOS on Apple silicon and Intel, and Windows x86_64.
Releases are unsigned; the installer verifies each archive's SHA-256 checksum before
installing.

A standalone install upgrades by running the installer again and is removed with
`se uninstall`; an npm install uses `npm update -g @stateengine/cli` and
`npm uninstall -g @stateengine/cli`. Manual archive downloads with checksum
verification, pinned versions, upgrades, uninstalling and building from source are
covered in **[docs/INSTALL.md](docs/INSTALL.md)**.

You also need [Git](https://git-scm.com/downloads) and at least one signed-in agent:
[Claude Code](https://code.claude.com/docs/en/setup) (`claude auth status`) or [Codex
CLI](https://developers.openai.com/codex/cli/) 0.152.0 or newer (`codex login status`).
StateEngine uses your own provider account; it never supplies one.

## 60-second quickstart

Give a saved agent a real task and check the result. This works anywhere, including
over SSH and on machines without a desktop:

```sh
cd /path/to/your/repo                # any Git repository (run `git init` first if needed)
se init --provider claude            # or: se init --provider codex
se launch main --task "Create notes.md with one sentence describing this repo." --detach
se status                            # project, agents, runtime and unread mail
se history --agent main              # read the conversation as it is saved
```

`se init` registers the folder, saves an agent named `main` and registers the MCP server
for the provider you chose. It records the project's identity in `.git/stateengine/`,
writes no files into your working tree and leaves your Git history alone, then prints the
exact launch command for your setup. `se launch` checks that the provider CLI is installed
and new enough before it starts the agent. A running agent is not a finished task: repeat
`se history --agent main` until the assistant's reply is saved, then check the result:

```sh
cat notes.md                         # PowerShell: Get-Content .\notes.md
```

Stop and come back later:

```sh
se stop main                         # stop for now; the conversation is saved
se launch main --resume --detach     # continue the same conversation in the background
se down                              # stop StateEngine's background runtime
```

On a desktop, `se launch main` (or `--resume`) opens the agent interactively in a window
instead; headless and SSH machines refuse that with `window-unavailable`.

`se resume --preview main` shows an agent's saved context and waiting mail without
restarting it or marking anything read. Lost? `se guide` lists short topics,
`se guide getting-started` walks through this flow, and `se help COMMAND` shows any
command's options. [docs/USING.md](docs/USING.md) explains what status and launch report.

## Connect any MCP tool

`se mcp` serves StateEngine's tools over newline-delimited JSON-RPC on stdin/stdout.
Agents that StateEngine launches get these tools automatically, and when Claude Code or
Codex is installed, `se init` registers the MCP server for it, so there is nothing more
to run. If a provider was not installed yet, init prints the exact command to run once
it is, for example:

```sh
claude mcp add --scope local stateengine -- se mcp
codex mcp add stateengine -- se mcp
```

Don't repeat these for a provider init already registered: Claude Code refuses a
duplicate name and a manual Codex entry replaces the one init wrote. For any other MCP
client, register the command `se` with the argument `mcp` and set the server's working
directory to your project folder, which selects the project; add `--home DIR` before
`mcp` when you use a custom state home.
`stateengine_help` is the index for agents, and `se schema OP --json` prints any
operation's full input and output schema (for example `se schema message.send --json`).

## Run a crew

```sh
se agent add reviewer --provider codex                 # a second saved agent
se captain set main                                    # main receives questions and blockers
se msg send reviewer "Please review the parser change"
se assignment write --action open --assignee reviewer --body "Review the parser change"
se assignment list
se status                                              # every agent, its session and unread mail
```

Agents use the same mail through MCP. A message is saved when it is sent; StateEngine
reports delivery and reading separately and never treats "sent" as "read" or "done".
`se watch --target PROJECT_ID/AGENT_ID --once --wait-ms 0` reads one page of an agent's
live and saved activity. `se agent list` prints each agent's ID (`ag_…`) and the
`Next:` line of `se status` shows the project ID (`prj_…`), so a target looks like
`prj_…/ag_…`. `se delegate` launches a one-shot temporary agent with an optional
context handoff.

## Find code with Atlas

Atlas indexes the repository in the background once the runtime is running (`se launch`
starts it, or run `se up`). Replace `<symbol>` with a function or type name from your
code and `<file>` with a path relative to the repository root:

```sh
se atlas find <symbol>               # code, text and project records
se atlas refs <symbol>               # references to a symbol
se atlas impact <symbol>             # dependents, possible tests and linked records
se atlas outline <file>              # declarations in one file
se atlas changes --since 10m         # what changed recently
```

Results are compact pointers (file and line range, with size when verified), so agents
read only the source they need. Agents get the same queries as MCP tools. Before a
search or file read, managed Claude Code and Codex sessions can also receive a few lines
of indexed context when Atlas has a confident answer (`hooks = false` in `[atlas]` turns
that off). Atlas is on by default and runs on Linux, macOS and Windows.

## Adopt sessions you already run

```sh
se init --adopt --provider claude    # Claude Code 2.1.295 or newer
se init --adopt --provider codex     # Codex 0.166.0 or newer
```

Adoption adds StateEngine hooks to the provider's user settings, keeping your existing
hooks, models and permissions, so sessions you start directly in Claude Code or Codex are
captured and can receive mail. It works on Linux and Windows. StateEngine never stops
processes it did not start, and `se uninstall` removes unchanged hook entries.
Details: [docs/USING.md](docs/USING.md#adopting-sessions-you-start-yourself).

## Other agents and custom harnesses

```sh
se init --harness qwen-code   # or goose, hermes, opencode, gemini, kimi, auggie, cline
```

Catalogue agents are detected when installed and signed in. Register any other agent
that speaks ACP version 1 over stdio with `se harness add NAME --command COMMAND`, then
select it with `se agent add NAME --harness HARNESS`. StateEngine
gives them its tools over HTTP MCP when the agent supports it, and otherwise through
`se mcp --stdio`. Resuming a saved conversation also requires the agent
to support loading sessions. Saved agents can also pin their own model, endpoint and
reasoning effort. See **[docs/HARNESSES.md](docs/HARNESSES.md)** for permission
profiles, per-agent models and harness configuration.

## Work on another machine

```sh
se remote add my-server --name build    # uses your normal SSH configuration
se remote list --host build
se remote watch --host build --target PROJECT_ID/AGENT_ID
```

StateEngine stages its own binary on the destination and keeps remote agents running when
you disconnect. Sending mail, permissions and remote launch are covered in
**[docs/REMOTE.md](docs/REMOTE.md)**.

## Where things live

StateEngine keeps settings, history and conversations in a **state home**, separate
from your repository: `~/.local/state/stateengine` on Linux, `%LOCALAPPDATA%\StateEngine`
on Windows and `~/Library/Application Support/StateEngine` on macOS (`--home DIR` or
`SE_HOME` selects another). `se doctor` checks an installation and names exact repairs.

## Documentation

| Guide | Covers |
| --- | --- |
| [docs/INSTALL.md](docs/INSTALL.md) | Install options, checksum verification, upgrade, uninstall, building from source |
| [docs/USING.md](docs/USING.md) | First-agent walkthrough, status terms, resume, adoption, Atlas, MCP tool arguments |
| [docs/HARNESSES.md](docs/HARNESSES.md) | Providers, permission profiles, per-agent models, ACP and named harnesses |
| [docs/REMOTE.md](docs/REMOTE.md) | SSH connections, remote mail, permissions and remote launch |
| [docs/OPS.md](docs/OPS.md) | Operation reference for every CLI command and MCP tool |

## Contributing and license

StateEngine is a Rust workspace; see [docs/INSTALL.md](docs/INSTALL.md#build-from-source)
to build it.

The Rust workspace is licensed under the [GNU Affero General Public License, version 3 only](LICENSE).
Third-party components retain their own licenses.

Outside pull requests require a signed [contributor agreement](CONTRIBUTING.md) before merge.
The agreement preserves your ownership and permits StateEngine LLC to offer your contribution
under additional licenses while continuing to offer it under the submission-date license.
