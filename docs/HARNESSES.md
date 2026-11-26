# Providers, models and harnesses

A **harness** is the coding agent StateEngine launches for a saved agent. Claude Code
and Codex are built in; SE Code (`secode`) and agents that speak the Agent Client
Protocol (ACP) are also supported.

## Providers and sign-in

Install **one** provider before `se init`, using its official instructions:

- [Codex CLI](https://developers.openai.com/codex/cli/) version 0.152.0 or newer: run
  `codex login`, finish browser sign-in, then check `codex login status`.
- [Claude Code](https://code.claude.com/docs/en/setup): run `claude auth login`,
  finish sign-in, then check `claude auth status`.

Continue only when the provider reports that you are signed in; an open sign-in page
is not a completed login. Run the provider and StateEngine as the same OS user on the
same machine. Provider access and billing belong to your provider account;
StateEngine does not supply one.

Choose the first agent's provider with `se init --provider claude` or
`se init --provider codex`, and add more with `se agent add NAME --provider ...`.

## Permission profiles

A permission profile is the saved set of rules for what an agent may do. `se init`
prints the selected provider's default profile and how to change it. For example, the
default Codex profile reads `workspace-write, approval never, network false, bypass false`:

- `workspace-write` allows edits in the agent's permitted workspace and scratch locations.
- `approval never` means no interactive requests for tool approval.
- `network false` disables tool network access.
- `bypass false` keeps sandbox bypass disabled.

These are provider tool permissions, not a provider sign-in check. Profiles live as
named `[profiles.NAME]` sections in the state home's `config.toml`; for example, set
`network = true` under `[profiles.default]` to allow network access. Relaunch the
agent to apply a change. `se config` changes saved agent settings, not permission
profiles.

## Per-agent model settings

A saved agent can use its own Codex model provider without changing other agents or
shared provider defaults. Replace `AGENT`, `LOCAL_MODEL` and the example endpoint:

```sh
se agent add AGENT --provider codex --model LOCAL_MODEL --model-provider local --base-url http://127.0.0.1:8080/v1 --wire-api responses --reasoning-effort high --context-window 200000
```

Read or change a saved value with `se config get agent.AGENT.model_provider` or
`se config set agent.AGENT.reasoning_effort high`. The other supported keys are
`base_url`, `wire_api` and `context_window`. Use `null` to inherit the provider
default; clear `base_url` and `wire_api` before clearing their `model_provider`.
Changes apply on the next launch; they do not reconfigure a running session.
`se config set` changes owner settings, so it must run in your own interactive terminal
(TTY): it refuses when stdin or stdout is piped or redirected, or when an agent runs it.

Endpoints must contain no credentials, query or fragment; authentication stays with
the provider's own setup. MCP agent creation uses the same keys inside
`provider_settings`. Claude supports `reasoning_effort` (low, medium, high or max);
the Codex routing and context fields are refused for other providers.

Profiles containing these overrides require a version of StateEngine that supports
them. Older readers refuse those profiles rather than drop settings.

## ACP protocol agents

An ACP agent is a separately installed assistant that speaks Agent Client Protocol
version 1 over standard input and output. Configure its executable and arguments in
your state home's `config.toml`; StateEngine does not run a shell to interpret those
arguments. StateEngine gives the agent its tools over authenticated HTTP MCP when the
agent advertises support, and otherwise attaches `se mcp --stdio`. Resuming also
requires loading saved sessions; agents without that capability can start fresh by
omitting `--resume`. Sign in and select a model using that agent's own setup.

The native agent owns its permissions and sandboxing. StateEngine does not add an
execution sandbox or network restriction to the protocol, so choose the agent's
native permission level explicitly. The saved `approval = "never"` setting allows
each protocol permission request once; it never selects a persistent "always allow"
option. Other approval settings refuse them with a reason, because a headless
approval interface is not implemented yet. `se init --harness` for a catalogue agent
saves a `[profiles.protocol]` profile with `approval = "never"` and prints it when it
is the first protocol agent and the shared profile is unchanged. Otherwise your
`[providers.acp].profile` and its settings are kept, and init prints the profile the
agent will use. A protocol mode or saved StateEngine profile does not establish OS
containment.

Agents that read files through their client instead of the disk can read text files
through StateEngine. The path must lie inside the folder the conversation opened in,
and every part of it is opened without following a link, so links and `..` are
refused even when they point back inside. One protocol message carries at most
1 MiB: a read whose text would not fit is refused and names the `line` and `limit`
that read it in parts, and files over 4 MiB are not read. StateEngine does not offer
file writes or terminals to protocol agents; those calls get the standard
unavailable reply. This limits what StateEngine does for the agent; it is not a
sandbox around the agent.

After installing and configuring a protocol agent, add these sections to the
existing configuration. Replace `protocol-agent` with its native executable,
`YOUR_MODEL` with your configured model, and use the agent's documented protocol
arguments in `acp.arguments`:

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

`{model}` expands only the saved model inside each argument. If you set `acp.mode`,
it must match the mode the agent reports before receiving work; omit it to use the
agent's announced default, including agents without modes. For a script, including
a package-manager script launcher on Windows, select its native interpreter as
`command` and put the script's absolute path first in `arguments`. StateEngine does
not execute `.cmd`, `.ps1` or shell shims as native images. If the provider needs
additional environment variables, list their names in `acp.environment`; keep
account credentials in the provider's own configuration.

```sh
se init --provider acp
se launch main --task "Read the README and explain what this project does." --detach
se agent show main
se history --agent main
se stop main
se launch main --resume --detach
```

Launch and status disclose that the native agent owns its policy. Status shows
current activity and any permission refusal; streamed text is explicitly provisional
until the completed turn appears in saved history. Resume loads the same conversation
and, before offering new input, checks that it ends with the latest captured exchange
(the last user message and every reply after it). Earlier messages, such as a banner
or a compaction summary, are not compared. A missing, changed, erased or oversized
latest exchange refuses resume instead of silently starting over. If capture was
disabled, omit `--resume` for a fresh conversation.

## Named harnesses

`se init --harness NAME` selects `claude`, `codex` or `secode` without a
configuration edit. For an installed, signed-in `qwen-code`, `goose`, `hermes`,
`opencode`, `gemini`, `kimi`, `auggie` or `cline`, init detects the installed
executable and any package entrypoint, then saves the shared protocol descriptor
automatically. Missing or unreadable installations refuse
with their actual cause and a native setup link. Init does not install software or
sign in to a provider, and saving the descriptor does not establish a successful
launch: the normal launch still verifies native capabilities and readiness. Existing
named entries take precedence over catalogue names and keep their original command
and permission choices.

A catalogue descriptor's `environment` lists only that agent's own documented variable
names (for example `GEMINI_API_KEY` for `gemini`). StateEngine saves the names, never
values, and you can add or remove names there. Every protocol agent also inherits the
proxy and TLS trust variables (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`,
`NODE_EXTRA_CA_CERTS` and related), including through the background runtime.

For any other installed protocol agent, register it from your own terminal without
editing the file by hand:

```sh
se down
se harness add my-agent --command protocol-agent --arg=--acp --env OPENAI_API_KEY
se up
se agent add helper --harness my-agent
```

`se harness add` appends `[harnesses.my-agent]` to `config.toml`, keeping the existing
contents, and maps the `[providers.acp].profile` launch profile to the agent's native
default. A running host keeps the configuration it started with, so registration
refuses while one runs. `se down` stops the host and the agents it manages; their
saved conversations stay, and `se up` starts it again with the new entry.
Registration also works before `se init`. `--env` lists variable names only; values
stay in your environment. The command must already be installed, built-in provider
names are refused, and an existing entry is never replaced.

To write the entry yourself, or to give several installed protocol agents the same
adapter, add a named entry to `config.toml` with an explicit mapping for every launch
profile it uses. This example maps `protocol-work` to the agent's announced native
mode; replace the command and arguments with the installed agent's documented values:

```toml
[harnesses.my-agent]
driver = "acp-stdio"
command = "protocol-agent"
arguments = ["--acp", "--model", "{model}"]
environment = []

[harnesses.my-agent.permissions.protocol-work]
arguments = []      # extra native arguments for this profile, if any
mode = ""           # native mode the agent must report; "" keeps its announced default
```

Use `se init --harness my-agent` or `se agent add helper --harness my-agent`.
Selecting a harness implies the ACP provider; a conflicting explicit provider
refuses. The `[providers.acp].profile` setting selects an existing launch profile,
such as `protocol-work` above. Permission entries can supply additional native
arguments, native mode environment values in `environment`, and an expected `mode`
that the agent must report before work starts. They do not override capabilities
reported by the running agent.

Descriptor `environment` lists inherited variable names, never account secrets. For
a model selected through a native environment variable, set
`model_environment = "NATIVE_MODEL_VARIABLE"` instead of an argument `{model}` slot.
To use the native default when no model is saved, put optional model flags in
`model_arguments = ["--model", "{model}"]`; they are appended only for a selected
model. Model slots in the main `arguments` remain required.

The saved agent retains its harness selection across configuration default changes
and resumes. Existing agents without a saved selection keep the legacy
`[providers.acp]` and `[acp]` configuration. Restore a missing descriptor before
launching its saved agents; there is no fallback to a different agent.
Descriptor-bound profiles use event schema version 2, so older binaries refuse them
instead of losing the saved selection.
