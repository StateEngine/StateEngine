//! Workflow topics describe the shipped command surface, not planned operations.
pub(super) struct Topic {
    pub name: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub body: &'static str,
}

pub(super) const TOPICS: &[Topic] = &[
    Topic {
        name: "getting-started",
        title: "Start work in an existing repository",
        summary: "Check the installation, register a repository and launch a first agent.",
        body: r#"Run se --version in a fresh terminal to check the installed executable.
From your repository, run se init --provider claude or se init --provider codex.
Use --repo DIR to register an existing folder from elsewhere. Setup preserves
your repository files and Git history and saves an initial agent named main.
Run the scoped launch command printed by init; se launch main starts or resumes
that saved agent. Authenticate with the chosen provider when it asks.

Run se status to see setup, agent and runtime facts. If selection is ambiguous,
use se --project PROJECT status with a saved project name or ID. --home DIR
selects a StateEngine data directory, not a repository or an agent identity.

Managed launches run on Linux and Windows. This alpha's macOS package supports
saved-state inspection; managed launches and the background host are unavailable.
Run se help init or se help launch for the installed command options.
"#,
    },
    Topic {
        name: "launch",
        title: "Launch and stop agents",
        summary: "Choose a provider, resume a saved conversation and inspect live work.",
        body: r#"Use se agent list and se agent show AGENT to find saved identities and settings.
se launch AGENT starts or resumes that agent's provider conversation and starts
the runtime if needed. --task TEXT supplies work; --detach runs headless.
--new explicitly starts a fresh conversation for the same saved agent. A missing
or incompatible resume reference is reported rather than silently replaced.
--provider and --model override a launch only when compatible with its conversation.

A live agent is not a completed task. Check se status and se history for observed
process, provider and capture facts. A default launch refuses a conflicting live
instance and reports its scoped work. Read se help launch before replacing it.
--force (MCP: force) explicitly consents to stopping existing sessions and their
scoped jobs before relaunching. A terminal asks for confirmation. --new (MCP: new)
instead selects a fresh conversation.
se agent stop AGENT stops one managed agent; se down stops this data home's
owned runtime and agent scope. Stopping work does not erase its saved history.

Sessions can control themselves. An agent with a current can-create grant can
also launch or stop its direct children; that grant does not expose a child's
private inbox or continuity. Other targets require the owner.
"#,
    },
    Topic {
        name: "continuity",
        title: "Return to saved work",
        summary: "Reopen a conversation, inspect context and save working notes.",
        body: r#"After closing your terminal or restarting, use se agent list to find the saved
agent, then se launch AGENT to reopen its conversation. se resume AGENT prints
the command to reopen it; it does not itself launch the provider. Avoid --new
when you want the previous conversation.

Owners can inspect se resume --preview AGENT without binding or acknowledging
a session. A bound agent uses stateengine_resume to read its own continuity.
Resume packets are bounded: inspect complete, omissions and continuation facts.
Use the returned cursor with since for that same principal and target, or follow
the printed retrieval commands. An omitted source is not an empty history.

stateengine_working_state_get and stateengine_working_state_set read and save
short working notes. A save must match the revision previously read; on conflict,
reread and reconcile instead of overwriting. se history is read-only inspection;
stateengine_event_read retrieves one authorized committed event by ID.
"#,
    },
    Topic {
        name: "messages",
        title: "Send and read project messages",
        summary: "Use direct mail or the shared floor, with honest read and retry semantics.",
        body: r#"se msg send RECIPIENT "Message text" sends direct mail to a registered recipient.
Use se help msg send for shared floor messages, their work action and explicit
addressees. Agents use stateengine_msg_send; their sender and project come from
the bound session, not from a claimed identity in the arguments.

Writes need a request identity. The CLI prints a generated key before sending;
MCP requires idempotency_key. If a reply is lost, retry the same intent with the
original key. A new key can create another message. A commit receipt proves
storage, not delivery, reading, a reply or completion of the requested task.

se msg list and se msg inbox inspect mail without marking it read. --full asks
for complete bodies within a bounded page; follow continuation when incomplete.
stateengine_msg_list supplies an agent's authorized view. stateengine_msg_read
reads a whole message and marks it read as its recipient; stateengine_msg_ack
marks it read without returning the body. stateengine_msg_dismiss archives it
without claiming a read. Owner inspection cannot manufacture a recipient's mark.

MCP direct mail uses to; floor mail additionally requires work.action and
work.addressees. quiet suppresses notifications while leaving the message unread.
"#,
    },
    Topic {
        name: "configuration",
        title: "Select projects and agent settings",
        summary: "Understand project selection, saved models and permission profiles.",
        body: r#"Owner project selection uses --project, SE_PROJECT, the closest registered
repository containing the current directory, a configured default, then the
sole registered project. Ambiguous or unreadable selection refuses with choices.
Use --home DIR consistently when operating another StateEngine data directory.
A bound session always uses its authenticated project and agent. Matching caller
assertions are optional checks; they never grant another identity or authority.

Read a saved model with se config get agent.AGENT.model.
Change it with se config set agent.AGENT.model MODEL. Saved profile and can-create fields
are also supported. Use se help config get and se help config set for exact keys.
General file-setting writes are not supported by these commands. Permission
profiles live in your data home's config.toml; a saved named profile is required
to opt into full bypass. Default launch permissions preserve provider sandbox
and approval behavior. Never put credentials in command arguments or messages.

Owner-only setup, credential changes and destructive administration are not
agent tools. A request key or an identity label is not permission to run them.
"#,
    },
    Topic {
        name: "remote",
        title: "Work with agents on another machine",
        summary: "Connect over SSH, discover allowed agents, watch and send safely.",
        body: r#"With a remote-enabled build, the owner runs se remote add DESTINATION --name NAME
to configure and verify a connection over system SSH. Read se help remote add
for setup options. se remote list --host NAME discovers allowed destination
agents; se remote watch --host NAME --target PROJECT-ID/AGENT-ID watches one.
On the destination, se watch --target PROJECT-ID/AGENT-ID uses the same view.

Agents use stateengine_remote_list, stateengine_remote_watch and
stateengine_remote_send through their admitted source session. Watch returns
bounded pages: retain the returned cursor and distinguish provisional provider
items from committed events. A gap or reset is explicit; it is not empty history.
Remote send selects an exact target and expected session. After an uncertain
reply, retry with the same key, body, target and session. Committed mail does not
prove delivery, reading or action.
The optional measure output estimates producer age at release, not a guaranteed
delivery-latency bound, and does not measure interface paint.

Launch agents normally on each machine; a remote connection grants no remote
launch. Disconnecting or forgetting a connection closes its source transport,
not the destination host or its agents. Remote administration is owner-only.
"#,
    },
    Topic {
        name: "tool-arguments",
        title: "Supply tool arguments and retry safely",
        summary: "Copy opaque IDs, use bound identity and retain keys and revisions.",
        body: r#"Managed Claude and Codex sessions discover the same MCP tools. Discovery shows
argument shapes; se schema OPERATION exports full input/output schemas, such as
se schema message.send or se schema atlas.refs. Runtime value and permission
checks still apply even when the short catalogue omits a long description.

Omit agent_id and project_id in a managed session. Supplied values must match
the authenticated caller; they never select another caller. target_agent_id
selects a controlled target only on tools that advertise it. Copy opaque IDs,
cursors and expected session IDs from results instead of constructing them.

Mutations require idempotency_key. Keep the same arguments and key when retrying
an uncertain result. Reusing a key for changed intent conflicts; using a new key
can repeat the effect. A committed message is not proof of delivery or task work.
Remote mail also pins the original target and expected session.

working_state_set.expect is the revision just read, or "absent" on a first write.
On a revision conflict, reread the current notes and reconcile them. Do not turn
a conditional update into an unconditional overwrite.
"#,
    },
    Topic {
        name: "atlas",
        title: "Find code and inspect references",
        summary: "Use optional code navigation with tagged targets and bounded results.",
        body: r#"Atlas is optional code navigation. se atlas lists find, refs, impact, changes
and outline. A query requires an installed, enabled controller; status reports
unavailable, disabled, absent or updating rather than pretending results are empty.
The native controller currently runs on Linux. Other compositions can report it
unavailable. Optional code indexing is separate from saved conversations and mail.

MCP targets retain their tagged JSON shape. For example, the target of
stateengine_atlas_refs can be {"Symbol":{"Name":{"name":"authenticate"}}}
or {"File":"src/auth.rs"}. Use se schema atlas.refs for its complete grammar.
root selects a registered worktree when a project has several; copy its ID from
results. File paths are relative to that registered root.

For stateengine_atlas_find, regex: true treats query as a case-sensitive regular
expression over live source; (?i) requests case-insensitive matching. Inspect
coverage, index state, confidence, omissions and continuation on bounded answers.
Name-only reference candidates are not claimed as resolved references.
"#,
    },
    Topic {
        name: "troubleshooting",
        title: "Diagnose a refusal or missing result",
        summary: "Find exact command help, inspect health and interpret incomplete results.",
        body: r#"se guide lists topics; se guide TOPIC reads just one. The MCP equivalent is
stateengine_help with no topic for the index, or topic set to an exact name.
The guide is installed content and its CLI needs no project or running host.
se help COMMAND explains the installed syntax; se schema OPERATION exports its
input and output schema. --json preserves typed results and errors.

se status reports setup, runtime and agent facts. se doctor checks the local
installation and names supported remedies. Follow its exact check and plan;
se doctor --fix CHECK-ID requires owner human presence and is not a general
repair shell. Diagnosis does not prove an unavailable source was empty or fixed.

If stuck, ask the user to run se diagnostic-bundle and share the redacted file.
This owner-only command includes home-wide status, diagnosis and recent startup
logs; it is not an MCP tool. Missing or unreadable sections remain explicit.

Read code, detail and remedy on refusals. Exit codes are 0 complete, 1 failed or
refused, 2 incomplete, 3 unreadable, 4 unknown target and 64 usage. An owner's
resume preview can exit 0 after dropping recent turns to its byte budget; its
complete: false and omission details still apply. Follow cursors and retrieval
commands instead of silently discarding missing rows. Unknown provider state
does not prove a process is absent, capture complete or a task finished.
"#,
    },
    Topic {
        name: "removal",
        title: "Stop or remove an installation",
        summary: "Distinguish stopping, project removal and uninstall while preserving work.",
        body: r#"se agent stop AGENT stops one managed agent. se down stops the owned runtime
scope for the selected data home. Neither command erases the saved conversation.

se --project PROJECT remove unregisters a project; --all explicitly selects every
registered project in the data home. Removal stops owned instances and removes
owned integration exposure while preserving repository files and retained history.
--keep-integrations explicitly leaves registered integrations. Inspect any changed
integration conflicts and remaining obligations in the result.

se uninstall removes this installation, not your repositories or retained history.
Removal and ordinary uninstall require the owner's human terminal. For unattended
uninstall, pass --yes explicitly; native ownership, agent ancestry and session
checks still apply. Both print their affected scope before effects and return
observed cleanup facts. A pending helper handoff
is not a completed uninstall. On Windows use the matching archive's uninstall.ps1
to wait for the final status; after an installed executable has been removed,
recover from the archive rather than retrying that missing executable.
Run se help remove or se help uninstall before choosing the scope.
"#,
    },
];
