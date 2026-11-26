# Working with agents on another machine

StateEngine can list, watch, message, launch and stop agents on another machine over SSH.
`se guide remote` gives the same overview from the installed binary.

## Connect

From your own terminal, use an SSH destination that already works with your normal
SSH configuration and host-key verification.

To pair a machine and initialize a remote project in one Owner-driven command:

```sh
se remote init my-server:/srv/repo --alias build --agent worker
```

Pass `--allow-launch` only when you explicitly want to grant remote launch consent
for the initialized agent; without it, launch permission stays off by default. If
any phase fails (SSH host-key check, staging, pairing, remote project init, or
launch consent), `se remote init` reports every completed phase alongside the
failed phase rather than claiming success.

To pair a machine without initializing a remote project:

```sh
se remote add my-server --name build
se remote list --host build
se remote watch --host build --target PROJECT_ID/AGENT_ID
```

The first command stages the matching native executable and starts or reuses your
remote host. A compatible running host and its agents keep running. If the saved host
has shut down while idle, the next remote operation starts it again over SSH and waits
for that cold startup.

## Send mail

Use the project, agent and current session IDs from `remote list` when sending:

```sh
se remote send --host build --target PROJECT_ID/AGENT_ID --session SESSION_ID --key request-1 "Check the failing test"
```

Reuse the same key and request when retrying an uncertain send. Launched agents use
the configured MCP remote tools, which preserve their own sending identity. Agent
sandboxes keep their existing permissions; a sandboxed CLI that cannot prove native
ownership directs the agent to MCP.

When a launched agent receives remote mail, its inbox shows the authenticated
sender's machine, project and agent address, with reply instructions outside the
message body. It replies using ordinary mail: select that sender address and set
`reply_to` to the received message ID. Only the original recipient can use that
contact. Replies stay saved while the source is offline and enter its ordinary inbox
when its native session reconnects; either agent can continue the thread. A saved
reply receipt confirms local storage. It does not claim the other agent has received
or read the reply.

## Disconnect and forget

`se remote disconnect --name build` closes the connection while the remote host and
agents continue. Run `remote add` again to reconnect. `se remote forget --name build`
also removes the saved local connection. Neither command stops remote work.

## Permissions

At the end of `remote add`, choose **destination** or **local** to review source agents
and allow or revoke one address. Revisit destination permissions with
`se remote permissions --name build`, or run `se remote permissions --local` on the
destination to review its incoming sources. These Owner controls require a terminal;
non-interactive pairing reports that permission review was skipped.

Revoking an agent blocks its address across session and machine-grant renewals
without removing the machine grant or other agents' access. An interrupted revoke
stays blocked and appears as pending in that view until you finish it or explicitly
allow the address. Agents appear after their first authenticated message; replying to
an arbitrary address never creates permission. Existing machine grants retain their
list, watch and send permissions.

`se remote grants` lists machine sessions and their authority revisions,
`se remote revoke` revokes a machine session and closes its connections, and
`se remote disable` closes this machine's remote listener.

## Remote launch

Remote launch requires a separate Owner decision. At the end of pairing choose
**launch**, or run `se remote permissions --name build --launch` in a terminal.
Choose an existing destination agent and allow or revoke future launches. The review
shows its saved provider and permission profile. Existing machine grants keep their
list, watch and send verbs; they do not gain launch permission.

A launched lead can call `stateengine_remote_launch`; from the CLI, use IDs from
`remote list`:

```sh
se remote launch --host build --target PROJECT_ID/AGENT_ID --key start-1            # fresh conversation
se remote launch --host build --target PROJECT_ID/AGENT_ID --resume --key start-2   # saved conversation
```

The destination starts that agent headlessly with its saved profile. Without `--resume`
it starts a fresh conversation; `--resume` reopens the latest saved conversation, and
`--resume SESSION` selects a specific saved session. Launch does not create an identity,
override its model, send work, or stop existing work. A start receipt confirms the
original launch; replaying it does not claim the agent is still running. Use its
returned session for remote send, which refuses a stopped or replaced session. A pending
launch retains its key; repeat the same launch with that key to observe its result.
Revoking launch consent blocks future reservations; already admitted launches and
running agents continue.

## Remote stop

A paired machine can stop a session that its own remote launch started. Pass the
target and the session from the launch receipt:

```sh
se remote stop --host build --target PROJECT_ID/AGENT_ID --session SESSION_ID --key stop-1
```

Agents use `stateengine_remote_stop` with the same fields. The destination refuses any
other session, including a later session of the same agent started by its Owner or by
another machine. To stop that work, the destination Owner runs `se stop AGENT` in a
terminal on that machine. Stop needs no extra permission: the recorded launch is the
authority, so it still works after launch consent is revoked. Removing the pairing
does refuse it, including a stop that is already in progress. The destination's own stop
path ends the session and reports its witness. If closure is not proved, the command
exits 2; repeat it with the same key.

## Reading IDs and cursors

Remote commands take exact IDs rather than names. `se remote list --host build` prints
each allowed agent's project ID, agent ID and current session ID: use
`PROJECT_ID/AGENT_ID` as `--target`, and the session ID as `--session` for `remote
send`. `remote watch` returns one bounded page with its cursors; pass them back with
`--cursors` to continue from where the page ended rather than constructing them.
Disconnecting or ending a watch never stops remote work.

Linux-to-Linux SSH remote is exercised nightly; Windows remote is not yet qualified.
