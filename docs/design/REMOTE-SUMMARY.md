# A fast window onto the machine doing the work

Connect with `se remote add <ssh-alias> --name <machine>`. StateEngine uses your
SSH configuration, prepares the native host when needed and reuses a saved
connection. You do not exchange invitation files, ports, hashes or console pastes.
An existing host and its agents are preserved if connection fails.

Agents share the machine connection while keeping their own verified identities
and mailboxes. CLI and MCP calls carry the actual sending agent; a failed agent
session never becomes human authority. Ordinary mail reaches the real target
agent and retains a stable return address across session changes.

Delivery starts with connection reuse with preserved identity and mail, followed
by a native comparison consumer and paired terminal timing qualification, real
cross-machine replies, then independent agent and link revocation. Connection
delivery leaves all four terminal clocks explicitly unqualified; the comparison
consumer and 100-pair timing cohorts must land before remote is considered complete.
Replies must return to the originating agent's mailbox through disconnect and
restart. Revoking one agent must leave others working; revoking a link must
fence all its agents and queued output.

Disconnect and forget close the connection without stopping the remote host or
agents. Remote host stop remains an explicit separate action. Resource limits
bound active work and queues, rather than the number of enrolled agents.

The approved behavior is in [45](45-remote-clients.md), its trust and acceptance
contract in [47](47-r0-contract.md), and measurements in
[80 §7](80-performance-budgets.md#7-proposed-client-interaction-budgets).
Implementation and qualification remain separate: native Linux and Windows VM
journeys, real default providers, outside mailbox/file readback and unchanged
process ownership must establish that the product works.
