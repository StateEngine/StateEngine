# 70 — Security

Status: deep design, 2026-10-30. Precedence as in 00. Builds on 00 §5.2 (logging), §5.4 (paths),
§5.5 (environment); OPS.md's `Auth` column is the authority table this section implements.

## 1. Threat model, stated honestly

### 1.1 What we protect
The history in `state.db` (turns can hold secrets), owner authority, session capabilities and bearers
(each acts as one agent), process custody (a wrong stop kills someone's work), the user's repo and
provider config (we reverse only our own marked entries), and the machine credential. Provider
credentials (`~/.claude/.credentials.json`, `~/.codex/auth.json`) are not ours: we never read, copy or
log them.

### 1.2 Who we defend against, by boundary
**Same OS user: mistakes, not hostile programs.** Anything running as the user can read our files and
`/proc/<pid>/environ`, attach a debugger, or run `se`. We don't pretend otherwise. Here we defend
against *mistakes, drift and misattribution* (Jimmy, 2026-09-04): a stale binding after relaunch, an
agent running an owner command in its shell, a name passed as an identity, inherited environment
changing who acts. The realistic attacker is a prompt-injected model reaching us through the **tool
surface** and the **agent's shell**; authority rules (§2) close both. An agent with an unrestricted
shell can still do anything the user can. Containing that is the provider sandbox's job, and our docs
say so.

**Real boundaries:** other OS users (file modes, pipe DACLs and socket directories keep them out;
loopback TCP is open to every local user, so every non-public route needs a bearer); web pages in the
user's browser (any site can send to `127.0.0.1`; Host/Origin admission in §4.2 stops DNS rebinding and
cross-site requests); other machines (loopback only, no remote access built); and the supply chain (§7).

### 1.3 Where adversarial review applies
Executable counterexamples are required only at process and machine boundaries: HTTP admission, IPC
peer authentication, credential and pin files, `se mcp token`, launch secret delivery, signing. A
finding that needs a hostile caller inside our process is answered by citing the trust-boundary ruling.

## 2. Principals and authority

### 2.1 Three authorities
`Authority = Owner(OwnerProof) | Session(BoundSession) | Anonymous`, constructible only by se-host
(00 G1). No input field, flag or environment variable carries authority; `--actor`, `--user-id` and
`--human-actor` do not exist.

| Path | How Owner is established | How Session is established |
| --- | --- | --- |
| CLI, host running | IPC peer credentials = the host's OS user, **and** the client process is not inside any owned agent tree (§2.3) | `SE_SESSION` handle + pin-file secret presented over IPC; host verifies hash, state and that the client is inside that session's tree |
| CLI, no host | The process can open the owner-only store and credential files, **and** passes the self-check of §2.3 | Same handle + pin file, verified against the store directly |
| HTTP listener | Never. No owner operation is served over TCP | `Authorization: Bearer sels-…`, verified per request |
| stdio `se mcp` | Never for tools | Per-call capability in `_meta` (`stateengine.session-capability-v1`) |
| Embedded SE Code | SE Code's own authenticated UI calls `Engine::owner()` in process (inside the boundary) | In-process `BoundSession` handle; no secret exists |
| Anonymous | `--version`, `help`, `schema`, `/stateengine/livez`, MCP `initialize`/`ping` | — |

An invalid, expired or revoked capability is a refusal. It never falls back to Owner, to `SE_PROJECT`,
or to cwd lookup.

### 2.2 Session capability lifecycle
1. **Mint.** `agent.launch` (or `session.begin` for an adopted, unmanaged session) creates 32 random
   bytes from the OS CSPRNG, stores only `sha256` in `credentials` with `kind=launch`, `state=prepared`
   and a 10-minute activation deadline. Text form `sec1.<session-id>.<base64url>`.
2. **Deliver**, never through argv or environment: an owner-only pin file
   `<state>/launch/<launch-id>/pin` created `O_EXCL` and read back (managed launches; `SE_SESSION` holds
   only the handle `ses_<uuid>`, so `env` in a captured turn reveals nothing usable); the stdout pipe of
   `session begin` (integrators only); an IPC response to a peer-authenticated client; or an in-process
   handle (SE Code).
3. **Activate** on first verified use, bound to the lifecycle id and lease generation.
4. **Verify per call**, including on a multiplexed MCP connection, so revocation applies on the next call.
5. **Revoke** on stop, takeover (lease generation CAS), `session.end`, `project.remove`, an expired pin
   or credential rotation; the pin file is deleted and its absence read back.

HTTP bearers (`sels-…`) are separate secrets minted by `se mcp token` over IPC, hashed, and revoked with
their session, so a leaked bearer is revocable without relaunch. Capabilities survive a host restart
because agents do on Linux and macOS. `Secret` is not `Clone`, `Display` or `Serialize`, debug-prints
`[redacted]`, zeroizes on drop, and compares in constant time.

### 2.3 Keeping an agent from acting as the owner
Five layers, each of which catches a different mistake:
1. **No tool exists.** The session MCP catalogue is generated from OPS.md's `Auth` column; owner and
   human-only operations have no MCP tool. A model cannot call what `tools/list` never listed.
2. **No escalation input.** Session calls take project and actor from the capability. Inputs use
   `deny_unknown_fields`, so `agent_id`/`project_id` in arguments is a usage refusal. The one target
   field, `target_agent_id` on launch, wake and stop (OPS.md `81faea2`), names an object, never the
   actor: it is honored only for an agent whose immutable `created_by` is the caller, while the caller
   holds `agent.<A>.can-create`, rechecked per call.
3. **The agent's shell acts as the agent.** `se` with `SE_SESSION` set acts as that session. An
   owner-only command refuses with `owner-required` and the fix "run this in your own terminal".
4. **Owner authority is withheld inside agent trees,** even when `SE_SESSION` was unset. One se-proc
   function answers "is this pid inside an owned agent tree?", called by the host for IPC clients
   and by the CLI on itself when no host runs:
   - Windows: `IsProcessInJob(client, job)` for each job handle the host holds (µs each). With no host
     running, no managed agent is alive on Windows (host death stops the job tree).
   - Linux: `/proc/<pid>/cgroup` lies under the agent cgroup subtree recorded at launch. For an
     `uncontained` agent, the macOS rule below: `getsid(pid)`/`getpgid(pid)` matches a live managed
     group, or the parent chain reaches its leader.
   - macOS: `getsid(pid)` equals a live managed session leader, or the parent chain reaches one
     (`proc_pidinfo` `PROC_PIDTBSDINFO`).
   - Provider markers, where present (`CLAUDECODE=1` in Claude's tool shells), also withhold Owner. Their
     absence proves nothing.
5. **Human-only verbs need human presence.** `decision ratify|reject|retract|supersede`,
   `project.remove`, `store.forget`, and `config.set` of a security key (permission profile, full-bypass
   opt-in, listener port) require all of: stdin and stdout are a console/TTY (`isatty`;
   `GetConsoleMode` succeeds), layer 4 says "outside every agent tree", and no `SE_SESSION` is set.
   There is no typed confirmation: Jimmy's ruling that friction is the enemy applies, and the three
   checks above are the human-presence proof. In SE Code, the UI passes a `HumanPresence` token created by a UI gesture; tool calls
   never carry one.

**Not stopped:** an agent that escapes its job or cgroup (a Linux user can move its own processes
between cgroups it owns; WMI process creation lands outside a Windows job), drives a TTY it allocates,
or reads the credential file. That is a hostile same-user program (§1.2). In unmanaged sessions the user
runs alone, human-only verbs still refuse (provider tool shells have no console stdin).

### 2.4 Optional hardening: Landlock and seccomp
Kernel containment is the alpha guarantee where the OS offers it: a Windows job, or on Linux a cgroup v2
scope delegated by the systemd user manager at first launch (BestAvailable, section 30), is what stop,
its witness and layer 4 above rely on. Landlock (deny writes under `/sys/fs/cgroup`) and a
seccomp filter could additionally keep a Linux agent from leaving its cgroup. Both are optional
hardening: **off by default for alpha and never a launch requirement.** A kernel without Landlock, or a
provider that misbehaves under a filter, launches exactly as it does with hardening off; `se doctor`
reports hardening as off, not as a failure.

**Residual, stated honestly.** With hardening off, any process running as the user, an agent included,
can write a pid into a `cgroup.procs` file the user owns and move it out of the agent's cgroup; stop then
no longer sees it. Even with hardening on, the user's other processes outside the agent tree keep that
ability. Moving a process out on purpose is a hostile same-user act, not a mistake, so under the
trust-boundary rule (§1.2) it is a stated limit, not a defended boundary.

**Uncontained fallback, stated honestly.** Where Linux has no systemd user manager or no delegation
(containers, WSL without systemd, minimal hosts), agents launch anyway in their own process group and
are marked `uncontained`. The bound is weaker than a cgroup, and it is weaker by accident as well as on
purpose: stop signals the process group and witnesses that group empty; a descendant that leaves the
group (`setsid`, a daemonizing tool, a double fork that calls `setpgid`) is not signalled and not
counted, so stop can report `witnessed` while such a descendant still runs. Layer 4 above uses the
session/group check and misses the same descendants. Nothing hides this: the launch receipt, `se status`
and `se agent list` carry `containment: "uncontained"` with its probe cause, the launch line says so,
and `se doctor` reports it as a warning with the fix. It is never silent and never reported as
contained.

## 3. Credentials

### 3.1 Machine credential
- 32 bytes from the OS CSPRNG, written at `init` to `<state>/credential` with `O_EXCL`, inside the
  owner-only state directory (§5); permissions read back before init reports success (G8).
- Uses: (a) the listener identity proof, `HMAC-SHA256(credential, challenge ‖ generation ‖ port)` at
  `/stateengine/local-http-proof`, which lets `se mcp token`, the CLI and SE Code confirm the port is
  our host before handing anything to it; (b) owner proof in direct mode, together with store access.
- Never crosses IPC (peer credentials authenticate there), never enters argv, environment, logs,
  backups (`store.backup` excludes runtime credentials) or support bundles.
- **Rotation:** if `doctor` finds the file or its directory looser than owner-only, exposure cannot be
  ruled out, so `doctor --fix` tightens permissions, writes a new credential, revokes all bearers and
  capabilities, and says agents re-bind on their next launch.

### 3.2 Never in argv or environment
Argv is world-readable on Linux and visible to admins through WMI on Windows; environment leaks into
transcripts, crash reports and children. Secrets travel only by §2.2's channels. Claude's
`--mcp-config <state>/launch/<id>/mcp.json` and Codex's inline app-server MCP config hold a URL and the
`headersHelper` command `se mcp token`, never a secret; so do the files `init --adopt` writes
(`.mcp.json`, `.claude/settings.local.json`, the `.codex/config.toml` marker block), so committing them
by accident leaks nothing. A token in a query string is refused.

### 3.3 Environment scrubbing for children
Launched agents get the user's environment minus every `SE_*`, `STATEENGINE_*` and `SECODE_*`, plus the
`SE_SESSION` handle and `SE_HOME` if set (00 §5.5); provider keys pass untouched. `process.start`
children (dev servers) also lose `SE_SESSION` unless the input asks for it. Helpers we spawn get a
minimal constructed environment. `status` and `doctor` name any stripped variable that is set.

## 4. Local listeners

### 4.1 Inventory
HTTP on `127.0.0.1:<port>`: `POST /mcp` and `GET /stateengine/mail/next_change` (plugin long-poll),
both session bearer; `GET /stateengine/livez` (anonymous, returns `{ok, api}` only);
`POST /stateengine/local-http-proof` (anonymous; the HMAC answer reveals nothing). IPC socket or pipe for
the CLI, hooks and `se mcp token`. Stdio `se mcp` with per-call capabilities. The draft's
`/stateengine/mcp-token` HTTP route is dropped: tokens are issued over IPC only.

### 4.2 HTTP admission, cheapest check first
1. Request target in origin-form; absolute-form refuses.
2. `Host` exactly `127.0.0.1:<port>` or `localhost:<port>` (stops DNS rebinding).
3. `Origin` absent, or exactly `http://127.0.0.1:<port>` / `http://localhost:<port>`; `null` and
   every other origin refuse. `Sec-Fetch-Site` present and not `same-origin`/`none` refuses.
4. Bearer required except `livez` and `local-http-proof`; looked up by hash, constant-time.
5. `POST` needs `Content-Type: application/json` (a form post from a web page cannot send it without
   a CORS preflight, and we never answer preflights: no `Access-Control-*` header is ever sent; `OPTIONS`
   gets 405).
6. Limits: 1 MiB body, 10 s for headers, 30 s per ordinary request, long-poll held at most 25 s (Claude's
   fetch ends at 30 s), 64 active connections total, one parked long-poll per session (a new one replaces
   the old). Parked long-polls have their own cap, equal to the session cap, and do not count toward the 64.
   Over limit is a refusal, never a queue that grows.

### 4.3 Port
Chosen once at `init` from a hash of the user's uid or SID in 20000–29999 (so OS users and a side-by-side
Node install on 3221 don't collide), bind-probed, persisted in `config.toml`. It never moves on its own,
because agents' MCP URLs name it; if something holds it at host start, the host refuses, naming the
holder's pid when readable and `se config set listener.port N`. A non-loopback address refuses before any
socket opens; alpha has no override.

**Squatting.** Another local user can take the port while our host is down. Claude would then send its
bearer to the squatter. So `se mcp token` first runs the local-http-proof against the port and prints no
header unless the HMAC verifies; the agent connects unauthenticated and the squatter learns nothing.

### 4.4 IPC
- **Unix:** socket in a 0700 directory (00 §5.4) whose owner is checked before bind; a stale socket is
  replaced only under `runtime.lock`. Peer check: `SO_PEERCRED` (Linux), `LOCAL_PEERCRED` +
  `LOCAL_PEERPID` (macOS); another uid refuses.
- **Windows:** `\\.\pipe\stateengine-<user-sid-hash>`, created with `FILE_FLAG_FIRST_PIPE_INSTANCE` (if
  someone else created it first, the host refuses and names it), `PIPE_REJECT_REMOTE_CLIENTS`, and a
  DACL granting only the user's SID. The host reads `GetNamedPipeClientProcessId`, opens the client's
  token and compares its user SID. Clients connect with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`
  so a squatting server cannot impersonate them, and check `GetNamedPipeServerProcessId` against the
  pid and start identity recorded in `endpoint.json`.
- Frames are length-prefixed JSON, at most 1 MiB, closed types with `deny_unknown_fields`.
- All peer and ACL calls live in se-proc, the only crate allowed `unsafe`.

## 5. File permissions per OS

| Object | Linux / macOS | Windows |
| --- | --- | --- |
| State, run and log directories | 0700, owner = euid, checked on every open | Explicit protected DACL: user SID full control + SYSTEM; inheritance from parent disabled |
| `state.db`, `-wal`, `-shm`, backups, `atlas.db` | 0600; the process sets `umask 077` before SQLite opens, since SQLite creates `-wal`/`-shm` after the db | Inherit the directory's protected DACL |
| `credential`, pins, `launch/<id>/*`, `endpoint.json` | 0600, created `O_EXCL` | Created with explicit security attributes; DACL read back |
| Socket / pipe | Socket inside the 0700 directory | Pipe DACL as §4.4 |
| Support bundle, `backup PATH` | 0600 at the user's chosen path | Created with the user-only DACL |
| Repo-local integration files | User's existing mode, untouched | Untouched |

**Readback (G8).** se-proc reads every secret-bearing file's mode or DACL back after creating it: owner
is the current user, and no ACE grants anyone but that user and SYSTEM. On each open of the store or
credential, a looser mode is a refusal naming `se doctor --fix`, never a silent chmod. No encryption at
rest: the key would sit beside the data under the same user, so OS disk encryption is the honest answer.

## 6. Secrets in captured turns, and `se forget`

Capture copies what the provider wrote, so a key the agent printed is now in our store. We run no
scanner that pretends to clean turns; a filter that misses one shape fakes confidence. Capture follows
per-session consent (incognito captures nothing); `se search sk-ant` finds candidates and
`se forget --event ID…` erases them. Support bundles are built from an **allowlist** of fields
(versions, config keys, counts, error codes, redacted paths), so no text can enter by omission.

**`se forget` mechanics** (human-only, explicit event ids, expected revisions):
1. One transaction with `PRAGMA secure_delete=ON` on the writer: replace the body with an erasure
   marker keeping event id, actor, time, `vendor_turn_ref` and byte length (no hash: a short secret's
   hash can be brute-forced); delete it from FTS; append `turn.erased{event, by, reason}`.
2. Merge FTS (`INSERT INTO turns_fts(turns_fts) VALUES('optimize')`) so old segments lose the tokens,
   then `PRAGMA wal_checkpoint(TRUNCATE)` so no WAL frame keeps the old page.
3. Read back: a bounded raw-byte scan of `state.db` and WAL finds no erased bytes; search finds nothing.
4. Re-capture stays erased: the catch-up sweep dedups on the kept `vendor_turn_ref`.
5. The `ErasureReceipt` names what it couldn't reach: each automatic backup holding the record and when
   it rotates out, the provider transcript (Claude's or Codex's), original Node files an import read,
   and SSD or filesystem remnants.

This is the one sanctioned exception to append-only content (G2): the event stays, its content goes.

## 7. Supply chain

**Dependency policy.**
- Prefer SE Code's crates at its pins (tokio 1, hyper 1 server-only, rusqlite 0.40 `bundled`), with no
  duplicate of those or libsqlite3-sys in `cargo tree -d`.
- A new direct dependency needs one review sentence on why std or an existing dep can't do it. No build
  script that downloads. Release builds run `--locked --offline` from a vendored mirror.
- **No outbound network:** `cargo tree -i` finds no `rustls`, `native-tls`, `openssl`, `reqwest` or hyper
  client in the shipped binary. That is the cheap, honest proof that nothing phones home.

**`cargo-deny`** (`deny.toml` at the workspace root):
- licenses: allow MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, CC0-1.0; deny GPL, LGPL, AGPL
  and unlicensed (closed-source product);
- advisories: RustSec, deny vulnerabilities and yanked crates, warn on unmaintained;
- bans: duplicate versions of the four shared crates above denied; wildcard versions denied;
- sources: crates.io only; no git dependencies in the product.
Third-party notices are generated into the package from the lockfile, as the open-source-ready repo
rule requires.

**Signing** (needed before public downloads, not for building). Windows: Trusted Signing via
`signtool`, RFC 3161 timestamps, `se.exe` and installer, `signtool verify /pa` in the pipeline; the
signing identity stays in the CI service, never on a seat. macOS: Developer ID, hardened runtime, no
entitlements, notarized with `rcodesign` from Linux; a bare Mach-O can't be stapled, so ship a stapled
`.pkg`. Linux: `SHA256SUMS` signed with an offline minisign key, verified by the installer.
`se --version --json` reports commit, toolchain and lockfile hash.

## 8. Out of scope
Hostile code running as the same OS user (including a compromised agent with an unrestricted shell);
administrator or root; physical access, swap, hibernation files, crash dumps and SSD remnants;
encryption at rest; provider-side data (Claude and Codex transcripts and clouds); network attackers (no
remote access is built; multiplayer authentication is a later design); sandboxing agents (we pass safe
defaults, with full bypass only through a named profile, and the provider enforces them); denial of
service by same-user processes; and prompt injection beyond what the tool surface and authority rules
contain.
