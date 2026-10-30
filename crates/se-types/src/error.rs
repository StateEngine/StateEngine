//! Canonical error names from section 50, 2026-10-30; declarations only.
use crate::{AgentId, ProjectId, Result};
use serde_json::Value;
use std::{error::Error, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Internal,
    Cancelled,
}
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Code {
    /// U: got, suggestion? | unknown command `{got}` | → `se help` |
    UsageUnknownCommand,
    /// U: flag, command, suggestion? | `{command}` has no flag `{flag}` | → `se help {command}` |
    UsageUnknownFlag,
    /// U: command, argument | `{command}` needs {argument} | → `se help {command}` |
    UsageMissingArgument,
    /// U: argument, got, expected | {argument}: `{got}` is not {expected} | correct the value |
    UsageInvalidValue,
    /// U: flags[] | {flags} cannot be used together | pick one |
    UsageConflictingFlags,
    /// U: flag, command | `{flag}` has no meaning for `{command}` | drop the flag |
    FlagNotApplicable,
    /// U: op, field | `{field}` is not an input of {op} | → `se schema {op}` / tools/list |
    InputUnknownField,
    /// U: field, limit_bytes, got_bytes | {field} is {got_bytes} bytes; limit {limit_bytes} | shorten or split it |
    InputTooLarge,
    /// U: old, replacement | `{old}` was renamed | → `{replacement}` (template; fill placeholders) |
    Renamed,
    /// U: old, reason, workflow | `{old}` was retired: {reason} | {workflow} |
    CommandRetired,
    /// U: flag | `{flag}` was removed; projects come from the registry | → `se init --repo DIR` or `-p P` |
    LegacyRootFlag,
    /// R: feature | {feature} is turned off | → `se config set {feature}.enabled true` |
    FeatureDisabled,
    /// R: feature | this build of se does not include {feature} | install the standard build from stateengine.ai |
    FeatureNotBuilt,
    /// U: family, requested, served[] | {family} v{requested} is not served (have {served}) | → `--json` |
    JsonVersionUnsupported,
    /// U: name | no tool `{name}` | use tools/list |
    ToolUnknown,
    /// A: name, reason | `{name}` is not available to this session ({reason}) | ask the owner, or use tools/list |
    ToolNotAvailable,
    /// R: what | refusing to print {what} to a terminal | run it through a pipe (integrations only) |
    SecretToTerminalRefused,
    /// U: what | {what} is read from stdin, which is a terminal | pipe the input |
    StdinRequired,
    /// A: op | `{op}` is an owner command; agent sessions can't run it | run it in your own terminal (unset `SE_SESSION`) |
    OwnerRequired,
    /// A: op, reason (no-tty | agent-process-tree) | `{op}` needs you at an interactive terminal not started by an agent | run `se {op}` in a terminal you opened |
    HumanTerminalRequired,
    /// A: op | `{op}` acts as an agent and needs a launched session | → `se launch AGENT` |
    SessionRequired,
    /// R: path | no machine credential at {path} | → `se init` |
    MachineCredentialMissing,
    /// X: path, reason | can't read the machine credential: {reason} | → `se doctor` |
    MachineCredentialUnreadable,
    /// A: expected, actual | this StateEngine home belongs to {expected}, you are {actual} | use your own `SE_HOME` |
    OsUserMismatch,
    /// A: reason (malformed | unknown | bad-secret) | the session credential is not valid ({reason}) | relaunch: → `se launch AGENT` |
    CapabilityInvalid,
    /// A: session, at, reason | session {session} was ended at {at} ({reason}) | → `se launch AGENT` |
    CapabilityRevoked,
    /// A: session, at | the session token expired at {at} | the helper renews it; if not → `se launch AGENT` |
    CapabilityExpired,
    /// U: flag_project, session_project | `-p {flag_project}` conflicts with this session's project {session_project} | drop `-p` |
    ProjectConflictsSession,
    /// A: grant | this session lacks permission `{grant}` | owner: → `se config set agent.{agent}.can-create true -p P` |
    GrantRequired,
    /// A: message, recipient | only {recipient} can mark {message} read or dismissed | read it with `se msg read` as that agent, or leave it |
    NotRecipient,
    /// A: decision | agents can propose decisions but not approve them | owner: → `se decision ratify {decision}` |
    SelfApprovalRefused,
    /// A: reason (host | origin | bearer-missing | bearer-invalid | second-principal) | local server refused the request: {reason} | reconnect through `se mcp token`; non-loopback access is not supported |
    ListenerAdmissionRefused,
    /// U: choices[] {name,id,root} | which project? none registered here | → `se init` (none) or `se … -p NAME` |
    ProjectRequired,
    /// K: selector | no project `{selector}` | → `se status --all` |
    ProjectUnknown,
    /// U: selector, matches[] | `{selector}` names {n} projects | use the id: `-p prj_…` |
    ProjectAmbiguous,
    /// R: project, at | project {project} was removed at {at} | re-adopt: → `se init --repo {root}` |
    ProjectRemoved,
    /// X: path, reason | can't read project registrations: {reason} | → `se doctor` |
    RegistrationUnreadable,
    /// U: cwd, candidates[] | {cwd} is registered twice | → `-p P`, then `se doctor --fix` |
    CwdRegistrationAmbiguous,
    /// X: home, reason | can't read StateEngine home {home}: {reason} | → `se doctor` |
    HomeUnreadable,
    /// R: home, kind (network | synced | read-only) | {home} is on a {kind} location; the store needs a local disk | set `SE_HOME` to a local folder |
    HomeUnsupportedLocation,
    /// X: path, reason | can't read {path}: {reason} | fix permissions or → `se doctor` |
    ConfigUnreadable,
    /// R: path, line, column, problem | {path}:{line}:{column}: {problem} | edit the file |
    ConfigInvalid,
    /// U: key, suggestion? | no setting `{key}` | → `se config list` |
    ConfigKeyUnknown,
    /// U: key, got, expected | {key}: `{got}` is not {expected} | → `se config get {key} --origin` |
    ConfigValueInvalid,
    /// U: key, scope | `{key}` is a {scope} setting | drop or add `-p` |
    ConfigScopeInvalid,
    /// R: path, version, supported | {path} is format v{version}; this se reads v{supported} | upgrade se |
    ConfigVersionUnsupported,
    /// R: profile | no permission profile `{profile}` | → `se config list`; define `[profiles.{profile}]` |
    ProfileUnknown,
    /// R: profile | full bypass is only allowed through a saved, named profile | add `bypass = true` under `[profiles.NAME]`, then → `se config set agent.A.profile NAME` |
    BypassNotOptedIn,
    /// R: path | {path} does not exist | → `se init --repo DIR` with an existing folder |
    RepoNotFound,
    /// R: path | {path} is not a folder | pick the repository folder |
    RepoNotDirectory,
    /// C: path, project, root | {path} is inside project {project} ({root}) | use it: → `se status -p {project}` |
    RepoInsideProject,
    /// C: root, project, requested | {root} is already project {project} | rerun without `--name` |
    RepoNameMismatch,
    /// C: path, entry | you changed {entry} in {path}; StateEngine won't overwrite it | keep it, or delete the entry and → `se doctor --fix` |
    IntegrationConflict,
    /// R: path, reason | couldn't write {path}: {reason} | → `se doctor` |
    IntegrationWriteFailed,
    /// R: path, entry | wrote {entry} in {path} but read back something else | → `se doctor --fix` |
    IntegrationReadbackMismatch,
    /// U: choices[] | name the project to remove | → `se remove -p P` or `se remove --all` |
    RemoveTargetRequired,
    /// I: stopped[], unwitnessed[], remaining[] | removal partly done: {remaining} | → `se remove -p P` (idempotent) |
    RemoveIncomplete,
    /// R: home | no StateEngine data in {home} | → `se init` |
    StoreAbsent,
    /// X: path, reason (permission | io | not-sqlite | foreign-application-id) | can't read the store: {reason} | → `se doctor` |
    StoreUnreadable,
    /// X: path, check | the store failed its integrity check ({check}) | → `se doctor --fix` (restores from the newest good backup + salvage) |
    StoreCorrupt,
    /// R: store_version, supported | the store was written by a newer se (schema {store_version}) | upgrade se |
    StoreTooNew,
    /// V: from, to | the store needs an upgrade that only the runtime performs | → `se up` |
    StoreMigrationRequired,
    /// R: from, to, step, rollback_copy | upgrade {from}→{to} failed at {step}; old copy kept at {rollback_copy} | → `se doctor` |
    StoreMigrationFailed,
    /// V: waited_ms | the store stayed locked for {waited_ms} ms | retry (`Retry::After`) |
    StoreBusy,
    /// V: path, free_bytes | not enough disk space at {path} | free space and retry |
    StoreDiskFull,
    /// R: path | {path} is read-only | fix permissions or `SE_HOME` |
    StoreReadOnly,
    /// C: entity, expected, current | {entity} changed (you had revision {expected}, now {current}) | reread: → `se working-state` / `se decision show ID` |
    RevisionConflict,
    /// C: key, original_event | key `{key}` was used for a different request | use a new key |
    IdempotencyKeyReused,
    /// K: event | no event {event} in this project | → `se search QUERY` |
    EventUnknown,
    /// X: event, reason | event {event} exists but can't be decoded: {reason} | → `se doctor` |
    EventUnreadable,
    /// U: reason (malformed | other-project | other-principal) | this cursor isn't valid here ({reason}) | rerun without `--since` |
    CursorInvalid,
    /// I: oldest_available | the cursor is older than retained history | rerun without `--since` |
    CursorExpired,
    /// R: path | {path} already exists | choose another path |
    BackupDestinationExists,
    /// R: path, step, reason | backup failed at {step}: {reason} | → `se doctor` |
    BackupFailed,
    /// R: path | the backup at {path} didn't verify | → `se backup` to a new path |
    BackupReadbackMismatch,
    /// X: path, reason | can't read Node state at {path}: {reason} | check the path |
    ImportSourceUnreadable,
    /// R: path, found, supported[] | {path} is format {found}; supported: {supported} | upgrade Node StateEngine first, then import |
    ImportFormatUnsupported,
    /// R: path, pid? | the old StateEngine is still running on {path} | stop it with the old `se down`, then retry |
    ImportSourceActive,
    /// I: families[] {name, rejected, unreadable} | import finished with rejected rows | rerun (idempotent); see the receipt |
    ImportIncomplete,
    /// R: events[] | erasure needs typed confirmation | rerun in a terminal and type the first id |
    ForgetConfirmationRequired,
    /// R: event, kind | only captured turns and messages can be erased; {event} is a {kind} | pick a captured record |
    ForgetNotCapturedRecord,
    /// I: erased[], residual[] | erased in the store; copies remain in {residual} | delete or let backups expire; provider transcripts belong to Claude/Codex |
    ForgetIncomplete,
    /// V: op | `{op}` needs the StateEngine runtime | → `se up` |
    RuntimeNotRunning,
    /// V: reason, log | the runtime didn't start: {reason} | see {log}; → `se doctor` |
    RuntimeStartFailed,
    /// I: waited_ms | the runtime is still starting after {waited_ms} ms | → `se status` |
    RuntimeStartPending,
    /// R: host (secode | daemon), pid, version | the runtime is hosted by {host} | quit SE Code to stop it |
    RuntimeOwnedElsewhere,
    /// R: running, this | runtime {running} is running; this se is {this} | → `se down`, then retry |
    RuntimeVersionMismatch,
    /// R: pid? | the old Node StateEngine is running on this home | stop it with the old `se down` |
    LegacyRuntimeRunning,
    /// V: generation | the runtime is changing hosts | retry (`WhenRuntimeReady`) |
    RuntimeHandoverInProgress,
    /// I: deadline_ms, pending[] | shutdown didn't finish in time: {pending} | → `se down` |
    RuntimeDrainTimeout,
    /// I: pid, reason | stop requested but exit not confirmed: {reason} | → `se status` |
    RuntimeStopUnwitnessed,
    /// R: port, holder? | port {port} is in use | → `se config set runtime.listen_port N` |
    ListenerPortInUse,
    /// R: address | `{address}` is not loopback; only 127.0.0.1 is allowed | fix `runtime.listen_address` |
    ListenerNonLoopback,
    /// V: endpoint, reason | can't reach the runtime: {reason} | → `se status` |
    IpcUnavailable,
    /// R: client, host | client API {client} vs runtime {host} | upgrade the older side |
    ApiVersionUnsupported,
    /// V: op | this stdio server has no runtime; `{op}` can't act | → `se up` |
    CustodyUnavailableHostless,
    /// K: selector, suggestion? | no agent `{selector}` in {project} | → `se agent list` |
    AgentUnknown,
    /// U: selector, matches[] | `{selector}` matches {n} agents | use the id |
    AgentAmbiguous,
    /// C: name, agent | `{name}` is already agent {agent} | → `se launch {name}` or pick another name |
    AgentNameTaken,
    /// U: name, rule | `{name}`: {rule} | choose another name |
    AgentNameInvalid,
    /// U: got | `{got}` isn't a provider (claude, codex) | |
    ProviderUnsupported,
    /// R: provider, searched[] | can't find the {provider} CLI | install it (`Cmd::Manual`), or → `se config set providers.{provider}.command PATH` |
    ProviderCliNotFound,
    /// R: provider, found, minimum | {provider} {found} is older than {minimum} | upgrade {provider} |
    ProviderCliTooOld,
    /// R: provider, output | couldn't read the {provider} version | → `se doctor` |
    ProviderCliUnrecognized,
    /// R: provider, version, needed | {provider} {version} lacks {needed} | upgrade {provider} |
    ProviderProtocolUnsupported,
    /// R: agent, saved, requested | {agent}'s conversation is a {saved} conversation | → `se launch {agent} --new --provider {requested}` |
    ProviderChangeBreaksResume,
    /// R: agent | {agent} has no saved conversation to resume | → `se launch {agent} --new` |
    ResumeReferenceMissing,
    /// X: agent, conversation, reason | can't verify conversation {conversation}: {reason} | → `se launch {agent} --new` (starts fresh, explicitly) |
    ResumeReferenceUnverifiable,
    /// C: agent, pid, since | {agent} is already running (since {since}) | message it, or → `se stop {agent}` |
    AgentAlreadyRunning,
    /// C: agent, launch_id | {agent} is already being launched | retry |
    LaunchInFlight,
    /// I: agent, waited_ms, last_observed | {agent} started but wasn't ready after {waited_ms} ms | → `se agent show {agent}` |
    LaunchReadinessTimeout,
    /// R: agent, provider, exit_code?, stderr_tail | {provider} exited during launch: {stderr_tail} | fix the provider error, then → `se launch {agent}` |
    LaunchFailed,
    /// R: tried[] | no terminal window could be opened ({tried}) | → `se launch AGENT --detach`, or set `launch.terminal` |
    WindowUnavailable,
    /// R: parent | Windows won't let the agent outlive {parent} | → `se up` first, then launch |
    JobBreakawayRefused,
    /// R: path | Linux cgroup delegation is off ({path}) | enable systemd user delegation (`Cmd::Manual`, exact text in doctor) |
    CgroupDelegationMissing,
    /// R: phase, reason | Codex app-server failed at {phase}: {reason} | → `se doctor` |
    CodexAppServerFailed,
    /// R: agent | {agent} isn't running, so there is nothing to wake | → `se launch {agent}` |
    WakeNotRunning,
    /// I: agent, pid, reason | stop sent but {agent}'s exit isn't confirmed | → `se agent show {agent}`, then `se stop {agent}` |
    StopUnwitnessed,
    /// I: stopped[], failed[] | stopped {n}; not confirmed: {failed} | → `se stop AGENT` for each |
    StopPartial,
    /// K: session | no session {session} | → `se agent show AGENT` |
    SessionUnknown,
    /// A: reason | a session id alone can't bind ({reason}) | launch through se, or → `se doctor --fix` for your integration |
    SessionBindingUnproven,
    /// C: expected, current | session generation is {current}, not {expected} | reread and retry |
    SessionGenerationMismatch,
    /// R: session, at | session {session} ended at {at} | → `se launch AGENT` |
    SessionAlreadyEnded,
    /// R: session | capture is off for this session | relaunch without `--incognito` |
    CaptureConsentMissing,
    /// U: field, problem | turn {field}: {problem} | fix the integration (→ `se doctor`) |
    TurnInvalid,
    /// X: path, reason | can't read the transcript {path}: {reason} | → `se doctor` |
    TranscriptUnreadable,
    /// I: path, offset, size | {path} shrank below the read offset | captured turns stay; → `se status` |
    TranscriptTruncated,
    /// U: event, problem | Claude `{event}` payload: {problem} | → `se doctor` (hook exits 0 anyway) |
    HookPayloadInvalid,
    /// K: to, suggestion? | no agent `{to}` to send to | → `se agent list` |
    RecipientUnknown,
    /// R: to, project | {to} is in project {project} | send from that project |
    RecipientOtherProject,
    /// K: id | no message {id} | → `se msg list --all` |
    MessageUnknown,
    /// K: id | can't reply to {id}: not found | drop `--reply-to` |
    ReplyTargetUnknown,
    /// K: id | no decision {id} | → `se decision list` |
    DecisionUnknown,
    /// U: key | `{key}` isn't a valid decision key | use lowercase letters, digits, `.`, `_`, `-` |
    DecisionKeyInvalid,
    /// R: id, state, action | can't {action} {id}: it is {state} | → `se decision show {id}` |
    DecisionStateInvalid,
    /// R: prior, replacement, reason (same | cycle | prior-not-governing | replacement-not-pending) | can't supersede: {reason} | → `se decision list --history` |
    SupersedeInvalid,
    /// K: observation | no observation {observation} | → `se process list` |
    ObservationUnknown,
    /// A: observation | {observation} belongs to another caller | use your own handle |
    ObservationNotYours,
    /// U: got | processes are selected by observation, not pid | → `se process list` |
    BarePidRefused,
    /// R: pid, expected_start, found_start | pid {pid} now belongs to a different process | nothing to stop; → `se process inspect --observation O` |
    ProcessIdentityChanged,
    /// X: pid, reason | can't read pid {pid}'s identity: {reason} | retry; → `se doctor` |
    ProcessIdentityUnreadable,
    /// R: program | `{program}` not found on PATH | give a full path |
    CommandNotFound,
    /// R: program, reason | couldn't start {program}: {reason} | |
    SpawnFailed,
    /// R: cwd, workspace | {cwd} is outside the project folder {workspace} | use a path inside the project |
    CwdOutsideWorkspace,
    /// U: key | `{key}` can't be set for a managed process | drop it |
    EnvKeyNotAllowed,
    /// I: observation, deadline_ms, remaining[] | {n} processes still alive after {deadline_ms} ms | retry with a longer `--deadline` |
    StopDeadlineExceeded,
    /// R: project | no code index for {project} yet | → `se config set atlas.enabled true -p P` (indexes in the background; `se status` shows progress) |
    AtlasIndexAbsent,
    /// I: indexed, total | index is {indexed}/{total} files; results may be partial | retry later |
    AtlasIndexing,
    /// X: path, reason | can't read atlas.db: {reason} | → `se doctor --fix` (rebuilds the index) |
    AtlasUnreadable,
    /// R: path, root | {path} is outside {root} | use a project-relative path |
    AtlasPathOutsideRoot,
    /// K: path | {path} isn't indexed | → `se atlas find PATH --kind path` |
    AtlasPathUnknown,
    /// K: symbol | no symbol `{symbol}` | → `se atlas find {symbol}` |
    AtlasSymbolUnknown,
    /// U: symbol, candidates[] | `{symbol}` names {n} symbols | add `--path` |
    AtlasSymbolAmbiguous,
    /// R: path, language? | {language} files aren't parsed | text search: `--kind text` |
    AtlasLanguageUnsupported,
    /// R: path, size, budget | {path} ({size}) exceeds the parse budget | none; the file stays text-searchable |
    AtlasFileOverBudget,
    /// R: check | `doctor --fix` can't repair {check} | follow the check's own fix line |
    RepairNotSupported,
    /// R: change | refusing to {change}: it weakens safety defaults | change it yourself by named profile |
    RepairWouldWeakenDefaults,
    /// U: path, reason | can't write the bundle to {path}: {reason} | → `se doctor --bundle PATH` |
    BundleDestinationInvalid,
    /// V: op, deadline_ms | `{op}` didn't finish in {deadline_ms} ms | retry |
    DeadlineExceeded,
    /// Z: op | `{op}` was interrupted | rerun; writes are all-or-nothing |
    Cancelled,
    /// N: task, report_id | internal task {task} failed ({report_id}) | → `se doctor --bundle` and send it |
    TaskFailed,
    /// N: report_id, location | StateEngine hit a bug ({report_id}) | → `se doctor --bundle` and send it |
    Internal,
}
/// Implement with exhaustive matches; adding a Code requires class/message/remedy.
pub trait ErrorCode {
    fn as_str(&self) -> &'static str;
    fn class(&self) -> Class;
    fn message(&self) -> String;
    fn remedy(&self, cx: &RenderCx) -> Remedy;
}
pub trait ErrorClass {
    fn exit_code(self) -> u8;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Argument {
    Literal(String),
    Placeholder(String),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Argv {
    pub args: Vec<Argument>,
}
pub trait LiteralCommand {
    fn literal_argv(&self) -> Result<Vec<&str>>;
}
#[derive(Clone, Debug, PartialEq)]
pub enum Cmd {
    Se(Argv),
    Tool { name: &'static str, args: Value },
    Manual,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Remedy {
    pub text: String,
    pub command: Option<Cmd>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderCx {
    pub project: Option<ProjectId>,
    pub agent: Option<AgentId>,
    pub terminal: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Detail {
    None,
    Field { field: String },
    Resource { resource: String, cause: String },
    Version { offered: String, supported: String },
    Conflict { expected: String, observed: String },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Retry {
    Never,
    AfterReread,
    After(Duration),
    WhenRuntimeReady,
}
#[derive(Debug)]
pub struct SeError {
    pub code: Code,
    pub retry: Retry,
    pub detail: Detail,
    pub cause: Option<Box<dyn Error + Send + Sync>>,
}
pub trait ErrorValue: Sized + Error {
    fn new(code: Code, detail: Detail) -> Self;
    fn with_retry(self, retry: Retry) -> Self;
    fn code(&self) -> Code;
    fn class(&self) -> Class;
    fn detail(&self) -> &Detail;
    fn retry(&self) -> &Retry;
    fn remedy(&self, cx: &RenderCx) -> Remedy;
}
/// Decoder validates class/exit against the code; source errors are never serialized.
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorEnvelope {
    pub schema: String,
    pub code: Code,
    pub class: Class,
    pub exit: u8,
    pub message: String,
    pub detail: Detail,
    pub retry: Retry,
    pub remedy: Remedy,
}
