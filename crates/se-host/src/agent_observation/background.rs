//! An agent's background processes: the live members of its owned native
//! scope other than its provider, StateEngine's own hook commands and a
//! Windows console host. Read on request from the scope se-proc already
//! tracks; nothing is polled or stored.
use se_core::ops::{BackgroundProcessView, BackgroundView};
use se_proc::{EnumerationExtent, NativeProcessRuntime, OwnedProcess, Population, ProcessIdentity};
use se_types::Read;
use std::{path::Path, time::Instant};

/// Console hosts the operating system attaches to a console process; they are
/// infrastructure, not work the agent started.
const CONSOLE_HOSTS: [&str; 2] = ["conhost.exe", "openconsole.exe"];

/// This agent's background processes, if the runtime retains its owned scope.
pub(crate) fn scope(
    native: &NativeProcessRuntime,
    process: &Option<std::sync::Arc<OwnedProcess>>,
) -> Option<Read<BackgroundView>> {
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    process
        .as_ref()
        .map(|process| observe(native, process, deadline))
}

/// The row's field: Codex runs tool commands in its shared app-server, so they
/// are never attributed to one agent and the row says so instead of zero.
pub(crate) fn row(
    provider: se_types::Provider,
    observed: Option<Read<BackgroundView>>,
) -> Option<Read<BackgroundView>> {
    match provider {
        se_types::Provider::Codex => Some(Read::Unknown {
            what: "Codex runs commands in its shared app-server, outside this agent's own processes, so they are not attributed to one agent.".into(),
        }),
        _ => observed,
    }
}

fn observe(
    native: &NativeProcessRuntime,
    process: &OwnedProcess,
    deadline: Instant,
) -> Read<BackgroundView> {
    let unreadable = |reason: String| Read::Unreadable {
        source: "agent process scope".into(),
        reason,
        error: None,
    };
    let observed = match native.observe_until(process, deadline) {
        Ok(observed) => observed,
        Err(error) => return unreadable(format!("{error:?}")),
    };
    let remaining = &observed.scope.remaining;
    if remaining.population == Population::Unknown
        || !matches!(remaining.extent, EnumerationExtent::Complete)
    {
        return Read::Unknown {
            what: "The agent's process scope could not be listed completely, so its background processes are not counted.".into(),
        };
    }
    let engine = std::env::current_exe().ok();
    let root = &observed.record.root;
    let mut members: Vec<&ProcessIdentity> = remaining
        .known_live
        .iter()
        .filter(|member| !infrastructure(member, root, engine.as_deref()))
        .collect();
    // Only the oldest start is shown, so only it pays for a wall-clock birth
    // read. One that exited since the listing is dropped and the next tried.
    members.sort_by_key(|member| start_order(&member.start));
    let mut oldest = None;
    let mut exited = 0_u32;
    for member in &members {
        match se_proc::observe_process_birth(member, deadline) {
            Ok(born) => {
                oldest = Some((born.unix_micros(), *member));
                break;
            }
            Err(error) if error.code == se_proc::ProcErrorCode::IdentityChanged => exited += 1,
            Err(error) => return unreadable(format!("{error:?}")),
        }
    }
    let processes = u32::try_from(members.len())
        .unwrap_or(u32::MAX)
        .saturating_sub(exited);
    let oldest = match oldest {
        Some((at, member)) => match se_core::ops::receipt::timestamp(at) {
            Ok(started_at) => Some(BackgroundProcessView {
                command: program(&member.image),
                started_at,
                started_at_us: at,
            }),
            Err(error) => return unreadable(error.to_string()),
        },
        None => None,
    };
    Read::Present {
        value: BackgroundView { processes, oldest },
    }
}

fn infrastructure(member: &ProcessIdentity, root: &ProcessIdentity, engine: Option<&Path>) -> bool {
    (member.pid == root.pid && member.start == root.start)
        || member.image == root.image
        || engine.is_some_and(|engine| member.image == engine)
        || CONSOLE_HOSTS
            .iter()
            .any(|host| program(&member.image).eq_ignore_ascii_case(host))
}

/// Native start order within one platform's start clock.
fn start_order(start: &se_proc::StartIdentity) -> u128 {
    match start {
        se_proc::StartIdentity::Linux { start_ticks } => u128::from(*start_ticks),
        se_proc::StartIdentity::Windows { creation_filetime } => u128::from(*creation_filetime),
        se_proc::StartIdentity::MacOs {
            seconds,
            microseconds,
        } => u128::from(*seconds) * 1_000_000 + u128::from(*microseconds),
    }
}

/// The program's file name only, never its arguments, which can carry secrets.
fn program(image: &Path) -> String {
    image
        .file_name()
        .map_or_else(|| image.to_string_lossy(), |name| name.to_string_lossy())
        .into_owned()
}
