//! Finite read-only Git commands; pack windows do not map whole pack files.
//! The caller supplies an isolated private Git directory and registered objects.
use std::{io, path::Path, process::ExitStatus, time::Instant};
pub const OUTPUT_BYTES: usize = 65_536;
pub const STDERR_BYTES: usize = 4096;
pub enum GitRead<'a> {
    Log {
        start: &'a str,
        commits: u16,
    },
    Changed {
        commit: &'a str,
        parent: Option<&'a str>,
    },
    RootTree {
        commit: &'a str,
    },
}
pub struct GitOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
impl GitRead<'_> {
    #[cfg(target_os = "linux")]
    fn arguments(&self) -> io::Result<Vec<String>> {
        let mut args = Vec::new();
        match self {
            Self::Log { start, commits } => {
                oid(start)?;
                if !(1..=129).contains(commits) {
                    return Err(invalid("Git history commit bound must be 1..129"));
                }
                args.extend(
                    [
                        "log",
                        "--first-parent",
                        "--no-show-signature",
                        "--no-decorate",
                        "--no-notes",
                        "--no-patch",
                        "-z",
                        "--format=%H%x00%P%x00%at%x00%an%x00%s%x00",
                    ]
                    .map(str::to_owned),
                );
                args.push(format!("--max-count={commits}"));
                args.push((*start).into());
                args.push("--".into());
            }
            Self::Changed { commit, parent } => {
                oid(commit)?;
                args.extend(
                    [
                        "diff-tree",
                        "--name-only",
                        "-z",
                        "--no-commit-id",
                        "-r",
                        "--no-renames",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--ignore-submodules=all",
                    ]
                    .map(str::to_owned),
                );
                if let Some(parent) = parent {
                    oid(parent)?;
                    args.push((*parent).into());
                } else {
                    args.push("--root".into());
                }
                args.push((*commit).into());
                args.push("--".into());
            }
            Self::RootTree { commit } => {
                oid(commit)?;
                args.extend([
                    "rev-parse".into(),
                    "--verify".into(),
                    format!("{commit}^{{tree}}"),
                ]);
            }
        }
        Ok(args)
    }
}
pub fn oid(value: &str) -> io::Result<()> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(
            "Git history requires an exact SHA-1 or SHA-256 object ID",
        ));
    }
    Ok(())
}
/// Native bounds apply before exec; neither this call nor its child raises the
/// inherited cold-worker address-space limit. No shell, hooks, network or pager.
pub fn read(
    image: &Path,
    control: &Path,
    objects: &Path,
    command: GitRead<'_>,
    deadline: Instant,
) -> io::Result<GitOutput> {
    let control_root = crate::NativeSourceRoot::open(control)?;
    let object_root = crate::NativeSourceRoot::open(objects)?;
    read_pinned(
        image,
        control,
        objects,
        [&control_root, &object_root],
        command,
        deadline,
    )
}
fn read_pinned(
    image: &Path,
    control: &Path,
    objects: &Path,
    roots: [&crate::NativeSourceRoot; 2],
    command: GitRead<'_>,
    deadline: Instant,
) -> io::Result<GitOutput> {
    if !image.is_absolute()
        || !control.is_absolute()
        || !objects.is_absolute()
        || deadline <= Instant::now()
        || deadline.saturating_duration_since(Instant::now()) > std::time::Duration::from_secs(900)
    {
        return Err(invalid(
            "absolute Git image/control/object paths and a live deadline are required",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::read(
            image,
            control,
            objects,
            roots,
            command.arguments()?,
            deadline,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (image, control, objects, roots, command, deadline);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bounded Git history process containment is not qualified on this platform",
        ))
    }
}
fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_owned())
}
mod control;
#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
mod linux;
mod objects;
mod repository;
pub use repository::{
    GitCommit, GitRegistration, GitRepository, GitWindow, HistoryLimit, MAX_COMMITS, WINDOW_BYTES,
};
