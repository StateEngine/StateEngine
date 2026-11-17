//! Child streams share the reactor instead of occupying finite blocking workers.
use std::{
    io,
    ops::{Deref, DerefMut},
    process::Stdio,
};
use tokio::process::Command;
#[cfg(windows)]
mod windows;
#[cfg(not(windows))]
pub(crate) use tokio::process::ChildStdin as Input;
#[cfg(not(windows))]
pub(crate) use tokio::process::ChildStdout as Output;
#[cfg(windows)]
pub(crate) use windows::Pipe as Input;
#[cfg(windows)]
pub(crate) use windows::Pipe as Output;
#[cfg(not(windows))]
type ErrorOutput = tokio::process::ChildStderr;
#[cfg(windows)]
type ErrorOutput = Output;

pub(crate) struct Pipes {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

pub(crate) struct Child {
    process: tokio::process::Child,
    pub stdin: Option<Input>,
    pub stdout: Option<Output>,
    pub stderr: Option<ErrorOutput>,
}

impl Deref for Child {
    type Target = tokio::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.process
    }
}
impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.process
    }
}

/// Only requested streams are replaced; null/inherited streams retain their
/// command configuration. All pipe setup finishes before starting the child.
pub(crate) async fn spawn(command: &mut Command, pipes: Pipes) -> io::Result<Child> {
    #[cfg(windows)]
    {
        let mut ends = Vec::new();
        for (enabled, readable) in [
            (pipes.stdin, true),
            (pipes.stdout, false),
            (pipes.stderr, false),
        ] {
            ends.push(if enabled {
                Some(windows::pipe(readable).await?)
            } else {
                None
            });
        }
        let mut take = |index: usize| -> Option<Input> {
            ends[index].take().map(|(parent, child)| {
                match index {
                    0 => command.stdin(Stdio::from(child)),
                    1 => command.stdout(Stdio::from(child)),
                    _ => command.stderr(Stdio::from(child)),
                };
                parent
            })
        };
        let stdin = take(0);
        let stdout = take(1);
        let stderr = take(2);
        let spawned = command.spawn();
        // Command retains configured File handles across spawn. Release those
        // parent copies now, so child exit produces EOF even if Command lives.
        if pipes.stdin {
            command.stdin(Stdio::null());
        }
        if pipes.stdout {
            command.stdout(Stdio::null());
        }
        if pipes.stderr {
            command.stderr(Stdio::null());
        }
        let process = spawned?;
        Ok(Child {
            process,
            stdin,
            stdout,
            stderr,
        })
    }
    #[cfg(not(windows))]
    {
        if pipes.stdin {
            command.stdin(Stdio::piped());
        }
        if pipes.stdout {
            command.stdout(Stdio::piped());
        }
        if pipes.stderr {
            command.stderr(Stdio::piped());
        }
        let mut process = command.spawn()?;
        Ok(Child {
            stdin: process.stdin.take(),
            stdout: process.stdout.take(),
            stderr: process.stderr.take(),
            process,
        })
    }
}
