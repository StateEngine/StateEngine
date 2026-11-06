//! Fixture images can briefly have a writable descriptor inherited by another
//! test's fork. Retry only the kernel's refusal before exec; never a child exit.
use std::{
    io,
    process::{Child, Command, ExitStatus, Output},
    time::{Duration, Instant},
};

#[allow(
    dead_code,
    reason = "Each fixture uses only its required command operations."
)]
pub trait ExecutableCommand {
    fn spawn_executable(&mut self) -> io::Result<Child>;
    fn output_executable(&mut self) -> io::Result<Output>;
    fn status_executable(&mut self) -> io::Result<ExitStatus>;
}

fn before_exec<T>(mut launch: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match launch() {
            Err(error)
                if cfg!(target_os = "linux")
                    && error.raw_os_error() == Some(26)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

impl ExecutableCommand for Command {
    fn spawn_executable(&mut self) -> io::Result<Child> {
        before_exec(|| self.spawn())
    }
    fn output_executable(&mut self) -> io::Result<Output> {
        before_exec(|| self.output())
    }
    fn status_executable(&mut self) -> io::Result<ExitStatus> {
        before_exec(|| self.status())
    }
}
