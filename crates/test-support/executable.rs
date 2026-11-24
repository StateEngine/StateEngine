//! Fixture images can briefly have a writable descriptor inherited by another
//! test's fork, and on Windows a freshly written image can be held open by the
//! loader or a malware scan. Retry only those refusals before exec; never a
//! child exit.
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
            Err(error) if busy_image(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

/// Linux `ETXTBSY` (26) or Windows `ERROR_SHARING_VIOLATION` (32).
fn busy_image(error: &io::Error) -> bool {
    let code = error.raw_os_error();
    (cfg!(target_os = "linux") && code == Some(26)) || (cfg!(windows) && code == Some(32))
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
