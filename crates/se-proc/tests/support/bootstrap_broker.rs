//! Retain this control's own same-token broker before entering its strict job.
use std::{
    io::Read,
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Child, Command, Stdio},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{JobObjects::IsProcessInJob, Threading::*},
};

pub const ENTRY: &str = "--detached-broker-fixture";
type Result<T = ()> = std::result::Result<T, String>;

fn outside(process: HANDLE) -> Result {
    let mut member = 1;
    // SAFETY: retained child/current-process handle and initialized BOOL output.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(format!(
            "observe fixture job membership: {}",
            std::io::Error::last_os_error()
        ));
    }
    if member != 0 {
        return Err("fixture process is inside a Windows job".into());
    }
    Ok(())
}
pub fn child() -> Result {
    // SAFETY: immutable current-process pseudo handle, used only for observation.
    outside(unsafe { GetCurrentProcess() })?;
    // Only the retained parent's EOF ends this private helper; it launches nothing.
    let mut buffer = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err("broker fixture accepts only EOF".into()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.to_string()),
        }
    }
}
pub struct Fixture {
    child: Child,
    joined: bool,
}
impl Fixture {
    pub fn start() -> Result<Self> {
        let child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg(ENTRY)
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!(
                "UNQUALIFIED Windows broker control: venue cannot create its same-token outside-job fixture: {error}; run the standalone control from a native login that permits breakaway"
            ))?;
        let mut fixture = Self {
            child,
            joined: false,
        };
        outside(fixture.child.as_raw_handle()).map_err(|reason| {
            format!(
                "UNQUALIFIED Windows broker control: {reason}; no detached broker was established"
            )
        })?;
        if fixture
            .child
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("outside-job broker fixture exited before the consumer".into());
        }
        println!(
            "retained own outside-job broker fixture PID={}",
            fixture.child.id()
        );
        Ok(fixture)
    }
    pub fn finish(&mut self) -> Result {
        if self.joined {
            return Ok(());
        }
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                self.joined = true;
                if !status.success() {
                    return Err(format!(
                        "owned broker fixture exited unsuccessfully: {status}"
                    ));
                }
                println!("owned outside-job broker fixture exited and joined");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "owned broker fixture did not exit on EOF; native custody remains unqualified"
                        .into(),
                );
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("owned broker fixture cleanup: {error}");
        }
    }
}
