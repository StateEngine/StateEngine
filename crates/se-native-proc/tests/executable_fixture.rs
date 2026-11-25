#![cfg(target_os = "linux")]
#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;

unsafe extern "C" {
    fn getpid() -> i32;
    fn write(fd: i32, bytes: *const u8, size: usize) -> isize;
    fn read(fd: i32, bytes: *mut u8, size: usize) -> isize;
}

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "executable-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0);
        assert!(
            removed.is_ok(),
            "remove only the owned scratch directory: {removed:?}"
        );
    }
}

/// A real sibling fork retains a writable CLOEXEC descriptor after the copying
/// thread closes its own handle. Failed exec never starts the copied image.
#[test]
fn inherited_writer_refuses_exec_then_launches_exactly_once_after_release() -> Check {
    let root = Scratch::new()?;
    let image = root.0.join("shell");
    fs::copy("/bin/sh", &image)?;
    let held = fs::OpenOptions::new().write(true).open(&image)?;
    let (mut reader, ready) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (mut release, proceed) = UnixStream::pair()?;
    let sibling = std::thread::spawn(move || -> std::io::Result<()> {
        let mut command = Command::new("/bin/true");
        // SAFETY: Only async-signal-safe syscalls run between fork and exec;
        // their buffers remain live on this child stack and descriptors are retained.
        unsafe {
            command.pre_exec(move || {
                let pid = getpid().to_ne_bytes();
                if write(ready.as_raw_fd(), pid.as_ptr(), pid.len()) != pid.len() as isize {
                    return Err(std::io::Error::last_os_error());
                }
                let mut byte = 0;
                if read(proceed.as_raw_fd(), &mut byte, 1) != 1 {
                    return Err(std::io::Error::other("fixture release closed"));
                }
                Ok(())
            });
        }
        let status = command.status()?;
        assert!(status.success());
        Ok(())
    });
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    let pid = i32::from_ne_bytes(bytes);
    drop(held);
    let inherited = fs::read_dir(format!("/proc/{pid}/fd"))?
        .find_map(|entry| {
            let entry = entry.ok()?;
            (fs::read_link(entry.path()).ok()? == image).then(|| entry.file_name())
        })
        .ok_or("sibling did not retain the copied image descriptor")?;
    let info = fs::read_to_string(format!(
        "/proc/{pid}/fdinfo/{}",
        inherited.to_string_lossy()
    ))?;
    let flags = u32::from_str_radix(
        info.lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .ok_or("native descriptor flags absent")?,
        8,
    )?;
    assert_ne!(flags & 1, 0, "inherited descriptor must be writable");
    assert_ne!(
        flags & 0o2000000,
        0,
        "CLOEXEC does not close a descriptor before exec"
    );
    let marker = root.0.join("executed");
    let make = || {
        let mut command = Command::new(&image);
        command
            .args(["-c", "printf once >> \"$FIXTURE_MARKER\"; exit 17"])
            .env("FIXTURE_MARKER", &marker);
        command
    };
    let refused = make()
        .output()
        .err()
        .ok_or("the inherited writer must prevent exec")?;
    assert_eq!(refused.raw_os_error(), Some(26));
    assert!(
        !marker.exists(),
        "kernel refusal must precede product execution"
    );
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        release.write_all(&[1])
    });
    let result = make().output_executable();
    release.join().map_err(|_| "release thread panicked")??;
    sibling.join().map_err(|_| "sibling thread panicked")??;
    let output = result?;
    assert_eq!(
        output.status.code(),
        Some(17),
        "a real child failure is not retried"
    );
    assert_eq!(fs::read_to_string(marker)?, "once");
    eprintln!(
        "native inherited writable CLOEXEC fd={inherited:?}, sibling={pid}; raw exec=ETXTBSY, executed once after release"
    );
    Ok(())
}

#[test]
fn persistent_writer_returns_the_original_native_error() -> Check {
    let root = Scratch::new()?;
    let image = root.0.join("shell");
    fs::copy("/bin/sh", &image)?;
    let _held = fs::OpenOptions::new().write(true).open(&image)?;
    let error = Command::new(image)
        .output_executable()
        .err()
        .ok_or("writer remains held")?;
    assert_eq!(error.raw_os_error(), Some(26));
    Ok(())
}

#[test]
fn unrelated_launch_errors_keep_their_native_cause() -> Check {
    let root = Scratch::new()?;
    let error = Command::new(root.0.join("absent"))
        .spawn_executable()
        .err()
        .ok_or("an absent executable stays absent")?;
    assert_eq!(error.raw_os_error(), Some(2));
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 23"]);
    assert_eq!(command.status_executable()?.code(), Some(23));
    Ok(())
}
