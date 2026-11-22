//! Bounded diagnostic command reads, bracketed by the exact native identity.
//! The result grants no authority to signal a PID.
use crate::{ProcResult, ProcessIdentity, ProcessRead, read_process_until};
use std::time::Instant;

pub fn read_process_command(
    expected: &ProcessIdentity,
    deadline: Instant,
) -> ProcResult<Option<String>> {
    // The live identity carries the image the process reports now, which an
    // in-place update or rename can change under the same birth.
    let live = || -> ProcResult<Option<ProcessIdentity>> {
        match read_process_until(expected.machine.clone(), expected.pid, deadline)? {
            ProcessRead::Present(value) if value.identity.same_birth(expected) => {
                Ok(Some(value.identity))
            }
            ProcessRead::Present(value) => {
                Err(crate::support::changed(expected, Some(&value.identity)))
            }
            ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => Ok(None),
        }
    };
    let Some(current) = live()? else {
        return Ok(None);
    };
    // Linux reports the full command line from procfs instead.
    #[cfg(target_os = "linux")]
    let _ = current;
    #[cfg(target_os = "linux")]
    let command = {
        use std::io::Read;
        let path = format!("/proc/{}/cmdline", expected.pid.0);
        let result = std::fs::File::open(path).and_then(|file| {
            let mut bytes = Vec::new();
            file.take(65537).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(_) if live()?.is_none() => return Ok(None),
            Err(cause) => {
                return Err(crate::support::native(
                    crate::ProcErrorCode::IdentityUnreadable,
                    "read process command",
                    cause,
                ));
            }
        };
        if bytes.len() > 65536 {
            return Err(crate::support::capacity("process command bytes", 65536));
        }
        if bytes.iter().all(|byte| *byte == 0) {
            if live()?.is_none() {
                return Ok(None);
            }
            return Err(crate::support::input(
                "process command",
                "live process command is unreadable (empty cmdline)",
            ));
        }
        // Escape arbitrary bytes and controls rather than silently replacing
        // invalid UTF-8 or allowing a command to forge report lines.
        bytes
            .strip_suffix(&[0])
            .unwrap_or(&bytes)
            .split(|b| *b == 0)
            .map(|arg| format!("\"{}\"", arg.escape_ascii()))
            .collect::<Vec<_>>()
            .join(" ")
    };
    #[cfg(any(windows, target_os = "macos"))]
    let command = format!(
        "executable only: {}",
        current.image.display().to_string().escape_debug()
    );
    if live()?.is_none() {
        return Ok(None);
    }
    Ok(Some(command))
}
