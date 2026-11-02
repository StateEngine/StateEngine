//! Output-only rendezvous with the public Windows uninstall script. The pipe
//! and token convey no admission: the normal owner checks and native envelope
//! must succeed before any handoff. The script owns the final outside readback.
use se_types::Result;
#[cfg(any(windows, test))]
use se_types::SeError;
use serde::{Deserialize, Serialize};

pub(crate) const DEFERRED_EXIT: u8 = 75;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pipe: String,
    token: String,
}
impl Request {
    #[cfg(any(windows, test))]
    fn validate(&self) -> Result<()> {
        if !self.pipe.starts_with("stateengine-uninstall-")
            || self.pipe.len() != 54
            || !self.pipe[22..].bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.token.len() != 64
            || !self.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SeError::invalid(
                "uninstall completion channel",
                "a local output pipe and 32-byte reply token created by uninstall.ps1",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn connect(&self) -> Result<Sender> {
        use std::os::windows::fs::OpenOptionsExt;
        self.validate()?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            // SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION: this output
            // recipient must never impersonate an elevated uninstall helper.
            .custom_flags(0x0010_0000 | 0x0001_0000)
            .open(format!(r"\\.\pipe\{}", self.pipe))
            .map_err(|error| {
                SeError::invalid(
                    "uninstall completion pipe",
                    "the waiting uninstall.ps1 output reader",
                )
                .with_cause(error)
            })?;
        Ok(Sender {
            file,
            token: self.token.clone(),
        })
    }
}
pub(crate) fn request() -> Result<Option<Request>> {
    #[cfg(windows)]
    {
        let pipe = std::env::var("SE_UNINSTALL_COMPLETION_PIPE");
        let token = std::env::var("SE_UNINSTALL_COMPLETION_TOKEN");
        if matches!(
            (&pipe, &token),
            (
                Err(std::env::VarError::NotPresent),
                Err(std::env::VarError::NotPresent)
            )
        ) {
            return Ok(None);
        }
        let request = Request {
            pipe: pipe.map_err(|e| {
                SeError::invalid("uninstall completion pipe", "the script's output pipe name")
                    .with_cause(e)
            })?,
            token: token.map_err(|e| {
                SeError::invalid("uninstall completion token", "the script's reply token")
                    .with_cause(e)
            })?,
        };
        request.validate()?;
        Ok(Some(request))
    }
    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

#[cfg(windows)]
std::thread_local! { static STARTED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) }; }
#[cfg(windows)]
pub(crate) fn mark_started(receiver: bool) {
    STARTED.set(Some(receiver));
}
pub(crate) fn take_started() -> Option<bool> {
    #[cfg(windows)]
    {
        STARTED.take()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
pub(crate) struct Sender {
    file: std::fs::File,
    token: String,
}
#[cfg(windows)]
impl Sender {
    pub(crate) fn finish(
        mut self,
        outcome: &Result<u8>,
        image: &std::path::Path,
        record: &std::path::Path,
        cleanup: &se_proc::UninstallHelperCleanup,
    ) -> Result<()> {
        use std::io::Write;
        // Success here covers the native image, owned record and directory
        // effects. The script must still observe the helper's teardown itself.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "se.uninstall-completion/v1",
            "token": self.token,
            "complete": matches!(outcome, Ok(0)),
            "error": outcome.as_ref().err().map(|error| format!("{}: {}", error.code().as_str(), error.body.message())),
            "image": image,
            "record": record,
            "helper": cleanup.path(),
            "directory": cleanup.directory_path(),
        }))
        .map_err(|error| {
            SeError::invalid(
                "uninstall completion reply",
                "a serializable helper outcome",
            )
            .with_cause(error)
        })?;
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.flush())
            .map_err(|error| {
                SeError::invalid(
                    "uninstall completion delivery",
                    "the live uninstall.ps1 output reader",
                )
                .with_cause(error)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channel_is_local_bounded_and_cannot_name_a_file_or_remote_pipe() {
        let mut request = Request {
            pipe: format!("stateengine-uninstall-{}", "a".repeat(32)),
            token: "b".repeat(64),
        };
        assert!(request.validate().is_ok());
        for pipe in [
            r"\\server\pipe\reply",
            r"C:\victim",
            "stateengine-uninstall-../victim",
            "stateengine-uninstall-é",
        ] {
            request.pipe = pipe.into();
            assert!(request.validate().is_err());
        }
        request.pipe = format!("stateengine-uninstall-{}", "a".repeat(32));
        request.token.clear();
        assert!(request.validate().is_err());
    }
}
