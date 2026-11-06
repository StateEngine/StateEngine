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
