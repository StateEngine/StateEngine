//! The stock remote TUI joins the exact thread through its existing private
//! Unix listener. Policy and credentials stay in the original thread RPC.
use super::*;
use std::ffi::OsString;

impl CodexHarness {
    pub(crate) fn console_arguments(
        &self,
        request: &HarnessRequest,
        conversation: &ProviderSessionId,
    ) -> Result<Vec<OsString>> {
        let socket = self.socket(request)?.ok_or_else(|| {
            incompatible(
                "attended Codex requires its private Unix listener",
                "Use headless Codex or attended Claude.",
            )
        })?;
        let socket = socket
            .to_str()
            .ok_or_else(|| SeError::invalid("Codex private listener", "a UTF-8 socket path"))?;
        Ok(vec![
            "resume".into(),
            conversation.as_str().into(),
            "--remote".into(),
            format!("unix://{socket}").into(),
            "--no-alt-screen".into(),
            "--cd".into(),
            request.cwd.to_local()?.into_os_string(),
        ])
    }
}
