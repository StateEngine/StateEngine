//! One successful version qualification, retained only for this warm harness.
//! Mutable shell, authentication, policy and actual readiness stay outside it.
use super::*;
use crate::client::lease::Deadline;
use se_proc::native_ipc::ExecutableStamp;

pub(super) struct Qualified {
    stamp: Option<ExecutableStamp>,
    minimum: (u16, u16, u16),
    pub version: ProviderVersion,
}
impl CodexHarness {
    async fn image_stamp(
        &self,
        command: &Path,
        deadline: &Deadline,
    ) -> Result<Option<ExecutableStamp>> {
        let command = command.to_owned();
        self.pool
            .run_owned(deadline, move || {
                ExecutableStamp::observe(&command).map_err(|e| {
                    se_core::scope::unreadable("Codex qualification image", &e.to_string())
                })
            })
            .await
    }
    pub(super) async fn qualify(
        &self,
        request: ProbeRequest,
        cx: CallContext,
        reuse: bool,
    ) -> Result<ProviderVersion> {
        let deadline = Deadline::idle()?.stage(cx.timeout)?;
        let stamp = if reuse {
            self.image_stamp(&request.command, &deadline).await?
        } else {
            None
        };
        let cached = {
            let qualified = self.probed.lock().map_err(|_| poisoned())?;
            qualified
                .as_ref()
                .filter(|entry| {
                    stamp.is_some()
                        && stamp == entry.stamp
                        && entry.minimum == crate::CODEX_MINIMUM_VERSION
                })
                .map(|entry| entry.version.clone())
        };
        let mut found = match cached {
            Some(version) => version,
            None => probe::probe(&request.command, deadline.remaining()?).await?,
        };
        #[cfg(windows)]
        {
            let environment = input::provider_environment();
            let candidates = self
                .pool
                .run_owned(&deadline, move || windows_shell::candidates(&environment))
                .await?;
            let mut selected = None;
            for shell in candidates {
                if windows_shell::probe(
                    &shell,
                    &self.pool,
                    &context(cx.generation, deadline.remaining()?),
                )
                .await?
                {
                    selected = Some(shell);
                    break;
                }
            }
            let shell = selected.ok_or_else(|| {
                incompatible(
                    "no standard unpackaged PowerShell candidate qualifies",
                    "Install the PowerShell MSI and retry; the sandbox will not be widened.",
                )
            })?;
            *self.windows_shell.lock().map_err(|_| poisoned())? = Some(shell);
        }
        if stamp.is_some() && self.image_stamp(&request.command, &deadline).await? != stamp {
            return Err(incompatible(
                "Codex executable changed during version qualification",
                "Retry the launch with the current executable.",
            ));
        }
        deadline.remaining()?;
        found.protocol = if cfg!(unix) {
            "app-server/private-unix-websocket"
        } else {
            "app-server/stdio-json-lines"
        }
        .into();
        *self.probed.lock().map_err(|_| poisoned())? = Some(Qualified {
            stamp,
            minimum: crate::CODEX_MINIMUM_VERSION,
            version: found.clone(),
        });
        Ok(found)
    }
}
