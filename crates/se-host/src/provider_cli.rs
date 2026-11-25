//! Whether a provider CLI is installed and meets the launch version floor, before any launch.
use crate::adoption::Kind;
use se_config::config_policy::ConfigFile;
use se_types::{Detail, Result, SeError};
use std::{path::PathBuf, time::Duration};

const BUDGET: Duration = Duration::from_secs(5);

/// One provider CLI as launch would find it. A refusal keeps the launch probe's own reason.
pub enum CliState {
    Ready {
        executable: PathBuf,
        version: String,
    },
    Missing,
    Refused(SeError),
}

pub fn observe(configuration: &ConfigFile, kind: Kind) -> CliState {
    let executable =
        match crate::resolve_provider_executable(configuration, kind.provider().into(), None, None)
        {
            Ok(executable) => executable,
            Err(error) if matches!(error.body.detail(), Detail::ProviderCliNotFound(_)) => {
                return CliState::Missing;
            }
            Err(error) => return CliState::Refused(error),
        };
    match version(&executable, kind) {
        Ok(version) => CliState::Ready {
            executable,
            version,
        },
        Err(error) => CliState::Refused(error),
    }
}

/// The same probes launch runs, on a private reactor so no caller runtime is blocked.
fn version(executable: &std::path::Path, kind: Kind) -> Result<String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        se_core::scope::unreadable("provider version probe", &error.to_string())
                    })?;
                runtime.block_on(async {
                    match kind {
                        Kind::Claude => se_harness::probe_claude_version(executable, BUDGET).await,
                        Kind::Codex => se_harness::codex_rpc::probe::probe(executable, BUDGET)
                            .await
                            .map(|probed| probed.version),
                    }
                })
            })
            .join()
            .map_err(|_| SeError::invalid("provider version probe", "a joined native probe"))?
    })
}
