//! Session adoption lives in `se-adoption`. The host supplies the policy it
//! owns: provider executable resolution and the first-setup Codex login.
pub use se_adoption::*;

#[cfg(feature = "listener")]
pub mod install {
    pub use se_adoption::install::*;
    use std::path::Path;

    const HOST: se_adoption::HostSetup = se_adoption::HostSetup {
        resolve: crate::process::launch_util::resolve_provider,
        codex_login: crate::process::codex_server::setup_codex_login,
    };

    pub fn prepare(
        home: &Path,
        configuration: &se_config::config_policy::ConfigFile,
        file: Option<&Path>,
        selected: Option<se_config::config_policy::Provider>,
    ) -> se_types::Result<Plan> {
        se_adoption::install::prepare(home, configuration, file, selected, &HOST)
    }
}
