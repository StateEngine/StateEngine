//! Session adoption lives in `se-adoption`. The host supplies the policy it
//! owns: provider executable resolution and the first-setup Codex login.
pub use se_adoption::*;

#[cfg(feature = "listener")]
const HOST: se_adoption::HostSetup = se_adoption::HostSetup {
    resolve: crate::process::launch_util::resolve_provider,
    codex_login: crate::process::codex_server::setup_codex_login,
};

#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub fn resolve_provider(
    configuration: &se_config::config_policy::ConfigFile,
    file: Option<&std::path::Path>,
) -> se_types::Result<std::path::PathBuf> {
    resolve_provider_for(Kind::Claude, configuration, file)
}
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub fn resolve_provider_for(
    kind: Kind,
    configuration: &se_config::config_policy::ConfigFile,
    file: Option<&std::path::Path>,
) -> se_types::Result<std::path::PathBuf> {
    se_adoption::resolve_provider_for(kind, configuration, file, HOST.resolve)
}

#[cfg(feature = "listener")]
pub mod install {
    pub use se_adoption::install::*;
    use std::path::Path;

    pub fn prepare(
        home: &Path,
        configuration: &se_config::config_policy::ConfigFile,
        file: Option<&Path>,
        selected: Option<se_config::config_policy::Provider>,
    ) -> se_types::Result<Plan> {
        se_adoption::install::prepare(home, configuration, file, selected, &super::HOST)
    }
}
