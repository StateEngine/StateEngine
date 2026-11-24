//! A detached host is stopped by `ChildCleanup` on every ordinary exit, but a
//! killed test process runs no Drop. This guard arms the home reaper alongside
//! that cleanup: the cleanup stops the host on the way out, while the reaper
//! keeps the fixture's own public down ready to run if the owner dies first.
use crate::*;

pub(super) struct ReaperGuard<'a> {
    cleanup: host_fixture::ChildCleanup<'a>,
    // Declared last: it disarms only after the cleanup has stopped the host.
    _reaper: home_reaper::HomeReaper,
}
impl<'a> ReaperGuard<'a> {
    pub(super) fn arm(
        f: &Fixture,
        ready: &'a host::StartedHost,
        credential: &'a Secret,
    ) -> std::io::Result<Self> {
        let image = f.home.join("fixture-down-se");
        std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
        let mut down = std::process::Command::new(&image);
        down.args(["--home"])
            .arg(&f.options.state_directory)
            .arg("down");
        for (name, _) in std::env::vars_os() {
            let value = name.to_string_lossy();
            if value.starts_with("SE_")
                || value.starts_with("STATEENGINE_")
                || value.starts_with("CODEX_")
                || value == "CLAUDECODE"
            {
                down.env_remove(name);
            }
        }
        provider_home::isolate(&mut down, &f.home);
        let cleanup = host_fixture::ChildCleanup {
            endpoint: &ready.endpoint,
            identity: &ready.ready.identity,
            credential,
        };
        Ok(Self {
            cleanup,
            _reaper: home_reaper::HomeReaper::arm(&down, &f.options.state_directory, false)?,
        })
    }
}
