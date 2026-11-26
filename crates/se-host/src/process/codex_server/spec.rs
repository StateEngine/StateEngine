//! Launch specification for the shared Codex app-server process.
use crate::{client::lease::Deadline, process::events};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
};

/// What the server needs from the launch that first asks for it.
pub(in crate::process) struct ServerLaunch {
    pub executable: PathBuf,
    /// Arguments before the server's own, such as an alias supervisor's.
    pub prefix: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub windows_sandbox: Option<&'static str>,
}

/// The stock server on the login's default control socket, in its own scope.
pub(super) fn codex_server_spec(
    lifecycle: se_types::LifecycleId,
    generation: se_proc::GenerationId,
    login: &Path,
    launch: ServerLaunch,
    scratch: &Path,
    deadline: &Deadline,
) -> se_proc::LaunchSpec {
    let mut environment = launch.environment;
    environment.retain(|(key, _)| {
        !["TMPDIR", "TMP", "TEMP"]
            .iter()
            .any(|name| key.to_string_lossy().eq_ignore_ascii_case(name))
    });
    for name in ["TMPDIR", "TMP", "TEMP"] {
        environment.push((name.into(), scratch.as_os_str().to_owned()));
    }
    let mut arguments = launch.prefix;
    if let Some(name) = launch.windows_sandbox {
        arguments.push("-c".into());
        arguments.push(format!("windows.sandbox={}", serde_json::json!(name)).into());
    }
    arguments.extend(["app-server".into(), "--listen".into(), "unix://".into()]);
    se_proc::LaunchSpec {
        executable_custody: None,
        lifecycle,
        generation,
        executable: launch.executable,
        arguments,
        cwd: login.to_owned(),
        environment: se_proc::Environment {
            entries: environment,
        },
        stdio: se_proc::StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        },
        mode: se_proc::LaunchMode::HeadlessPersistent,
        window: None,
        // Each agent's sandbox is set on its own thread; the server's scope
        // only routes its temporary files.
        policy: se_proc::LaunchPolicy {
            containment: se_proc::ContainmentRequirement::BestAvailable,
            writes: se_proc::WritePolicy::ReadOnly {
                scratch: scratch.to_owned(),
            },
            network: se_proc::NetworkPolicy::Allow,
            hardening: se_proc::OptionalHardening::Off,
        },
        deadline: deadline.at(),
        notifications: Arc::new(events::Wake::default()),
    }
}
