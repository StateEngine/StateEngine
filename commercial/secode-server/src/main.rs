// SPDX-License-Identifier: LicenseRef-StateEngine-Proprietary
//! Website-only composition. The public SE Code executable supplies None.
mod native;
use secode_stateengine_api as api;
use std::{num::NonZeroU32, path::PathBuf};

fn main() {
    // Helpers and metadata use the public dispatch before any state access.
    // Only a persistent service owns an embedded host; volatile sessions stay
    // outside StateEngine by construction.
    let service = std::env::args_os().nth(1).is_some_and(|verb| {
        matches!(
            verb.to_str(),
            Some("serve" | "serve-service" | "serve-terminal" | "handover")
        )
    });
    if !service {
        secode_product::run(None);
        return;
    }
    match composition() {
        Ok(engine) => secode_product::run(Some(engine)),
        Err(error) => {
            eprintln!("StateEngine startup: {error}");
            std::process::exit(1);
        }
    }
}
fn composition() -> Result<secode_product::StateEngine, String> {
    let _initialized = se_host::initialize_host_process().map_err(|error| error.to_string())?;
    let state_home = state_home()?;
    let helper_executable = std::env::current_exe()
        .map_err(|error| format!("cannot read the installed server image: {error}"))?
        .with_file_name(if cfg!(windows) { "se.exe" } else { "se" });
    Ok(secode_product::StateEngine {
        factory: se_host::embedded_factory,
        epoch: native_epoch,
        config: api::HostConfig {
            state_home,
            helper_executable,
            linux_delegation: api::LinuxDelegation::AutoUserManager,
            api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode,
            features: Vec::new(),
            limits: api::Limits {
                page_items: positive(128)?,
                payload_bytes: positive(1024 * 1024)?,
                notice_ids: positive(128)?,
            },
        },
    })
}
fn positive(value: u32) -> Result<NonZeroU32, String> {
    NonZeroU32::new(value).ok_or_else(|| "linked host limit must be positive".to_owned())
}
fn variable(name: &str) -> Result<Option<PathBuf>, String> {
    match std::env::var_os(name) {
        Some(value) if value.is_empty() => Err(format!("{name} is empty")),
        value => Ok(value.map(PathBuf::from)),
    }
}
fn state_home() -> Result<PathBuf, String> {
    if let Some(home) = variable("SE_HOME")? {
        return if home.is_absolute() {
            Ok(home)
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(home))
                .map_err(|error| error.to_string())
        };
    }
    #[cfg(windows)]
    let home = required("LOCALAPPDATA")?.join("StateEngine");
    #[cfg(target_os = "macos")]
    let home = required("HOME")?.join("Library/Application Support/StateEngine");
    #[cfg(not(any(windows, target_os = "macos")))]
    let home = match variable("XDG_STATE_HOME")? {
        Some(path) if path.is_absolute() => path.join("stateengine"),
        Some(_) => return Err("XDG_STATE_HOME must be absolute".to_owned()),
        None => required("HOME")?.join(".local/state/stateengine"),
    };
    if !home.is_absolute() {
        return Err("StateEngine state directory must be absolute; set SE_HOME".to_owned());
    }
    Ok(home)
}
fn required(name: &str) -> Result<PathBuf, String> {
    variable(name)?
        .filter(|path| path.is_absolute())
        .ok_or_else(|| format!("{name} must name an absolute directory; set SE_HOME"))
}

fn native_epoch(config: &api::HostConfig) -> Result<api::HostEpoch, String> {
    native::epoch(&config.state_home)
}
