use super::events;
use super::*;
use crate::{CallContext, CancellationState, client::lease::Deadline};
use se_core::ops::agent_launch::LaunchPlan;
use se_types::{Result, Secret};

pub(super) fn call(generation: se_types::Generation, deadline: &Deadline) -> Result<CallContext> {
    Ok(CallContext {
        generation,
        timeout: deadline.remaining()?,
        cancellation: Arc::new(CancellationState { _private: () }),
    })
}
pub(super) async fn wait(wake: &events::Wake, deadline: &Deadline) -> Result<()> {
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline.at()),
        wake.event.notified(),
    )
    .await
    .map_err(|_| {
        se_core::scope::unreadable(
            "native process wait",
            "original launch/stop deadline expired; native custody is retained",
        )
    })?;
    deadline.remaining()?;
    Ok(())
}
pub(super) fn token(prefix: &str) -> Result<Secret> {
    let random = se_proc::random_secret().map_err(|e| error("session credential entropy", e))?;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut value = zeroize::Zeroizing::new(prefix.as_bytes().to_vec());
    let mut accumulator = 0u32;
    let mut bits = 0;
    for byte in random.expose() {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            value.push(ALPHABET[((accumulator >> bits) & 63) as usize]);
        }
    }
    if bits > 0 {
        value.push(ALPHABET[((accumulator << (6 - bits)) & 63) as usize]);
    }
    Secret::new(std::mem::take(&mut *value))
}
pub(super) fn policy(plan: &LaunchPlan, home: &std::path::Path) -> Result<se_proc::LaunchPolicy> {
    let scratch = home.join("launch").join(
        se_proc::session_launch_id(&plan.session)
            .map_err(|e| error("launch scratch", e))?
            .as_str(),
    );
    Ok(se_proc::LaunchPolicy {
        containment: se_proc::ContainmentRequirement::BestAvailable,
        writes: match plan.resolved.sandbox {
            se_core::config_policy::EffectiveSandbox::ReadOnly => {
                se_proc::WritePolicy::ReadOnly { scratch }
            }
            se_core::config_policy::EffectiveSandbox::WorkspaceWrite => {
                se_proc::WritePolicy::Workspace {
                    roots: vec![plan.cwd.to_local()?],
                    scratch,
                }
            }
            se_core::config_policy::EffectiveSandbox::Bypass => {
                se_proc::WritePolicy::NamedUnrestricted {
                    profile: plan.profile.named_profile.clone(),
                }
            }
        },
        network: if plan.resolved.network {
            se_proc::NetworkPolicy::Allow
        } else {
            se_proc::NetworkPolicy::Offline
        },
        hardening: se_proc::OptionalHardening::Off,
    })
}
pub(super) fn resolve_command(command: &str) -> Result<PathBuf> {
    let path = PathBuf::from(command);
    if path.is_absolute() {
        return se_proc::canonicalize_path(path).map_err(|e| error("provider executable", e));
    }
    if path.components().count() != 1 {
        return Err(se_types::SeError::invalid(
            "provider command",
            "an absolute path or executable name resolved through the host's explicit PATH",
        ));
    }
    let paths = std::env::var_os("PATH").ok_or_else(|| {
        se_core::scope::unreadable(
            "provider executable",
            "PATH is absent from the host's admitted environment",
        )
    })?;
    for directory in std::env::split_paths(&paths) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(command);
        if candidate.is_file() {
            return se_proc::canonicalize_path(candidate)
                .map_err(|e| error("provider executable", e));
        }
    }
    Err(se_core::scope::unreadable(
        "provider executable",
        "configured provider command was not found in absolute PATH entries",
    ))
}
pub(super) fn view(
    root: &se_proc::ProcessIdentity,
    deadline: std::time::Instant,
) -> Result<se_core::ops::ProcessView> {
    let born = se_proc::observe_process_birth(root, deadline)
        .map_err(|e| error("provider process birth", e))?;
    Ok(se_core::ops::ProcessView {
        pid: root.pid.0,
        started_at: se_core::ops::receipt::timestamp(born.unix_micros())?,
        exe: root.image.to_string_lossy().into_owned(),
        machine_id: root.machine.to_string(),
    })
}
