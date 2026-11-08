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
#[cfg(unix)]
pub(super) fn stabilize_alias(
    mut invocation: crate::ProviderInvocation,
    required: bool,
) -> Result<crate::ProviderInvocation> {
    if !required {
        return Ok(invocation);
    }
    let selected = invocation.executable.to_local()?;
    // A native alias can exec an interpreter after its first image is observed.
    // Keep a stable parent in the owned scope instead of weakening root identity.
    // The fixed program passes separate argv words through "$@"; provider paths,
    // arguments and credentials are never interpolated into shell source.
    let parent =
        se_proc::canonicalize_path("/bin/sh").map_err(|e| error("provider alias supervisor", e))?;
    let mut arguments = vec![
        "-c".into(),
        concat!(
            "exec 3<&0; \"$@\" <&3 3<&- & se_provider_pid=$!; exec 3<&-; ",
            "trap 'kill -TERM \"$se_provider_pid\"; wait \"$se_provider_pid\"; exit $?' TERM; ",
            "trap 'kill -INT \"$se_provider_pid\"; wait \"$se_provider_pid\"; exit $?' INT; ",
            "wait \"$se_provider_pid\"; se_provider_status=$?; trap - TERM INT; exit \"$se_provider_status\""
        ).into(),
        "se-provider-alias".into(),
        selected.into_os_string(),
    ];
    arguments.append(&mut invocation.arguments);
    invocation.executable = NativePath::from_local(parent)?;
    invocation.arguments = arguments;
    Ok(invocation)
}
pub(super) fn policy(
    plan: &LaunchPlan,
    home: &std::path::Path,
    configuration: &se_core::config_policy::ConfigFile,
) -> Result<se_proc::LaunchPolicy> {
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
                    roots: super::git_workspace::roots(
                        plan.cwd.to_local()?,
                        configuration
                            .profiles
                            .get(&plan.profile.named_profile)
                            .is_some_and(|profile| profile.git_write),
                    )?,
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

// Every provider and launch surface uses the same native scratch grant. Inherit
// the owner's temp location only when its named profile explicitly bypasses it.
pub(super) fn route_temporary_files(
    environment: &mut se_proc::Environment,
    policy: &se_proc::LaunchPolicy,
) {
    let scratch = match &policy.writes {
        se_proc::WritePolicy::ReadOnly { scratch }
        | se_proc::WritePolicy::Workspace { scratch, .. } => scratch,
        se_proc::WritePolicy::NamedUnrestricted { .. } => return,
    };
    environment.entries.retain(|(key, _)| {
        !["TMPDIR", "TMP", "TEMP"].contains(&key.to_string_lossy().to_ascii_uppercase().as_str())
    });
    for key in ["TMPDIR", "TMP", "TEMP"] {
        environment
            .entries
            .push((key.into(), scratch.as_os_str().to_owned()));
    }
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_command(command: &str) -> Result<PathBuf> {
    let found = find_command(command, None)?.ok_or_else(|| {
        se_core::scope::unreadable(
            "provider executable",
            "configured command was not found in absolute PATH entries",
        )
    })?;
    se_proc::canonicalize_path(found).map_err(|e| error("provider executable", e))
}

pub(super) fn resolve_provider_command(
    command: &str,
    provider: se_types::Provider,
    configuration_file: Option<&std::path::Path>,
) -> Result<PathBuf> {
    let (name, title, install) = match provider {
        se_types::Provider::Codex => ("codex", "Codex", "https://developers.openai.com/codex/cli"),
        se_types::Provider::Claude => (
            "claude",
            "Claude Code",
            "https://code.claude.com/docs/en/setup",
        ),
    };
    let destination = match configuration_file {
        Some(path) => format!("configuration file {}", path.display()),
        None => "the host application's provider configuration".into(),
    };
    let help = se_types::Remedy {
        text: format!(
            "Configured {title} command: {command:?}. Install {title} using {install}, or set command to its native executable's absolute path under [providers.{name}] in {destination}. Restart this home's runtime from your owner terminal with the same configuration selection after changing PATH or configuration, then retry the launch."
        ),
        command: Some(se_types::Cmd::Manual),
    };
    let with_help = |mut error: se_types::SeError| {
        error.body = error.body.with_remedy(help.clone());
        error
    };
    match find_command(command, Some(provider)) {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Err(with_help(se_types::SeError::new(
            se_types::Detail::ProviderCliNotFound(se_types::details::ProviderCliNotFound {
                provider: name.into(),
                searched: vec![command.into()],
            }),
        ))),
        Err(error) => Err(with_help(error)),
    }
}

fn find_command(command: &str, provider: Option<se_types::Provider>) -> Result<Option<PathBuf>> {
    let path = PathBuf::from(command);
    if path.is_absolute() {
        return native_executable(&path, provider).map_err(|e| error("provider executable", e));
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
    let mut unreadable = None;
    for directory in std::env::split_paths(&paths) {
        if !directory.is_absolute() {
            continue;
        }
        match native_executable(&directory.join(command), provider) {
            Ok(Some(candidate)) => {
                // Multicall launchers select the provider through argv[0].
                // Image identity is still observed by the native process arena.
                return Ok(Some(candidate));
            }
            Ok(None) => (),
            Err(error) if unreadable.is_none() => unreadable = Some(error),
            Err(_) => (),
        }
    }
    match unreadable {
        Some(cause) => Err(error("provider executable", cause)),
        None => Ok(None),
    }
}
// Match native Windows executable lookup without invoking a command shell or
// treating an npm batch shim as an executable process image.
#[cfg(windows)]
#[path = "windows_executable.rs"]
mod windows_executable;

fn native_executable(
    path: &std::path::Path,
    provider: Option<se_types::Provider>,
) -> std::io::Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows_executable::resolve(path, provider)
    }
    #[cfg(not(windows))]
    {
        let _ = provider;
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(Some(path.to_path_buf())),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
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

#[cfg(test)]
mod temporary_environment_tests {
    use super::*;
    use se_proc::{Environment, LaunchPolicy, NetworkPolicy, OptionalHardening, WritePolicy};

    #[test]
    fn every_sandboxed_surface_replaces_all_temp_spellings_and_keeps_named_bypass() {
        let scratch = PathBuf::from("launch-scratch");
        for writes in [
            WritePolicy::ReadOnly {
                scratch: scratch.clone(),
            },
            WritePolicy::Workspace {
                roots: vec![PathBuf::from("project")],
                scratch: scratch.clone(),
            },
            WritePolicy::NamedUnrestricted {
                profile: "operator-bypass".into(),
            },
        ] {
            let bypass = matches!(writes, WritePolicy::NamedUnrestricted { .. });
            let mut environment = Environment {
                entries: vec![
                    ("TMPDIR".into(), "outside-one".into()),
                    ("Temp".into(), "outside-two".into()),
                    ("tmp".into(), "outside-three".into()),
                    ("PATH".into(), "provider-path".into()),
                ],
            };
            let before = environment.entries.clone();
            route_temporary_files(
                &mut environment,
                &LaunchPolicy {
                    containment: se_proc::ContainmentRequirement::BestAvailable,
                    writes,
                    network: NetworkPolicy::Offline,
                    hardening: OptionalHardening::Off,
                },
            );
            if bypass {
                assert_eq!(environment.entries, before);
            } else {
                assert_eq!(environment.entries.len(), 4);
                for key in ["TMPDIR", "TMP", "TEMP"] {
                    assert!(
                        environment
                            .entries
                            .iter()
                            .any(|(name, value)| name == key && value == scratch.as_os_str())
                    );
                }
                assert!(
                    environment
                        .entries
                        .iter()
                        .any(|(key, value)| key == "PATH" && value == "provider-path")
                );
            }
        }
    }
}
