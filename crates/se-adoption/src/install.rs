//! Owner-only installation of opt-in native provider hooks.
use super::Kind;
use se_core::ops::*;
use se_types::{NativePath, Result, SeError};
use std::path::{Path, PathBuf};
pub struct Plan {
    kind: Kind,
    provider: PathBuf,
    config_home: PathBuf,
    entries: Vec<(String, serde_json::Value)>,
    /// The lifecycle hooks capture and mail need, whoever owns them; the
    /// optional Atlas entry is not among them.
    required: Vec<(String, serde_json::Value)>,
}
#[cfg(any(target_os = "linux", windows))]
pub fn prepare(
    home: &Path,
    configuration: &se_config::config_policy::ConfigFile,
    file: Option<&Path>,
    selected: Option<se_config::config_policy::Provider>,
    host: &super::HostSetup,
) -> Result<Plan> {
    let kind = match selected.unwrap_or(se_config::config_policy::Provider::Claude) {
        se_config::config_policy::Provider::Claude => Kind::Claude,
        se_config::config_policy::Provider::Codex => Kind::Codex,
        _ => {
            return Err(SeError::invalid(
                "init --adopt provider",
                "Claude Code or Codex",
            ));
        }
    };
    let adapter = kind.adapter();
    let provider = super::resolve_provider_for(kind, configuration, file, host.resolve)?;
    let super::ProviderSetup {
        executable: provider,
        config_home,
    } = adapter.prepare(&provider, host)?;
    if !config_home.is_absolute() {
        return Err(SeError::invalid(
            "provider settings home",
            "an absolute native path",
        ));
    }
    let image = std::env::current_exe()
        .and_then(se_proc::canonicalize_path)
        .map_err(|e| se_core::scope::unreadable("installed executable", &e.to_string()))?;
    Ok(Plan {
        kind,
        provider,
        config_home,
        entries: adapter.hooks(
            &image,
            home,
            configuration.atlas.enabled && configuration.atlas.hooks,
        )?,
        required: adapter.hooks(&image, home, false)?,
    })
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn prepare(
    _home: &Path,
    _configuration: &se_config::config_policy::ConfigFile,
    _file: Option<&Path>,
    _selected: Option<se_config::config_policy::Provider>,
    _host: &super::HostSetup,
) -> Result<Plan> {
    Err(SeError::invalid(
        "provider adoption",
        "a supported Linux or Windows installation",
    ))
}
pub struct Installed {
    pub integration: IntegrationEffect,
    pub next: NextStep,
    pub changed: Vec<String>,
}
pub fn install(
    home: &Path,
    root: &Path,
    plan: Plan,
    project: &se_types::ProjectId,
) -> Result<Installed> {
    let kind = plan.kind;
    let adapter = kind.adapter();
    let path = plan.config_home.join(kind.settings());
    se_proc::native_ipc::prepare_adoption_image_cache(
        home,
        &plan.provider,
        &se_proc::native_ipc::IpcIoBound {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )
    .map_err(|e| se_core::scope::unreadable("adoption executable cache", &e.to_string()))?;
    let (mut registration, write_plan) = registration(home, root, &plan, project)?;
    // Journal before changing provider files: a partial install or upgrade
    // always retains the exact entries that uninstall must remove, never a
    // whole-file backup.
    super::publish_for(home, kind, &registration)?;
    let fresh = matches!(write_plan, WritePlan::Fresh(_));
    let changed = match write_plan {
        WritePlan::Fresh(planned) => super::settings::commit(&path, planned)?,
        WritePlan::Upgrade(planned) => {
            let changed = super::settings::commit(&path, planned)?;
            if let Some(upgrade) = registration.upgrade.as_mut() {
                upgrade.phase = super::UpgradePhase::AwaitingDiscovery;
                super::publish_for(home, kind, &registration)?;
            }
            changed
        }
        WritePlan::None => false,
    };
    let absent = super::settings::missing(&path, &plan.required)?;
    let installed = absent.is_empty();
    let unfinished = !registration.installed
        || registration.discovery_refusal.is_some()
        || registration.upgrade.as_ref().is_some_and(|u| {
            u.entries
                .iter()
                .any(|entry| plan.required.contains(entry) && absent.contains(entry))
        });
    if unfinished && !installed {
        return Err(missing_resumed_hooks(&path, &absent));
    }
    confirm_discovery(
        home,
        root,
        &path,
        &plan,
        &mut registration,
        installed,
        fresh,
    )?;
    let active = adapter.active(home, project)?;
    let integration = integration(kind, &path, changed, installed, active)?;
    let next = NextStep {
        text: format!("Start {} directly in this project", kind.label()),
        command: kind.name().into(),
        argv: vec![kind.name().into()],
    };
    let mut changes = vec![if installed && active {
        format!(
            "Enabled capture and mail for {} sessions started directly in this registered project; provider permissions remain unchanged",
            kind.label()
        )
    } else {
        "Registered project adoption; capture and mail remain unconfirmed until the provider runs its installed hooks".into()
    }];
    if let Some(notice) = adapter.notice() {
        changes.push(notice);
    }
    Ok(Installed {
        integration,
        next,
        changed: changes,
    })
}

/// An earlier install stopped before it finished. Its hooks may have landed
/// and been removed since, so they are never written again here.
fn missing_resumed_hooks(path: &Path, absent: &[(String, serde_json::Value)]) -> SeError {
    let entries: Vec<_> = absent
        .iter()
        .map(|(event, entry)| format!("{event}: {entry}"))
        .collect();
    SeError::invalid(
        "provider adoption installation",
        &format!(
            "these hooks an unfinished earlier install recorded in {}; they may have been removed there, so they were not added again. Add them back under hooks in that file, then run this command again: {}",
            path.display(),
            entries.join("; ")
        ),
    )
}

fn confirm_discovery(
    home: &Path,
    root: &Path,
    path: &Path,
    plan: &Plan,
    registration: &mut super::Registration,
    installed: bool,
    fresh: bool,
) -> Result<()> {
    let kind = plan.kind;
    let adapter = kind.adapter();
    let pending_upgrade = match &registration.upgrade {
        Some(upgrade) if installed => {
            let absent = super::settings::missing(path, &upgrade.entries)?;
            upgrade
                .entries
                .iter()
                .filter(|entry| !absent.contains(entry))
                .cloned()
                .collect()
        }
        _ => Vec::new(),
    };
    let discovery = if installed {
        if fresh {
            adapter.setup(home, registration, root, &plan.required)
        } else if !pending_upgrade.is_empty() {
            adapter.upgrade(home, registration, root, &pending_upgrade, &plan.required)
        } else {
            adapter.discover(home, registration, root, &plan.required)
        }
    } else {
        Ok(())
    };
    let refusal = discovery.as_ref().err().map(ToString::to_string);
    if registration.discovery_refusal != refusal {
        registration.discovery_refusal = refusal;
        super::publish_for(home, kind, registration)?;
    }
    // A persisted refusal is retryable evidence, never a successful install.
    discovery?;
    let mut finish = false;
    if !registration.installed {
        // Finished only once discovery confirmed it, so a refused fresh run or
        // retry stays unfinished until discovery succeeds.
        registration.installed = true;
        finish = true;
    }
    if installed && registration.upgrade.is_some() {
        registration.upgrade = None;
        finish = true;
    }
    if finish {
        super::publish_for(home, kind, registration)?;
    }
    Ok(())
}

enum WritePlan {
    None,
    Fresh(super::settings::Planned),
    Upgrade(super::settings::Planned),
}

/// The saved registration, or a new one whose custody and layout are exactly
/// what its planned write adds, with that plan. A saved installation that
/// never finished is only read, never written again; a completed installation
/// may upgrade only hooks it has never journaled (or an unfinished upgrade).
fn registration(
    home: &Path,
    root: &Path,
    plan: &Plan,
    project: &se_types::ProjectId,
) -> Result<(super::Registration, WritePlan)> {
    let kind = plan.kind;
    let path = plan.config_home.join(kind.settings());
    let (mut registration, write_plan) = match super::read_for(home, kind)? {
        Some(mut saved) => {
            if saved.settings.to_local()? != path || saved.provider.to_local()? != plan.provider {
                return Err(SeError::invalid(
                    "provider adoption installation",
                    "the original provider and settings location; uninstall this integration before changing them",
                ));
            }
            if !saved.installed {
                // Whether the unfinished write landed is unknown, so this only
                // reads: an absent entry the configuration no longer requests
                // leaves custody, and nothing is written again.
                let absent = super::settings::missing(&path, &saved.hooks)?;
                saved
                    .hooks
                    .retain(|entry| plan.entries.contains(entry) || !absent.contains(entry));
                let hooks = &saved.hooks;
                saved
                    .layout
                    .created_events
                    .retain(|event| hooks.iter().any(|(known, _)| known == event));
                (saved, WritePlan::None)
            } else {
                let write_plan = plan_upgrade(&path, plan, &mut saved)?;
                (saved, write_plan)
            }
        }
        None => {
            let planned = super::settings::plan(&path, &plan.entries)?;
            let registration = super::Registration {
                layout: planned.layout.clone(),
                installed: false,
                schema: 1,
                settings: NativePath::from_local(path.clone())?,
                provider: NativePath::from_local(plan.provider.clone())?,
                config_home: NativePath::from_local(plan.config_home.clone())?,
                hooks: planned.entries.clone(),
                projects: vec![],
                discovery: None,
                discovery_refusal: None,
                installation: Some(uuid::Uuid::new_v4().to_string()),
                upgrade: None,
            };
            (registration, WritePlan::Fresh(planned))
        }
    };
    let selected = super::Project {
        project: project.clone(),
        root: NativePath::from_local(root.to_owned())?,
        discovery: None,
    };
    if !registration
        .projects
        .iter()
        .any(|p| p.root == selected.root && p.project == selected.project)
    {
        registration.projects.push(selected);
    }
    if registration.projects.len() > 4096 {
        return Err(SeError::invalid(
            "provider adoption",
            "at most 4096 registered projects",
        ));
    }
    Ok((registration, write_plan))
}

/// Plan appending only hooks never previously journaled on an active existing
/// adoption. Previously journaled hooks (including any from an interrupted
/// upgrade) are never re-appended, preserving owner removals.
fn plan_upgrade(path: &Path, plan: &Plan, saved: &mut super::Registration) -> Result<WritePlan> {
    if let Some(upgrade) = saved.upgrade.as_mut() {
        let absent = super::settings::missing(path, &upgrade.entries)?;
        let dropped: Vec<_> = upgrade
            .entries
            .iter()
            .filter(|entry| !plan.entries.contains(entry) && absent.contains(entry))
            .cloned()
            .collect();
        if !dropped.is_empty() {
            upgrade.entries.retain(|entry| !dropped.contains(entry));
            saved.hooks.retain(|entry| !dropped.contains(entry));
            let hooks = &saved.hooks;
            saved
                .layout
                .created_events
                .retain(|event| hooks.iter().any(|(known, _)| known == event));
        }
        if upgrade.entries.is_empty() {
            saved.upgrade = None;
        }
    }
    // Apply removal preservation only to previously owned required hooks; a
    // newly introduced required hook not yet in `saved.hooks` is still owed.
    let owned_required: Vec<_> = plan
        .required
        .iter()
        .filter(|entry| {
            saved.hooks.contains(entry)
                && !saved
                    .upgrade
                    .as_ref()
                    .is_some_and(|u| u.entries.contains(entry))
        })
        .cloned()
        .collect();
    if !super::settings::missing(path, &owned_required)?.is_empty() {
        return Ok(WritePlan::None);
    }
    let owed: Vec<_> = plan
        .entries
        .iter()
        .filter(|entry| !saved.hooks.contains(entry))
        .cloned()
        .collect();
    if owed.is_empty() {
        return Ok(WritePlan::None);
    }
    let planned = super::settings::plan(path, &owed)?;
    if planned.entries.is_empty() {
        return Ok(WritePlan::None);
    }
    for entry in &planned.entries {
        if !saved.hooks.contains(entry) {
            saved.hooks.push(entry.clone());
        }
    }
    match saved.upgrade.as_mut() {
        Some(upgrade) => {
            for entry in &planned.entries {
                if !upgrade.entries.contains(entry) {
                    upgrade.entries.push(entry.clone());
                }
            }
            upgrade.phase = super::UpgradePhase::Writing;
        }
        None => {
            saved.upgrade = Some(super::UpgradeJournal {
                entries: planned.entries.clone(),
                phase: super::UpgradePhase::Writing,
            });
        }
    }
    saved.layout.created_file |= planned.layout.created_file;
    saved.layout.created_hooks |= planned.layout.created_hooks;
    saved.layout.created_state |= planned.layout.created_state;
    for event in &planned.layout.created_events {
        if !saved.layout.created_events.contains(event) {
            saved.layout.created_events.push(event.clone());
        }
    }
    Ok(WritePlan::Upgrade(planned))
}

fn integration(
    kind: Kind,
    path: &Path,
    changed: bool,
    installed: bool,
    active: bool,
) -> Result<IntegrationEffect> {
    Ok(IntegrationEffect {
        path: path.display().to_string(),
        entry: format!("{} user-started session hooks", kind.label()),
        action: if changed {
            FileOutcome::Written
        } else {
            FileOutcome::Unchanged
        },
        witness: Witness {
            state: if installed && active {
                WitnessState::Witnessed
            } else {
                WitnessState::Unknown
            },
            method: if kind == Kind::Codex {
                "provider hook discovery and authenticated execution observation"
            } else {
                "protected provider settings readback"
            }
            .into(),
            observed_at: receipt::timestamp(now_us()?)?,
            detail: Some(if !installed {
                "Existing integration entries were edited or removed; those edits were preserved and capture and mail are unconfirmed".into()
            } else if kind == Kind::Codex && !active {
                "Provider discovered and trusted the installed hooks; awaiting the first authenticated hook run".into()
            } else {
                "Exact integration entries read back; existing user hooks and provider permissions were preserved".into()
            }),
        },
    })
}

pub fn uninstall(
    home: &Path,
) -> std::result::Result<Vec<IntegrationEffect>, (Vec<IntegrationEffect>, SeError)> {
    let mut effects = Vec::new();
    for kind in Kind::ALL {
        match super::settings::uninstall_steps(home, kind) {
            Ok(steps) => {
                if let Some(path) = steps.settings_edited {
                    match removed_hooks_effect(&path, kind) {
                        Ok(effect) => effects.push(effect),
                        Err(error) => return Err((effects, error)),
                    }
                }
                if let Some(journal) = steps.registration_revoked {
                    match revoked_registration_effect(&journal, kind) {
                        Ok(effect) => effects.push(effect),
                        Err(error) => return Err((effects, error)),
                    }
                }
            }
            Err(failure) => {
                if let Some(path) = failure.settings_edited
                    && let Ok(effect) = removed_hooks_effect(&path, kind)
                {
                    effects.push(effect);
                }
                if let Ok(effect) = failed_effect(&failure.failed_path, kind, &failure.error) {
                    effects.push(effect);
                }
                return Err((effects, failure.error));
            }
        }
    }
    Ok(effects)
}

fn removed_hooks_effect(path: &Path, kind: Kind) -> Result<IntegrationEffect> {
    Ok(IntegrationEffect {
        path: path.display().to_string(),
        entry: format!("{} user-started session hooks", kind.label()),
        action: FileOutcome::Removed,
        witness: Witness {
            state: WitnessState::Witnessed,
            method: "removed exact journaled entries; preserved unrelated hooks and edits".into(),
            observed_at: receipt::timestamp(now_us()?)?,
            detail: Some(
                "Provider settings, permissions and running provider processes were preserved"
                    .into(),
            ),
        },
    })
}

fn revoked_registration_effect(path: &Path, kind: Kind) -> Result<IntegrationEffect> {
    Ok(IntegrationEffect {
        path: path.display().to_string(),
        entry: format!("{} adoption registration", kind.label()),
        action: FileOutcome::Removed,
        witness: Witness {
            state: WitnessState::Witnessed,
            method: "native owned adoption registration removal".into(),
            observed_at: receipt::timestamp(now_us()?)?,
            detail: Some(
                "Adoption registration revoked; any remaining provider hooks are inert".into(),
            ),
        },
    })
}

fn failed_effect(path: &Path, kind: Kind, error: &SeError) -> Result<IntegrationEffect> {
    Ok(IntegrationEffect {
        path: path.display().to_string(),
        entry: format!("{} provider integration revocation", kind.label()),
        action: FileOutcome::Unreadable,
        witness: Witness {
            state: WitnessState::Failed,
            method: format!("{} provider integration revocation failed", kind.label()),
            observed_at: receipt::timestamp(now_us()?)?,
            detail: Some(error.to_string()),
        },
    })
}

fn now_us() -> Result<i64> {
    se_core::clock::now_us().map_err(|error| match error {
        se_core::clock::ClockError::BeforeEpoch(_) => {
            super::invalid("an observation clock after the Unix epoch")
        }
        se_core::clock::ClockError::OutOfRange => {
            super::invalid("a representable observation clock")
        }
    })
}
