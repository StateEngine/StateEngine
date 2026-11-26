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
        entries: adapter.hooks(&image, home)?,
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
    let expected_hooks = plan.entries.clone();
    let mut registration = registration(home, root, &plan, project)?;
    se_proc::native_ipc::prepare_adoption_image_cache(
        home,
        &registration.provider.to_local()?,
        &se_proc::native_ipc::IpcIoBound {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )
    .map_err(|e| se_core::scope::unreadable("adoption executable cache", &e.to_string()))?;
    // Journal before changing provider files: a partial install always retains
    // the exact entries that uninstall must remove, never a whole-file backup.
    super::publish_for(home, kind, &registration)?;
    let changed = if registration.installed {
        false
    } else {
        let changed = super::settings::merge(&path, &registration.hooks)?;
        registration.installed = true;
        super::publish_for(home, kind, &registration)?;
        changed
    };
    let installed = super::settings::missing(&path, &expected_hooks)?.is_empty();
    let discovery = if installed {
        adapter.discover(home, &mut registration, root)
    } else {
        Ok(())
    };
    let refusal = discovery.as_ref().err().map(ToString::to_string);
    if registration.discovery_refusal != refusal {
        registration.discovery_refusal = refusal;
        super::publish_for(home, kind, &registration)?;
    }
    // A persisted refusal is retryable evidence, never a successful install.
    discovery?;
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

fn registration(
    home: &Path,
    root: &Path,
    plan: &Plan,
    project: &se_types::ProjectId,
) -> Result<super::Registration> {
    let kind = plan.kind;
    let path = plan.config_home.join(kind.settings());
    let mut registration = match super::read_for(home, kind)? {
        Some(saved) => {
            if saved.settings.to_local()? != path || saved.provider.to_local()? != plan.provider {
                return Err(SeError::invalid(
                    "provider adoption installation",
                    "the original provider and settings location; uninstall this integration before changing them",
                ));
            }
            saved
        }
        None => super::Registration {
            layout: super::settings::layout(&path, &plan.entries)?,
            installed: false,
            schema: 1,
            settings: NativePath::from_local(path.clone())?,
            provider: NativePath::from_local(plan.provider.clone())?,
            config_home: NativePath::from_local(plan.config_home.clone())?,
            hooks: super::settings::missing(&path, &plan.entries)?,
            projects: vec![],
            discovery: None,
            discovery_refusal: None,
            installation: Some(uuid::Uuid::new_v4().to_string()),
        },
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
    Ok(registration)
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

pub fn uninstall(home: &Path) -> Result<Vec<IntegrationEffect>> {
    let mut effects = Vec::new();
    for kind in Kind::ALL {
        for path in super::settings::uninstall_for(home, kind)? {
            effects.push(IntegrationEffect { path: path.display().to_string(), entry: format!("{} user-started session hooks", kind.label()), action: FileOutcome::Removed, witness: Witness { state: WitnessState::Witnessed, method: "removed exact journaled entries; preserved unrelated hooks and edits".into(), observed_at: receipt::timestamp(now_us()?)?, detail: Some("Provider settings, permissions and running provider processes were preserved; adoption registration revoked".into()) } });
        }
    }
    Ok(effects)
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
