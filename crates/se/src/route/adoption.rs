//! Owner-only installation of opt-in native provider hooks.
use crate::{bootstrap::Bootstrap, config::Origin};
use se_core::ops::*;
use se_types::{NativePath, Result, SeError};
use std::path::{Path, PathBuf};
pub(crate) struct Plan {
    provider: PathBuf,
    config_home: PathBuf,
    entries: Vec<(String, serde_json::Value)>,
}
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn prepare(cx: &Bootstrap, input: &ProjectInit) -> Result<Plan> {
    if input
        .provider
        .is_some_and(|p| p != se_core::config_policy::Provider::Claude)
    {
        return Err(SeError::invalid(
            "init --adopt provider",
            "Claude Code; other provider adoption is not available in this build",
        ));
    }
    let provider = se_host::adoption::resolve_provider(
        &cx.config.value,
        match &cx.config.origin {
            Origin::File(file) => Some(file.as_path()),
            _ => None,
        },
    )?;
    se_host::qualify_claude_adoption(&provider)?;
    let config_home = se_host::claude_config_home(&std::env::vars_os().collect::<Vec<_>>())?;
    if !config_home.is_absolute() {
        return Err(SeError::invalid(
            "Claude settings home",
            "an absolute native path",
        ));
    }
    let image = std::env::current_exe()
        .map_err(|e| se_core::scope::unreadable("installed executable", &e.to_string()))?;
    Ok(Plan {
        provider,
        config_home,
        entries: se_host::adoption::settings::hooks(&image, &cx.home)?,
    })
}
#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn prepare(_cx: &Bootstrap, _input: &ProjectInit) -> Result<Plan> {
    Err(SeError::invalid(
        "provider adoption",
        "a supported Linux or Windows installation",
    ))
}
pub(crate) fn install(
    cx: &Bootstrap,
    root: &Path,
    plan: Plan,
    output: &mut AnyOutput,
) -> Result<()> {
    let AnyOutput::ProjectInit(output) = output else {
        return Err(SeError::invalid(
            "adoption setup",
            "the committed project setup result",
        ));
    };
    let path = plan.config_home.join("settings.json");
    let expected_hooks = plan.entries.clone();
    let mut registration = match se_host::adoption::read(&cx.home)? {
        Some(saved) => {
            if saved.settings.to_local()? != path || saved.provider.to_local()? != plan.provider {
                return Err(SeError::invalid(
                    "provider adoption installation",
                    "the original provider and settings location; uninstall this integration before changing them",
                ));
            }
            saved
        }
        None => se_host::adoption::Registration {
            layout: se_host::adoption::settings::layout(&path, &plan.entries)?,
            installed: false,
            schema: 1,
            settings: NativePath::from_local(path.clone())?,
            provider: NativePath::from_local(plan.provider)?,
            config_home: NativePath::from_local(plan.config_home)?,
            hooks: se_host::adoption::settings::missing(&path, &plan.entries)?,
            projects: vec![],
        },
    };
    let selected = se_host::adoption::Project {
        project: output.value.project.id.clone(),
        root: NativePath::from_local(root.to_owned())?,
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
    // Journal before changing provider files: a partial install always retains
    // the exact entries that uninstall must remove, never a whole-file backup.
    se_host::adoption::publish(&cx.home, &registration)?;
    let changed = if registration.installed {
        false
    } else {
        let changed = se_host::adoption::settings::merge(&path, &registration.hooks)?;
        registration.installed = true;
        se_host::adoption::publish(&cx.home, &registration)?;
        changed
    };
    let installed = se_host::adoption::settings::missing(&path, &expected_hooks)?.is_empty();
    output.value.integrations.push(IntegrationEffect {
        path: path.display().to_string(),
        entry: "Claude Code user-started session hooks".into(),
        action: if changed {
            FileOutcome::Written
        } else {
            FileOutcome::Unchanged
        },
        witness: Witness {
            state: if installed { WitnessState::Witnessed } else { WitnessState::Unknown },
            method: "protected provider settings readback".into(),
            observed_at: receipt::timestamp(super::execute::now_us()?)?,
            detail: Some(if installed {
                "Exact integration entries read back; existing user hooks and provider permissions were preserved".into()
            } else {
                "Existing integration entries were edited or removed by the user; those edits were preserved, and capture and mail remain unconfirmed".into()
            }),
        },
    });
    output.value.next = NextStep {
        text: "Start Claude Code directly in this project".into(),
        command: "claude".into(),
        argv: vec!["claude".into()],
    };
    output.value.changed.push(if installed {
        "Enabled capture and mail for Claude sessions started directly in this registered project; provider permissions remain unchanged".into()
    } else {
        "Kept project adoption registered and preserved user edits to its provider hooks; capture and mail remain unconfirmed".into()
    });
    output.value.changed.push("If Claude asks whether to trust these StateEngine hooks, choose Allow to enable capture and mail; declining keeps Claude usable with the integration inactive".into());
    Ok(())
}

pub(crate) fn uninstall(cx: &Bootstrap) -> Result<Vec<IntegrationEffect>> {
    se_host::adoption::settings::uninstall(&cx.home)?.into_iter().map(|path| {
        Ok(IntegrationEffect { path: path.display().to_string(), entry: "Claude Code user-started session hooks".into(), action: FileOutcome::Removed, witness: Witness { state: WitnessState::Witnessed, method: "removed exact journaled entries; preserved unrelated hooks and edits".into(), observed_at: receipt::timestamp(super::execute::now_us()?)?, detail: Some("Provider settings, permissions and running provider processes were preserved; adoption registration revoked".into()) } })
    }).collect()
}
