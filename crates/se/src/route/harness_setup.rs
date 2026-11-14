//! Prepare a catalogue choice from an existing installation before setup writes.
use crate::bootstrap::Bootstrap;
use se_config::config_policy::ConfigFile;
use se_core::{harness_selection::catalog, ops::ProjectInit};
use se_types::{Result, SeError};

pub(super) fn prepare(cx: &Bootstrap, input: &ProjectInit) -> Result<ConfigFile> {
    let mut configuration = cx.config.value.clone();
    let Some(name) = input.harness.as_deref() else {
        return Ok(configuration);
    };
    if configuration.harnesses.contains_key(name) {
        return Ok(configuration);
    }
    let Some(preset) = catalog::presets()?.get(name) else {
        return Ok(configuration);
    };
    if input
        .provider
        .is_some_and(|provider| provider != se_types::Provider::Acp)
    {
        return Err(SeError::invalid(
            "harness provider",
            "this named harness uses provider acp; select --provider acp or omit --provider",
        ));
    }
    let mut descriptor = preset.descriptor.clone();
    let defaults = &configuration.providers.acp;
    let native = descriptor.permissions.remove("default").ok_or_else(|| {
        SeError::invalid(
            "harness catalogue",
            "an announced native permission default",
        )
    })?;
    descriptor
        .permissions
        .insert(defaults.profile.clone(), native);
    configuration
        .harnesses
        .insert(name.into(), descriptor.clone());
    configuration.validate()?;
    let resolved = resolve(&configuration, name, preset).map_err(|mut error| {
        error.body = error.body.with_remedy(se_types::Remedy {
            text: format!("{} must already be installed and logged in. Complete its native setup at {}, then retry this init command; no setup configuration has been published.", preset.title, preset.setup_url),
            command: Some(se_types::Cmd::Manual),
        });
        error
    })?;
    descriptor.command = resolved
        .0
        .to_str()
        .ok_or_else(|| SeError::invalid("harness executable", "a UTF-8 native path"))?
        .into();
    if let Some(script) = resolved.1 {
        descriptor.arguments.insert(
            0,
            script
                .to_str()
                .ok_or_else(|| SeError::invalid("harness package entry", "a UTF-8 native path"))?
                .into(),
        );
    }
    configuration.harnesses.insert(name.into(), descriptor);
    configuration.validate()?;
    Ok(configuration)
}

#[cfg(any(target_os = "linux", windows))]
fn resolve(
    configuration: &ConfigFile,
    name: &str,
    preset: &catalog::Preset,
) -> Result<(std::path::PathBuf, Option<std::path::PathBuf>)> {
    let executable = se_host::resolve_provider_executable(
        configuration,
        se_types::Provider::Acp,
        None,
        Some(name),
    )?;
    let script = preset
        .package
        .as_ref()
        .map(|package| se_host::harness_setup::node_entrypoint(package, &executable))
        .transpose()?;
    Ok((executable, script))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn resolve(
    _: &ConfigFile,
    _: &str,
    _: &catalog::Preset,
) -> Result<(std::path::PathBuf, Option<std::path::PathBuf>)> {
    Err(SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: "native harness catalogue setup".into(),
            reason: "native protocol launches are not implemented on this platform".into(),
            next_step: "Use a supported Linux or Windows installation for this protocol harness."
                .into(),
        },
    )))
}
