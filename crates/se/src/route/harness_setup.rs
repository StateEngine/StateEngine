//! Harness descriptors in `config.toml`: prepare a catalogue choice from an
//! existing installation before setup writes, or register an owner's own
//! protocol agent by appending its entry, so existing bytes survive.
use super::{files::Files, init_config, owner};
use crate::{bootstrap::Bootstrap, config::Origin};
use se_config::config_policy::{
    Approval, ConfigFile, Profile,
    harness::{Driver, HarnessDescriptor, PermissionChoice},
};
use se_core::{
    harness_selection::catalog,
    ops::{AnyOutput, HarnessAdd, HarnessAddOutput, ProjectInit, inputs::Validate},
    scope,
    store_error::store_error,
};
use se_types::{Result, SeError};
use std::collections::BTreeMap;

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
    let native = descriptor.permissions.remove("default").ok_or_else(|| {
        SeError::invalid(
            "harness catalogue",
            "an announced native permission default",
        )
    })?;
    let profile = protocol_profile(&mut configuration)?;
    descriptor.permissions.insert(profile, native);
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

/// Protocol sessions are headless and cannot collect approval, so catalogue
/// setup saves a named profile whose approval is explicit, and init prints it.
/// `[providers.acp].profile` serves every protocol agent, so it moves to that
/// profile only while nothing else depends on it: the shared choice and its
/// `default` profile are as shipped and no protocol agent is configured yet.
/// Otherwise the owner's profile, and an existing `protocol` profile, stay as
/// written and the catalogue agent maps its native default to them.
fn protocol_profile(configuration: &mut ConfigFile) -> Result<String> {
    const PROTOCOL: &str = "protocol";
    let acp = &configuration.providers.acp;
    let shipped = |profile: &Profile| -> Result<bool> {
        let identity = |value: &Profile| {
            serde_json::to_value(value)
                .map_err(|e| SeError::invalid("launch profile", &e.to_string()))
        };
        Ok(identity(profile)? == identity(&Profile::default())?)
    };
    let untouched = acp.profile == "default"
        && acp.command.is_none()
        && configuration.harnesses.is_empty()
        && match configuration.profiles.get("default") {
            Some(profile) => shipped(profile)?,
            None => true,
        };
    if !untouched {
        return Ok(acp.profile.clone());
    }
    configuration.providers.acp.profile = PROTOCOL.into();
    configuration
        .profiles
        .entry(PROTOCOL.into())
        .or_insert_with(|| Profile {
            approval: Some(Approval::Never),
            ..Default::default()
        });
    Ok(PROTOCOL.into())
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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

pub(super) fn add(cx: &Bootstrap, input: HarnessAdd) -> Result<AnyOutput> {
    input.validate()?;
    let observed_owner = owner::observe(&[])?;
    observed_owner.authorize(
        "harness.add",
        observed_owner.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    let files = Files::open(&cx.home).map_err(|e| store_error(&e))?;
    let path = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let mut pin = se_proc::OwnedFile::open(&path)
        .map_err(|e| scope::unreadable("harness configuration", &e.to_string()))?;
    let (observed, prior) = init_config::load_observed_config(&mut pin)?;
    init_config::observed_matches_bootstrap(&observed, cx)?;
    if observed.harnesses.contains_key(&input.name) {
        return Err(SeError::invalid(
            "harness name",
            &format!(
                "a new name; [harnesses.{}] already exists in {}. Edit that entry there, or choose another name",
                input.name,
                path.display()
            ),
        ));
    }
    let profile = observed.providers.acp.profile.clone();
    let descriptor = HarnessDescriptor {
        driver: Driver::AcpStdio,
        command: input.command.clone(),
        arguments: input.arguments.clone(),
        model_arguments: Vec::new(),
        environment: input.environment.clone(),
        model_environment: None,
        unadvertised_http_mcp: false,
        permissions: BTreeMap::from([(profile.clone(), PermissionChoice::default())]),
    };
    // Without a file yet, start from the defaults the observed reader applied.
    let text = match &prior {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| SeError::invalid("configuration", "UTF-8 TOML"))?
            .to_owned(),
        None => toml::to_string_pretty(&observed)
            .map_err(|e| scope::unreadable("configuration encoding", &e.to_string()))?,
    };
    let bytes = with_harness(&text, &input.name, &descriptor)?;
    let updated: ConfigFile = toml::from_str(&bytes)
        .map_err(|e| scope::unreadable("harness configuration", &e.to_string()))?;
    updated.validate()?;
    let saved = updated
        .harnesses
        .get(&input.name)
        .ok_or_else(|| scope::unreadable("harness configuration", "the new entry is absent"))?;
    if identity(saved)? != identity(&descriptor)? {
        return Err(scope::unreadable(
            "harness configuration",
            "the edited file decodes to a different descriptor; nothing was written",
        ));
    }
    resolve_command(&updated, &input.name)?;
    init_config::publish_bytes(&path, pin, &files, prior.as_deref(), bytes.as_bytes())?;
    Ok(HarnessAddOutput {
        name: input.name,
        command: input.command,
        arguments: input.arguments,
        environment: input.environment,
        profile,
        configuration: path.display().to_string(),
    }
    .into())
}

/// Appends `[harnesses.NAME]` and its permission mapping after the existing
/// bytes, which stay exactly as the owner wrote them. The caller decodes the
/// result, so a file that already defines `harnesses` another way refuses.
fn with_harness(text: &str, name: &str, descriptor: &HarnessDescriptor) -> Result<String> {
    let entry = BTreeMap::from([("harnesses", BTreeMap::from([(name, descriptor)]))]);
    let encoded = toml::to_string(&entry)
        .map_err(|e| scope::unreadable("harness encoding", &e.to_string()))?;
    let mut updated = text.to_owned();
    if !updated.is_empty() {
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push('\n');
    }
    updated.push_str(&encoded);
    Ok(updated)
}

fn identity(descriptor: &HarnessDescriptor) -> Result<serde_json::Value> {
    serde_json::to_value(descriptor)
        .map_err(|e| scope::unreadable("harness identity", &e.to_string()))
}

/// The command must already be installed: a descriptor nothing can run would
/// only fail later, at an agent's first launch.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn resolve_command(configuration: &ConfigFile, name: &str) -> Result<()> {
    se_host::resolve_provider_executable(configuration, se_types::Provider::Acp, None, Some(name))
        .map(drop)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn resolve_command(_: &ConfigFile, _: &str) -> Result<()> {
    Ok(())
}
