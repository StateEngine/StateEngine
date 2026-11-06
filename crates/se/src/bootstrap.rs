//! Ambient inputs are collected only after metadata and syntax have completed.
//! This module does not open a store, create directories or establish authority.
use se_types::{Detail, Result, SeError, Secret, details};
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};

/// Called by the process entry before file/store access or worker creation.
/// Windows fixes only the default owner for newly created files; existing
/// ownership remains a strict readback requirement. Unix does no work here.
pub fn initialize_file_owner() -> Result<()> {
    se_proc::initialize_file_creation_owner().map(|_| ()).map_err(|error| {
        SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
            subject: "process default file owner".into(),
            reason: error.to_string(),
            next_step: "Restore access to the current process token and retry the command; no store or configuration file has been opened".into(),
        })).with_cause(error)
    })
}

#[derive(Debug)]
pub struct Bootstrap {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub project: Option<String>,
    pub selections: se_core::ops::CliSelections,
    pub config: crate::config::Loaded<se_core::config_policy::ConfigFile>,
    pub session: Option<Secret>,
    pub log: Option<String>,
    pub no_color: bool,
    pub json: bool,
    pub(crate) retry_invocation: Option<crate::route::startup_retry::Invocation>,
    pub legacy_environment_present: bool,
}

/// An agent marker cannot select an owner-only operation, even when its opaque
/// handle is malformed. Refuse before session-pin or configuration reads.
pub(crate) fn check_session_route(operation: &se_core::ops::AnyOp) -> Result<()> {
    if std::env::var_os("SE_SESSION").is_some()
        && (matches!(operation.meta().auth, se_core::registry::Auth::Owner)
            || operation.requires_human_terminal()?)
    {
        return Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: operation.meta().name.into(),
            },
        )));
    }
    Ok(())
}

impl Bootstrap {
    /// A session handle is opaque here. Only the native admission adapter may
    /// verify it; its presence must never fall through to owner authentication.
    pub fn resolve(
        home: Option<PathBuf>,
        project: Option<String>,
        no_color: bool,
        json: bool,
        operation: &se_core::ops::AnyOp,
    ) -> Result<Self> {
        let home = state_home(home)?;
        let config = if matches!(
            operation,
            se_core::ops::AnyOp::DoctorInspect(_) | se_core::ops::AnyOp::DoctorRepair(_)
        ) {
            // Doctor uses explicit named repairs, not runtime configuration.
            // In particular, root recovery must not read config through the
            // loose directory before its metadata-only tightening.
            crate::config::Loaded {
                value: se_core::config_policy::ConfigFile::default(),
                origin: crate::config::Origin::BuiltIn,
            }
        } else {
            let (path, explicit) = configuration_path(&home)?;
            crate::config::load::<se_core::config_policy::ConfigFile>(&path, explicit)?
        };
        let session = session_input(&home)?;
        let project = match project {
            Some(project) => Some(project),
            None if session.is_none() => text_variable("SE_PROJECT")?,
            None => None,
        };
        config.value.validate()?;
        let cwd = std::env::current_dir().map_err(|error| {
            unreadable(
                "current directory",
                error,
                "Restore access to the working directory",
            )
        })?;
        Ok(Self {
            home,
            cwd,
            config,
            project,
            selections: se_core::ops::CliSelections::default(),
            session,
            log: text_variable("SE_LOG")?,
            no_color: no_color
                || std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            json,
            retry_invocation: None,
            // Inspect names only. Legacy values never participate in resolution.
            legacy_environment_present: std::env::vars_os().any(|(name, _)| {
                name.to_str()
                    .is_some_and(|name| name.starts_with("STATEENGINE_"))
            }),
        })
    }
}

/// Share runtime selection with doctor, which must defer the actual read until
/// protected admission. An absent default file and an absent explicit file
/// retain their different meanings in the config loader.
pub(crate) fn configuration_path(home: &Path) -> Result<(PathBuf, bool)> {
    let selected = variable("SE_CONFIG")?;
    let explicit = selected.is_some();
    let path = match selected {
        Some(path) => absolute(PathBuf::from(path), "SE_CONFIG")?,
        None => home.join("config.toml"),
    };
    Ok((path, explicit))
}

/// Resolve only the state-home selection. The private installer entry uses the
/// same platform policy without loading configuration or a session credential.
pub(crate) fn state_home(home: Option<PathBuf>) -> Result<PathBuf> {
    let home = match home {
        Some(path) => path,
        None => match variable("SE_HOME")? {
            Some(path) => PathBuf::from(path),
            None => default_home()?,
        },
    };
    absolute(home, "state home")
}

pub(crate) fn session_input(home: &std::path::Path) -> Result<Option<Secret>> {
    let Some(value) = std::env::var_os("SE_SESSION") else {
        return Ok(None);
    };
    let invalid = |reason: String| {
        SeError::new(Detail::CapabilityInvalid(details::CapabilityInvalid {
        subject: "SE_SESSION".into(), reason,
        next_step: "Use the opaque session handle supplied to a launched agent; invalid session input cannot grant owner authority".into(),
    }))
    };
    let handle = value
        .to_str()
        .ok_or_else(|| invalid("must be a canonical session handle".into()))?;
    let _: se_types::SessionId = handle.parse().map_err(|_| {
        invalid("must be a canonical ses_ UUID handle, never credential bytes".into())
    })?;
    let files =
        se_proc::NativeStateFiles::open(home).map_err(|error| invalid(error.to_string()))?;
    se_proc::read_session_pin(&files, handle)
        .map(Some)
        .map_err(|error| invalid(error.to_string()))
}

fn variable(name: &str) -> Result<Option<OsString>> {
    match std::env::var_os(name) {
        Some(value) if value.is_empty() => Err(configuration(name, "is empty")),
        value => Ok(value),
    }
}

fn text_variable(name: &str) -> Result<Option<String>> {
    variable(name)?
        .map(|value| {
            value
                .into_string()
                .map_err(|_| configuration(name, "must be valid UTF-8"))
        })
        .transpose()
}

fn absolute(path: PathBuf, subject: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(configuration(subject, "must name a directory or file"));
    }
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().map_err(|error| {
        unreadable(
            "current directory",
            error,
            "Pass an absolute --home and SE_CONFIG",
        )
    })?;
    Ok(cwd.join(path))
}

fn default_home() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let path = variable("LOCALAPPDATA")?
        .map(PathBuf::from)
        .ok_or_else(|| configuration("LOCALAPPDATA", "is unavailable; set SE_HOME"))?
        .join("StateEngine");
    #[cfg(target_os = "macos")]
    let path = user_home()?.join("Library/Application Support/StateEngine");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let path = match variable("XDG_STATE_HOME")? {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(configuration("XDG_STATE_HOME", "must be absolute"));
            }
            path.join("stateengine")
        }
        None => user_home()?.join(".local/state/stateengine"),
    };
    if !path.is_absolute() {
        return Err(configuration(
            "platform state directory",
            "must be absolute; set SE_HOME",
        ));
    }
    Ok(path)
}

#[cfg(not(target_os = "windows"))]
fn user_home() -> Result<PathBuf> {
    let path = variable("HOME")?
        .map(PathBuf::from)
        .ok_or_else(|| configuration("HOME", "is unavailable; set SE_HOME"))?;
    if !path.is_absolute() {
        return Err(configuration("HOME", "must be absolute; set SE_HOME"));
    }
    Ok(path)
}

/// Read a TEXT/BODY value before dispatch; '-' consumes at most limit + 1 bytes.
/// Oversize input is refused, never truncated and then committed.
pub fn text_input(value: String, field: &str, limit: usize) -> Result<String> {
    let value = if value == "-" {
        let mut bytes = Vec::new();
        let bound = limit.saturating_add(1) as u64;
        std::io::stdin()
            .lock()
            .take(bound)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                unreadable(
                    "stdin",
                    error,
                    "Restore readable stdin and retry the same command key",
                )
            })?;
        if bytes.len() > limit {
            return Err(SeError::too_large(field, limit, bytes.len()));
        }
        String::from_utf8(bytes).map_err(|_| SeError::invalid(field, "UTF-8 text"))?
    } else {
        value
    };
    if value.len() > limit {
        return Err(SeError::too_large(field, limit, value.len()));
    }
    Ok(value)
}

fn configuration(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::ConfigurationInvalid(
        details::ConfigurationInvalid {
            subject: subject.into(),
            reason: reason.into(),
            next_step: "Correct the selected environment variable or pass an explicit --home"
                .into(),
        },
    ))
}

fn unreadable(subject: &str, error: std::io::Error, next_step: &str) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
        subject: subject.into(),
        reason: error.to_string(),
        next_step: next_step.into(),
    }))
    .with_cause(error)
}
