//! The one user configuration file. Domain keys and policy belong to se-core;
//! this adapter supplies only file loading, origins and parse diagnostics.
use se_types::{Detail, Result, SeError, details};
use serde::de::DeserializeOwned;
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

/// Platform rendezvous inputs are captured before launching the host with its
/// minimal environment. Libraries receive these explicitly, never via env.
#[cfg(unix)]
pub(crate) fn unix_socket_paths() -> Result<se_proc::native_ipc::UnixSocketPaths> {
    fn path(name: &str) -> Result<Option<PathBuf>> {
        std::env::var_os(name)
            .map(|value| {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err(SeError::invalid(name, "an absolute platform directory"));
                }
                Ok(path)
            })
            .transpose()
    }
    #[cfg(target_os = "linux")]
    let runtime_directory = path("XDG_RUNTIME_DIR")?;
    #[cfg(not(target_os = "linux"))]
    let runtime_directory = None;
    #[cfg(target_os = "macos")]
    let temporary_directory = Some(path("TMPDIR")?.unwrap_or_else(|| PathBuf::from("/tmp")));
    #[cfg(not(target_os = "macos"))]
    let temporary_directory = None;
    Ok(se_proc::native_ipc::UnixSocketPaths {
        runtime_directory,
        temporary_directory,
    })
}

#[derive(Debug)]
pub enum Origin {
    BuiltIn,
    File(PathBuf),
}

#[derive(Debug)]
pub struct Loaded<T> {
    pub value: T,
    pub origin: Origin,
}

/// The core-owned config type must deny unknown fields at every table and
/// validate policy after decoding. An absent default file means defaults; an
/// explicit SE_CONFIG that cannot be opened retains its actual failure.
pub fn load<T: DeserializeOwned + Default>(path: &Path, explicit: bool) -> Result<Loaded<T>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound && !explicit => {
            // A dangling symlink is unreadable configuration, not absence.
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Ok(Loaded {
                        value: T::default(),
                        origin: Origin::BuiltIn,
                    });
                }
                Ok(_) => {}
                Err(error) => return Err(unreadable(path, error)),
            }
            return Err(unreadable(path, error));
        }
        Err(error) => return Err(unreadable(path, error)),
    };
    let value = toml::from_str(&text).map_err(|error| parse_error(path, &text, error))?;
    Ok(Loaded {
        value,
        origin: Origin::File(path.to_path_buf()),
    })
}

fn parse_error(path: &Path, text: &str, error: toml::de::Error) -> SeError {
    let line = error.span().map(|span| {
        1 + text.as_bytes()[..span.start.min(text.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
    });
    let location = match line {
        Some(line) => format!("{} line {line}", path.display()),
        None => path.display().to_string(),
    };
    // serde's deny_unknown_fields uses this fixed diagnostic. Keep the key and
    // line, without printing the source snippet or any configuration values.
    if let Some(field) = error
        .message()
        .strip_prefix("unknown field `")
        .and_then(|message| message.split_once('`').map(|(field, _)| field))
    {
        return SeError::new(Detail::InputUnknownField(details::InputUnknownField {
            op: format!("config.toml ({location})"),
            field: field.into(),
            next_step: "Remove the unknown key from the selected user config file".into(),
        }));
    }
    SeError::new(Detail::ConfigurationInvalid(
        details::ConfigurationInvalid {
            subject: location,
            reason: "invalid TOML or a configuration value with an unsupported type or value"
                .into(),
            next_step:
                "Correct the selected config.toml; version must be 1 and keys must be supported"
                    .into(),
        },
    ))
    .with_cause(error)
}

fn unreadable(path: &Path, error: std::io::Error) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
        subject: format!("configuration file {}", path.display()),
        reason: error.to_string(),
        next_step: "Restore read access or select an existing user file with SE_CONFIG".into(),
    }))
    .with_cause(error)
}
