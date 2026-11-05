//! Read-only setup observations. A native root, its contents and optional Git
//! metadata are observed before the first setup write.
use crate::bootstrap::Bootstrap;
use se_core::{
    ops::{GitView, ProjectInit},
    scope,
};
use se_types::{Result, SeError};
use std::path::{Path, PathBuf};

pub(super) struct Repository {
    pub path: PathBuf,
    pub name: String,
    pub nonempty: bool,
    pub git: Option<GitView>,
}
pub(super) fn observe(cx: &Bootstrap, input: &ProjectInit) -> Result<Repository> {
    let requested = input
        .repo
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| cx.cwd.clone());
    let path = se_proc::canonicalize_path(if requested.is_absolute() {
        requested
    } else {
        cx.cwd.join(requested)
    })
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SeError::new(se_types::Detail::RepoInvalid(se_types::details::RepoInvalid {
                subject: "--repo".into(), reason: "the requested directory does not exist".into(),
                next_step: "Select an existing directory with --repo DIR, or create that directory and retry.".into(),
            }))
        } else { scope::unreadable("repository root", &e.to_string()) }
    })?;
    if !path.is_dir() {
        return Err(SeError::new(se_types::Detail::RepoInvalid(
            se_types::details::RepoInvalid {
                subject: "--repo".into(),
                reason: "the selected path is not a directory".into(),
                next_step: "Select an existing directory with --repo DIR.".into(),
            },
        )));
    }
    if canonical_destination(&cx.home)?.starts_with(&path) {
        return Err(SeError::invalid(
            "state home",
            "a state home outside the registered repository; managed init writes no repository files",
        ));
    }
    if cx.config.value.runtime.listen_port.is_none() {
        let configuration = match &cx.config.origin {
            crate::config::Origin::File(selected) => selected.clone(),
            crate::config::Origin::BuiltIn => cx.home.join("config.toml"),
        };
        if canonical_destination(&configuration)?.starts_with(&path) {
            return Err(SeError::invalid(
                "setup configuration",
                "a selected configuration outside the repository when setup must persist its listener port",
            ));
        }
    }
    let name = input
        .name
        .clone()
        .or_else(|| path.file_name().and_then(|s| s.to_str()).map(derived_name))
        .ok_or_else(|| {
            SeError::invalid(
                "project name",
                "--name for a root without a UTF-8 final component",
            )
        })?;
    let mut resolved = input.clone();
    resolved.name = Some(name.clone());
    se_core::ops::inputs::Validate::validate(&resolved).map_err(|error| {
        if input.name.is_none() && matches!(error.body.detail(), se_types::Detail::UsageInvalidValue(detail) if detail.argument == "name") {
            SeError::new(se_types::Detail::RepoInvalid(se_types::details::RepoInvalid {
                subject: "derived project name".into(), reason: "the directory name is not a supported project name".into(),
                next_step: "Add --name NAME using 1..64 ASCII letters, digits, spaces, periods, underscores or hyphens, starting with a letter or digit.".into(),
            })).with_cause(error)
        } else { error }
    })?;
    let nonempty = std::fs::read_dir(&path)
        .map_err(|e| scope::unreadable("repository contents", &e.to_string()))?
        .next()
        .transpose()
        .map_err(|e| scope::unreadable("repository contents", &e.to_string()))?
        .is_some();
    let git = super::super::git_state::observe(&path)?;
    Ok(Repository {
        path,
        name,
        nonempty,
        git,
    })
}
fn derived_name(directory: &str) -> String {
    let name: String = directory
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || " ._-".contains(character) {
                character
            } else {
                ' '
            }
        })
        .collect();
    let name = name.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        "Project".into()
    } else {
        name[..name.len().min(64)].trim_end().into()
    }
}

fn canonical_destination(path: &Path) -> Result<PathBuf> {
    let mut parent = path;
    let mut missing = Vec::new();
    loop {
        match se_proc::canonicalize_path(parent) {
            Ok(mut resolved) => {
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    parent
                        .file_name()
                        .ok_or_else(|| SeError::invalid("state home", "a native absolute path"))?
                        .to_owned(),
                );
                parent = parent
                    .parent()
                    .ok_or_else(|| SeError::invalid("state home", "a native absolute path"))?;
            }
            Err(error) => {
                return Err(scope::unreadable(
                    "state home resolution",
                    &error.to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::derived_name;
    #[test]
    fn directory_labels_produce_valid_bounded_project_names() -> se_types::Result<()> {
        for (directory, expected) in [
            ("my repo (v2)", "my repo v2"),
            (".private", "private"),
            ("café ü", "caf"),
            ("日本語", "Project"),
        ] {
            let name = derived_name(directory);
            assert_eq!(name, expected);
            se_core::ops::inputs::name("name", &name)?;
        }
        let name = derived_name(&"a".repeat(100));
        assert_eq!(name.len(), 64);
        se_core::ops::inputs::name("name", &name)
    }
}
