use se_types::{Result, SeError};
use std::{
    ffi::{OsStr, OsString},
    path::{Component, PathBuf},
};
pub(super) struct Options {
    pub program: bool,
    pub home: PathBuf,
    pub profiles: Vec<PathBuf>,
    pub fish: Option<PathBuf>,
    pub child: usize,
}
pub(super) fn path(value: &OsStr) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    let text = path
        .to_str()
        .ok_or_else(|| invalid("lossless UTF-8 paths"))?;
    if !path.is_absolute()
        || text.bytes().any(|byte| byte.is_ascii_control())
        || path.components().any(|part| {
            !matches!(
                part,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(invalid(
            "normalized absolute paths without control characters",
        ));
    }
    Ok(path)
}
fn setting(name: &str) -> Result<Option<PathBuf>> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(|value| path(&value))
        .transpose()
}
impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self> {
        let mut cursor = 2;
        let mut program = false;
        let mut home = None;
        let mut profiles = Vec::new();
        let mut fish = None;
        let user = setting("HOME")?;
        let config = setting("XDG_CONFIG_HOME")?
            .or_else(|| user.as_ref().map(|value| value.join(".config")));
        loop {
            let value = args.get(cursor).ok_or_else(|| {
                invalid("__install-hold [options] -- <absolute child> [arguments]")
            })?;
            if value == "--" {
                cursor += 1;
                break;
            }
            if value == "--prepare-program" && !program {
                program = true;
                cursor += 1;
                continue;
            }
            let argument = args
                .get(cursor + 1)
                .ok_or_else(|| invalid("a value for every installer option"))?;
            let selected = path(argument)?;
            match value.to_str() {
                Some("--home") if home.is_none() => home = Some(selected),
                Some("--xdg-state-home")
                    if setting("XDG_STATE_HOME")?.as_ref() == Some(&selected) => {}
                Some("--xdg-config-home") if config.as_ref() == Some(&selected) => (),
                Some("--profile")
                    if profiles.len() < 8
                        && user.as_ref().is_some_and(|root| {
                            selected.starts_with(root) && selected != *root
                        }) =>
                {
                    profiles.push(selected)
                }
                Some("--fish-directory")
                    if fish.is_none()
                        && config
                            .as_ref()
                            .is_some_and(|root| selected == root.join("fish/conf.d")) =>
                {
                    fish = Some(selected)
                }
                _ => {
                    return Err(invalid(
                        "known installer options matching the selected HOME/XDG roots",
                    ));
                }
            }
            cursor += 2;
        }
        path(
            args.get(cursor)
                .ok_or_else(|| invalid("an absolute child executable"))?,
        )?;
        let expected = crate::bootstrap::state_home(None)?;
        let home = home.unwrap_or_else(|| expected.clone());
        if home != expected {
            return Err(invalid(
                "--home matching the selected SE_HOME or XDG state home",
            ));
        }
        path(home.as_os_str())?;
        if !program && (!profiles.is_empty() || fish.is_some()) {
            return Err(invalid("--prepare-program for shell integration choices"));
        }
        Ok(Self {
            program,
            home,
            profiles,
            fish,
            child: cursor,
        })
    }
}
pub(super) fn invalid(expected: &str) -> SeError {
    SeError::invalid("private installer preparation", expected)
}
