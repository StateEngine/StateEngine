//! Windows Codex sandbox selection. A workspace-write request reaches the
//! provider as read-only until an implementation is named, so the host names
//! one in the provider's own launch settings and reads the provider's own
//! readiness before trusting the launch.
use super::incompatible;
use se_types::Result;
use serde_json::Value;
use std::path::Path;

/// One Windows sandbox implementation a Codex build can select.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Implementation {
    Mxc,
    Elevated,
    Unelevated,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Implementation {
    /// The implementation a launch names when the user has chosen none. It
    /// needs no administrator-approved setup, so a first launch works on a
    /// clean Windows install.
    pub const DEFAULT: Implementation = Implementation::Unelevated;

    pub fn key(self) -> &'static str {
        match self {
            Implementation::Mxc => "mxc",
            Implementation::Elevated => "elevated",
            Implementation::Unelevated => "unelevated",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "mxc" => Ok(Implementation::Mxc),
            "elevated" => Ok(Implementation::Elevated),
            "unelevated" => Ok(Implementation::Unelevated),
            other => Err(incompatible(
                &format!(
                    "the configured Windows sandbox implementation `{other}` is not one this provider accepts"
                ),
                "Set windows.sandbox to mxc, elevated or unelevated in your Codex configuration.",
            )),
        }
    }
}

/// The provider's own answer about the implementation it is configured with.
/// Only a Windows call site asks for it; its parsing is shared and tested here.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    NotConfigured,
    UpdateRequired,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Readiness {
    pub fn parse(value: &Value) -> Result<Self> {
        match value.get("status").and_then(Value::as_str) {
            Some("ready") => Ok(Readiness::Ready),
            Some("notConfigured") => Ok(Readiness::NotConfigured),
            Some("updateRequired") => Ok(Readiness::UpdateRequired),
            _ => Err(se_core::scope::unreadable(
                "Windows Codex sandbox readiness",
                "the provider's own ready, notConfigured or updateRequired answer",
            )),
        }
    }
}

/// The implementation this launch names: the user's own value first, otherwise
/// the default. Only a workspace-write launch names one, because a read-only
/// launch writes nothing and needs no sandbox.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn selection(request: &crate::HarnessRequest) -> Result<Option<Implementation>> {
    if !matches!(
        request.policy.writes,
        se_proc::WritePolicy::Workspace { .. }
    ) {
        return Ok(None);
    }
    Ok(Some(
        user_choice(&crate::codex_capture::existing_home()?)?.unwrap_or(Implementation::DEFAULT),
    ))
}

/// The `windows.sandbox` the user set in their own Codex file, if any. The host
/// chooses before the provider starts, so it reads the user's global file; a
/// value set only in a project layer appears later and never changes this
/// choice. A file that cannot be read or parsed refuses: it never means "unset".
#[cfg_attr(not(windows), allow(dead_code))]
pub fn user_choice(home: &Path) -> Result<Option<Implementation>> {
    let path = home.join("config.toml");
    let text = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() > 1 << 20 => {
            return Err(incompatible(
                "the user's Codex configuration is larger than 1 MiB",
                "Move the oversized Codex configuration aside, then retry the launch.",
            ));
        }
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            incompatible(
                "the user's Codex configuration is not UTF-8",
                "Save the Codex configuration as UTF-8, then retry the launch.",
            )
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(se_core::scope::unreadable(
                &format!("the user's Codex configuration at {}", path.display()),
                &error.to_string(),
            ));
        }
    };
    let parsed: toml::Value = toml::from_str(&text).map_err(|error| {
        incompatible(
            &format!("the user's Codex configuration does not parse: {error}"),
            "Correct the Codex configuration, then retry the launch.",
        )
    })?;
    let Some(windows) = parsed.get("windows") else {
        return Ok(None);
    };
    let toml::Value::Table(windows) = windows else {
        return Err(se_core::scope::unreadable(
            "the user's Windows Codex configuration",
            "an object-valued windows table",
        ));
    };
    match windows.get("sandbox") {
        None => Ok(None),
        Some(toml::Value::String(name)) => Implementation::parse(name).map(Some),
        Some(_) => Err(incompatible(
            "your Codex configuration sets windows.sandbox to a value that is not a string",
            "Set windows.sandbox to \"mxc\", \"elevated\" or \"unelevated\".",
        )),
    }
}

/// The provider's own answer for the implementation this launch named. The
/// refusal names that answer and the provider's own repair command.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn require_ready(
    implementation: Implementation,
    readiness: Readiness,
) -> Result<Implementation> {
    match readiness {
        Readiness::Ready => Ok(implementation),
        Readiness::NotConfigured => Err(incompatible(
            &format!(
                "the Windows sandbox `{}` is not set up on this machine",
                implementation.key()
            ),
            "Run `codex sandbox setup --elevated --user <your account> --codex-home <your Codex \
             home>` from an elevated prompt, then retry the launch.",
        )),
        Readiness::UpdateRequired => Err(incompatible(
            &format!(
                "the Windows sandbox `{}` needs a newer Codex on this machine",
                implementation.key()
            ),
            "Upgrade Codex to 0.152.0 or later, then retry the launch.",
        )),
    }
}

#[cfg(test)]
use crate::test_directory;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refusal<T>(value: Result<T>) -> String {
        match value {
            Err(error) => format!("{error:?}"),
            Ok(_) => panic!("expected a refusal"),
        }
    }

    fn home(
        contents: Option<&str>,
    ) -> std::result::Result<super::test_directory::PrivateDirectory, Box<dyn std::error::Error>>
    {
        let path = super::test_directory::private_directory()?;
        if let Some(contents) = contents {
            std::fs::write(path.join("config.toml"), contents)?;
        }
        Ok(path)
    }

    #[test]
    fn the_users_own_value_is_read_or_the_file_refuses()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(user_choice(&home(None)?).ok(), Some(None));
        assert_eq!(
            user_choice(&home(Some("[windows]\nsandbox = \"elevated\"\n"))?)
                .ok()
                .flatten(),
            Some(Implementation::Elevated)
        );
        // An unrelated table is not a value.
        assert_eq!(
            user_choice(&home(Some("[windows]\nallow_mxc = true\n"))?)
                .ok()
                .flatten(),
            None
        );
        let number = refusal(user_choice(&home(Some("[windows]\nsandbox = 3\n"))?));
        assert!(number.contains("not a string"), "{number}");
        let scalar = refusal(user_choice(&home(Some("windows = \"elevated\"\n"))?));
        assert!(scalar.contains("object-valued windows table"), "{scalar}");
        let unknown = refusal(user_choice(&home(Some(
            "[windows]\nsandbox = \"legacy\"\n",
        ))?));
        assert!(unknown.contains("`legacy`"), "{unknown}");
        let broken = refusal(user_choice(&home(Some("windows = \n"))?));
        assert!(broken.contains("does not parse"), "{broken}");
        Ok(())
    }

    #[test]
    fn only_a_workspace_write_launch_names_an_implementation() {
        // Selection reads the user's home, so the default alone is the subject.
        assert_eq!(Implementation::DEFAULT, Implementation::Unelevated);
        assert_eq!(Implementation::DEFAULT.key(), "unelevated");
    }

    #[test]
    fn an_unready_implementation_refuses_with_a_step_that_works() {
        let missing = refusal(require_ready(
            Implementation::Unelevated,
            Readiness::NotConfigured,
        ));
        assert!(
            missing.contains("Windows sandbox `unelevated` is not set up"),
            "{missing}"
        );
        assert!(
            missing.contains("codex sandbox setup --elevated"),
            "{missing}"
        );
        let stale = refusal(require_ready(
            Implementation::Mxc,
            Readiness::UpdateRequired,
        ));
        assert!(stale.contains("needs a newer Codex"), "{stale}");
        assert!(stale.contains("0.152.0"), "{stale}");
        assert_eq!(
            require_ready(Implementation::Mxc, Readiness::Ready).ok(),
            Some(Implementation::Mxc)
        );
    }

    #[test]
    fn readiness_parses_only_the_three_provider_answers() {
        for (answer, expected) in [
            ("ready", Readiness::Ready),
            ("notConfigured", Readiness::NotConfigured),
            ("updateRequired", Readiness::UpdateRequired),
        ] {
            let read = Readiness::parse(&json!({ "status": answer }));
            assert_eq!(read.ok(), Some(expected), "{answer}");
        }
        assert!(Readiness::parse(&json!({ "status": "elsewhere" })).is_err());
        assert!(Readiness::parse(&json!({})).is_err());
    }
}
