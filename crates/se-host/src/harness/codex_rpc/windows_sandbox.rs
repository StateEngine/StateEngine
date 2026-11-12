//! Windows Codex sandbox selection. A workspace-write request reaches the
//! provider as read-only until an implementation is named, so the host names
//! one and reads the provider's own readiness before trusting the launch.
use super::incompatible;
use se_types::Result;
use serde_json::{Value, json};

/// One Windows sandbox implementation a Codex build can select.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Implementation {
    Mxc,
    Elevated,
    Unelevated,
}

impl Implementation {
    /// Native isolation first, then the stronger legacy boundary, then the
    /// weaker one that needs no administrator-approved setup.
    pub const PREFERENCE: [Implementation; 3] = [
        Implementation::Mxc,
        Implementation::Elevated,
        Implementation::Unelevated,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Implementation::Mxc => "mxc",
            Implementation::Elevated => "elevated",
            Implementation::Unelevated => "unelevated",
        }
    }
}

impl Implementation {
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

/// The provider's own answer about the implementation it would use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    NotConfigured,
    UpdateRequired,
}

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

/// The implementation this launch asks for. `windows.sandbox` travels as one
/// explicit per-launch key, so the user's own config file is never replaced.
/// A value the user set needs no key at all: theirs is already in force.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    pub implementation: Implementation,
    pub from_user: bool,
}

impl Selection {
    /// `None` when the user's own configuration already supplies this value.
    pub fn sandbox_key(self) -> Option<(&'static str, String)> {
        (!self.from_user).then(|| {
            (
                "windows.sandbox",
                json!(self.implementation.key()).to_string(),
            )
        })
    }
}

/// The readiness request for one named implementation. The answer covers that
/// implementation only, so each choice is asked about separately.
pub fn readiness_request(implementation: Implementation) -> Value {
    json!({ "config": { "windows.sandbox": json!(implementation.key()) } })
}

/// A value the user set in their own Codex configuration. The host never
/// overrides it; the selection then only reports whether it is ready.
pub fn user_selection(config: &Value) -> Option<String> {
    config
        .get("windows")
        .and_then(|windows| windows.get("sandbox"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The first host-chosen implementation the provider answers ready for.
pub fn choose(attempted: &[(Implementation, Readiness)]) -> Result<Selection> {
    for (implementation, readiness) in attempted {
        if *readiness == Readiness::Ready {
            return Ok(Selection {
                implementation: *implementation,
                from_user: false,
            });
        }
    }
    Err(not_ready(attempted))
}

/// The user's own value. Their choice wins even when another implementation is
/// ready: the host reports the state and never substitutes one they did not pick.
pub fn decide(
    implementation: Implementation,
    readiness: Readiness,
    from_user: bool,
) -> Result<Selection> {
    if readiness != Readiness::Ready {
        return Err(incompatible(
            &format!(
                "your configured Windows sandbox `{}` is not ready ({readiness:?})",
                implementation.key()
            ),
            "Install or repair that sandbox with `codex sandbox setup --elevated` from an \
             elevated prompt, or choose another windows.sandbox in your Codex configuration.",
        ));
    }
    Ok(Selection {
        implementation,
        from_user,
    })
}

fn not_ready(attempted: &[(Implementation, Readiness)]) -> se_types::SeError {
    let answers = attempted
        .iter()
        .map(|(implementation, readiness)| format!("{}: {readiness:?}", implementation.key()))
        .collect::<Vec<_>>()
        .join(", ");
    incompatible(
        &format!("no Windows sandbox implementation is ready to hold workspace-write ({answers})"),
        "Install Codex's Windows sandbox with `codex sandbox setup --elevated` from an elevated \
         prompt, or enable native isolation (mxc) on Windows 11 24H2 or later.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection(value: Result<Selection>) -> Selection {
        match value {
            Ok(selection) => selection,
            Err(error) => panic!("expected a selection, got {error:?}"),
        }
    }

    fn refusal(value: Result<Selection>) -> String {
        match value {
            Ok(_) => panic!("expected a refusal"),
            Err(error) => format!("{error:?}"),
        }
    }

    #[test]
    fn ready_implementation_wins_in_preference_order() {
        let chosen = selection(choose(&[
            (Implementation::Mxc, Readiness::UpdateRequired),
            (Implementation::Elevated, Readiness::NotConfigured),
            (Implementation::Unelevated, Readiness::Ready),
        ]));
        assert_eq!(chosen.implementation, Implementation::Unelevated);
        assert!(!chosen.from_user);
        assert!(chosen.sandbox_key().is_some());
    }

    #[test]
    fn no_ready_implementation_refuses_with_every_answer_and_a_working_step() {
        let text = refusal(choose(&[
            (Implementation::Mxc, Readiness::NotConfigured),
            (Implementation::Elevated, Readiness::UpdateRequired),
        ]));
        assert!(text.contains("mxc: NotConfigured"), "{text}");
        assert!(text.contains("elevated: UpdateRequired"), "{text}");
        assert!(text.contains("sandbox setup --elevated"), "{text}");
    }

    #[test]
    fn a_user_set_implementation_is_reported_and_never_sent_as_an_override() {
        let chosen = selection(decide(Implementation::Elevated, Readiness::Ready, true));
        assert_eq!(chosen.implementation, Implementation::Elevated);
        assert!(chosen.from_user);
        assert!(chosen.sandbox_key().is_none());
    }

    #[test]
    fn an_unready_user_value_refuses_rather_than_substituting_another() {
        let text = refusal(decide(
            Implementation::Elevated,
            Readiness::UpdateRequired,
            true,
        ));
        assert!(
            text.contains("your configured Windows sandbox `elevated`"),
            "{text}"
        );
        assert!(text.contains("sandbox setup --elevated"), "{text}");
    }

    #[test]
    fn an_unknown_configured_value_names_what_is_accepted() {
        let text = match Implementation::parse("legacy") {
            Ok(_) => panic!("expected a refusal"),
            Err(error) => format!("{error:?}"),
        };
        assert!(text.contains("`legacy`"), "{text}");
        assert!(text.contains("mxc, elevated or unelevated"), "{text}");
    }

    #[test]
    fn readiness_parses_only_the_three_provider_answers() {
        assert!(matches!(
            Readiness::parse(&json!({"status": "ready"})),
            Ok(Readiness::Ready)
        ));
        assert!(matches!(
            Readiness::parse(&json!({"status": "notConfigured"})),
            Ok(Readiness::NotConfigured)
        ));
        assert!(matches!(
            Readiness::parse(&json!({"status": "updateRequired"})),
            Ok(Readiness::UpdateRequired)
        ));
        assert!(Readiness::parse(&json!({"status": "elsewhere"})).is_err());
        assert!(Readiness::parse(&json!({})).is_err());
    }

    #[test]
    fn user_selection_reads_only_a_named_string() {
        assert_eq!(
            user_selection(&json!({"windows": {"sandbox": "elevated"}})),
            Some("elevated".to_owned())
        );
        assert_eq!(user_selection(&json!({"windows": {"sandbox": 3}})), None);
        assert_eq!(user_selection(&json!({})), None);
    }
}
