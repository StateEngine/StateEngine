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

/// The layer a host-chosen implementation adds to `thread/start`: one
/// per-launch key, never an edit to the user's file (a value they set already
/// stands). The TOML string decodes to the bare implementation name.
pub fn launch_config(implementation: Implementation) -> (&'static str, Value) {
    (
        "windows.sandbox",
        Value::String(json!(implementation.key()).to_string()),
    )
}

/// The readiness request for one named implementation. The answer covers that
/// implementation only, so each choice is asked about separately.
pub fn readiness_request(implementation: Implementation) -> Value {
    json!({ "config": { "windows.sandbox": json!(implementation.key()) } })
}

/// The value the user set in their own Codex configuration, if any. Only an
/// absent `windows` table means "nothing set": a non-string value refuses
/// rather than defaulting.
pub fn configured(config: &Value) -> Result<Option<Implementation>> {
    let Some(windows) = config.get("windows") else {
        return Ok(None);
    };
    if !windows.is_object() {
        return Err(se_core::scope::unreadable(
            "the user's Windows Codex configuration",
            "an object-valued windows table",
        ));
    }
    match windows.get("sandbox") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => Implementation::parse(name).map(Some),
        Some(_) => Err(incompatible(
            "your Codex configuration sets windows.sandbox to a value that is not a string",
            "Set windows.sandbox to \"mxc\", \"elevated\" or \"unelevated\".",
        )),
    }
}

/// The first host-chosen implementation the provider answers ready for.
pub fn choose(attempted: &[(Implementation, Readiness)]) -> Result<Implementation> {
    attempted
        .iter()
        .find(|(_, readiness)| *readiness == Readiness::Ready)
        .map(|(implementation, _)| *implementation)
        .ok_or_else(|| not_ready(attempted))
}

/// The user's own value. Their choice wins even when another implementation is
/// ready: the host reports the state and never substitutes one they did not pick.
pub fn require_ready(
    implementation: Implementation,
    readiness: Readiness,
) -> Result<Implementation> {
    if readiness == Readiness::Ready {
        return Ok(implementation);
    }
    Err(incompatible(
        &format!(
            "your configured Windows sandbox `{}` is not ready ({readiness:?})",
            implementation.key()
        ),
        "Install or repair that sandbox with `codex sandbox setup --elevated` from an \
         elevated prompt, or choose another windows.sandbox in your Codex configuration.",
    ))
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

    fn refusal<T>(value: Result<T>) -> String {
        format!("{:?}", value.expect_err("expected a refusal"))
    }

    #[test]
    fn ready_implementation_wins_in_preference_order() {
        let chosen = choose(&[
            (Implementation::Mxc, Readiness::UpdateRequired),
            (Implementation::Elevated, Readiness::NotConfigured),
            (Implementation::Unelevated, Readiness::Ready),
        ]);
        assert_eq!(chosen.ok(), Some(Implementation::Unelevated));
    }

    #[test]
    fn no_ready_implementation_refuses_with_every_answer() {
        let text = refusal(choose(&[
            (Implementation::Mxc, Readiness::NotConfigured),
            (Implementation::Elevated, Readiness::UpdateRequired),
        ]));
        assert!(text.contains("mxc: NotConfigured"), "{text}");
        assert!(text.contains("elevated: UpdateRequired"), "{text}");
        assert!(text.contains("sandbox setup --elevated"), "{text}");
    }

    #[test]
    fn an_absent_windows_table_means_the_user_set_nothing() {
        assert_eq!(configured(&json!({ "model": "x" })).ok(), Some(None));
        let nulled = configured(&json!({ "windows": { "allow_mxc": null } }));
        assert_eq!(nulled.ok(), Some(None));
    }

    #[test]
    fn a_non_string_user_value_refuses() {
        let text = refusal(configured(&json!({ "windows": { "sandbox": 3 } })));
        assert!(text.contains("not a string"), "{text}");
        let text = refusal(configured(&json!({ "windows": "elevated" })));
        assert!(text.contains("object-valued windows table"), "{text}");
        let text = refusal(configured(&json!({ "windows": { "sandbox": "legacy" } })));
        assert!(text.contains("`legacy`"), "{text}");
    }

    #[test]
    fn a_user_set_implementation_needs_no_host_key() {
        let chosen = configured(&json!({ "windows": { "sandbox": "elevated" } }));
        assert_eq!(chosen.ok().flatten(), Some(Implementation::Elevated));
    }

    #[test]
    fn an_unready_user_value_refuses_without_substituting() {
        let unready = require_ready(Implementation::Elevated, Readiness::UpdateRequired);
        let text = refusal(unready);
        assert!(text.contains("configured Windows sandbox `elevated` {text}"));
        assert!(text.contains("sandbox setup --elevated"), "{text}");
    }

    #[test]
    fn the_launch_layer_names_the_bare_provider_choice() {
        let (key, value) = launch_config(Implementation::Unelevated);
        assert_eq!(key, "windows.sandbox");
        // The provider reads this as TOML, so the quoted spelling decodes to
        // the bare name readiness was asked about.
        let source = value.as_str().expect("a TOML string, not a JSON scalar");
        let decoded = serde_json::from_str::<Value>(source);
        assert_eq!(decoded, Ok(json!("unelevated")));
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
