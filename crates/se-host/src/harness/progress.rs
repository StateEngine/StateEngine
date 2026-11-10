//! Bounded, redacted turn observations. Silence is not evidence of failure.
use se_core::ops::ProviderActivityView;
use std::time::{Duration, Instant};

const QUIET_BOUND: Duration = Duration::from_secs(30);
#[derive(Default)]
pub(crate) struct Progress {
    phase: Phase,
    last_event: Option<Instant>,
}
#[derive(Default)]
enum Phase {
    #[default]
    Idle,
    Active,
    Completed,
    Interrupted,
    Failed,
    Authentication,
    RetryingAuthentication,
}
impl Progress {
    pub(crate) fn offered(&mut self) {
        self.phase = Phase::Active;
        self.last_event = Some(Instant::now());
    }
    pub(crate) fn event(&mut self) {
        if matches!(self.phase, Phase::Active | Phase::RetryingAuthentication) {
            self.phase = Phase::Active;
            self.last_event = Some(Instant::now());
        }
    }
    pub(crate) fn retrying_authentication(&mut self) {
        self.phase = Phase::RetryingAuthentication;
        self.last_event = Some(Instant::now());
    }
    pub(crate) fn terminal(&mut self, status: &str, authentication: bool) {
        self.phase = if authentication {
            Phase::Authentication
        } else {
            match status {
                "completed" => Phase::Completed,
                "interrupted" => Phase::Interrupted,
                _ => Phase::Failed,
            }
        };
        self.last_event = Some(Instant::now());
    }
    pub(crate) fn view(&self, provider: &str) -> ProviderActivityView {
        let quiet = self.last_event.map(|at| at.elapsed());
        let (activity, detail, needs_help) = match self.phase {
            Phase::Idle => ("idle", "No active provider turn has been observed.", false),
            Phase::Active if quiet.is_some_and(|age| age >= QUIET_BOUND) => (
                "waiting",
                "Waiting for provider output; no event has been observed for at least 30 seconds. Sign-in, provider service availability and long-running work are not distinguished by silence.",
                true,
            ),
            Phase::Active => (
                "awaiting-provider",
                "An input offer or active turn was observed; waiting for the next provider event. Native process liveness does not prove a reply.",
                false,
            ),
            Phase::Completed => (
                "turn-completed",
                "The provider completed a turn. Check saved history and requested files; this does not establish task success.",
                false,
            ),
            Phase::Interrupted => (
                "interrupted",
                "The provider reported an interrupted turn.",
                true,
            ),
            Phase::Failed => (
                "failed",
                "The provider turn or connection failed. Provider diagnostics are withheld.",
                true,
            ),
            Phase::RetryingAuthentication => (
                "retrying-authentication",
                "The provider rejected authentication and is retrying; no later output has been observed.",
                true,
            ),
            Phase::Authentication => (
                "authentication-required",
                "The provider rejected authentication for this turn.",
                true,
            ),
        };
        let next_step = needs_help.then(|| {
            let (status, login) = if provider == "Claude" {
                ("claude auth status", "claude auth login")
            } else {
                ("codex login status", "codex login")
            };
            if matches!(self.phase, Phase::Authentication | Phase::RetryingAuthentication) {
                format!("Complete or renew sign-in with `{login}` in your own terminal, or correct the provider API key if you use one. A cached `{status}` result does not prove the provider will accept that credential. Read this agent's saved history before retrying uncertain input.")
            } else {
                format!("Run `{status}` in your own terminal; if signed out or sign-in is pending, finish `{login}`. Check provider service availability if signed in. Read this agent's saved history before retrying uncertain input.")
            }
        });
        ProviderActivityView {
            activity: activity.into(),
            detail: detail.into(),
            quiet_seconds: quiet.map(|age| age.as_secs()),
            next_step,
        }
    }
}

/// Interpret only protocol-owned structured fields, never diagnostic text.
pub(super) fn codex_authentication(error: &serde_json::Value) -> bool {
    error
        .get("codexErrorInfo")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|info| {
            [
                "httpConnectionFailed",
                "responseStreamDisconnected",
                "responseStreamConnectionFailed",
            ]
            .iter()
            .any(|kind| {
                info.get(*kind)
                    .and_then(|value| value.get("httpStatusCode"))
                    .and_then(serde_json::Value::as_u64)
                    == Some(401)
            })
        })
}
