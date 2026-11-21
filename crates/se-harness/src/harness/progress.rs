//! Bounded, redacted turn observations. Silence is not evidence of failure.
use se_core::ops::ProviderActivityView;
use std::time::{Duration, Instant};

const QUIET_BOUND: Duration = Duration::from_secs(30);
#[derive(Default)]
pub struct Progress {
    phase: Phase,
    last_event: Option<Instant>,
    /// When the current phase began; events within an active turn keep it.
    phase_started: Option<Instant>,
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
    fn enter(&mut self, phase: Phase) {
        let now = Instant::now();
        if std::mem::discriminant(&self.phase) != std::mem::discriminant(&phase) {
            self.phase_started = Some(now);
        }
        self.phase = phase;
        self.last_event = Some(now);
    }
    pub fn offered(&mut self) {
        self.enter(Phase::Active);
    }
    pub fn event(&mut self) {
        if matches!(self.phase, Phase::Active | Phase::RetryingAuthentication) {
            self.enter(Phase::Active);
        }
    }
    pub fn retrying_authentication(&mut self) {
        self.enter(Phase::RetryingAuthentication);
    }
    pub fn terminal(&mut self, status: &str, authentication: bool) {
        let phase = if authentication {
            Phase::Authentication
        } else {
            match status {
                "completed" => Phase::Completed,
                "interrupted" => Phase::Interrupted,
                _ => Phase::Failed,
            }
        };
        self.enter(phase);
    }
    pub fn view(&self, provider: &str) -> ProviderActivityView {
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
            phase_started_at: self.phase_started.and_then(|at| {
                let wall = std::time::SystemTime::now().checked_sub(at.elapsed())?;
                let micros = wall.duration_since(std::time::UNIX_EPOCH).ok()?.as_micros();
                se_types::format_timestamp(i64::try_from(micros).ok()?).ok()
            }),
            phase_seconds: self.phase_started.map(|at| at.elapsed().as_secs()),
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
