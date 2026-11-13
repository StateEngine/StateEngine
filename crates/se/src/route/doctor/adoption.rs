//! Informational hook suppression is distinct from pending adoption failures.
use super::*;

pub(super) fn check(cx: &Bootstrap, at: &str) -> DiagnosisCheck {
    let (state, observed) = match se_host::adoption::diagnostic::observations(&cx.home) {
        Ok(rows) if rows.is_empty() => (
            CheckState::Ok,
            "No retained native hook suppression observations".into(),
        ),
        Ok(rows) => (
            CheckState::Ok,
            format!(
                "Latest IPC owner ancestry refusals (one retained per hook action): {}. Managed transport owns these hooks; if a user-started session is missing, retain this diagnostic and its native ancestry for diagnosis. These historical observations do not establish current session membership.",
                rows.iter()
                    .map(|row| format!(
                        "{} project={} at={}",
                        row.action.name(),
                        row.project,
                        row.observed_at
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ),
        Err(error) => (
            CheckState::Unmeasured,
            format!("Native hook suppression diagnostics are unreadable: {error}"),
        ),
    };
    super::check(
        "adoption.suppressed",
        "Native adoption hook suppression",
        state,
        observed,
        at,
    )
}
