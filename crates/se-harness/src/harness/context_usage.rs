//! The latest context usage a provider reported for its live conversation.
//! Only the provider's own numbers are kept; nothing is estimated.
use se_core::ops::ContextWindowView;
use se_types::Read;
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextUsage {
    /// Tokens in context at the provider's latest report.
    pub used: u64,
    /// The window size the provider reported with it, if any.
    pub window: Option<u64>,
    pub observed: SystemTime,
}
impl ContextUsage {
    pub fn now(used: u64, window: Option<u64>) -> Self {
        Self {
            used,
            window,
            observed: SystemTime::now(),
        }
    }
}
/// The status value for a live binding: its latest report, or why there is none.
pub fn view(
    usage: Option<ContextUsage>,
    configured: Option<u64>,
    provider: &str,
) -> Read<ContextWindowView> {
    match usage {
        Some(usage) => Read::Present {
            value: ContextWindowView::new(
                usage.used,
                usage.window,
                configured,
                Some(usage.observed),
            ),
        },
        None => Read::Unknown {
            what: format!("{provider} has not reported token usage in this conversation yet"),
        },
    }
}
