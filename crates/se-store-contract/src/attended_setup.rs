//! Interpretation of retained attended setup records.
/// A window that never connected may be replaced by an ordinary launch after
/// its credentials were revoked. This is not an activated conversation.
pub const ATTENDED_SETUP_EXPIRED: &str = "attended setup exceeded its activation deadline";
pub const ATTENDED_RECONNECT_FAILED: &str =
    "expired attended setup replacement failed before activation";
pub fn expired_attended_setup(record: &crate::ProjectionRecord) -> bool {
    attended_setup_reason(record) == Some(ATTENDED_SETUP_EXPIRED)
}
pub fn retryable_attended_setup(record: &crate::ProjectionRecord) -> bool {
    matches!(
        attended_setup_reason(record),
        Some(ATTENDED_SETUP_EXPIRED | ATTENDED_RECONNECT_FAILED)
    )
}
fn attended_setup_reason(record: &crate::ProjectionRecord) -> Option<&str> {
    if record.current.revision.value.get() != 2
        || !matches!(
            &record.original.as_deref().unwrap_or(&record.current).body,
            crate::EventBody::SessionPrepared {
                provider: crate::Provider::Claude,
                surface: Some(crate::SessionSurface::Window),
                ..
            }
        )
    {
        return None;
    }
    match &record.current.body {
        crate::EventBody::SessionRevoked {
            reason: crate::StoredText::Present(reason),
            ..
        } => Some(reason),
        _ => None,
    }
}
