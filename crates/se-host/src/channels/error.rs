//! Closed channel failures are shared with the native error envelope.
pub use se_types::MessagingChannelError as ChannelError;
pub type ChannelResult<T> = Result<T, ChannelError>;
/// A custody failure keeps the real native cause instead of a bare code.
pub(crate) fn credential_store_unavailable(cause: impl std::fmt::Display) -> ChannelError {
    ChannelError::CredentialStoreUnavailable {
        cause: cause.to_string(),
    }
}
