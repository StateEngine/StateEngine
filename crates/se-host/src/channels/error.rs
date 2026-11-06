//! Closed channel failures are shared with the native error envelope.
pub use se_types::MessagingChannelError as ChannelError;
pub type ChannelResult<T> = Result<T, ChannelError>;
