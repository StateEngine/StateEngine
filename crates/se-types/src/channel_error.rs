//! Stable transport/control failures never retain provider errors containing URLs.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessagingChannelError {
    InvalidToken,
    PollerConflict,
    ProviderUnreachable,
    ProviderProtocol,
    ReplayUnavailable,
    PairingExpired,
    RevisionConflict,
    IdempotencyConflict,
    Unsupported,
    CredentialStoreUnavailable,
    CredentialAbsent,
    CredentialScopeMismatch,
    ReceiverNotRunning,
    SaveOutcomeUnknown,
    QueueFull,
    MessageTooLarge,
    BindingRevoked,
    SendOutcomeUnknown,
    InvalidInput,
    ContentErased,
    RateLimited { retry_after_seconds: u32 },
}
impl std::fmt::Display for MessagingChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for MessagingChannelError {}

impl MessagingChannelError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::PollerConflict => "poller_conflict",
            Self::ProviderUnreachable => "provider_unreachable",
            Self::ProviderProtocol => "provider_protocol",
            Self::ReplayUnavailable => "receive_replay_unavailable",
            Self::PairingExpired => "pairing_expired",
            Self::RevisionConflict => "revision_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Unsupported => "unsupported",
            Self::CredentialStoreUnavailable => "credential_store_unavailable",
            Self::CredentialAbsent => "credential_absent",
            Self::CredentialScopeMismatch => "credential_scope_mismatch",
            Self::ReceiverNotRunning => "receiver_not_running",
            Self::SaveOutcomeUnknown => "save_outcome_unknown",
            Self::QueueFull => "queue_full",
            Self::MessageTooLarge => "message_too_large",
            Self::BindingRevoked => "binding_revoked",
            Self::SendOutcomeUnknown => "send_outcome_unknown",
            Self::InvalidInput => "invalid_input",
            Self::ContentErased => "content_erased",
            Self::RateLimited { .. } => "rate_limited",
        }
    }
}

impl MessagingChannelError {
    pub fn remedy(self) -> &'static str {
        match self {
            Self::InvalidToken => {
                "Enter a valid bot token in the protected native Channels screen; never send it in agent mail or chat."
            }
            Self::PollerConflict => {
                "Stop the other Telegram receiver for this bot before reconnecting; preserve pending updates."
            }
            Self::PairingExpired => {
                "Restart pairing in Channels and approve the exact numeric phone identity again."
            }
            Self::RevisionConflict | Self::BindingRevoked => {
                "Refresh the native connection and target. Keep the original request key when resolving an earlier outcome."
            }
            Self::IdempotencyConflict => {
                "Reuse the original key only with its original payload; select a new key for a different intended change."
            }
            Self::CredentialStoreUnavailable
            | Self::CredentialScopeMismatch
            | Self::CredentialAbsent => {
                "Restore protected native credential custody for this exact home and Owner; never fall back to a token in configuration or agent input."
            }
            Self::Unsupported => {
                "Choose Save only or approve the action locally. Remote credential entry, cost overrides and unsupported native lifecycle steps require a supported native flow."
            }
            Self::ReceiverNotRunning => {
                "Open this StateEngine home to run its receiver. Receiving does not continue after logout or reboot until the host starts again."
            }
            Self::SaveOutcomeUnknown => {
                "Inspect the original saved receipt before resending. Provider updates retain their original deduplication identity."
            }
            Self::SendOutcomeUnknown => {
                "Inspect the original reply and delivery status; an uncertain send is never automatically resent."
            }
            Self::QueueFull => {
                "Wait for pending mail or channel output to drain; this input has not been reported as Saved."
            }
            Self::MessageTooLarge => {
                "Shorten or split the message explicitly; StateEngine does not silently truncate channel text."
            }
            Self::ContentErased => {
                "Erased reply content is never retransmitted; later channel mail can continue."
            }
            Self::InvalidInput => {
                "Refresh Channels and use its typed inputs, exact revisions and original mutation keys."
            }
            Self::ReplayUnavailable => {
                "The provider could not replay an earlier receive session. Inspect the receive coverage gap; unsaved messages in that interval may need resending."
            }
            Self::ProviderProtocol | Self::ProviderUnreachable | Self::RateLimited { .. } => {
                "Keep the connection open and inspect its retry status; saved local mail remains durable during the outage."
            }
        }
    }
    pub fn refusal(self) -> crate::SeError {
        let mut error = crate::SeError::new(crate::Detail::MessagingChannelRefused(
            crate::details::MessagingChannelRefused {
                reason: self,
                next_step: self.remedy().into(),
            },
        ));
        error.body = error.body.with_retry(match self {
            Self::RateLimited {
                retry_after_seconds,
            } => crate::Retry::After(std::time::Duration::from_secs(u64::from(
                retry_after_seconds.clamp(1, 3600),
            ))),
            Self::ProviderUnreachable
            | Self::ProviderProtocol
            | Self::ReplayUnavailable
            | Self::RevisionConflict
            | Self::CredentialStoreUnavailable
            | Self::SaveOutcomeUnknown
            | Self::SendOutcomeUnknown => crate::Retry::AfterReread,
            Self::ReceiverNotRunning => crate::Retry::WhenRuntimeReady,
            _ => crate::Retry::Never,
        });
        error
    }
}
