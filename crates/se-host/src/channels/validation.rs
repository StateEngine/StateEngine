//! Closed native inputs are validated before native credential/provider work.
use super::*;
impl ChannelRequest {
    pub fn validate(&self) -> ChannelResult<()> {
        let revision = |value: u64| value > 0 && value <= i64::MAX as u64;
        let valid = match self {
            Self::CredentialCatalog | Self::Capabilities => true,
            Self::Targets(input) => input.after.as_ref().is_none_or(|c| c.as_str().len() <= 512),
            Self::ConnectTelegram(input) => {
                revision(input.credential.revision)
                    && revision(input.target.selection_revision)
                    && match &input.policy {
                        ChannelPolicy::SaveOnly => true,
                        ChannelPolicy::ConfirmResume {
                            profile,
                            profile_revision,
                            cost_limit,
                        } => {
                            !profile.is_empty()
                                && profile.len() <= 64
                                && !profile.chars().any(char::is_control)
                                && revision(*profile_revision)
                                && cost_limit.is_none_or(|cost| cost > 0 && cost <= i64::MAX as u64)
                        }
                    }
            }
            Self::ConfirmPairing(input) => revision(input.expected_pairing_revision),
            Self::RestartPairing(input) | Self::Disconnect(input) => {
                revision(input.expected_revision)
            }
            Self::Inspect(input) => {
                (input.receipt.is_none() || input.connection.is_some())
                    && input.cursor.as_ref().is_none_or(|c| c.len() <= 512)
                    && input.wait_until_us.is_none_or(|at| at >= 0)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ChannelError::InvalidInput)
        }
    }
}
pub(super) fn bounded_rows<'de, D, T>(input: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let rows = <Vec<T> as serde::Deserialize>::deserialize(input)?;
    if rows.len() > 100 {
        return Err(serde::de::Error::custom("at most 100 channel rows"));
    }
    Ok(rows)
}
pub(super) fn bounded_string<'de, D, const N: usize>(input: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(input)?;
    if value.len() > N {
        return Err(serde::de::Error::custom(
            "channel string exceeds its byte bound",
        ));
    }
    Ok(value)
}
/// Shared consent text for the guided native TUI and desktop flows.
pub const CHANNEL_CONSENT: &str = "Telegram can see this channel's contents. A paired account may send Owner instructions to the selected agent and read its linked replies. Receiving runs only while this StateEngine host is running; reopen StateEngine after logout or reboot. This setup does not install login startup. Messages not yet saved locally can expire from Telegram after its retention window (currently up to 24 hours). Disconnect revokes the binding, cancels queued output and forgets this channel's local token; rotate the bot credential separately if compromised. Saved, notice received, Read, Replied and Telegram send results are separate facts.";
