//! Execute native Owner channel requests and format their bounded JSON payloads.
use crate::{ChannelRequest, Channels, host::AsChannelDeadline, validation::CHANNEL_CONSENT};
use se_store::CommitReceipt;
use se_types::{Result, SeError};
use serde_json::{Value, json};

pub struct ChannelExecution {
    pub value: Value,
    pub committed: Option<(&'static str, CommitReceipt)>,
}

fn receipt(receipt: &CommitReceipt) -> Value {
    json!({
        "event_id": receipt.primary_event,
        "idempotency_key": receipt.request_key,
        "durability": format!("{:?}", receipt.durability),
    })
}

impl Channels {
    pub async fn execute(
        &self,
        input: ChannelRequest,
        deadline: &impl AsChannelDeadline,
    ) -> Result<ChannelExecution> {
        let mut committed = None;
        let value = match input {
            ChannelRequest::Capabilities => json!({
                "consent": CHANNEL_CONSENT,
                "receiver": "existing_store_owning_host",
                "automatic_login_startup": false,
                "remote_credentials": "unsupported_until_protected_native_add_machine_flow",
                "cost_limit_override": false,
                "confirmed_resume": self.supports_resume(),
                "connectors": self.transports.iter().map(|t| t.descriptor()).collect::<Vec<_>>(),
            }),
            ChannelRequest::Targets(input) => {
                serde_json::to_value(self.targets(input, deadline).await?).map_err(|_| {
                    SeError::invalid(
                        "channel saved-agent choices",
                        "bounded native Rust selections",
                    )
                })?
            }
            ChannelRequest::CredentialCatalog => {
                serde_json::to_value(self.credential_catalog(deadline).await?).map_err(|_| {
                    SeError::invalid("credential catalog", "bounded non-secret references")
                })?
            }
            ChannelRequest::Inspect(input) => {
                serde_json::to_value(self.inspect(input, deadline).await?).map_err(|_| {
                    SeError::invalid("channel snapshot", "serializable bounded facts")
                })?
            }
            ChannelRequest::Connect(input) => {
                let result = self.connect_channel(input, deadline).await?;
                committed = Some(("channel.connect", result.receipt.clone()));
                let link = std::str::from_utf8(result.ticket.expose_link())
                    .map_err(|_| SeError::invalid("pairing link", "UTF-8 native presentation"))?;
                json!({
                    "receipt": receipt(&result.receipt),
                    "connection": result.connection.id,
                    "revision": result.connection.revision,
                    "verified_bot": result.connection.bot,
                    "pairing": {
                        "uri": link,
                        "message": result.ticket.expose_message(),
                        "expires_at_us": result.ticket.expires_at_us,
                        "revision": result.ticket.revision,
                    },
                })
            }
            ChannelRequest::RestartPairing(input) => {
                let result = self.restart_pairing(input, deadline).await?;
                committed = result
                    .receipt
                    .as_ref()
                    .map(|receipt| ("channel.pairing.restart", receipt.clone()));
                let link = std::str::from_utf8(result.expose_link())
                    .map_err(|_| SeError::invalid("pairing link", "UTF-8 native presentation"))?;
                json!({
                    "connection": result.connection,
                    "revision": result.revision,
                    "pairing": {
                        "uri": link,
                        "message": result.expose_message(),
                        "expires_at_us": result.expires_at_us,
                        "revision": result.revision,
                    },
                })
            }
            ChannelRequest::ConfirmPairing(input) => {
                let result = self.confirm_pairing(input, deadline).await?;
                committed = Some(("channel.pairing.confirm", result.clone()));
                json!({"receipt": receipt(&result)})
            }
            ChannelRequest::Disconnect(input) => {
                let result = self.disconnect(input, deadline).await?;
                committed = Some(("channel.disconnect", result.receipt.clone()));
                json!({
                    "receipt": receipt(&result.receipt),
                    "credential_removal": result.credential_removal,
                })
            }
        };
        Ok(ChannelExecution { value, committed })
    }
}
