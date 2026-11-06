//! Protected native channel frames share the existing authenticated IPC stream.
use super::*;
use crate::client::lease::Deadline;
use crate::{IpcResponse, IpcResult, OperationOutput, channels::*};
use se_types::{ErrorEnvelope, RenderCx, Result, SeError};
use serde_json::{Value, json};

fn receipt(receipt: &se_store::CommitReceipt) -> Value {
    json!({"event_id":receipt.primary_event,"idempotency_key":receipt.request_key,"durability":format!("{:?}",receipt.durability)})
}
pub(crate) struct ChannelsExecuted {
    output: OperationOutput,
    committed: Option<CommittedWrite>,
}
fn known(operation: &str, receipt: &se_store::CommitReceipt) -> CommittedWrite {
    CommittedWrite {
        operation: operation.into(),
        key: receipt.request_key.clone(),
        natural_events: vec![],
        committed_events: receipt.events.clone(),
    }
}
impl HostedRouter {
    pub(crate) async fn execute_channels(
        &self,
        input: ChannelRequest,
        deadline: &Deadline,
    ) -> Result<ChannelsExecuted> {
        self.check_open()?;
        let mut committed = None;
        let value = match input {
            ChannelRequest::Capabilities => {
                json!({"consent":CHANNEL_CONSENT,"receiver":"existing_store_owning_host","automatic_login_startup":false,"remote_credentials":"unsupported_until_protected_native_add_machine_flow","cost_limit_override":false,"confirmed_resume":self.channels.supports_resume()})
            }
            ChannelRequest::Targets(input) => serde_json::to_value(
                self.channels.targets(input, deadline).await?,
            )
            .map_err(|_| {
                SeError::invalid(
                    "channel saved-agent choices",
                    "bounded native Rust selections",
                )
            })?,
            ChannelRequest::CredentialCatalog => serde_json::to_value(
                self.channels.credential_catalog(deadline).await?,
            )
            .map_err(|_| SeError::invalid("credential catalog", "bounded non-secret references"))?,
            ChannelRequest::Inspect(input) => serde_json::to_value(
                self.channels.inspect(input, deadline).await?,
            )
            .map_err(|_| SeError::invalid("channel snapshot", "serializable bounded facts"))?,
            ChannelRequest::ConnectTelegram(input) => {
                let result = self.channels.connect_telegram(input, deadline).await?;
                committed = Some(known("channel.connect", &result.receipt));
                let link = std::str::from_utf8(result.ticket.expose_link())
                    .map_err(|_| SeError::invalid("pairing link", "UTF-8 native presentation"))?;
                json!({"receipt":receipt(&result.receipt),"connection":result.connection.id,"revision":result.connection.revision,"verified_bot":result.connection.bot,"pairing":{"uri":link,"expires_at_us":result.ticket.expires_at_us,"revision":result.ticket.revision}})
            }
            ChannelRequest::RestartPairing(input) => {
                let result = self.channels.restart_pairing(input, deadline).await?;
                committed = result
                    .receipt
                    .as_ref()
                    .map(|receipt| known("channel.pairing.restart", receipt));
                let link = std::str::from_utf8(result.expose_link())
                    .map_err(|_| SeError::invalid("pairing link", "UTF-8 native presentation"))?;
                json!({"connection":result.connection,"revision":result.revision,"pairing":{"uri":link,"expires_at_us":result.expires_at_us,"revision":result.revision}})
            }
            ChannelRequest::ConfirmPairing(input) => {
                let result = self.channels.confirm_pairing(input, deadline).await?;
                committed = Some(known("channel.pairing.confirm", &result));
                json!({"receipt":receipt(&result)})
            }
            ChannelRequest::Disconnect(input) => {
                let result = self.channels.disconnect(input, deadline).await?;
                committed = Some(known("channel.disconnect", &result.receipt));
                json!({"receipt":receipt(&result.receipt),"credential_removal":result.credential_removal})
            }
        };
        Ok(ChannelsExecuted {
            output: OperationOutput {
                schema: "se.channels/1".into(),
                value,
                window: None,
            },
            committed,
        })
    }
}
impl AdmittedExchange {
    pub(crate) fn take_channels(&mut self) -> Option<ChannelRequest> {
        self.channels.take()
    }
    pub(crate) async fn reply_channels(
        self,
        output: Result<ChannelsExecuted>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        let mut connection = self.connection;
        let known = output
            .as_ref()
            .ok()
            .and_then(|value| value.committed.clone());
        let response_error = |error: SeError| match &known {
            Some(known) => known.response_error(error),
            None => error,
        };
        let result = match output {
            Ok(value) => IpcResult::Output(Box::new(value.output)),
            Err(error) => IpcResult::Error(ErrorEnvelope::new(error.body, &RenderCx::default())?),
        };
        let mut response = IpcResponse {
            version: se_types::API_VERSION,
            request_id: self.request_id,
            generation: connection.connection.negotiated().generation,
            result,
        };
        let unavailable = deadline.remaining().err().or_else(|| {
            crate::client::wire::encode_response(
                &response,
                connection.connection.negotiated().maximum_reply_bytes.get() as usize,
            )
            .err()
        });
        if let Some(error) = unavailable {
            response.result = IpcResult::Error(ErrorEnvelope::new(
                response_error(error).body,
                &RenderCx::default(),
            )?);
        }
        connection
            .connection
            .reply(&response, deadline)
            .await
            .map_err(response_error)?;
        Ok(connection)
    }
}
