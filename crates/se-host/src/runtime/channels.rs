//! Protected native channel frames share the existing authenticated IPC stream.
use super::*;
use crate::{IpcResponse, IpcResult, OperationOutput, channels::*, client::lease::Deadline};
use se_types::{ErrorEnvelope, RenderCx, Result, SeError};

pub(crate) struct ChannelsExecuted {
    output: OperationOutput,
    committed: Option<CommittedWrite>,
}

impl HostedRouter {
    pub(crate) async fn execute_channels(
        &self,
        input: ChannelRequest,
        deadline: &Deadline,
    ) -> Result<ChannelsExecuted> {
        self.check_open()?;
        let executed = self.channels.execute(input, deadline).await?;
        let committed = executed
            .committed
            .map(|(operation, receipt)| CommittedWrite {
                operation: operation.into(),
                key: receipt.request_key,
                natural_events: vec![],
                committed_events: receipt.events,
            });
        Ok(ChannelsExecuted {
            output: OperationOutput {
                schema: "se.channels/1".into(),
                value: executed.value,
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
