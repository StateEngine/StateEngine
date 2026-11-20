//! Complete admitted exchanges and preserve their replies.
use super::*;

impl AdmittedExchange {
    pub(crate) fn take_spawner(&mut self) -> Option<Result<OperationOutput>> {
        self.spawner.take()
    }
    pub(crate) async fn wait_for_peer_close(&self) -> Result<()> {
        self.connection.connection.wait_for_peer_close().await
    }

    #[cfg(feature = "remote")]
    pub(crate) fn take_owner_call(&mut self) -> Option<crate::remote::OwnerCall> {
        self.owner.take()
    }
    pub(crate) async fn reply_owner(
        mut self,
        result: Result<OperationOutput>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        let result = match result {
            Ok(value) => IpcResult::Output(Box::new(value)),
            Err(error) => IpcResult::Error(envelope(&error)?),
        };
        let mut response = IpcResponse {
            version: se_types::API_VERSION,
            request_id: self.request_id,
            generation: self.connection.connection.negotiated().generation,
            result,
        };
        if let Err(error) = crate::client::wire::encode_response(
            &response,
            self.connection
                .connection
                .negotiated()
                .maximum_reply_bytes
                .get() as usize,
        ) {
            response.result = IpcResult::Error(envelope(&error)?);
        }
        self.connection
            .connection
            .reply(&response, deadline)
            .await?;
        Ok(self.connection)
    }
    pub fn take_call(&mut self) -> Result<RoutedCall> {
        self.call
            .take()
            .ok_or_else(|| SeError::invalid("admitted exchange", "one owned call consumer"))?
    }

    /// The original id/API/G are taken from the admitted exchange. A complete
    /// response is budgeted and written once; an incomplete write consumes it.
    pub async fn reply(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        self.reply_with_error(output, deadline, None).await
    }
    pub(crate) async fn reply_draining(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        match deadline.remaining() {
            Ok(_) => self.reply(output, deadline).await,
            Err(expired) => {
                // Report known finish facts using the existing finite transport
                // cleanup allowance; neither execution nor storage is renewed.
                self.reply_with_error(
                    output,
                    &super::super::shutdown::cleanup_deadline()?,
                    Some(expired),
                )
                .await
            }
        }
    }
    async fn reply_with_error(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
        unavailable: Option<SeError>,
    ) -> Result<HostedConnection> {
        // An execution error already carries its authoritative outcome. Only a
        // completed output needs conversion when the shutdown budget expired.
        let unavailable = output.as_ref().ok().and(unavailable);
        let mut connection = self.connection;
        let committed = output
            .as_ref()
            .ok()
            .and_then(|completed| completed.committed.clone());
        let capture_keys = output
            .as_ref()
            .ok()
            .map(|completed| completed.capture_keys.clone())
            .unwrap_or_default();
        let capture_events: Vec<_> = output
            .as_ref()
            .ok()
            .into_iter()
            .flat_map(|completed| &completed.capture_commits)
            .map(|commit| commit.event_id.clone())
            .collect();
        let result = match output {
            Ok(mut completed) => {
                completed.host_phases.admission = self.admission;
                completed.host_phases.admitted_to_encode_us =
                    Some(timings::micros(self.admitted_at.elapsed()));
                encode_executed(completed).map(|o| IpcResult::Output(Box::new(o)))
            }
            Err(error) => envelope(&error).map(IpcResult::Error),
        };
        let response_error = |error: SeError| {
            let error = committed
                .as_ref()
                .map_or(error.body.clone().into(), |known| {
                    known.response_error(error)
                });
            if !capture_events.is_empty() {
                SeError::new(se_types::Detail::CaptureIncomplete(
                    se_types::details::CaptureIncomplete {
                        committed_events: capture_events.clone(),
                        natural_keys: capture_keys.clone(),
                        reason: error.to_string(),
                    },
                ))
                .with_cause(error)
            } else {
                error
            }
        };
        let result = match (result, unavailable) {
            (_, Some(expired)) => IpcResult::Error(envelope(&response_error(expired))?),
            (Ok(result), None) => result,
            (Err(error), None) => IpcResult::Error(envelope(&response_error(error))?),
        };
        let mut response = IpcResponse {
            version: se_types::API_VERSION,
            request_id: self.request_id,
            generation: connection.connection.negotiated().generation,
            result,
        };
        // Encode/validate before consuming the channel. A known commit whose
        // output exceeds its negotiated budget still receives a typed key error.
        if let Err(error) = crate::client::wire::encode_response(
            &response,
            connection.connection.negotiated().maximum_reply_bytes.get() as usize,
        ) {
            response.result = IpcResult::Error(envelope(&response_error(error))?);
        }
        connection.connection.reply(&response, deadline).await?;
        Ok(connection)
    }
}
