//! A read-only owner mail stream uses one request and one authenticated socket.
use super::*;
impl BlockingConnection {
    /// Consume frames until the sink closes or cancellation. Heartbeats carry
    /// only a resume cursor and do not trigger another request or store read.
    pub fn follow_mail(
        &mut self,
        call: crate::IpcEnvelope,
        options: &ClientOptions,
        mut consume: impl FnMut(crate::OperationOutput) -> Result<()>,
    ) -> Result<()> {
        use crate::client::wire;
        let crate::IpcRequest::Operation(operation) = &call.request else {
            return Err(SeError::invalid("mail follow", "message.list"));
        };
        if operation.name != "message.list"
            || call
                .cli_selections
                .as_ref()
                .and_then(|s| s.get("mail_follow"))
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            || !matches!(self.credential, ClientCredential::Machine(_))
            || call.version != self.hello.version
            || call.generation != self.hello.generation
            || options
                .expected_generation
                .is_some_and(|generation| generation != self.hello.generation)
        {
            return Err(SeError::invalid(
                "mail follow",
                "an owner-authenticated message-list stream",
            ));
        }
        let deadline = Deadline::from_options(options)?;
        let frame = wire::encode_call(&call)?;
        let mut stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("mail follow", "an open authenticated channel"))?;
        let writing = deadline.stage(WRITE_TIMEOUT)?;
        stream.set_bound(writing.native_bound());
        wire::write_frame_bounded(&mut stream, &frame, &writing)?;
        loop {
            let deadline = Deadline::from_options(options)?;
            stream.set_bound(deadline.native_bound());
            let limit = self.hello.maximum_reply_bytes.get() as usize;
            let bytes = wire::read_payload_bounded(&mut stream, limit, &deadline)?;
            let response = wire::decode_response(
                bytes.as_bytes(),
                call.version,
                call.generation,
                call.request_id,
                limit,
            )?;
            match response.result {
                crate::IpcResult::Output(output) => consume(*output)?,
                crate::IpcResult::Error(error) => return Err(error.body().clone().into()),
            }
        }
    }
}
