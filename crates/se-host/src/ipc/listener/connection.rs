//! One authenticated request/response channel, including clean peer EOF.
use super::channel::receive_optional;
use super::*;

pub struct IpcConnection {
    pub(super) stream: Option<Arc<NativeStream>>,
    pub(super) peer: PeerProof,
    pub(super) hello: ServerHello,
    pub(super) authority: PresentedAuthority,
    pub(super) awaiting: Option<u64>,
    pub(super) _connection_slot: tokio::sync::OwnedSemaphorePermit,
}
impl IpcConnection {
    /// Only while a cancellable read owns the outstanding request. A caller
    /// cannot pipeline another frame before its response; EOF retires the read.
    pub(crate) async fn wait_for_peer_close(&self) -> Result<()> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| SeError::invalid("IPC channel", "an admitted outstanding read"))?;
        let mut byte = [0];
        loop {
            if let Err(error) = stream.readable().await {
                match error.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected => return Ok(()),
                    _ => return Err(wire::io_failure("wait IPC peer close", error)),
                }
            }
            match stream.try_read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(SeError::invalid(
                        "IPC request",
                        "one outstanding operation per connection; await its response",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::NotConnected
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(wire::io_failure("read IPC peer close", error)),
            }
        }
    }

    pub fn connection_authority(&self) -> &PresentedAuthority {
        &self.authority
    }
    pub fn peer(&self) -> &PeerProof {
        &self.peer
    }
    pub fn negotiated(&self) -> &ServerHello {
        &self.hello
    }
    /// Runtime rechecks G, revocation and scope for each returned envelope before
    /// dispatch. A per-call invalid credential must not use connection authority.
    pub async fn read_request(&mut self, deadline: &Deadline) -> Result<IpcEnvelope> {
        self.read_request_or_closed(deadline).await?.ok_or_else(|| {
            wire::io_failure(
                "IPC request channel closed",
                std::io::ErrorKind::UnexpectedEof.into(),
            )
        })
    }
    /// EOF before any next-frame byte is an ordinary connection close. Partial
    /// headers and bodies still refuse; no incomplete call can reach dispatch.
    pub async fn read_request_or_closed(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<IpcEnvelope>> {
        if self.awaiting.is_some() {
            return Err(SeError::invalid(
                "IPC request",
                "one outstanding operation per connection",
            ));
        }
        let stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("IPC channel", "a complete prior exchange"))?;
        let Some(bytes) = receive_optional(&stream, deadline, wire::MAX_FRAME_BYTES).await? else {
            return Ok(None);
        };
        let call = wire::decode_call(bytes.as_bytes())?;
        if call.version != self.hello.version || call.generation != self.hello.generation {
            return Err(SeError::invalid(
                "IPC call",
                "the exact negotiated API and generation",
            ));
        }
        self.awaiting = Some(call.request_id);
        self.stream = Some(stream);
        Ok(Some(call))
    }
    pub(crate) async fn read_after_idle(
        &mut self,
        idle: &Deadline,
    ) -> Result<Option<(IpcEnvelope, Deadline)>> {
        if self.awaiting.is_some() {
            return Err(SeError::invalid("IPC request", "one outstanding operation"));
        }
        let stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("IPC channel", "a complete prior exchange"))?;
        let Some((bytes, deadline)) =
            super::channel::receive_after_idle(&stream, idle, wire::MAX_FRAME_BYTES).await?
        else {
            return Ok(None);
        };
        let call = wire::decode_call(bytes.as_bytes())?;
        if call.version != self.hello.version || call.generation != self.hello.generation {
            return Err(SeError::invalid(
                "IPC call",
                "the negotiated API and generation",
            ));
        }
        self.awaiting = Some(call.request_id);
        self.stream = Some(stream);
        Ok(Some((call, deadline)))
    }
    pub async fn reply(&mut self, response: &IpcResponse, deadline: &Deadline) -> Result<()> {
        if self.awaiting != Some(response.request_id)
            || response.version != self.hello.version
            || response.generation != self.hello.generation
        {
            return Err(SeError::invalid(
                "IPC reply",
                "the exact outstanding request ID, API and generation",
            ));
        }
        let frame = wire::encode_response(response, self.hello.maximum_reply_bytes.get() as usize)?;
        let stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("IPC channel", "a complete prior exchange"))?;
        send(&stream, &frame, &deadline.stage(WRITE_TIMEOUT)?).await?;
        self.awaiting = None;
        self.stream = Some(stream);
        Ok(())
    }
}
