//! Completion waits and retained native operation release.
use super::*;

impl<R: ProviderStdioApi + Send + Sync + 'static> WindowsProviderIo<R> {
    /// Wait for one ticket's terminal result until `until`; `None` means it is
    /// still pending and its custody stays with the caller.
    pub(super) async fn settle(
        &self,
        port: &Port,
        ticket: &StdioTicket,
        until: Instant,
    ) -> Result<Option<StdioCompletion>> {
        loop {
            // Register before checking, so a nudge between the two is not lost.
            let mut notified = pin!(port.wake.0.notified());
            notified.as_mut().enable();
            match self
                .runtime
                .take_completion(ticket)
                .map_err(|e| native("provider stream completion", &e))?
            {
                StdioCompletion::Pending => {}
                done => return Ok(Some(done)),
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return Ok(None);
            }
        }
    }
    /// Release a ticket whose result was taken; a failed release is owed to
    /// `close` rather than dropped.
    pub(super) fn release(&self, port: &Port, ticket: StdioTicket, taken: bool) {
        if self.runtime.release_operation(&ticket).is_err() {
            self.owe(port, ticket, taken);
        }
    }
    pub(super) fn owe(&self, port: &Port, ticket: StdioTicket, taken: bool) {
        // Poison still refuses normal close, but must never discard custody.
        let mut owed = port
            .unreleased
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owed.push(Unreleased { ticket, taken });
    }
    /// Close host stdin without waiting; `close` drains its ticket.
    pub(super) fn retire_stdin(&self, port: &Port, writer: &mut Writer) {
        writer.open = false;
        if writer.finished || writer.closing.is_some() {
            return;
        }
        if let Ok(ticket) = self.runtime.begin_close(&port.port, StdioCloseScope::Stdin) {
            writer.closing = Some(ticket);
        }
    }
}

pub(super) fn port(transport: &ProviderTransport) -> Result<&Port> {
    transport
        .windows
        .as_ref()
        .ok_or_else(|| SeError::invalid("provider transport", "one opened by this platform"))
}

pub(super) async fn bounded<T>(
    cx: &CallContext,
    work: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::time::timeout(cx.timeout, work)
        .await
        .map_err(|_| deadline_exceeded(cx))
}

pub(super) fn deadline_exceeded(cx: &CallContext) -> SeError {
    SeError::new(se_types::Detail::DeadlineExceeded(
        se_types::details::DeadlineExceeded {
            op: "provider stream".into(),
            deadline_ms: u64::try_from(cx.timeout.as_millis()).unwrap_or(u64::MAX),
        },
    ))
}

pub(super) fn native(what: &str, error: &ProcError) -> SeError {
    let reason = match &error.native {
        Some(failure) => format!("{:?}: {}", error.code, failure.reason),
        None => format!("{:?}", error.code),
    };
    se_core::scope::unreadable(what, &reason)
}

pub(super) fn poisoned() -> SeError {
    se_core::scope::unreadable("provider stream state", "a poisoned lock")
}
