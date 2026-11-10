use se_types::remote::{MachineSession, RemoteInvocation, RemoteRequest, RemoteSourceSession};
use se_types::{Detail, Result, SeError, details};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Immutable trusted-local call context. This is deliberately not serde: a wire
/// source stamp is data, while this value comes from source IPC/native admission.
/// Same-process code is inside the trust boundary (AGENTS.md, trust-boundary law).
pub struct RemoteCallContext {
    source: Option<RemoteSourceSession>,
    fenced: Option<Arc<AtomicBool>>,
}
impl RemoteCallContext {
    /// Human CLI key lookup still requires its actual native Owner/ancestry guard.
    /// This value alone grants no authority and cannot select a human device key.
    pub fn human_device() -> Self {
        Self {
            source: None,
            fenced: None,
        }
    }

    /// The broker calls this only after protected local IPC verifies this exact
    /// source session/generation. Its session owner closes the shared fence on
    /// end/revoke; a successor requires fresh admission and a new context/watch.
    pub fn from_verified_source(source: RemoteSourceSession, fenced: Arc<AtomicBool>) -> Self {
        Self {
            source: Some(source),
            fenced: Some(fenced),
        }
    }
    pub fn source(&self) -> Option<&RemoteSourceSession> {
        self.source.as_ref()
    }

    /// Invoke before enqueue and again before transmission/output release. It
    /// cannot undo an operation the remote host already admitted before fencing.
    pub fn check_current(&self) -> Result<()> {
        if self
            .fenced
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Acquire))
        {
            return Err(SeError::new(Detail::CapabilityInvalid(details::CapabilityInvalid {
                subject: "remote source session".into(),
                reason: "the originating source session/generation was fenced".into(),
                next_step: "Reconnect through the current admitted source session; do not use a human device key.".into(),
            })));
        }
        Ok(())
    }

    pub fn invocation(
        &self,
        device: &MachineSession,
        request: RemoteRequest,
    ) -> Result<RemoteInvocation> {
        self.check_current()?;
        if !device.subject.admits_source(self.source()) {
            return Err(SeError::new(Detail::CapabilityInvalid(details::CapabilityInvalid {
                subject: "remote grant subject".into(),
                reason: "the immutable source context does not match this device grant".into(),
                next_step: "Use the Owner-configured binding for this exact source agent; no human-key fallback is permitted.".into(),
            })));
        }
        request.validate()?;
        Ok(RemoteInvocation {
            source: self.source.clone(),
            request,
        })
    }
}
