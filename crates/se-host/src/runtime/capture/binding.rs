//! Metadata access for the coordinator's already trusted, restored native pin.
//! A caller-supplied pathname is never accepted as a binding.
use super::*;

impl CaptureHandle {
    /// Startup custody is installed before listener publication. A recovered
    /// monitor must wait for that publication before capture or provider RPC.
    pub(crate) async fn wait_until_open(&self, deadline: &Deadline) -> Result<()> {
        while self.fenced.load(std::sync::atomic::Ordering::Acquire) {
            if self.lease.upgrade().is_none() {
                return Err(se_core::scope::unreadable(
                    "provider recovery readiness",
                    "the original host lease was released before readiness",
                ));
            }
            let remaining = deadline.remaining()?;
            tokio::time::sleep(remaining.min(std::time::Duration::from_millis(25))).await;
        }
        deadline.remaining()?;
        Ok(())
    }
    pub fn binding(&self, identity: crate::SessionIdentity) -> Result<Read<crate::TranscriptPin>> {
        let source = {
            let pins = self.sources.registry()?;
            match pins.active.get(&identity.session) {
                Some(pin) => Arc::clone(pin),
                None => {
                    if pins.publishing.contains(&identity.session) {
                        return Err(busy());
                    }
                    if let Some(error) = pins
                        .failed
                        .get(&identity.session)
                        .or(pins.unavailable.as_ref())
                    {
                        return Err(error.clone().into());
                    }
                    return Ok(Read::Absent {
                        checked:
                            "no trusted transcript binding was restored for this exact session"
                                .into(),
                    });
                }
            }
        };
        let source = try_guard(&source)?;
        if source.binding.identity.project != identity.project
            || source.binding.identity.agent != identity.agent
            || source.binding.identity.session != identity.session
        {
            return Err(SeError::invalid(
                "restored capture binding",
                "the exact project, agent and session",
            ));
        }
        Ok(Read::Present {
            value: source.binding.clone(),
        })
    }
}
