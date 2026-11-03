//! Metadata access for the coordinator's already trusted, restored native pin.
//! A caller-supplied pathname is never accepted as a binding.
use super::*;

impl CaptureHandle {
    pub fn binding(&self, identity: crate::SessionIdentity) -> Result<Read<crate::TranscriptPin>> {
        let source = {
            let pins = try_guard(&self.sources.pins)?;
            match pins.active.get(&identity.session) {
                Some(pin) => Arc::clone(pin),
                None => {
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
