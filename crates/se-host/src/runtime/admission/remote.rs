use super::*;
impl AdmissionContext {
    pub(in crate::runtime) fn remote_owner(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        presence: Option<&crate::client::presence::OwnerPresence>,
        requires_terminal: bool,
    ) -> Result<crate::remote::auth::VerifiedLocalOwner> {
        let phase = self
            .reads
            .read_phase()
            .map_err(|error| store_error(&error))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let (admission, terminal) = self.caller(
                &phase,
                peer,
                connection,
                override_authority,
                grant,
                presence,
            )?;
            if requires_terminal {
                crate::remote::auth::VerifiedLocalOwner::from_native(&admission, &terminal)
            } else {
                crate::remote::auth::VerifiedLocalOwner::from_machine(&admission)
            }
        })();
        super::super::executor::close_read(result, phase.close())
    }
}
