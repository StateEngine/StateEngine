//! Channel control is a native Owner capability, never a session or HTTP grant.
use super::*;
impl AdmissionContext {
    pub(crate) fn channel_owner(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
    ) -> Result<()> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            if override_authority.is_some()
                || !matches!(connection, PresentedAuthority::OwnerProof { .. })
            {
                return Err(SeError::new(se_types::Detail::OwnerRequired(
                    se_types::details::OwnerRequired {
                        op: "native channel control".into(),
                    },
                )));
            }
            let key = self.machine_key()?;
            let current = Sha256::from_bytes(Hasher::digest(key.expose()).into());
            if grant.owner_key != Some(current) {
                return Err(SeError::invalid(
                    "channel Owner connection",
                    "the same current protected machine credential",
                ));
            }
            self.owner_peer(&phase, peer)?;
            Ok(())
        })();
        super::super::executor::close_read(result, phase.close())
    }
}
