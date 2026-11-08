use super::*;

impl Security {
    /// Construct Ready from fresh grant facts on the bounded blocking pool.
    pub fn ready(&self, device: &AuthenticatedDevice) -> Result<RemoteReady> {
        let grant = self.current(device)?;
        Ok(RemoteReady {
            protocol: se_types::ApiVersion {
                major: CLIENT_PROTOCOL_MAJOR,
                minor: CLIENT_PROTOCOL_MINOR,
            },
            host: self.host,
            instance: self.instance,
            generation: self.generation,
            grant: grant.grant,
            authority_revision: grant.authority_revision.value.get(),
            scope: grant.scope,
            expires_at: se_types::UnixMicros::new(
                u64::try_from(grant.expires_at_us)
                    .map_err(|_| refused("session expiry outside clock range"))?,
            )?,
        })
    }
}
