//! Owner-authenticated hook admission with a natively observed provider ancestor.
use super::*;
impl AdmissionContext {
    pub(crate) fn adoption(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        input: crate::adoption::Input,
    ) -> Result<crate::adoption::NativeCall> {
        self.channel_owner(peer, connection, authority, grant)?;
        if input.offered.len() > 4096 {
            return Err(crate::adoption::invalid(
                "at most 4096 pending native mail offers",
            ));
        }
        let registration = crate::adoption::read_for(&self.state_directory, input.kind)?
            .ok_or_else(|| crate::adoption::invalid("an explicitly adopted project"))?;
        let root = input.cwd.to_local()?;
        let project = registration
            .project(&root)?
            .ok_or_else(|| crate::adoption::invalid("an exactly registered project root"))?;
        if project.project != input.project {
            return Err(crate::adoption::invalid("the registered project identity"));
        }
        let bound = se_proc::native_ipc::IpcIoBound {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(3),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        se_proc::native_ipc::restore_adoption_provider_cache(
            &self.state_directory,
            &registration.provider.to_local()?,
            &bound,
        )
        .map_err(|e| se_core::scope::unreadable("adopted provider image cache", &e.to_string()))?;
        let provider = se_proc::native_ipc::provider_ancestor(
            peer.native(),
            &registration.provider.to_local()?,
            &bound,
        )
        .map_err(|error| {
            se_core::scope::unreadable("adopted provider ancestry", &error.to_string())
        })?;
        crate::adoption::metadata::authorize(
            &self.state_directory,
            self.generation,
            &registration,
            &provider,
            &input,
        )?;
        let expected = if input.kind == crate::adoption::Kind::Codex {
            crate::adoption::codex::transcript(&registration, &input)?
        } else {
            crate::claude::transcript_path(
                &registration.config_home.to_local()?,
                &root,
                &input.conversation,
            )
        };
        if input.transcript.to_local()? != expected {
            return Err(crate::adoption::invalid(
                "the native provider transcript location for this registered project and conversation",
            ));
        }
        Ok(crate::adoption::NativeCall { input, provider })
    }
}
