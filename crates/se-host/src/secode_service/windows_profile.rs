//! Retain the exact protected profile directory across service operations.
use super::*;

impl LaunchCoordinator {
    pub(super) async fn qualify_secode_profile(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let path = service.journal.profile.to_local()?;
        if service.journal.profile_identity.is_none() && service.journal.service.is_some() {
            return Err(error(
                "SE Code private profile",
                format!(
                    "{}: the original service has no retained profile identity; preserve the profile and recover its original custody before starting another service",
                    path.display()
                ),
            ));
        }
        let display_path = path.clone();
        let retained = service.profile_guard.clone();
        let (guard, identity) = self
            .store
            .pool
            .run_owned(deadline, move || {
                let guard = match retained {
                    Some(guard) => guard,
                    None => Arc::new(
                        se_proc::NativeProfileFiles::open(&path)
                            .map_err(|cause| error("SE Code private profile", format!("{cause}; restore current-user ownership and a protected current-user-only DACL on the profile, then retry")))?,
                    ),
                };
                let identity = guard
                    .identity()
                    .map_err(|cause| error("SE Code private profile identity", format!("{cause}; restore the original profile and its protected permissions, then retry")))?;
                Ok((guard, identity))
            })
            .await?;
        if service
            .journal
            .profile_identity
            .is_some_and(|original| original != identity)
        {
            return Err(error(
                "SE Code private profile identity",
                format!(
                    "{}: the profile directory differs from the original retained directory; preserve both locations and restore the original profile before retrying",
                    display_path.display()
                ),
            ));
        }
        service.profile_guard = Some(guard);
        if service.journal.profile_identity.is_none() {
            service.journal.profile_identity = Some(identity);
            service.persist(self, deadline).await?;
        }
        Ok(())
    }
}
