//! Retain the exact protected profile directory across service operations.
use super::*;

impl LaunchCoordinator {
    pub(super) async fn qualify_secode_profile_parent(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<PathBuf> {
        let requested = service.journal.profile.to_local()?;
        let expected = service.journal.profile_parent_identity;
        let fresh = service.journal.bootstrap.is_none();
        if !fresh && expected.is_none() {
            return Err(error(
                "SE Code profile parent",
                format!(
                    "{}: initializer has no retained parent identity; preserve the profile and reconcile the original initializer before retrying",
                    requested.display()
                ),
            ));
        }
        let retained = service.profile_parent_guard.clone();
        let (guard, identity, resolved) = self.store.pool.run_owned(deadline, move || {
            let parent = requested.parent().ok_or_else(|| error("SE Code profile parent", "profile parent is absent"))?;
            let base = parent.parent().ok_or_else(|| error("SE Code profile parent", "profile ancestor is absent"))?;
            let guard = match retained {
                Some(guard) => guard,
                None if expected.is_some() => Arc::new(se_proc::NativeProfileFiles::open(parent)
                    .map_err(|cause| error("SE Code profile parent", format!("{cause}; restore the original protected parent, then retry")))?),
                None => {
                    se_proc::NativeStateFiles::create(base).map_err(|cause| error("SE Code profile parent", cause))?;
                    Arc::new(se_proc::NativeProfileFiles::create(parent)
                        .map_err(|cause| error("SE Code profile parent", format!("{cause}; restore current-user ownership and a protected current-user-only DACL, then retry")))?)
                }
            };
            let identity = guard.identity().map_err(|cause| error("SE Code profile parent", format!("{cause}; restore the original protected parent, then retry")))?;
            if expected.is_some_and(|original| original != identity) {
                return Err(error("SE Code profile parent", format!("{} changed; restore the original protected parent before retrying", parent.display())));
            }
            let name = requested.file_name().ok_or_else(|| error("SE Code profile", "profile name is absent"))?;
            let resolved = guard.resolved_root().map_err(|cause| error("SE Code profile parent", cause))?.join(name);
            if fresh {
                match std::fs::symlink_metadata(&resolved) {
                    Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => (),
                    Err(cause) => return Err(error("SE Code profile", format!("{}: {cause}; repair access and retry", resolved.display()))),
                    Ok(_) => return Err(error("SE Code profile", format!("{} already exists; move it aside to preserve it, then retry", resolved.display()))),
                }
            }
            Ok((guard, identity, resolved))
        }).await?;
        service.profile_parent_guard = Some(guard);
        if expected.is_none() {
            service.journal.profile_parent_identity = Some(identity);
            service.persist(self, deadline).await?;
        }
        Ok(resolved)
    }

    pub(super) async fn qualify_secode_profile(
        &self,
        service: &mut Service,
        initialized_path: Option<PathBuf>,
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
                if let Some(expected) = initialized_path {
                    let resolved = guard.resolved_root().map_err(|cause| error("SE Code private profile", cause))?;
                    if resolved != expected {
                        return Err(error("SE Code private profile", format!("{} does not identify the initialized profile; restore the original location and retry", expected.display())));
                    }
                }
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
