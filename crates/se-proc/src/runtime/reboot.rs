//! Same-machine boot evidence closes recorded custody without querying a PID.
use crate::{support::*, *};
use se_types::BootId;

pub(super) fn macos_boot_session() -> ProcResult<Option<BootId>> {
    #[cfg(target_os = "macos")]
    {
        crate::owner_probe::macos::boot_session()
            .map(Some)
            .map_err(|e| input("reboot recovery", &e.to_string()))
    }
    #[cfg(not(target_os = "macos"))]
    Ok(None)
}

impl NativeProcessRuntime {
    /// The previous boot comes from the protected root's persisted identity.
    /// Windows native process identities carry absolute birth time, so only the
    /// separately retained native boot GUID can prove a reboot there.
    pub fn witness_reboot(
        &self,
        source: &RecoverySource,
        previous: &BootId,
    ) -> ProcResult<Option<StopWitness>> {
        let (lifecycle, root, scope, guarantee, saved_macos_boot) = match source {
            RecoverySource::Record(r)
                if r.state != LifecycleState::Historical && r.ownership_release.is_none() =>
            {
                (
                    &r.lifecycle,
                    &r.root,
                    &r.scope,
                    r.guarantee,
                    r.macos_boot_session.as_ref(),
                )
            }
            RecoverySource::RootPrepared(r) => (
                &r.scope.reservation.lifecycle,
                &r.pre_exec,
                &r.scope.scope,
                r.scope.guarantee,
                r.macos_boot_session.as_ref(),
            ),
            _ => return Ok(None),
        };
        crate::checkpoint::validate_recovery(source)
            .map_err(|e| input("reboot recovery source", &e.to_string()))?;
        if root.machine != self.inner.config.machine {
            return Err(input(
                "reboot recovery",
                "recorded machine differs from this native arena",
            ));
        }
        let (previous, observed) = if let Some(current) = &self.inner.macos_boot_session {
            // Darwin's legacy boot timestamp can change without a reboot.
            let Some(previous) = saved_macos_boot else {
                return Ok(None);
            };
            (previous, current.clone())
        } else {
            (previous, crate::bootstrap::runtime_boot_identity()?)
        };
        if !root.boot.matches_reboot_id(previous)
            || !self.inner.owner.boot.matches_reboot_id(&observed)
        {
            return Err(input(
                "reboot recovery",
                "boot evidence differs from the native checkpoint or arena",
            ));
        }
        if &observed == previous {
            return Ok(None);
        }
        let at = now()?;
        Ok(Some(StopWitness {
            lifecycle: lifecycle.clone(),
            root: RootWitness::Identified {
                expected: root.clone(),
                evidence: Box::new(ExitEvidence::BootChanged {
                    previous: previous.clone(),
                    observed,
                }),
                status: ExitStatus::Unavailable {
                    reason: ExitStatusUnavailable::NotRecorded,
                },
            },
            scope: scope.clone(),
            scope_exit: ScopeObservation {
                scope: scope.clone(),
                remaining: RemainingScope {
                    population: Population::Empty,
                    known_live: Vec::new(),
                    extent: EnumerationExtent::NotRequested,
                    observed_at_unix_ns: at,
                },
                exit_basis: Some(ScopeExitBasis::Reboot),
            },
            observed_at_unix_ns: at,
            guarantee,
        }))
    }
}
