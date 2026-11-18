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
    /// Publish an exit only from the shared, already verified reboot proof.
    pub fn witness_reboot(&self, proof: &VerifiedReboot) -> ProcResult<StopWitness> {
        if proof.root.machine != self.inner.config.machine {
            return Err(input("reboot recovery", "proof belongs to another machine"));
        }
        let root = &proof.root;
        let scope = &proof.scope;
        let guarantee = proof.guarantee;
        let previous = &proof.previous;
        let observed = proof.observed.clone();
        let at = now()?;
        Ok(StopWitness {
            lifecycle: proof.lifecycle.clone(),
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
        })
    }
}
