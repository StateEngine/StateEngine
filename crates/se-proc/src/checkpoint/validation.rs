use super::*;
type Result<T> = std::result::Result<T, CheckpointError>;
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(invalid(reason)) }
}
fn identity(value: &ProcessIdentity) -> Result<()> {
    require(
        value.pid.0 != 0 && value.image.is_absolute(),
        "positive PID and absolute native image required",
    )?;
    let valid = match (&value.boot, &value.start) {
        (BootIdentity::Linux { boot_id }, StartIdentity::Linux { .. }) => {
            *boot_id != [0; 16] && value.pid.0 <= i32::MAX as u32
        }
        (
            BootIdentity::MacOs { microseconds, .. },
            StartIdentity::MacOs {
                microseconds: start,
                ..
            },
        ) => {
            (0..1000000).contains(microseconds)
                && *start < 1000000
                && value.pid.0 <= i32::MAX as u32
        }
        (
            BootIdentity::WindowsAbsoluteCreationClock,
            StartIdentity::Windows { creation_filetime },
        ) => *creation_filetime != 0,
        _ => false,
    };
    require(valid, "boot/start identity OS or native range mismatch")?;
    require(
        serde_json::to_vec(value).map_err(invalid)?.len() <= 8192,
        "single native identity exceeds 8 KiB",
    )
}
fn scope(value: &ScopeIdentity) -> Result<()> {
    match value {
        ScopeIdentity::LinuxPrepared { nonce } | ScopeIdentity::MacOsPrepared { nonce } => {
            require(*nonce != [0; 16], "prepared scope nonce is zero")
        }
        ScopeIdentity::LinuxTracked {
            process_group,
            root,
        }
        | ScopeIdentity::MacOsTracked {
            process_group,
            root,
        } => {
            require(
                process_group.0 != 0 && process_group.0 <= i32::MAX as u32,
                "invalid tracked process group",
            )?;
            identity(root)
        }
        ScopeIdentity::WindowsJob { host, name } => require(
            host.0 != [0; 16] && !name.is_empty() && name.len() <= 1024 && !name.contains('\0'),
            "invalid named job identity",
        ),
        ScopeIdentity::LinuxCgroup {
            path,
            inode,
            boot_id,
            ..
        } => require(
            path.is_absolute() && *inode != 0 && *boot_id != [0; 16],
            "invalid native cgroup identity",
        ),
    }
}
fn binding(
    scope: &ScopeIdentity,
    owner: &ProcessIdentity,
    host: &HostInstanceId,
    nonce: Option<&[u8; 16]>,
    guarantee: &ContainmentGuarantee,
) -> Result<()> {
    let valid = match (scope, &owner.boot, guarantee) {
        (
            ScopeIdentity::LinuxPrepared { nonce: actual },
            BootIdentity::Linux { .. },
            ContainmentGuarantee::Uncontained { .. },
        ) => nonce.is_none_or(|expected| expected == actual),
        (
            ScopeIdentity::LinuxTracked { root, .. },
            BootIdentity::Linux { .. },
            ContainmentGuarantee::Uncontained { .. },
        ) => root.boot == owner.boot && root.machine == owner.machine,
        (
            ScopeIdentity::LinuxCgroup { boot_id, .. },
            BootIdentity::Linux { boot_id: current },
            ContainmentGuarantee::KernelScope {
                explicit_breakaway: false,
            },
        ) => boot_id == current,
        (
            ScopeIdentity::WindowsJob { host: actual, .. },
            BootIdentity::WindowsAbsoluteCreationClock,
            ContainmentGuarantee::KernelScope { .. },
        ) => actual == host,
        (
            ScopeIdentity::MacOsPrepared { nonce: actual },
            BootIdentity::MacOs { .. },
            ContainmentGuarantee::TrackedTree {
                escape_prevented: false,
                ..
            },
        ) => nonce.is_none_or(|expected| expected == actual),
        (
            ScopeIdentity::MacOsTracked { root, .. },
            BootIdentity::MacOs { .. },
            ContainmentGuarantee::TrackedTree {
                escape_prevented: false,
                ..
            },
        ) => root.boot == owner.boot && root.machine == owner.machine,
        _ => false,
    };
    require(
        valid,
        "native scope/owner/platform/nonce/guarantee mismatch",
    )
}
pub(super) fn reservation(value: &LaunchReservation, lifecycle: &LifecycleId) -> Result<()> {
    require(
        value.format_version == 1
            && &value.lifecycle == lifecycle
            && value.host.0 != [0; 16]
            && value.scope_nonce != [0; 16],
        "reservation version/lifecycle/host/nonce mismatch",
    )?;
    identity(&value.owner)?;
    require(
        match (&value.parent, &value.owner.boot) {
            (ReservationParent::Windows, BootIdentity::WindowsAbsoluteCreationClock) => true,
            (ReservationParent::MacOs, BootIdentity::MacOs { .. }) => true,
            (
                ReservationParent::LinuxUserManager | ReservationParent::LinuxTracked,
                BootIdentity::Linux { .. },
            ) => true,
            (ReservationParent::Linux { boot_id, .. }, BootIdentity::Linux { boot_id: owner }) => {
                boot_id == owner
            }
            _ => false,
        },
        "reservation parent differs from native owner platform/boot",
    )?;
    if let ReservationParent::Linux {
        path,
        inode,
        boot_id,
        ..
    } = &value.parent
    {
        require(
            path.is_absolute() && *inode != 0 && *boot_id != [0; 16],
            "invalid native reservation parent",
        )?;
    }
    Ok(())
}
pub(super) fn prepared(value: &ScopeCheckpoint, lifecycle: &LifecycleId) -> Result<()> {
    reservation(&value.reservation, lifecycle)?;
    scope(&value.scope)?;
    let parent_matches = match (&value.parent, &value.reservation.owner.boot) {
        (ReservationParent::Windows, BootIdentity::WindowsAbsoluteCreationClock) => true,
        (ReservationParent::MacOs, BootIdentity::MacOs { .. }) => true,
        (ReservationParent::LinuxTracked, BootIdentity::Linux { .. }) => matches!(
            value.scope,
            ScopeIdentity::LinuxPrepared { .. } | ScopeIdentity::LinuxTracked { .. }
        ),
        (
            ReservationParent::Linux {
                path,
                inode,
                boot_id,
                ..
            },
            BootIdentity::Linux { boot_id: current },
        ) => path.is_absolute() && *inode != 0 && boot_id == current,
        _ => false,
    };
    require(
        parent_matches,
        "resolved parent differs from prepared scope/native platform",
    )?;
    binding(
        &value.scope,
        &value.reservation.owner,
        &value.reservation.host,
        Some(&value.reservation.scope_nonce),
        &value.guarantee,
    )
}
pub(super) fn root(value: &RootCheckpoint, lifecycle: &LifecycleId) -> Result<()> {
    prepared(&value.scope, lifecycle)?;
    identity(&value.pre_exec)?;
    require(
        value.intended_executable.is_absolute()
            && value.pre_exec.machine == value.scope.reservation.owner.machine
            && value.pre_exec.boot == value.scope.reservation.owner.boot,
        "root checkpoint machine or executable mismatch",
    )
}
fn remaining(value: &RemainingScope) -> Result<()> {
    require(
        value.known_live.len() <= 4096,
        "native diagnostic member capacity exceeded",
    )?;
    require(
        value.population != Population::Empty || value.known_live.is_empty(),
        "empty scope contains known live members",
    )?;
    for member in &value.known_live {
        identity(member)?;
    }
    Ok(())
}
pub(super) fn process(value: &ProcessRecord, lifecycle: &LifecycleId) -> Result<()> {
    require(
        value.format_version == 1 && &value.lifecycle == lifecycle && value.host.0 != [0; 16],
        "process record version/lifecycle/host mismatch",
    )?;
    identity(&value.owner)?;
    identity(&value.root)?;
    scope(&value.scope)?;
    require(
        value.owner.machine == value.root.machine && value.owner.boot == value.root.boot,
        "native owner/root machine mismatch",
    )?;
    binding(
        &value.scope,
        &value.owner,
        &value.host,
        None,
        &value.guarantee,
    )?;
    require(
        !matches!(
            value.state,
            LifecycleState::Exited | LifecycleState::Historical
        ),
        "terminal exited/historical state requires its explicit checkpoint variant",
    )?;
    match &value.scope {
        ScopeIdentity::WindowsJob { host, .. } => {
            require(host == &value.host, "job host differs from record")?
        }
        ScopeIdentity::LinuxTracked { root, .. } | ScopeIdentity::MacOsTracked { root, .. } => {
            require(
                root == &value.root,
                "tracked scope root differs from record",
            )?
        }
        ScopeIdentity::LinuxPrepared { .. } | ScopeIdentity::MacOsPrepared { .. } => {
            return Err(invalid("published process still has a prepared scope"));
        }
        _ => {}
    }
    if let Some(release) = &value.ownership_release {
        require(
            value.state == LifecycleState::StopUnproved
                && release.lifecycle == value.lifecycle
                && release.generation == value.generation
                && release.scope == value.scope
                && matches!(
                    release.scope,
                    ScopeIdentity::LinuxTracked { .. } | ScopeIdentity::MacOsTracked { .. }
                ),
            "unwitnessed release binding/state mismatch",
        )?;
        remaining(&release.remaining)?;
    }
    Ok(())
}
fn source(value: &CheckpointSource, lifecycle: &LifecycleId) -> Result<()> {
    match value {
        CheckpointSource::Reservation(v) => reservation(v, lifecycle),
        CheckpointSource::Scope(v) => prepared(v, lifecycle),
        CheckpointSource::Root(v) => root(v, lifecycle),
        CheckpointSource::Process(v) => process(v, lifecycle),
    }
}
fn source_scope(value: &CheckpointSource) -> Option<&ScopeIdentity> {
    match value {
        CheckpointSource::Reservation(_) => None,
        CheckpointSource::Scope(v) => Some(&v.scope),
        CheckpointSource::Root(v) => Some(&v.scope.scope),
        CheckpointSource::Process(v) => Some(&v.scope),
    }
}
fn source_root(value: &CheckpointSource) -> Option<&ProcessIdentity> {
    match value {
        CheckpointSource::Root(v) => Some(&v.pre_exec),
        CheckpointSource::Process(v) => Some(&v.root),
        _ => None,
    }
}
pub(super) fn checkpoint(value: &Checkpoint) -> Result<()> {
    require(
        value.format_version == 1,
        "unsupported native custody schema version",
    )?;
    let expected_root = match &value.checkpoint {
        CheckpointKind::Reservation(v) => {
            reservation(v, &value.lifecycle)?;
            RootPublication::NoChildCreated
        }
        CheckpointKind::Scope(v) => {
            prepared(v, &value.lifecycle)?;
            RootPublication::Unpublished
        }
        CheckpointKind::Root(v) => {
            root(v, &value.lifecycle)?;
            RootPublication::Identified
        }
        CheckpointKind::Process(v) => {
            process(v, &value.lifecycle)?;
            RootPublication::Identified
        }
        CheckpointKind::Released {
            source: retained,
            release,
        } => {
            source(retained, &value.lifecycle)?;
            remaining(&release.remaining)?;
            scope(&release.scope)?;
            let (expected, generation, publication) = match retained.as_ref() {
                CheckpointSource::Reservation(v) => {
                    let scope = match v.parent {
                        ReservationParent::LinuxTracked => ScopeIdentity::LinuxPrepared {
                            nonce: v.scope_nonce,
                        },
                        ReservationParent::MacOs => ScopeIdentity::MacOsPrepared {
                            nonce: v.scope_nonce,
                        },
                        _ => {
                            return Err(invalid(
                                "owner release cannot relinquish a kernel-contained reservation",
                            ));
                        }
                    };
                    (scope, v.generation, RootPublication::NoChildCreated)
                }
                CheckpointSource::Scope(v) => (
                    v.scope.clone(),
                    v.reservation.generation,
                    RootPublication::Unpublished,
                ),
                CheckpointSource::Root(v) => (
                    v.scope.scope.clone(),
                    v.scope.reservation.generation,
                    RootPublication::Identified,
                ),
                CheckpointSource::Process(v) => {
                    require(
                        v.ownership_release.is_none(),
                        "release source already carries a release marker",
                    )?;
                    (v.scope.clone(), v.generation, RootPublication::Identified)
                }
            };
            require(
                matches!(
                    expected,
                    ScopeIdentity::LinuxPrepared { .. }
                        | ScopeIdentity::LinuxTracked { .. }
                        | ScopeIdentity::MacOsPrepared { .. }
                        | ScopeIdentity::MacOsTracked { .. }
                ),
                "owner release cannot relinquish a kernel job or cgroup",
            )?;
            require(
                release.lifecycle == value.lifecycle
                    && release.scope == expected
                    && release.generation.get() >= generation.get()
                    && release.released_at_unix_ns != 0
                    && release.remaining.observed_at_unix_ns <= release.released_at_unix_ns,
                "owner release lifecycle/scope/generation/time differs from retained custody",
            )?;
            publication
        }
        CheckpointKind::Exit {
            source: retained,
            witness,
        } => {
            source(retained, &value.lifecycle)?;
            scope(&witness.scope)?;
            remaining(&witness.scope_exit.remaining)?;
            require(
                witness.lifecycle == value.lifecycle
                    && witness.scope == witness.scope_exit.scope
                    && witness.scope_exit.remaining.population == Population::Empty
                    && witness.scope_exit.exit_basis.is_some(),
                "exit witness lifecycle/scope/empty proof mismatch",
            )?;
            let (owner, host, guarantee) = match retained.as_ref() {
                CheckpointSource::Reservation(v) => (&v.owner, &v.host, None),
                CheckpointSource::Scope(v) => (
                    &v.reservation.owner,
                    &v.reservation.host,
                    Some(&v.guarantee),
                ),
                CheckpointSource::Root(v) => (
                    &v.scope.reservation.owner,
                    &v.scope.reservation.host,
                    Some(&v.scope.guarantee),
                ),
                CheckpointSource::Process(v) => (&v.owner, &v.host, Some(&v.guarantee)),
            };
            binding(&witness.scope, owner, host, None, &witness.guarantee)?;
            require(
                guarantee.is_none_or(|expected| expected == &witness.guarantee),
                "exit guarantee differs from retained custody",
            )?;
            require(
                witness.scope_exit.exit_basis != Some(ScopeExitBasis::RemovedPinnedLinuxCgroup)
                    || matches!(witness.scope, ScopeIdentity::LinuxCgroup { .. }),
                "removed-cgroup exit evidence requires a recorded cgroup",
            )?;
            if let Some(scope) = source_scope(retained) {
                require(
                    scope == &witness.scope,
                    "exit witness differs from retained scope",
                )?;
            }
            match &witness.root {
                RootWitness::NoChildCreated => {
                    require(
                        source_root(retained).is_none(),
                        "no-child witness contradicts identified root",
                    )?;
                    RootPublication::NoChildCreated
                }
                RootWitness::UnpublishedScope => {
                    require(
                        source_root(retained).is_none(),
                        "unpublished witness contradicts identified root",
                    )?;
                    RootPublication::Unpublished
                }
                RootWitness::PinnedUnpublished { pid, .. } => {
                    require(
                        pid.0 != 0 && source_root(retained).is_none(),
                        "invalid unpublished root witness",
                    )?;
                    RootPublication::Unpublished
                }
                RootWitness::Identified {
                    expected, evidence, ..
                } => {
                    identity(expected)?;
                    if let Some(root) = source_root(retained) {
                        require(root == expected, "exit root differs from retained root")?;
                    }
                    match evidence.as_ref() {
                        ExitEvidence::NativeExitedRecord { state } => require(
                            matches!(state, NativeState::Exited | NativeState::ExitedAwaitingReap),
                            "live state in exit evidence",
                        )?,
                        ExitEvidence::Replaced { observed } => {
                            identity(observed)?;
                            require(
                                observed.pid == expected.pid && observed != expected,
                                "invalid replaced-process evidence",
                            )?;
                        }
                        _ => {}
                    }
                    RootPublication::Identified
                }
            }
        }
        CheckpointKind::FailedReservation {
            reservation: v,
            no_scope_created,
            ..
        } => {
            reservation(v, &value.lifecycle)?;
            require(
                *no_scope_created,
                "failed reservation cannot hide created native custody",
            )?;
            RootPublication::NoChildCreated
        }
        CheckpointKind::Historical(v) => {
            require(
                !v.reason.is_empty() && v.reason.len() <= 8192,
                "historical provenance reason is absent or oversized",
            )?;
            if let Read::Present { value: root } = &v.root {
                identity(root)?;
            }
            if let Read::Present { value } = &v.scope {
                scope(value)?;
            }
            RootPublication::Unknown
        }
    };
    require(
        value.root_identity == expected_root,
        "indexed root publication state differs from checkpoint",
    )
}
