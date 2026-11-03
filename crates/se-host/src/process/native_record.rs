//! Native checkpoint codec plus matching protected indices; no PID discovery.
use super::*;
use se_proc::{
    Checkpoint, CheckpointKind, CheckpointPrincipal, ContainmentGuarantee, RootPublication,
};
use se_store::{
    Actor, ContainmentFact, ProcessIdentityRecord, RecordedIdentity, RootIdentityState,
};
use se_types::{BootId, NativePath, ProcessFields, ProcessInstance, Result, Sha256};
use std::num::{NonZeroU32, NonZeroU64};

pub(super) fn identity(
    plan: &se_core::ops::agent_launch::LaunchPlan,
    checkpoint: CheckpointKind,
    root: Option<(&se_proc::ProcessIdentity, [u8; 32])>,
    guarantee: Option<ContainmentGuarantee>,
    boot: &BootId,
) -> Result<ProcessIdentityRecord> {
    identity_meta(
        &super::owned::LifecycleMetadata::from_launch(plan),
        checkpoint,
        root,
        guarantee,
        boot,
    )
}
pub(super) fn identity_meta(
    plan: &super::owned::LifecycleMetadata,
    checkpoint: CheckpointKind,
    root: Option<(&se_proc::ProcessIdentity, [u8; 32])>,
    guarantee: Option<ContainmentGuarantee>,
    boot: &BootId,
) -> Result<ProcessIdentityRecord> {
    let publication = match &checkpoint {
        CheckpointKind::Reservation(_) => RootPublication::NoChildCreated,
        CheckpointKind::Scope(_) => RootPublication::Unpublished,
        CheckpointKind::Exit { witness, .. } => match witness.root {
            se_proc::RootWitness::NoChildCreated => RootPublication::NoChildCreated,
            se_proc::RootWitness::UnpublishedScope
            | se_proc::RootWitness::PinnedUnpublished { .. } => RootPublication::Unpublished,
            se_proc::RootWitness::Identified { .. } => RootPublication::Identified,
        },
        _ => RootPublication::Identified,
    };
    let containment = match guarantee {
        None => ContainmentFact::NotLaunched,
        Some(ContainmentGuarantee::KernelScope { .. }) => ContainmentFact::Contained {
            kind: if cfg!(windows) {
                se_store::ContainmentKind::Job
            } else {
                se_store::ContainmentKind::Cgroup
            },
            observed_at_us: crate::runtime::start::now_unix_micros()?,
        },
        Some(ContainmentGuarantee::TrackedTree { .. }) => ContainmentFact::Uncontained {
            cause: se_store::ContainmentCause::NoDelegation,
            observed_at_us: crate::runtime::start::now_unix_micros()?,
            probe: None,
        },
        Some(ContainmentGuarantee::Uncontained { reason }) => ContainmentFact::Uncontained {
            cause: match reason {
                se_proc::UncontainedReason::NoUserManager => {
                    se_store::ContainmentCause::NoUserManager
                }
                se_proc::UncontainedReason::NoDelegation => {
                    se_store::ContainmentCause::NoDelegation
                }
                se_proc::UncontainedReason::CgroupV2Absent => {
                    se_store::ContainmentCause::CgroupV2Absent
                }
                se_proc::UncontainedReason::CgroupUnreadable => {
                    se_store::ContainmentCause::CgroupUnreadable
                }
                se_proc::UncontainedReason::ScopeCreateFailed => {
                    se_store::ContainmentCause::ScopeCreateFailed
                }
            },
            observed_at_us: crate::runtime::start::now_unix_micros()?,
            probe: None,
        },
    };
    let native = Checkpoint {
        format_version: 1,
        lifecycle: plan.lifecycle.clone(),
        principal: CheckpointPrincipal::Agent(plan.agent.id.clone()),
        session: Some(plan.session.clone()),
        root_identity: publication,
        checkpoint,
    };
    let record =
        se_proc::encode_checkpoint(&native).map_err(|e| error("native process checkpoint", e))?;
    Ok(ProcessIdentityRecord {
        record: plan.lifecycle.clone(),
        principal: Actor::Agent(plan.agent.id.clone()),
        session: Some(plan.session.clone()),
        root_identity: match publication {
            RootPublication::NoChildCreated => RootIdentityState::NoChildCreated,
            RootPublication::Unpublished => RootIdentityState::Unpublished,
            RootPublication::Identified => RootIdentityState::Identified,
            RootPublication::Unknown => RootIdentityState::Unknown,
        },
        instance: match root {
            Some((root, argv)) => RecordedIdentity::Present(instance(root, argv, boot)?),
            None => RecordedIdentity::Absent {
                reason: "no root published".into(),
            },
        },
        custody: se_store::NativeCustody {
            format_version: 1,
            record,
        },
        containment,
    })
}
pub(super) fn instance(
    root: &se_proc::ProcessIdentity,
    argv: [u8; 32],
    boot: &BootId,
) -> Result<ProcessInstance> {
    let started = match root.start {
        se_proc::StartIdentity::Linux { start_ticks } => {
            se_types::StartIdentity::Linux { start_ticks }
        }
        se_proc::StartIdentity::Windows { creation_filetime } => se_types::StartIdentity::Windows {
            creation_filetime: NonZeroU64::new(creation_filetime)
                .ok_or_else(|| se_types::SeError::invalid("native creation time", "nonzero"))?,
        },
        se_proc::StartIdentity::MacOs {
            seconds,
            microseconds,
        } => se_types::StartIdentity::Macos {
            start_seconds: seconds,
            start_micros: microseconds,
        },
    };
    ProcessInstance::from_observation(ProcessFields {
        machine: root.machine.clone(),
        boot: boot.clone(),
        pid: NonZeroU32::new(root.pid.0)
            .ok_or_else(|| se_types::SeError::invalid("native PID", "nonzero"))?,
        started,
        executable: NativePath::from_local(root.image.clone())?,
        argv_sha256: Sha256::from_bytes(argv),
    })
}
