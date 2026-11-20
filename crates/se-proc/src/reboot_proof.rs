//! Verify reboot evidence against the recorded process and the observed machine.
use crate::{
    Checkpoint, CheckpointKind, CheckpointSource, ContainmentGuarantee, ExitEvidence,
    LifecycleState, ProcessIdentity, RootWitness, ScopeIdentity,
};
use se_types::{BootId, MachineId, ProcessInstance};

pub use se_custody::{RebootBoot, match_recorded_root};

pub(crate) fn valid_witness_boots(
    source: &CheckpointSource,
    root: &ProcessIdentity,
    previous: &BootId,
    observed: &BootId,
) -> bool {
    if !matches!(
        source,
        CheckpointSource::Root(_) | CheckpointSource::Process(_)
    ) {
        return false;
    }
    let (Some(before), Some(after)) = (RebootBoot::parse(previous), RebootBoot::parse(observed))
    else {
        return false;
    };
    if std::mem::discriminant(&before) != std::mem::discriminant(&after) || before == after {
        return false;
    }
    match (&root.boot, &before, source) {
        (crate::BootIdentity::Linux { boot_id }, RebootBoot::Linux(id), _) => {
            id.as_str() == format!("linux:{}", se_types::hex_lower(boot_id))
        }
        (crate::BootIdentity::WindowsAbsoluteCreationClock, RebootBoot::Windows(_), _) => true,
        (
            crate::BootIdentity::MacOs { .. },
            RebootBoot::MacOs(id),
            CheckpointSource::Root(root),
        ) => root.macos_boot_session.as_ref() == Some(id),
        (
            crate::BootIdentity::MacOs { .. },
            RebootBoot::MacOs(id),
            CheckpointSource::Process(record),
        ) => record.macos_boot_session.as_ref() == Some(id),
        _ => false,
    }
}

/// The machine is independently read from the protected local home.
pub struct ObservedBoot {
    pub machine: MachineId,
    pub boot: RebootBoot,
}

pub fn observe_reboot_boot(machine: MachineId) -> crate::ProcResult<ObservedBoot> {
    let boot = crate::bootstrap::runtime_boot_identity()?;
    let boot = RebootBoot::parse(&boot).ok_or_else(|| {
        crate::support::input("native reboot boot identity", "invalid native boot format")
    })?;
    Ok(ObservedBoot { machine, boot })
}

#[derive(Clone, Debug)]
pub struct VerifiedReboot {
    pub(crate) lifecycle: crate::LifecycleId,
    pub(crate) root: ProcessIdentity,
    pub(crate) scope: ScopeIdentity,
    pub(crate) guarantee: ContainmentGuarantee,
    pub(crate) previous: BootId,
    pub(crate) observed: BootId,
}

pub enum RebootProof {
    Proven(Box<VerifiedReboot>),
    NotProven,
    Unreadable(String),
}

pub fn prove_reboot(
    checkpoint: &Checkpoint,
    instance: &ProcessInstance,
    current: &ObservedBoot,
) -> RebootProof {
    match checked(checkpoint, instance, current) {
        Ok(Some(proof)) => RebootProof::Proven(Box::new(proof)),
        Ok(None) => RebootProof::NotProven,
        Err(reason) => RebootProof::Unreadable(reason),
    }
}

fn checked(
    checkpoint: &Checkpoint,
    instance: &ProcessInstance,
    current: &ObservedBoot,
) -> Result<Option<VerifiedReboot>, String> {
    crate::checkpoint::validate(checkpoint).map_err(|e| e.to_string())?;
    let (facts, witness) = match &checkpoint.checkpoint {
        CheckpointKind::Process(record) => (process_facts(record), None),
        CheckpointKind::Root(root) => (Some(root_facts(root)), None),
        CheckpointKind::Exit { source, witness } => {
            let facts = match source.as_ref() {
                CheckpointSource::Process(record) => process_facts(record),
                CheckpointSource::Root(root) => Some(root_facts(root)),
                _ => None,
            };
            (facts, Some(witness))
        }
        _ => return Ok(None),
    };
    let Some((root, scope, guarantee, saved_mac, argv)) = facts else {
        return Ok(None);
    };
    let witness = match witness.filter(|w| w.ended_by_reboot()) {
        None => se_custody::RebootWitness::None,
        Some(w) => match &w.root {
            RootWitness::Identified { evidence, .. } => match evidence.as_ref() {
                ExitEvidence::BootChanged { previous, .. } => {
                    se_custody::RebootWitness::Previous(previous)
                }
                _ => se_custody::RebootWitness::MissingBootEvidence,
            },
            _ => se_custody::RebootWitness::MissingRoot,
        },
    };
    let Some(previous) = se_custody::classify_reboot(
        root,
        argv,
        saved_mac,
        instance,
        &current.machine,
        &current.boot,
        witness,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(VerifiedReboot {
        lifecycle: checkpoint.lifecycle.clone(),
        root: root.clone(),
        scope: scope.clone(),
        guarantee,
        previous,
        observed: current.boot.id().clone(),
    }))
}

type RootFacts<'a> = (
    &'a ProcessIdentity,
    &'a ScopeIdentity,
    ContainmentGuarantee,
    Option<&'a BootId>,
    Option<[u8; 32]>,
);

fn process_facts(record: &crate::ProcessRecord) -> Option<RootFacts<'_>> {
    if record.state == LifecycleState::Historical || record.ownership_release.is_some() {
        return None;
    }
    Some((
        &record.root,
        &record.scope,
        record.guarantee,
        record.macos_boot_session.as_ref(),
        Some(record.argv_sha256),
    ))
}

fn root_facts(root: &crate::RootCheckpoint) -> RootFacts<'_> {
    (
        &root.pre_exec,
        &root.scope.scope,
        root.scope.guarantee,
        root.macos_boot_session.as_ref(),
        None,
    )
}
