//! Verify reboot evidence against the recorded process and the observed machine.
use crate::{
    Checkpoint, CheckpointKind, CheckpointSource, ContainmentGuarantee, ExitEvidence,
    LifecycleState, ProcessIdentity, RootWitness, ScopeIdentity, StartIdentity,
};
use se_types::{BootId, MachineId, ProcessInstance};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebootBoot {
    Linux(BootId),
    MacOs(BootId),
    Windows(BootId),
}

impl RebootBoot {
    pub(crate) fn parse(value: &BootId) -> Option<Self> {
        let text = value.as_str();
        if let Some(id) = text.strip_prefix("linux:")
            && id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && id.bytes().any(|b| b != b'0')
        {
            return Some(Self::Linux(value.clone()));
        }
        if let Some(id) = text.strip_prefix("macos:")
            && guid(id, 36, &[8, 13, 18, 23])
        {
            return Some(Self::MacOs(value.clone()));
        }
        if let Some(id) = text.strip_prefix("windows:")
            && guid(id, 35, &[8, 13, 18])
        {
            return Some(Self::Windows(value.clone()));
        }
        None
    }
    fn id(&self) -> &BootId {
        match self {
            Self::Linux(id) | Self::MacOs(id) | Self::Windows(id) => id,
        }
    }
}

fn guid(value: &str, length: usize, separators: &[usize]) -> bool {
    value.len() == length
        && value.bytes().enumerate().all(|(i, b)| {
            if separators.contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && value.bytes().any(|b| b != b'0' && b != b'-')
}

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

/// Match the native root against the indexed process without inventing argv for a prepared root.
pub fn match_recorded_root(
    root: &ProcessIdentity,
    argv: Option<[u8; 32]>,
    instance: &ProcessInstance,
) -> Result<(), String> {
    let fields = instance.fields();
    let start = match (&root.start, &fields.started) {
        (
            StartIdentity::Linux { start_ticks: a },
            se_types::StartIdentity::Linux { start_ticks: b },
        ) => a == b,
        (
            StartIdentity::Windows {
                creation_filetime: a,
            },
            se_types::StartIdentity::Windows {
                creation_filetime: b,
            },
        ) => *a == b.get(),
        (
            StartIdentity::MacOs {
                seconds: a,
                microseconds: b,
            },
            se_types::StartIdentity::Macos {
                start_seconds: c,
                start_micros: d,
            },
        ) => a == c && b == d,
        _ => false,
    };
    if !start
        || root.machine != fields.machine
        || root.pid.0 != fields.pid.get()
        || root.image != fields.executable.to_local().map_err(|e| e.to_string())?
        || argv.is_some_and(|value| value != *fields.argv_sha256.as_bytes())
    {
        return Err(
            "checkpoint root differs from the recorded machine, PID, birth, image or argv".into(),
        );
    }
    Ok(())
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
    if RebootBoot::parse(current.boot.id()).as_ref() != Some(&current.boot) {
        return Err("observed boot format is invalid".into());
    }
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
    match_recorded_root(root, argv, instance)?;
    if root.machine != current.machine {
        return Err("recorded root belongs to a different machine".into());
    }
    let indexed = &instance.fields().boot;
    let previous = match &root.boot {
        crate::BootIdentity::Linux { boot_id } => {
            let expected = format!("linux:{}", se_types::hex_lower(boot_id));
            if indexed.as_str() != expected {
                return Err("recorded Linux boot differs from the root".into());
            }
            RebootBoot::parse(indexed)
        }
        crate::BootIdentity::WindowsAbsoluteCreationClock => match RebootBoot::parse(indexed) {
            value @ Some(RebootBoot::Windows(_)) => value,
            _ => None,
        },
        crate::BootIdentity::MacOs {
            seconds,
            microseconds,
        } => {
            let Some(saved) = saved_mac else {
                return Ok(None);
            };
            let legacy = format!("macos-{seconds}-{microseconds}");
            if indexed != saved && indexed.as_str() != legacy {
                return Err("recorded macOS boot differs from the root".into());
            }
            match RebootBoot::parse(saved) {
                value @ Some(RebootBoot::MacOs(_)) => value,
                _ => None,
            }
        }
    }
    .ok_or_else(|| "recorded boot format is invalid".to_string())?;
    if std::mem::discriminant(&previous) != std::mem::discriminant(&current.boot) {
        return Err("recorded and observed boot platforms differ".into());
    }
    if let Some(witness) = witness
        && witness.ended_by_reboot()
    {
        let RootWitness::Identified { evidence, .. } = &witness.root else {
            return Err("reboot witness has no root".into());
        };
        let ExitEvidence::BootChanged {
            previous: witnessed,
            ..
        } = evidence.as_ref()
        else {
            return Err("reboot witness has no boot evidence".into());
        };
        if witnessed != previous.id() {
            return Err("reboot witness differs from the recorded boot".into());
        }
    }
    if previous == current.boot {
        return Ok(None);
    }
    Ok(Some(VerifiedReboot {
        lifecycle: checkpoint.lifecycle.clone(),
        root: root.clone(),
        scope: scope.clone(),
        guarantee,
        previous: previous.id().clone(),
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
