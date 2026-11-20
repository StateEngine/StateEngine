//! Portable classification of recorded and observed boot evidence.
use crate::{BootIdentity, ProcessIdentity, StartIdentity};
use se_types::{BootId, MachineId, ProcessInstance};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebootBoot {
    Linux(BootId),
    MacOs(BootId),
    Windows(BootId),
}

impl RebootBoot {
    pub fn parse(value: &BootId) -> Option<Self> {
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
            && let Some((entry, sequence)) = id.split_once(':')
            && guid(entry, 35, &[8, 13, 18])
            && !sequence.is_empty()
            && sequence.bytes().all(|b| b.is_ascii_digit())
            && sequence.parse::<u32>().is_ok()
        {
            return Some(Self::Windows(value.clone()));
        }
        None
    }
    /// Windows records written before the boot sequence was added name only
    /// the boot entry, which is identical on every boot of that install.
    pub fn legacy_windows_entry(value: &BootId) -> Option<&str> {
        value
            .as_str()
            .strip_prefix("windows:")
            .filter(|id| guid(id, 35, &[8, 13, 18]))
    }
    /// The boot entry of a current Windows boot identity.
    pub fn windows_entry(value: &BootId) -> Option<&str> {
        match Self::parse(value) {
            Some(Self::Windows(_)) => value
                .as_str()
                .strip_prefix("windows:")
                .and_then(|id| id.split_once(':'))
                .map(|(entry, _)| entry),
            _ => None,
        }
    }
    pub fn id(&self) -> &BootId {
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

/// Classify a recorded root on the machine independently observed by the caller.
pub enum RebootWitness<'a> {
    None,
    MissingRoot,
    MissingBootEvidence,
    Previous(&'a BootId),
}

pub fn classify_reboot(
    root: &ProcessIdentity,
    argv: Option<[u8; 32]>,
    saved_mac: Option<&BootId>,
    instance: &ProcessInstance,
    machine: &MachineId,
    current: &RebootBoot,
    witness: RebootWitness<'_>,
) -> Result<Option<BootId>, String> {
    if RebootBoot::parse(current.id()).as_ref() != Some(current) {
        return Err("observed boot format is invalid".into());
    }
    match_recorded_root(root, argv, instance)?;
    if &root.machine != machine {
        return Err("recorded root belongs to a different machine".into());
    }
    let indexed = &instance.fields().boot;
    let previous = match &root.boot {
        BootIdentity::Linux { boot_id } => {
            let expected = format!("linux:{}", se_types::hex_lower(boot_id));
            if indexed.as_str() != expected {
                return Err("recorded Linux boot differs from the root".into());
            }
            RebootBoot::parse(indexed)
        }
        BootIdentity::WindowsAbsoluteCreationClock => match RebootBoot::parse(indexed) {
            value @ Some(RebootBoot::Windows(_)) => value,
            // A legacy record cannot tell its boot from this one.
            _ if RebootBoot::legacy_windows_entry(indexed).is_some() => return Ok(None),
            _ => None,
        },
        BootIdentity::MacOs {
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
    if std::mem::discriminant(&previous) != std::mem::discriminant(current) {
        return Err("recorded and observed boot platforms differ".into());
    }
    match witness {
        RebootWitness::None => {}
        RebootWitness::MissingRoot => return Err("reboot witness has no root".into()),
        RebootWitness::MissingBootEvidence => {
            return Err("reboot witness has no boot evidence".into());
        }
        RebootWitness::Previous(witnessed) if witnessed != previous.id() => {
            return Err("reboot witness differs from the recorded boot".into());
        }
        RebootWitness::Previous(_) => {}
    }
    if &previous == current {
        return Ok(None);
    }
    Ok(Some(previous.id().clone()))
}
