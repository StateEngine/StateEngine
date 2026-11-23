//! Independent judge of the reboot classifier: a reboot is claimed only for the
//! recorded root on this machine whose recorded boot differs from the observed
//! one, and every disagreement refuses instead of proving or denying a reboot.
#![cfg(unix)]

use se_custody::{
    BootIdentity, ProcessId, ProcessIdentity, RebootBoot, RebootWitness, StartIdentity,
    classify_reboot,
};
use se_types::{BootId, MachineId, NativePath, ProcessFields, ProcessInstance, Sha256};
use std::num::NonZeroU32;
use std::path::PathBuf;

type Judged = Result<(), Box<dyn std::error::Error>>;

const OLD: [u8; 16] = [0x11; 16];
const NEW: [u8; 16] = [0x22; 16];
const ARGV: [u8; 32] = [7; 32];

fn linux(bytes: [u8; 16]) -> se_types::Result<BootId> {
    BootId::new(format!("linux:{}", se_types::hex_lower(&bytes)))
}

fn machine() -> se_types::Result<MachineId> {
    MachineId::new("judge-machine")
}

fn root() -> se_types::Result<ProcessIdentity> {
    Ok(ProcessIdentity {
        machine: machine()?,
        boot: BootIdentity::Linux { boot_id: OLD },
        pid: ProcessId(4242),
        start: StartIdentity::Linux { start_ticks: 900 },
        image: PathBuf::from("/opt/provider/bin/agent"),
    })
}

fn instance(
    boot: BootId,
    pid: u32,
    start_ticks: u64,
) -> Result<ProcessInstance, Box<dyn std::error::Error>> {
    Ok(ProcessInstance::from_observation(ProcessFields {
        machine: machine()?,
        boot,
        pid: NonZeroU32::new(pid).ok_or("pid is zero")?,
        started: se_types::StartIdentity::Linux { start_ticks },
        executable: NativePath::from_local(PathBuf::from("/opt/provider/bin/agent"))?,
        argv_sha256: Sha256::from_bytes(ARGV),
    })?)
}

fn observed(bytes: [u8; 16]) -> Result<RebootBoot, Box<dyn std::error::Error>> {
    Ok(RebootBoot::parse(&linux(bytes)?).ok_or("observed boot does not parse")?)
}

fn classify(
    root: &ProcessIdentity,
    instance: &ProcessInstance,
    machine: &MachineId,
    current: &RebootBoot,
    witness: RebootWitness<'_>,
) -> Result<Option<BootId>, String> {
    classify_reboot(root, Some(ARGV), None, instance, machine, current, witness)
}

#[test]
fn a_changed_boot_on_this_machine_proves_the_recorded_root_rebooted() -> Judged {
    let (root, machine, new) = (root()?, machine()?, observed(NEW)?);
    let recorded = instance(linux(OLD)?, 4242, 900)?;
    let proven = classify(&root, &recorded, &machine, &new, RebootWitness::None);
    assert_eq!(
        proven,
        Ok(Some(linux(OLD)?)),
        "the recorded boot is the previous one"
    );
    let previous = linux(OLD)?;
    let witnessed = classify(
        &root,
        &recorded,
        &machine,
        &new,
        RebootWitness::Previous(&previous),
    );
    assert_eq!(
        witnessed,
        Ok(Some(linux(OLD)?)),
        "a matching committed witness is kept"
    );
    Ok(())
}

#[test]
fn the_same_boot_proves_nothing() -> Judged {
    let recorded = instance(linux(OLD)?, 4242, 900)?;
    let same = classify(
        &root()?,
        &recorded,
        &machine()?,
        &observed(OLD)?,
        RebootWitness::None,
    );
    assert_eq!(same, Ok(None), "an unchanged boot is not a reboot");
    Ok(())
}

#[test]
fn every_disagreement_refuses_instead_of_claiming_a_reboot() -> Judged {
    let (root, machine, new) = (root()?, machine()?, observed(NEW)?);
    let recorded = instance(linux(OLD)?, 4242, 900)?;
    let none = || RebootWitness::None;
    let refused = |what: &str, result: Result<Option<BootId>, String>| {
        assert!(result.is_err(), "{what} must refuse, got {result:?}");
    };
    let other = MachineId::new("other-machine")?;
    refused(
        "another machine",
        classify(&root, &recorded, &other, &new, none()),
    );
    let pid = instance(linux(OLD)?, 4243, 900)?;
    refused("another pid", classify(&root, &pid, &machine, &new, none()));
    let birth = instance(linux(OLD)?, 4242, 901)?;
    refused(
        "another birth",
        classify(&root, &birth, &machine, &new, none()),
    );
    let argv = classify_reboot(
        &root,
        Some([8; 32]),
        None,
        &recorded,
        &machine,
        &new,
        none(),
    );
    refused("another argv", argv);
    let indexed = instance(linux([0x33; 16])?, 4242, 900)?;
    refused(
        "an indexed boot unlike the root's own",
        classify(&root, &indexed, &machine, &new, none()),
    );
    let stranger = linux([0x44; 16])?;
    let named = RebootWitness::Previous(&stranger);
    refused(
        "a witness naming another boot",
        classify(&root, &recorded, &machine, &new, named),
    );
    let rootless = RebootWitness::MissingRoot;
    refused(
        "a reboot witness without a root",
        classify(&root, &recorded, &machine, &new, rootless),
    );
    let bare = RebootWitness::MissingBootEvidence;
    refused(
        "a reboot witness without boot evidence",
        classify(&root, &recorded, &machine, &new, bare),
    );
    let mac = RebootBoot::parse(&BootId::new("macos:12345678-1234-1234-1234-123456789abc")?)
        .ok_or("macOS boot does not parse")?;
    refused(
        "another platform's boot",
        classify(&root, &recorded, &machine, &mac, none()),
    );
    let forged = RebootBoot::Linux(BootId::new("linux:not-a-boot")?);
    refused(
        "a malformed observed boot",
        classify(&root, &recorded, &machine, &forged, none()),
    );
    Ok(())
}

#[test]
fn boot_formats_parse_strictly_and_legacy_windows_is_named() -> Judged {
    let ok = |text: &str| BootId::new(text).map(|id| RebootBoot::parse(&id).is_some());
    let entry = "12345678-1234-1234-123456789abcdef0";
    assert!(ok(&format!("linux:{}", se_types::hex_lower(&OLD)))?);
    assert!(
        !ok("linux:00000000000000000000000000000000")?,
        "an all-zero Linux boot"
    );
    assert!(
        !ok("linux:1111111111111111111111111111111")?,
        "a short Linux boot"
    );
    assert!(
        !ok("linux:1111111111111111111111111111111G")?,
        "a non-hex Linux boot"
    );
    assert!(ok(&format!("windows:{entry}:17"))?);
    assert!(
        !ok(&format!("windows:{entry}"))?,
        "the legacy Windows entry alone"
    );
    assert!(!ok(&format!("windows:{entry}:"))?, "an empty sequence");
    assert!(
        !ok(&format!("windows:{entry}:4294967296"))?,
        "a sequence past u32"
    );
    let legacy = BootId::new(format!("windows:{entry}"))?;
    assert_eq!(RebootBoot::legacy_windows_entry(&legacy), Some(entry));
    let current = BootId::new(format!("windows:{entry}:17"))?;
    assert_eq!(RebootBoot::legacy_windows_entry(&current), None);
    assert_eq!(RebootBoot::windows_entry(&current), Some(entry));
    Ok(())
}
