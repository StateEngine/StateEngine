//! A real, independently observed process group; closing stdin ends this child.
use super::*;
use se_proc as p;
use std::{
    io::{BufRead, BufReader},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

pub struct Child(std::process::Child);
impl Child {
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Self(
            Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import sys; print('ready',flush=True); sys.stdin.readline()",
                ])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut ready = String::new();
        BufReader::new(child.0.stdout.take().ok_or("ready pipe")?).read_line(&mut ready)?;
        assert_eq!(ready.trim(), "ready");
        Ok(child)
    }
    pub fn live(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(self.0.try_wait()?.is_none())
    }
    pub fn finish(&mut self) -> Check {
        drop(self.0.stdin.take());
        assert!(
            self.0.wait()?.success(),
            "owned child did not exit normally"
        );
        Ok(())
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub fn identity(
    f: &Fixture,
    session: &SessionId,
    child: &Child,
) -> Result<(ProcessIdentityRecord, p::ProcessRecord), Box<dyn std::error::Error>> {
    let machine = se_types::MachineId::new("public-custody-cli")?;
    let observed = p::read_process(machine.clone(), p::ProcessId(child.0.id()))
        .map_err(|e| format!("native child: {e:?}"))?;
    let p::ProcessRead::Present(observed) = observed else {
        return Err("child must start live".into());
    };
    let root = observed.identity;
    let p::StartIdentity::Linux { start_ticks } = root.start else {
        return Err("Linux child required".into());
    };
    let argv: [u8; 32] =
        Sha256::digest(std::fs::read(format!("/proc/{}/cmdline", child.0.id()))?).into();
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000 + serial(), [81; 10])?;
    let record = p::ProcessRecord {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        host: p::HostInstanceId([7; 16]),
        owner: p::current_process_identity(machine.clone())
            .map_err(|e| format!("native owner: {e:?}"))?,
        generation: p::GenerationId::new(1)?,
        root: root.clone(),
        scope: p::ScopeIdentity::LinuxTracked {
            process_group: root.pid,
            root: root.clone(),
        },
        guarantee: p::ContainmentGuarantee::Uncontained {
            reason: p::UncontainedReason::NoDelegation,
        },
        entry: p::EntryMethod::LinuxProcessGroup,
        state: p::LifecycleState::Running,
        ownership_release: None,
        exit_status: None,
        observed_at_unix_ns: observed.observed_at_unix_ns,
        argv_sha256: argv,
    };
    let identity = ProcessIdentityRecord {
        record: lifecycle.clone(),
        principal: Actor::Agent(f.a.clone()),
        session: Some(session.clone()),
        root_identity: RootIdentityState::Identified,
        instance: RecordedIdentity::Present(se_types::ProcessInstance::from_observation(
            se_types::ProcessFields {
                boot: p::current_runtime_identity(machine.clone())
                    .map_err(|e| format!("boot: {e:?}"))?
                    .boot_id,
                machine,
                pid: std::num::NonZeroU32::new(child.0.id()).ok_or("pid")?,
                started: se_types::StartIdentity::Linux { start_ticks },
                executable: NativePath::from_local(root.image)?,
                argv_sha256: se_types::Sha256::from_bytes(argv),
            },
        )?),
        custody: NativeCustody {
            format_version: 1,
            record: p::encode_checkpoint(&p::Checkpoint {
                format_version: 1,
                lifecycle,
                principal: p::CheckpointPrincipal::Agent(f.a.clone()),
                session: Some(session.clone()),
                root_identity: p::RootPublication::Identified,
                checkpoint: p::CheckpointKind::Process(record.clone()),
            })?,
        },
        containment: ContainmentFact::Uncontained {
            cause: ContainmentCause::NoDelegation,
            observed_at_us: 1,
            probe: None,
        },
    };
    Ok((identity, record))
}

pub fn exit_checkpoint(record: &p::ProcessRecord) -> p::CheckpointKind {
    p::CheckpointKind::Exit {
        source: Box::new(p::CheckpointSource::Process(record.clone())),
        witness: p::StopWitness {
            lifecycle: record.lifecycle.clone(),
            root: p::RootWitness::Identified {
                expected: record.root.clone(),
                evidence: Box::new(p::ExitEvidence::Absent),
                status: p::ExitStatus::Code(0),
            },
            scope: record.scope.clone(),
            scope_exit: p::ScopeObservation {
                scope: record.scope.clone(),
                exit_basis: Some(p::ScopeExitBasis::ObservedEmpty),
                remaining: p::RemainingScope {
                    population: p::Population::Empty,
                    known_live: vec![],
                    extent: p::EnumerationExtent::Complete,
                    observed_at_unix_ns: record.observed_at_unix_ns + 1,
                },
            },
            observed_at_unix_ns: record.observed_at_unix_ns + 1,
            guarantee: record.guarantee,
        },
    }
}
pub fn release(
    record: &p::ProcessRecord,
) -> Result<p::UnwitnessedRelease, Box<dyn std::error::Error>> {
    Ok(p::UnwitnessedRelease {
        lifecycle: record.lifecycle.clone(),
        generation: record.generation,
        revision: std::num::NonZeroU64::new(4).ok_or("release revision")?,
        scope: record.scope.clone(),
        remaining: p::RemainingScope {
            population: p::Population::Populated,
            known_live: vec![record.root.clone()],
            extent: p::EnumerationExtent::Partial {
                reason: "tracked group does not prevent escape".into(),
                omitted: None,
            },
            observed_at_unix_ns: record.observed_at_unix_ns + 1,
        },
        released_at_unix_ns: record.observed_at_unix_ns + 1,
    })
}
