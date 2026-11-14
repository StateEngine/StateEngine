//! Independent native owner admission controls; no process is signalled.
use se_proc::{
    AgentTreeBasis, BootIdentity, ContainmentGuarantee, EntryMethod, GenerationId, HostInstanceId,
    LifecycleId, LifecycleState, MachineId, OwnerTarget, ProcessId, ProcessIdentity, ProcessRead,
    ProcessRecord, ScopeIdentity, StartIdentity, observe_owner, read_process,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn identity() -> Result<ProcessIdentity> {
    match read_process(
        MachineId::new("owner-bound-review")?,
        ProcessId(std::process::id()),
    )
    .map_err(|error| format!("native self read failed: {error:?}"))?
    {
        ProcessRead::Present(live) => Ok(live.identity),
        other => Err(format!("self native identity unavailable: {other:?}").into()),
    }
}

fn record(root: ProcessIdentity) -> Result<ProcessRecord> {
    let host = HostInstanceId([4; 16]);
    let scope = match &root.boot {
        BootIdentity::Linux { .. } => ScopeIdentity::LinuxTracked {
            process_group: root.pid,
            root: root.clone(),
        },
        BootIdentity::MacOs { .. } => ScopeIdentity::MacOsTracked {
            process_group: root.pid,
            root: root.clone(),
        },
        BootIdentity::WindowsAbsoluteCreationClock => ScopeIdentity::WindowsJob {
            host,
            name: "owner-bound-review".into(),
        },
    };
    let entry = match &root.boot {
        BootIdentity::Linux { .. } => EntryMethod::LinuxProcessGroup,
        BootIdentity::MacOs { .. } => EntryMethod::MacOsSpawn,
        BootIdentity::WindowsAbsoluteCreationClock => EntryMethod::WindowsJobList,
    };
    Ok(ProcessRecord {
        format_version: 1,
        lifecycle: LifecycleId::from_parts(1_700_000_000_000, [4; 10])?,
        host,
        owner: root.clone(),
        generation: GenerationId::new(1)?,
        root,
        scope,
        tracked_obligations: None,
        guarantee: ContainmentGuarantee::TrackedTree {
            atomic_signal: false,
            escape_prevented: false,
        },
        entry,
        state: LifecycleState::Running,
        ownership_release: None,
        exit_status: None,
        observed_at_unix_ns: 2,
        argv_sha256: [4; 32],
    })
}

#[test]
fn native_self_and_pinned_peer_remain_observable() -> Result {
    let first = observe_owner(OwnerTarget::Current, &[])?;
    assert_eq!(first.pid(), ProcessId(std::process::id()));
    assert!(first.agent_trees().is_empty());
    let peer = observe_owner(
        OwnerTarget::Process {
            pid: first.pid(),
            start: first.start(),
        },
        &[],
    )?;
    assert_eq!(peer.owner(), first.owner());
    assert_eq!(peer.start(), first.start());
    assert!(peer.agent_trees().is_empty());
    #[cfg(target_os = "macos")]
    assert!(
        matches!(
            first.ancestry_bound(),
            se_proc::AncestryBound::UnopenableAncestor { .. }
        ),
        "hosted regression control did not reach a protected ancestor"
    );
    Ok(())
}

#[test]
fn exact_native_root_is_never_reported_outside() -> Result {
    let owned = record(identity()?)?;
    let observed = observe_owner(OwnerTarget::Current, &[owned])?;
    assert_eq!(observed.agent_trees().len(), 1);
    assert_eq!(observed.agent_trees()[0].record_index, 0);
    assert_eq!(observed.agent_trees()[0].basis, AgentTreeBasis::ExactRoot);
    Ok(())
}

#[test]
fn pinned_peer_rejects_wrong_birth_on_every_platform() -> Result {
    let current = identity()?;
    let wrong = match current.start {
        StartIdentity::Linux { start_ticks } => StartIdentity::Linux {
            start_ticks: start_ticks.checked_add(1).ok_or("birth overflow")?,
        },
        StartIdentity::MacOs {
            seconds,
            microseconds,
        } => StartIdentity::MacOs {
            seconds: seconds.checked_add(1).ok_or("birth overflow")?,
            microseconds,
        },
        StartIdentity::Windows { creation_filetime } => StartIdentity::Windows {
            creation_filetime: creation_filetime.checked_add(1).ok_or("birth overflow")?,
        },
    };
    assert!(
        observe_owner(
            OwnerTarget::Process {
                pid: current.pid,
                start: &wrong
            },
            &[]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn invalid_peer_pid_is_not_an_empty_tree() -> Result {
    let current = identity()?;
    for pid in [ProcessId(0), ProcessId(u32::MAX)] {
        assert!(
            observe_owner(
                OwnerTarget::Process {
                    pid,
                    start: &current.start
                },
                &[]
            )
            .is_err()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn protected_numeric_root_without_birth_proof_refuses() -> Result {
    let observed = observe_owner(OwnerTarget::Current, &[])?;
    let se_proc::AncestryBound::UnopenableAncestor { pid, .. } = observed.ancestry_bound() else {
        return Err("protected-ancestor fixture absent".into());
    };
    let mut root = identity()?;
    root.pid = *pid;
    let error = observe_owner(OwnerTarget::Current, &[record(root)?])
        .expect_err("numeric protected PID was accepted without birth proof");
    assert_eq!(error.operation, "inspect bounded ancestry");
    Ok(())
}
