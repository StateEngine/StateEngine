//! Protects: a persistent Windows job is a durable custody fact. Records written
//! before the flag existed keep kill-on-close semantics, only a persistent
//! record plans cold re-adoption, and the codec still refuses unknown fields.
//! These are codec and planning facts; native Job Object behaviour is judged
//! by windows_persistent_job_review on Windows.
use se_proc::*;
use se_types::AgentId;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn identity(pid: u32, creation_filetime: u64) -> Check<ProcessIdentity> {
    Ok(ProcessIdentity {
        machine: MachineId::new("persistent-job-codec-judge")?,
        boot: BootIdentity::WindowsAbsoluteCreationClock,
        start: StartIdentity::Windows { creation_filetime },
        pid: ProcessId(pid),
        image: std::env::current_exe()?,
    })
}

fn record(persistent: bool, state: LifecycleState) -> Check<ProcessRecord> {
    let host = HostInstanceId([7; 16]);
    Ok(ProcessRecord {
        macos_boot_session: None,
        format_version: 1,
        lifecycle: LifecycleId::from_parts(1_700_000_000_000, [9; 10])?,
        host,
        owner: identity(4_000, 11)?,
        generation: GenerationId::new(1)?,
        root: identity(4_004, 12)?,
        scope: ScopeIdentity::WindowsJob {
            host,
            name: r"Local\SE-persistent-job-codec-judge".into(),
            persistent,
        },
        tracked_obligations: None,
        guarantee: ContainmentGuarantee::KernelScope {
            explicit_breakaway: true,
        },
        entry: EntryMethod::WindowsJobList,
        state,
        ownership_release: None,
        exit_status: None,
        observed_at_unix_ns: 2,
        argv_sha256: [4; 32],
    })
}

fn checkpoint(record: ProcessRecord) -> Check<Checkpoint> {
    Ok(Checkpoint {
        format_version: 1,
        lifecycle: record.lifecycle.clone(),
        principal: CheckpointPrincipal::Agent(AgentId::from_parts(1_700_000_000_000, [4; 10])?),
        session: None,
        root_identity: RootPublication::Identified,
        checkpoint: CheckpointKind::Process(record),
    })
}

fn scope_of(checkpoint: &Checkpoint) -> Check<&ScopeIdentity> {
    match &checkpoint.checkpoint {
        CheckpointKind::Process(record) => Ok(&record.scope),
        _ => Err("process checkpoint variant lost".into()),
    }
}

/// The encoded WindowsJob object, wherever the checkpoint nests it.
fn job_object(
    value: &mut serde_json::Value,
) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("WindowsJob") {
                return map.get_mut("WindowsJob")?.as_object_mut();
            }
            map.values_mut().find_map(job_object)
        }
        serde_json::Value::Array(items) => items.iter_mut().find_map(job_object),
        _ => None,
    }
}

fn encoded_job(checkpoint: &Checkpoint) -> Check<serde_json::Map<String, serde_json::Value>> {
    let mut value: serde_json::Value = serde_json::from_slice(&encode_checkpoint(checkpoint)?)?;
    Ok(job_object(&mut value)
        .ok_or("encoded checkpoint has no WindowsJob scope")?
        .clone())
}

/// Bytes written before the flag existed: a non-persistent record encodes
/// exactly as it did, and those bytes decode to a kill-on-close job.
#[test]
fn records_without_the_flag_stay_kill_on_close_jobs() -> Check {
    let original = checkpoint(record(false, LifecycleState::Running)?)?;
    let job = encoded_job(&original)?;
    assert!(
        !job.contains_key("persistent"),
        "a kill-on-close job changed its stored bytes: {job:?}"
    );
    assert_eq!(
        job.keys().map(String::as_str).collect::<Vec<_>>(),
        ["host", "name"],
        "older readers would refuse an added WindowsJob field"
    );
    let bytes = encode_checkpoint(&original)?;
    let decoded = decode_checkpoint(1, &bytes)?;
    assert!(matches!(
        scope_of(&decoded)?,
        ScopeIdentity::WindowsJob {
            persistent: false,
            ..
        }
    ));
    assert_eq!(encode_checkpoint(&decoded)?, bytes);
    Ok(())
}

#[test]
fn a_persistent_job_keeps_its_flag_across_the_codec() -> Check {
    let original = checkpoint(record(true, LifecycleState::Running)?)?;
    let job = encoded_job(&original)?;
    assert_eq!(job.get("persistent"), Some(&serde_json::Value::Bool(true)));
    let bytes = encode_checkpoint(&original)?;
    let decoded = decode_checkpoint(1, &bytes)?;
    assert_eq!(scope_of(&decoded)?, scope_of(&original)?);
    assert_eq!(encode_checkpoint(&decoded)?, bytes);
    Ok(())
}

/// The flag is optional, not a hole: unknown or mistyped job fields still fail
/// closed instead of being read as a kill-on-close job.
#[test]
fn unknown_or_mistyped_job_fields_are_refused() -> Check {
    let original = checkpoint(record(true, LifecycleState::Running)?)?;
    let cases: [(&str, serde_json::Value); 3] = [
        ("persistent_scope", serde_json::Value::Bool(true)),
        ("kill_on_close", serde_json::Value::Bool(false)),
        ("persistent", serde_json::Value::String("true".into())),
    ];
    for (field, inserted) in cases {
        let mut value: serde_json::Value = serde_json::from_slice(&encode_checkpoint(&original)?)?;
        job_object(&mut value)
            .ok_or("encoded checkpoint has no WindowsJob scope")?
            .insert(field.into(), inserted);
        let bytes = serde_json::to_vec(&value)?;
        assert!(
            decode_checkpoint(1, &bytes).is_err(),
            "decoder admitted a WindowsJob with {field}"
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
mod planning {
    use super::*;

    // Planning registers no readiness source. This reactor refuses instead of
    // pretending, so any accidental registration fails the judge loudly.
    #[cfg(unix)]
    struct PlanningOnly;
    #[cfg(unix)]
    impl NativeReactor for PlanningOnly {
        fn register(
            &self,
            _: std::fs::File,
            _: NativeInterest,
            _: std::sync::Arc<dyn NativeReadiness>,
        ) -> ProcResult<Box<dyn NativeRegistration>> {
            Err(ProcError {
                code: ProcErrorCode::ContainmentUnavailable,
                detail: Box::new(ProcErrorDetail::Input {
                    field: "planning judge".into(),
                    reason: "recovery planning must not register readiness".into(),
                }),
                native: None,
            })
        }
    }

    fn runtime() -> Check<NativeProcessRuntime> {
        NativeProcessRuntime::open(HostConfig {
            machine: MachineId::new("persistent-job-codec-judge")?,
            instance: HostInstanceId([8; 16]),
            helper_executable: std::env::current_exe()?,
            linux_delegation: LinuxDelegation::CurrentScope,
            limits: ResourceLimits {
                max_lifecycles: 1,
                max_diagnostic_members: 4,
                max_observation_bytes: 65536,
                max_stdio_buffer_bytes: 4096,
            },
            #[cfg(unix)]
            reactor: std::sync::Arc::new(PlanningOnly),
        })
        .map_err(|e| format!("{e:?}").into())
    }

    fn plan(runtime: &NativeProcessRuntime, record: ProcessRecord) -> Check<RecoveryDisposition> {
        Ok(runtime
            .plan_recovery(RecoverySource::Record(Box::new(record)))
            .map_err(|e| format!("{e:?}"))?
            .disposition)
    }

    /// Only a persistent record may be re-adopted; every older or kill-on-close
    /// record keeps the query-only exit proof, whatever its live state.
    #[test]
    fn only_a_persistent_job_plans_cold_readoption() -> Check {
        let runtime = runtime()?;
        for state in [
            LifecycleState::Starting,
            LifecycleState::Running,
            LifecycleState::LeaderExited,
            LifecycleState::StopRequested,
            LifecycleState::StopUnproved,
            LifecycleState::Lost,
        ] {
            assert_eq!(
                plan(&runtime, record(true, state)?)?,
                RecoveryDisposition::ReattachWindowsJob,
                "persistent {state:?}"
            );
            assert_eq!(
                plan(&runtime, record(false, state)?)?,
                RecoveryDisposition::VerifyExitedThenResume,
                "kill-on-close {state:?}"
            );
        }
        Ok(())
    }

    /// Terminal records never reach re-adoption: the codec refuses a published
    /// Exited or Historical record before any disposition is chosen.
    #[test]
    fn terminal_records_never_plan_readoption() -> Check {
        let runtime = runtime()?;
        for persistent in [true, false] {
            for state in [LifecycleState::Exited, LifecycleState::Historical] {
                let planned = runtime
                    .plan_recovery(RecoverySource::Record(Box::new(record(persistent, state)?)));
                assert!(
                    planned.is_err(),
                    "terminal {state:?} (persistent {persistent}) reached planning"
                );
            }
        }
        Ok(())
    }

    /// The decoded form of pre-flag bytes plans exactly like a kill-on-close job.
    #[test]
    fn decoded_pre_flag_bytes_plan_the_exit_proof() -> Check {
        let runtime = runtime()?;
        let bytes = encode_checkpoint(&checkpoint(record(false, LifecycleState::Running)?)?)?;
        let CheckpointKind::Process(decoded) = decode_checkpoint(1, &bytes)?.checkpoint else {
            return Err("process checkpoint variant lost".into());
        };
        assert_eq!(
            plan(&runtime, decoded)?,
            RecoveryDisposition::VerifyExitedThenResume
        );
        Ok(())
    }
}
