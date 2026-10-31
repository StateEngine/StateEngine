use crate::*;
pub(super) fn database_check<T, E: std::fmt::Display>(
    f: &Fixture,
    stage: &str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|error| {
        eprintln!(
            "DATABASE FAILURE stage={stage} root={} error={error}",
            f.options.state_directory.display()
        );
        #[cfg(windows)]
        for name in ["state.db", "state.db-wal", "state.db-shm"] {
            let path = f.options.state_directory.join(name);
            match path.try_exists() {
                Ok(true) => {
                    if let Err(error) = fixture::dump_windows_acl(&path) {
                        eprintln!("outside ACL readback {}: {error}", path.display());
                    }
                }
                Ok(false) => eprintln!("outside path measured absent: {}", path.display()),
                Err(error) => eprintln!("outside path unreadable {}: {error}", path.display()),
            }
        }
        format!("{stage} [{}]: {error}", f.options.state_directory.display()).into()
    })
}
pub(super) fn stop_native(
    endpoint: &se_host::EndpointRecord,
    credential: &Secret,
    name: &str,
) -> Check {
    let until = se_types::UnixMicros::new(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros()
            + 10_000_000) as u64,
    )?;
    let reply = se_host::client::BlockingIpcClient::stop(
        endpoint,
        credential,
        key(name)?,
        until,
        &options(),
    )?;
    assert!(
        matches!(reply.outcome,se_host::client::endpoint::RuntimeStopOutcome::Facts{ref pending,..} if !pending.is_empty())
    );
    Ok(())
}
pub(super) fn wait_native_exit(identity: &se_proc::ProcessIdentity) -> Check {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match se_proc::NativeProcessRuntime::read_process(identity.machine.clone(), identity.pid)
            .map_err(|error| format!("native child readback {error:?}"))?
        {
            se_proc::ProcessRead::Absent { .. } => return Ok(()),
            se_proc::ProcessRead::Present(observed)
                if observed.identity == *identity
                    && observed.state == se_proc::NativeState::ExitedAwaitingReap =>
            {
                return Ok(());
            }
            se_proc::ProcessRead::Present(observed) if observed.identity != *identity => {
                return Err("native host PID was reused before its exit witness".into());
            }
            _ => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "exact private host {} did not exit after stop",
                        identity.pid.0
                    )
                    .into());
                }
                std::thread::park_timeout(Duration::from_millis(10));
            }
        }
    }
}
pub(super) struct ChildCleanup<'a> {
    pub endpoint: &'a se_host::EndpointRecord,
    pub identity: &'a se_proc::ProcessIdentity,
    pub credential: &'a Secret,
}
impl Drop for ChildCleanup<'_> {
    fn drop(&mut self) {
        if let Ok(se_proc::ProcessRead::Present(observed)) =
            se_proc::NativeProcessRuntime::read_process(
                self.identity.machine.clone(),
                self.identity.pid,
            )
            && observed.identity == *self.identity
            && observed.state != se_proc::NativeState::ExitedAwaitingReap
            && let Err(error) = stop_native(self.endpoint, self.credential, "fixture-failed-stop")
                .and_then(|()| wait_native_exit(self.identity))
        {
            eprintln!(
                "fixture retains exact native child {}: {error}",
                self.identity.pid.0
            );
        }
    }
}
pub(super) fn positive(value: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(value).ok_or_else(|| "zero native limit".into())
}
pub(super) fn options() -> se_host::client::ClientOptions {
    se_host::client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
pub(super) fn bound() -> Result<se_host::client::lease::Deadline, Box<dyn std::error::Error>> {
    Ok(se_host::client::lease::Deadline::from_options(&options())?)
}
pub(super) fn secret() -> Result<Secret, Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 32];
    if let Err(error) = getrandom::fill(&mut bytes) {
        bytes.fill(0);
        return Err(error.to_string().into());
    }
    Ok(Secret::new(bytes)?)
}
pub(super) fn copy_secret(secret: &Secret) -> Result<Secret, Box<dyn std::error::Error>> {
    Ok(Secret::new(secret.expose().to_vec())?)
}
pub(super) fn publish(f: &Fixture, name: &str, bytes: &[u8]) -> Check {
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join(name))?;
    Ok(())
}
pub(super) fn epoch(machine: MachineId) -> Result<HostEpoch, Box<dyn std::error::Error>> {
    let native = se_proc::current_runtime_identity(machine.clone())
        .map_err(|error| format!("native runtime identity: {error:?}"))?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    let mut argv = Hasher::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            arg.as_bytes().to_vec()
        };
        #[cfg(windows)]
        let bytes = {
            use std::os::windows::ffi::OsStrExt;
            arg.encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        argv.update((bytes.len() as u64).to_le_bytes());
        argv.update(bytes);
    }
    Ok(HostEpoch {
        owner: ProcessInstance::from_observation(ProcessFields {
            machine,
            boot: native.boot_id,
            pid: positive(peer.pid())?,
            started: peer.started().clone(),
            executable: peer.image().clone(),
            argv_sha256: Sha256::from_bytes(argv.finalize().into()),
        })?,
        generation: HostGeneration::new(1)?,
    })
}
pub(super) fn start_options(
    f: &Fixture,
    epoch: HostEpoch,
) -> Result<se_host::HostStart, Box<dyn std::error::Error>> {
    Ok(se_host::HostStart {
        state_directory: f.options.state_directory.clone(),
        epoch,
        kind: se_host::HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(4).ok_or("requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue")?,
            resident_bytes: positive(1024 * 1024)?,
            group_bytes: positive(1024 * 1024)?,
        },
        limits: se_host::HostLimits {
            sessions: positive(8)?,
            active_connections: positive(8)?,
            preauth_connections: positive(4)?,
            parked_mail_waits: positive(8)?,
            resident_queue_bytes: positive(1024 * 1024)?,
            session_notice_ids: positive(128)?,
            aggregate_notice_ids: positive(1024)?,
            response_bytes: positive(1024 * 1024)?,
            blocking_jobs: positive(2)?,
        },
    })
}
pub(super) fn key(value: &str) -> Result<se_types::IdempotencyKey, Box<dyn std::error::Error>> {
    Ok(se_types::IdempotencyKey::new(value)?)
}
pub(super) fn record(number: u8) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::from_parts(
        1_700_000_000_000 + serial(),
        [number; 10],
    )?)
}
pub(super) struct SessionSetup<'a> {
    pub session: &'a SessionId,
    pub conversation: &'a ProviderSessionId,
    pub source: RecordId,
    pub pin: &'a se_proc::NativeSourcePin,
    pub credential: &'a Secret,
}
pub(super) fn prepare_session(
    f: &Fixture,
    direct: &mut SqliteDirect,
    lease: &Lease,
    setup: SessionSetup<'_>,
) -> Check {
    let SessionSetup {
        session,
        conversation,
        source,
        pin,
        credential,
    } = setup;
    let issued = record(51)?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                EventBody::SessionPrepared {
                    session: session.clone(),
                    agent: f.a.clone(),
                    provider: Provider::Claude,
                    native_ref: conversation.as_str().into(),
                    consent: Consent::Capture,
                    generation: 1,
                    expected: Expected::Absent,
                },
                EventBody::CredentialIssued {
                    credential: issued,
                    session: session.clone(),
                    purpose: "session".into(),
                    secret_sha256: Hasher::digest(credential.expose()).into(),
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                EventBody::SessionActivated {
                    session: session.clone(),
                    expected: revision(1)?,
                    incumbent: None,
                    process: None,
                    containment: ContainmentFact::NotLaunched,
                    witnesses: vec![],
                },
                EventBody::CredentialActivated {
                    credential: issued,
                    session: session.clone(),
                    expected: revision(1)?,
                    first_request: record(52)?,
                },
                EventBody::CaptureSource {
                    source,
                    session: session.clone(),
                    consent: Consent::Capture,
                    native_ref: "trusted-test-provider".into(),
                    incarnation: pin.identity().to_vec(),
                    expected: Expected::Absent,
                },
            ],
        )?,
        lease,
    )?;
    Ok(())
}
pub(super) fn verify_capture(
    f: &Fixture,
    source: RecordId,
    expected_turns: usize,
    offset: u64,
) -> Check {
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(f.scoped(Visibility::Owner))?;
    let turns = read.turns(f.a.clone(), budget(10, 65536, None)?)?;
    assert_eq!(turns.items().len(), expected_turns);
    if expected_turns > 0 {
        let EventBody::SessionTurn {
            text: StoredText::Present(text),
            ..
        } = &turns.items()[0].body
        else {
            return Err("captured turn body missing".into());
        };
        assert_eq!(text, "outside provider text");
    }
    let current = present(read.capture_source(source)?)?;
    let EventBody::CaptureProgress { new_offset, .. } = current.current.body else {
        return Err("capture progress missing".into());
    };
    assert_eq!(new_offset, offset);
    read.close()?;
    Ok(())
}
