//! Retrying a settled SE Code notice retirement after a pre-publication write
//! failure must persist and witness the retired journal before returning Ok.
use se_harness::{
    Deadline, ProviderIoPlatform, SessionIdentity,
    secode_process::{NoticeBinding, NoticeStatus, SecodeHarness, ServiceIdentity},
};
use se_proc::NativeProcessRuntime;
use se_secode_service::{
    HostPort, PortFuture, Service, Services,
    custody::{InitialInputIntent, Journal, Notice, ResumeSupport},
    mail,
};
use se_store::{Admission, CommitReceipt, SqliteSnapshot};
use se_types::{AgentId, NativePath, NoticeId, ProjectId, Read, Result, SessionId, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

static FAIL_OPEN: AtomicBool = AtomicBool::new(false);

struct TestHost;

impl HostPort for TestHost {
    fn services(&self) -> &Services {
        unimplemented!()
    }
    fn native(&self) -> &Arc<NativeProcessRuntime> {
        unimplemented!()
    }
    fn io(&self) -> &Arc<dyn ProviderIoPlatform> {
        unimplemented!()
    }
    fn secode_harness(&self) -> &Arc<SecodeHarness> {
        unimplemented!()
    }
    fn owner(&self) -> &se_proc::ProcessIdentity {
        unimplemented!()
    }
    fn host_id(&self) -> se_proc::HostInstanceId {
        unimplemented!()
    }
    fn home(&self) -> &Path {
        unimplemented!()
    }
    fn epoch(&self) -> &se_types::HostEpoch {
        unimplemented!()
    }
    fn generation(&self) -> se_types::Generation {
        unimplemented!()
    }
    fn configuration(&self) -> &se_config::config_policy::ConfigFile {
        unimplemented!()
    }
    fn configuration_file(&self) -> Option<&Path> {
        unimplemented!()
    }
    fn http_port(&self) -> u16 {
        unimplemented!()
    }
    fn maximum_sessions(&self) -> u32 {
        unimplemented!()
    }
    fn runtime_handle(&self) -> tokio::runtime::Handle {
        unimplemented!()
    }
    fn run_blocking<'a, T: Send + 'static>(
        &'a self,
        _deadline: &'a Deadline,
        op: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> PortFuture<'a, T> {
        Box::pin(async move { op() })
    }
    fn store_read<'a, T: Send + 'static>(
        &'a self,
        _admission: Admission,
        _deadline: &'a Deadline,
        _op: impl FnOnce(&mut se_core::commit::Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> PortFuture<'a, T> {
        unimplemented!()
    }
    fn commit_step<'a, O: Send + 'static, T: Send + 'static>(
        &'a self,
        _admission: Admission,
        _deadline: &'a Deadline,
        _plan: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, SqliteSnapshot>,
        ) -> Result<se_core::commit::OpStep<O, T>>
        + Send
        + 'static,
        _finish: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, SqliteSnapshot>,
            T,
            CommitReceipt,
        ) -> Result<O>
        + Send
        + 'static,
    ) -> PortFuture<'a, O> {
        unimplemented!()
    }
    fn resolve_secode_provider<'a>(&'a self, _deadline: &'a Deadline) -> PortFuture<'a, PathBuf> {
        unimplemented!()
    }
    fn saved_session_capability<'a>(
        &'a self,
        _profile: PathBuf,
        _policy_hash: Option<Sha256>,
        _expected: SessionIdentity,
        _deadline: &'a Deadline,
    ) -> PortFuture<'a, se_types::Secret> {
        unimplemented!()
    }
    fn is_job_unsettled(&self, _project: &ProjectId, _agent: &AgentId) -> Result<bool> {
        unimplemented!()
    }
    fn mark_job_mail_pending(&self, _project: &ProjectId, _agent: &AgentId) -> Result<()> {
        unimplemented!()
    }
    fn observe_client_stream(
        &self,
        _project: &ProjectId,
        _agent: &AgentId,
    ) -> Result<Read<String>> {
        unimplemented!()
    }
    fn adopt_restart<'a>(
        &'a self,
        _service: &'a mut Service,
        _deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        unimplemented!()
    }
    fn restore_restart_state<'a>(
        &'a self,
        _service: &'a mut Service,
        _deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        unimplemented!()
    }
    fn verify_captured_end<'a>(
        &'a self,
        _admission: Admission,
        _source: se_store::RecordId,
        _end: u64,
        _deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        unimplemented!()
    }
    fn native_instance(
        &self,
        _root: &se_proc::ProcessIdentity,
        _argv: [u8; 32],
        _boot: &se_types::BootId,
    ) -> Result<se_types::ProcessInstance> {
        unimplemented!()
    }
    fn allocate_facts() -> Result<se_core::dispatch::CallFacts> {
        unimplemented!()
    }
    fn open_owned_file(
        path: &Path,
        subject: &str,
        _deadline: &Deadline,
    ) -> Result<Option<se_proc::OwnedFile>> {
        if FAIL_OPEN.load(Ordering::SeqCst) {
            return Err(se_core::scope::unreadable(
                subject,
                "injected pre-publication journal read failure",
            ));
        }
        se_proc::OwnedFile::open(path)
            .map_err(|e| se_core::scope::unreadable(subject, &format!("{e:?}")))
    }
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn retry_after_pre_publication_failure_persists_retired_notice() -> Result<()> {
    let dir = TempDir(
        std::env::temp_dir().join(format!("se-retire-settled-notice-{}", std::process::id())),
    );
    let _ = std::fs::remove_dir_all(&dir.0);
    let _files = se_proc::NativeStateFiles::create(&dir.0)
        .map_err(|e| se_core::scope::unreadable("test custody dir", &format!("{e:?}")))?;
    let path = dir.0.join("journal.json");

    let notice_id = NoticeId::new("notice-0102030405060708090a0b0c0d0e0f10")?;
    let expected_input = mail::input(&notice_id);
    let journal = Journal {
        version: 1,
        retired: false,
        lost: false,
        stop_failure: None,
        project: ProjectId::from_parts(1, [1u8; 10])?,
        agent: AgentId::from_parts(2, [2u8; 10])?,
        profile: NativePath::from_local(dir.0.join("profile"))?,
        session: SessionId::from_parts(3, [3u8; 10])?,
        vendor_session: "synthetic-session".into(),
        initial_input: "synthetic-input".into(),
        initial_sha256: Sha256::from_bytes([0u8; 32]),
        initial_offered: InitialInputIntent::Unrecorded,
        session_create_attempted: false,
        policy_sha256: None,
        previous_policy_sha256: None,
        client_closed: None,
        resume_release: None,
        input_free_resume: ResumeSupport::default(),
        notice: Some(Notice {
            effect: None,
            input: expected_input.clone(),
            binding: NoticeBinding {
                service: ServiceIdentity {
                    incarnation: "inc-1".into(),
                    service_instance: "svc-1".into(),
                    generation: 1,
                    registration_version: "1".into(),
                },
                session_id: "synthetic-session".into(),
                target_id: Some("target-1".into()),
                binding: Some("binding-1".into()),
                hold_id: None,
                status: NoticeStatus::Ready,
            },
            messages: vec!["msg-synthetic-1".into()],
        }),
        restart: None,
        bootstrap: None,
        service: None,
        retirement: None,
        registration: None,
        server_sha256: None,
        endpoint: None,
        identity: None,
        capability_repair: None,
    };

    let host = TestHost;
    let deadline = Deadline::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)))?;
    let mut service = Service::new(journal, path.clone());
    FAIL_OPEN.store(false, Ordering::SeqCst);
    service.persist(&host, &deadline).await?;

    // Inject a pre-publication write failure on the first retirement attempt.
    FAIL_OPEN.store(true, Ordering::SeqCst);
    let first = service
        .retire_settled_notice(&host, &notice_id, &deadline)
        .await;
    FAIL_OPEN.store(false, Ordering::SeqCst);
    assert!(
        first.is_err(),
        "first retirement must fail when journal cannot be opened before publication"
    );

    // Independent disk readback must still show the unretired notice.
    let before_retry = Journal::read::<TestHost>(&path, &deadline)?.ok_or_else(|| {
        se_core::scope::unreadable(
            "test journal",
            "journal must remain on disk after failed retirement",
        )
    })?;
    assert_eq!(
        before_retry.notice.as_ref().map(|n| n.input.as_str()),
        Some(expected_input.as_str()),
        "failed first retirement must not have published notice=None"
    );

    // Retrying on the same retained service must flush/persist the retirement.
    service
        .retire_settled_notice(&host, &notice_id, &deadline)
        .await?;

    // Independent disk readback must now witness notice == None.
    let after_retry = Journal::read::<TestHost>(&path, &deadline)?.ok_or_else(|| {
        se_core::scope::unreadable(
            "test journal",
            "journal must remain on disk after successful retirement",
        )
    })?;
    assert!(
        after_retry.notice.is_none(),
        "retried retirement must durably clear journal.notice on disk"
    );
    Ok(())
}
