#![allow(
    dead_code,
    reason = "Shared native fixture helpers serve different public API test binaries."
)]
use se_proc::{NativeStateFiles, StateFileError, StateFileErrorCode};
use se_store::*;
use se_types::{
    AgentId, EventId, HumanId, IdempotencyKey, MessageId, PageRequest, ProjectId, Read,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    io::Write,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub type Check = Result<(), Box<dyn Error>>;
pub static NEXT: AtomicU64 = AtomicU64::new(1);
pub fn serial() -> u64 {
    NEXT.fetch_add(1, Ordering::Relaxed)
}
macro_rules! id {
    ($name:ident,$ty:ident) => {
        pub fn $name() -> Result<$ty, Box<dyn Error>> {
            let n = serial();
            Ok($ty::from_parts(1_700_000_000_000 + n, [n as u8; 10])?)
        }
    };
}
id!(agent, AgentId);
id!(event, EventId);
id!(message, MessageId);

fn native_error(e: StateFileError) -> Box<StoreError> {
    Box::new(StoreError {
        code: match e.code {
            StateFileErrorCode::AlreadyExists => StoreErrorCode::AlreadyExists,
            StateFileErrorCode::LocationUnsafe => StoreErrorCode::LocationUnsafe,
            StateFileErrorCode::SourceChanged => StoreErrorCode::SourceChanged,
            _ => StoreErrorCode::Unreadable,
        },
        cause: e.to_string(),
        detail: StoreDetail::None,
        remedy: se_types::Remedy {
            text: "Inspect the native filesystem refusal".into(),
            command: None,
        },
        retry: se_types::Retry::Never,
    })
}
pub struct Files(pub NativeStateFiles);
impl StateFiles for Files {
    fn retire_empty_staging(&self, staged: ProtectedStaging) -> StoreResult<std::fs::File> {
        self.0
            .retire_empty_staging(se_proc::ProtectedStateStaging {
                path: staged.path,
                file: staged.file,
            })
            .map_err(native_error)
    }
    fn create_staging(&self, directory: &Path) -> StoreResult<ProtectedStaging> {
        let s = self.0.create_staging(directory).map_err(native_error)?;
        Ok(ProtectedStaging {
            path: s.path,
            file: s.file,
        })
    }
    fn readback(&self, path: &Path) -> StoreResult<Read<fs::File>> {
        Ok(match self.0.readback(path).map_err(native_error)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: format!("{} measured absent", path.display()),
            },
        })
    }
    fn publish_no_replace(&self, stage: &Path, target: &Path) -> StoreResult<()> {
        self.0
            .publish_no_replace(stage, target)
            .map_err(native_error)
    }
}
/// Real protected filesystem plus a retained native file lock, not a custody double.
pub struct Lease {
    pub files: Files,
    pub identity: Mutex<LeaseIdentity>,
    _lock: fs::File,
}
impl RuntimeLease for Lease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        Ok(self
            .identity
            .lock()
            .map_err(|e| {
                Box::new(StoreError {
                    code: StoreErrorCode::Unreadable,
                    cause: e.to_string(),
                    detail: StoreDetail::None,
                    remedy: se_types::Remedy {
                        text: "Lease mutex poisoned".into(),
                        command: None,
                    },
                    retry: se_types::Retry::Never,
                })
            })?
            .clone())
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}
impl Lease {
    pub fn acquire(
        root: &Path,
        mode: LeaseMode,
        store: Option<StoreId>,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let files = Files(NativeStateFiles::open(root)?);
        let path = root.join("runtime.lock");
        if files.0.readback(&path)?.is_none() {
            let mut stage = files.0.create_staging(root)?;
            stage.file.write_all(b"runtime lease")?;
            drop(stage.file);
            files.0.publish_no_replace(&stage.path, &path)?;
        }
        // Native readback intentionally has no write access on Windows. The file
        // is verified first; lock acquisition uses the platform's actual OS lock.
        let _verified = files.0.readback(&path)?.ok_or("runtime lock absent")?;
        let lock = fs::OpenOptions::new().read(true).write(true).open(path)?;
        match mode {
            LeaseMode::DirectClient => lock.lock_shared()?,
            LeaseMode::Host => lock.lock()?,
        }
        Ok(Arc::new(Self {
            files,
            identity: Mutex::new(LeaseIdentity {
                store,
                generation: 1,
                mode,
            }),
            _lock: lock,
        }))
    }
}
pub struct Fixture {
    pub home: PathBuf,
    pub options: StoreOptions,
    pub store: StoreId,
    pub owner: HumanId,
    pub project: ProjectId,
    pub a: AgentId,
    pub b: AgentId,
}
impl Fixture {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let n = serial();
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let home =
            std::env::temp_dir().join(format!("otto-store-{}-{nonce}-{n}", std::process::id()));
        let root = home.join("state");
        drop(NativeStateFiles::create(&root)?);
        Ok(Self {
            home,
            options: StoreOptions {
                state_directory: root,
                busy_timeout: Duration::from_secs(2),
            },
            store: StoreId::from_parts(1_700_000_000_000 + n, [1; 10])?,
            owner: HumanId::from_parts(1_700_000_000_000 + serial(), [2; 10])?,
            project: ProjectId::from_parts(1_700_000_000_000 + serial(), [3; 10])?,
            a: agent()?,
            b: agent()?,
        })
    }
    pub fn admission(&self, scope: Scope, actor: Actor) -> Admission {
        Admission {
            scope,
            actor,
            session: None,
            generation: 1,
        }
    }
    pub fn owner_project(&self) -> Admission {
        self.admission(
            Scope::Project(self.project.clone()),
            Actor::Human(self.owner.clone()),
        )
    }
    pub fn scoped(&self, visibility: Visibility) -> ReadScope {
        ReadScope {
            admission: self.owner_project(),
            visibility,
        }
    }
    pub fn self_scope(&self, a: &AgentId) -> ReadScope {
        ReadScope {
            admission: self.admission(
                Scope::Project(self.project.clone()),
                Actor::Agent(a.clone()),
            ),
            visibility: Visibility::SelfOnly(a.clone()),
        }
    }
    pub fn batch(
        &self,
        admission: Admission,
        request: Option<RequestIdentity>,
        bodies: Vec<EventBody<InputText>>,
    ) -> Result<AtomicBatch, Box<dyn Error>> {
        let mut events = Vec::new();
        for body in bodies {
            events.push(NewEvent {
                header: EventHeader {
                    event: event()?,
                    scope: admission.scope.clone(),
                    actor: admission.actor.clone(),
                    session: None,
                    origin: self.store.clone(),
                    door: Door::Cli,
                    occurred_at_us: 1_700_000_000_000_000,
                    cause: None,
                    supersedes: None,
                },
                body,
            });
        }
        Ok(AtomicBatch {
            expected_incarnation: 1,
            admission,
            request,
            events,
            import_checkpoint: None,
        })
    }
    pub fn direct(&self) -> Result<(SqliteDirect, Arc<Lease>), Box<dyn Error>> {
        let lease = Lease::acquire(&self.options.state_directory, LeaseMode::DirectClient, None)?;
        let mut direct = SqliteFactory::create_direct(&self.options, &*lease, self.store.clone())?;
        lease.identity.lock().map_err(|_| "lease mutex")?.store = Some(self.store.clone());
        direct.append(
            self.batch(
                self.admission(Scope::Registry, Actor::Human(self.owner.clone())),
                Some(request("owner")?),
                vec![EventBody::PrincipalRegistered {
                    principal: Actor::Human(self.owner.clone()),
                    kind: PrincipalKind::Human,
                    owner: self.owner.clone(),
                    created_by: None,
                    name: "Owner".into(),
                    role: "owner".into(),
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
        direct.append(
            self.batch(
                self.owner_project(),
                Some(request("project")?),
                vec![EventBody::ProjectRegistered {
                    project: self.project.clone(),
                    name: "Project".into(),
                    roots: vec![],
                    owner: self.owner.clone(),
                    history_from: None,
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
        for (a, name) in [(&self.a, "Alpha"), (&self.b, "Beta")] {
            direct.append(
                self.batch(
                    self.owner_project(),
                    Some(request(name)?),
                    vec![EventBody::PrincipalRegistered {
                        principal: Actor::Agent(a.clone()),
                        kind: PrincipalKind::Agent,
                        owner: self.owner.clone(),
                        created_by: None,
                        name: name.into(),
                        role: "builder".into(),
                        expected: Expected::Absent,
                    }],
                )?,
                &*lease,
            )?;
        }
        Ok((direct, lease))
    }
    pub fn send(
        &self,
        sender: Actor,
        recipient: Actor,
        id: MessageId,
        body: &str,
        key: &str,
    ) -> Result<AtomicBatch, Box<dyn Error>> {
        self.batch(
            self.admission(Scope::Project(self.project.clone()), sender),
            Some(request(key)?),
            vec![EventBody::MessageSent {
                message: id,
                recipient,
                kind: "finding".into(),
                body: InputText::Inline(body.into()),
                refs: vec![],
                reply_to: None,
            }],
        )
    }
    pub fn working(
        &self,
        text: &str,
        expected: Expected,
        key: &str,
    ) -> Result<AtomicBatch, Box<dyn Error>> {
        self.batch(
            self.admission(
                Scope::Project(self.project.clone()),
                Actor::Agent(self.a.clone()),
            ),
            Some(request(key)?),
            vec![EventBody::WorkingStateSet {
                agent: self.a.clone(),
                text: InputText::Inline(text.into()),
                expected,
            }],
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.home) {
            eprintln!("cleanup {}: {e}", self.home.display());
        }
    }
}
pub fn request(input: &str) -> Result<RequestIdentity, Box<dyn Error>> {
    Ok(RequestIdentity {
        key: IdempotencyKey::new(input)?,
        intent: IntentDigest {
            operation: "judge.public-api",
            codec_version: 1,
            sha256: Sha256::digest(input.as_bytes()).into(),
        },
    })
}
pub fn revision(n: u64) -> Result<Expected, Box<dyn Error>> {
    Ok(Expected::Revision(Revision {
        value: NonZeroU64::new(n).ok_or("revision zero")?,
    }))
}
pub fn budget(
    limit: u32,
    bytes: u32,
    after: Option<se_types::Cursor>,
) -> Result<ReadBudget, Box<dyn Error>> {
    Ok(ReadBudget {
        page: PageRequest {
            after,
            limit: NonZeroU32::new(limit).ok_or("zero limit")?,
            max_bytes: NonZeroU32::new(bytes).ok_or("zero bytes")?,
        },
        deadline: Duration::from_secs(2),
    })
}
pub fn query(recipient: Option<Actor>, unread: bool) -> MessageQuery {
    MessageQuery {
        recipient,
        sender: None,
        kind: None,
        unread_only: unread,
        full_body: true,
    }
}
pub fn present<T>(value: Read<T>) -> Result<T, Box<dyn Error>> {
    match value {
        Read::Present { value } => Ok(value),
        _ => Err("expected present".into()),
    }
}
pub fn same_receipt(a: &CommitReceipt, b: &CommitReceipt) {
    assert_eq!(a.request_key, b.request_key);
    assert_eq!(a.primary_event, b.primary_event);
    assert_eq!(a.events, b.events);
    assert_eq!(a.first, b.first);
    assert_eq!(a.last, b.last);
    assert_eq!(a.writer, b.writer);
    assert_eq!(a.durability, b.durability);
    assert_eq!(a.wakes.len(), b.wakes.len());
    for (a, b) in a.wakes.iter().zip(&b.wakes) {
        assert_eq!(a.project, b.project);
        assert_eq!(a.principal, b.principal);
        assert_eq!(a.through, b.through);
    }
}

#[cfg(windows)]
pub fn dump_windows_acl(path: &Path) -> Check {
    let literal = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
$path='{literal}'
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$acl=Get-Acl -LiteralPath $path
$binary=$acl.GetSecurityDescriptorBinaryForm()
$raw=New-Object System.Security.AccessControl.RawSecurityDescriptor($binary,0)
Write-Output "ACL path=$path owner=$($raw.Owner.Value) token_user=$($identity.User.Value) token_owner=$($identity.Owner.Value) control=$($raw.ControlFlags)"
foreach($ace in $raw.DiscretionaryAcl) {{ Write-Output "ACE type=$($ace.AceType) flags=$($ace.AceFlags) mask=$($ace.AccessMask) sid=$($ace.SecurityIdentifier.Value)" }}
"#
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;
    eprint!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err("outside native ACL readback failed".into());
    }
    Ok(())
}
