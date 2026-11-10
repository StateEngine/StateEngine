//! Provider planning and stream attachment only. The launch coordinator owns
//! profile bootstrap, the service process, durable intent and native effects.
use super::*;
use crate::{Harness, HarnessBinding, HarnessRequest, ProviderIoPlatform};
use se_types::{NativePath, Read, Result};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub(crate) struct Managed {
    pub control: Arc<Control>,
    pub service: ServiceIdentity,
    pub profile: NativePath,
    pub process: se_types::ProcessInstance,
    pub session: String,
    pub initial_input: String,
}
pub(crate) struct SecodeHarness {
    io: Arc<dyn ProviderIoPlatform>,
    home: PathBuf,
    maximum: usize,
    images: Mutex<BTreeMap<PathBuf, Arc<Mutex<Images>>>>,
    prepared: Mutex<BTreeMap<se_types::SessionId, Managed>>,
}
pub(crate) struct Binding {
    pub managed: Managed,
    pub completion: stream::Completion,
    pub diagnostics: Mutex<stream::Diagnostics>,
    pub(super) io: Arc<dyn ProviderIoPlatform>,
    pub(super) transport: crate::ProviderTransport,
    pub(super) drains: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl SecodeHarness {
    pub fn new(io: Arc<dyn ProviderIoPlatform>, home: PathBuf, maximum: u32) -> Self {
        Self {
            io,
            home,
            maximum: maximum as usize,
            images: Mutex::default(),
            prepared: Mutex::default(),
        }
    }
    pub fn images(&self, path: &std::path::Path) -> Result<Arc<Mutex<Images>>> {
        self.images
            .lock()
            .map_err(|_| unreadable("SE Code executable custody", "poisoned image registry"))?
            .get(path)
            .cloned()
            .ok_or_else(|| incompatible("selected CLI has no completed capability probe"))
    }
    pub fn register(&self, session: &se_types::SessionId, prepared: Managed) -> Result<()> {
        let mut values = self
            .prepared
            .lock()
            .map_err(|_| unreadable("SE Code preparation", "poisoned binding registry"))?;
        if values.contains_key(session) || values.len() >= self.maximum {
            return Err(unreadable(
                "SE Code preparation",
                "original preparation or finite capacity is already retained",
            ));
        }
        values.insert(session.clone(), prepared);
        Ok(())
    }
    pub fn retire(&self, session: &se_types::SessionId) -> Result<()> {
        self.prepared
            .lock()
            .map_err(|_| unreadable("SE Code preparation", "poisoned binding registry"))?
            .remove(session);
        Ok(())
    }
    pub fn recover(&self, managed: Managed) -> HarnessBinding {
        HarnessBinding {
            claude: None,
            codex: None,
            secode: Some(Arc::new(Binding {
                managed,
                completion: stream::Completion::default(),
                diagnostics: Mutex::new(stream::Diagnostics {
                    recovered: true,
                    ..Default::default()
                }),
                io: self.io.clone(),
                transport: crate::ProviderTransport::console(),
                drains: tokio::sync::Mutex::default(),
            })),
            _private: (),
        }
    }
    pub fn profile(&self, request: &HarnessRequest) -> PathBuf {
        super::private_profile(
            &self.home,
            &request.identity.project,
            &request.identity.agent,
        )
    }
}
pub(crate) fn session(request: &HarnessRequest) -> Result<String> {
    match &request.resume {
        Read::Present { value } => Ok(value.to_string()),
        Read::Absent { .. } => {
            let bytes = request.identity.session.canonical_bytes()?.ok_or_else(|| {
                unreadable(
                    "SE Code session reservation",
                    "a fresh launch requires its canonical UUID identity",
                )
            })?;
            Ok(format!("ses_{}", se_types::hex_lower(&bytes)))
        }
        Read::Unknown { what } => Err(unreadable("SE Code saved session", what)),
        Read::Unreadable { reason, .. } => Err(unreadable("SE Code saved session", reason)),
    }
}
pub(crate) fn input(request: &HarnessRequest) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(request.key.as_str().as_bytes());
    format!("msg_{}", se_types::hex_lower(&digest[..16]))
}
pub(crate) fn bound(binding: &HarnessBinding) -> Result<&Arc<Binding>> {
    binding.secode.as_ref().ok_or_else(|| {
        unreadable(
            "SE Code binding",
            "retained external-service binding absent",
        )
    })
}
impl Harness for SecodeHarness {
    fn kind(&self) -> crate::HarnessKind {
        crate::HarnessKind::Secode
    }
    fn probe<'a>(
        &'a self,
        request: crate::ProbeRequest,
        cx: crate::CallContext,
    ) -> crate::HostFuture<'a, crate::ProviderVersion> {
        Box::pin(async move {
            let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
            let command = request.command.clone();
            let mut images = tokio::task::spawn_blocking(move || Images::open(&command))
                .await
                .map_err(|e| unreadable("SE Code image probe", e))??;
            let capabilities = probe::capabilities(&images.server, &deadline).await?;
            images.resume_supported = probe::supports_resume(&capabilities);
            let version = probe::version(&images.cli, &deadline).await?;
            let command = request.command.clone();
            let images = tokio::task::spawn_blocking(move || {
                let mut images = images;
                images.version = version.clone();
                images.validate()?;
                Ok::<_, se_types::SeError>(images)
            })
            .await
            .map_err(|e| unreadable("SE Code image readback", e))??;
            let mut registry = self
                .images
                .lock()
                .map_err(|_| unreadable("SE Code image probe", "poisoned image registry"))?;
            if registry.len() >= self.maximum && !registry.contains_key(&command) {
                return Err(unreadable(
                    "SE Code image probe",
                    "finite image registry is full",
                ));
            }
            let version = images.version.clone();
            registry.insert(command.clone(), Arc::new(Mutex::new(images)));
            Ok(crate::ProviderVersion {
                kind: self.kind(),
                executable: NativePath::from_local(command)?,
                version,
                protocol: "resident-jsonl+authenticated-control-v1".into(),
            })
        })
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _: crate::CallContext,
    ) -> crate::HostFuture<'a, crate::ConfigPlan> {
        Box::pin(async move {
            if request.mode != se_proc::LaunchMode::HeadlessConsole {
                return Err(incompatible(
                    "managed SE Code requires a headless native console cancellation path",
                ));
            }
            if request.initial_input.as_str().len() > 262144 {
                return Err(incompatible("initial UTF-8 input exceeds 256 KiB"));
            }
            session(request)?;
            Ok(crate::ConfigPlan {
                edits: Vec::new(),
                ephemeral_files: Vec::new(),
            })
        })
    }
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _: crate::CallContext,
    ) -> crate::HostFuture<'a, crate::ProviderInvocation> {
        Box::pin(async move {
            Ok(crate::ProviderInvocation {
                executable: request.executable.clone(),
                arguments: vec![
                    "run".into(),
                    "--service".into(),
                    self.profile(request).into_os_string(),
                    "--session".into(),
                    session(request)?.into(),
                    "--stdin".into(),
                    "--jsonl".into(),
                    "--resident".into(),
                    "--input-id".into(),
                    input(request).into(),
                ],
                environment: se_proc::Environment {
                    entries: super::provider_environment(),
                },
            })
        })
    }
    fn attach<'a>(
        &'a self,
        attach: crate::HarnessAttach,
        retained: &'a mut Option<HarnessBinding>,
        cx: crate::CallContext,
    ) -> crate::HostFuture<'a, crate::LaunchOutcome> {
        Box::pin(async move {
            let managed = self
                .prepared
                .lock()
                .map_err(|_| unreadable("SE Code attach", "poisoned preparation registry"))?
                .get(&attach.request.identity.session)
                .cloned()
                .ok_or_else(|| {
                    unreadable(
                        "SE Code attach",
                        "coordinator has not prepared the original private service",
                    )
                })?;
            if managed.session != session(&attach.request)?
                || managed.initial_input != input(&attach.request)
            {
                return Err(unreadable(
                    "SE Code attach",
                    "prepared service coordinates differ from original launch",
                ));
            }
            let binding = Arc::new(Binding {
                managed,
                completion: stream::Completion::default(),
                diagnostics: Mutex::default(),
                io: self.io.clone(),
                transport: attach.transport,
                drains: tokio::sync::Mutex::default(),
            });
            *retained = Some(HarnessBinding {
                claude: None,
                codex: None,
                secode: Some(binding.clone()),
                _private: (),
            });
            stream::start(&binding, cx.generation).await;
            let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
            let text = attach.request.initial_input.as_str();
            let write = binding
                .io
                .write(
                    &binding.transport,
                    text.as_bytes().to_vec(),
                    copy(&cx, &deadline)?,
                )
                .await;
            let close = binding
                .io
                .finish_input(&binding.transport, copy(&cx, &deadline)?)
                .await;
            // A write failure, including a partial write, has no replay path.
            // Original keyed readback is the only acceptance authority.
            let write_failure = match write {
                Ok(written)
                    if written.completed_bytes as usize == text.len()
                        && written.failure.is_none() =>
                {
                    None
                }
                Ok(written) => Some(written.failure.map(se_types::SeError::from).unwrap_or_else(
                    || unreadable("SE Code initial stdin", "partial write; pending/no-replay"),
                )),
                Err(error) => Some(error),
            };
            let mut write_failure = match (write_failure, close) {
                (Some(write), Err(close)) => Some(close.with_cause(write)),
                (failure, Ok(())) => failure,
                (None, Err(close)) => Some(close),
            };
            loop {
                let receipt = binding
                    .managed
                    .control
                    .acceptance(
                        &binding.managed.service,
                        &binding.managed.session,
                        &binding.managed.initial_input,
                        &deadline,
                    )
                    .await
                    .map_err(|read| match write_failure.take() {
                        Some(original) => read.with_cause(original),
                        None => read,
                    })?;
                match receipt.verify_initial(
                    &binding.managed.service,
                    &binding.managed.session,
                    &binding.managed.initial_input,
                    text,
                )? {
                    Read::Present { .. } => break,
                    Read::Absent { .. } if write_failure.is_some() => {
                        return Err(write_failure.unwrap_or_else(|| {
                            unreadable("SE Code initial input", "pending/no-replay")
                        }));
                    }
                    Read::Absent { .. } => {
                        tokio::time::sleep(
                            deadline
                                .remaining()?
                                .min(std::time::Duration::from_millis(25)),
                        )
                        .await
                    }
                    _ => {
                        return Err(unreadable(
                            "SE Code initial input",
                            "unreadable keyed acceptance; pending/no-replay",
                        ));
                    }
                }
            }
            if let Some(failure) = write_failure {
                return Err(unreadable(
                    "SE Code initial stdin",
                    "original keyed input is accepted, but writing or closing its original stdin failed; acceptance is retained and must not be replayed",
                ).with_cause(failure));
            }
            let notice = binding
                .managed
                .control
                .binding(&binding.managed.session, &deadline)
                .await?;
            binding.managed.service.require_same(&notice.service)?;
            notice.require_ready()?;
            let images = self.images(&attach.request.executable.to_local()?)?;
            let version = images
                .lock()
                .map_err(|_| unreadable("SE Code version", "poisoned image custody"))?
                .version
                .clone();
            Ok(crate::LaunchOutcome {
                witness: crate::BindingWitness {
                    identity: attach.request.identity,
                    conversation: se_types::ProviderSessionId::new(
                        binding.managed.session.clone(),
                    )?,
                    lifecycle: attach.record.lifecycle,
                    provider: crate::ProviderVersion {
                        kind: self.kind(),
                        executable: attach.request.executable,
                        version,
                        protocol: "resident-jsonl+authenticated-control-v1".into(),
                    },
                },
                binding: retained.take().ok_or_else(|| {
                    unreadable("SE Code attach", "retained transport disappeared")
                })?,
            })
        })
    }
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: crate::CallContext,
    ) -> crate::HostFuture<'a, crate::ProviderInterrupt> {
        Box::pin(async move {
            let binding = bound(binding)?;
            let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
            let current = binding
                .managed
                .control
                .binding(&binding.managed.session, &deadline)
                .await?;
            binding.managed.service.require_same(&current.service)?;
            binding
                .managed
                .control
                .request(
                    reqwest::Method::POST,
                    &["api", "session", &binding.managed.session, "interrupt"],
                    Some(&serde_json::json!({})),
                    &deadline,
                )
                .await?;
            let held = binding
                .managed
                .control
                .binding(&binding.managed.session, &deadline)
                .await?;
            binding.managed.service.require_same(&held.service)?;
            if held.status == NoticeStatus::Ready {
                return Err(unreadable(
                    "SE Code stop fence",
                    "native mail remains eligible after interrupt",
                ));
            }
            Ok(crate::ProviderInterrupt { conversation: se_types::ProviderSessionId::new(binding.managed.session.clone())?, requested: true, vendor_event: Read::Absent { checked: "authenticated hold is separate from native client cancellation and execution settlement".into() } })
        })
    }
    fn close_binding<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: crate::CallContext,
    ) -> crate::HostFuture<'a, ()> {
        Box::pin(async move { stream::close(bound(binding)?, &cx).await })
    }
}
fn copy(
    cx: &crate::CallContext,
    deadline: &crate::client::lease::Deadline,
) -> Result<crate::CallContext> {
    Ok(crate::CallContext {
        generation: cx.generation,
        cancellation: cx.cancellation.clone(),
        timeout: deadline.remaining()?,
    })
}
