//! Native inbox wait and protected offer journal for user-owned sessions.
use super::{failure, forward_to, managed_ancestry_refusal, native};
use crate::{bootstrap::Bootstrap, route};
use se_host::adoption::{Input, Kind, Registration};
use se_types::{Result, SeError};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

struct MailWait {
    registration: Registration,
    provider: se_proc::native_ipc::NativeIpcPeer,
    files: se_proc::NativeStateFiles,
    directory: PathBuf,
    offered_path: PathBuf,
    offered: Vec<se_types::MessageId>,
    _lock: File,
}
pub(super) fn wait(cx: &Bootstrap, input: Input) -> Result<u8> {
    let Some(mut waiter) = MailWait::open(cx, &input)? else {
        return Ok(0);
    };
    let Some(target) = waiter.endpoint(cx, &input)? else {
        return Ok(0);
    };
    waiter.run(cx, input, target)
}
fn native_bound() -> se_proc::native_ipc::IpcIoBound {
    se_proc::native_ipc::IpcIoBound {
        deadline: std::time::Instant::now() + Duration::from_secs(3),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}
impl MailWait {
    fn open(cx: &Bootstrap, input: &Input) -> Result<Option<Self>> {
        let registration = se_host::adoption::read_for(&cx.home, input.kind)?
            .ok_or_else(|| SeError::invalid("native mail wait", "current adoption registration"))?;
        let peer = se_proc::native_ipc::observe_ipc_self_bounded(&native_bound())
            .map_err(|e| SeError::invalid("native mail wait", &e.to_string()))?;
        let provider = se_proc::native_ipc::provider_ancestor(
            &peer,
            &registration.provider.to_local()?,
            &native_bound(),
        )
        .map_err(|e| SeError::invalid("native mail wait", &e.to_string()))?;
        let directory = cx.home.join("observed-mail");
        let files = se_proc::NativeStateFiles::open(&cx.home).map_err(native)?;
        files.prepare_directory(&directory).map_err(native)?;
        let mut offer_identity = Sha256::new();
        offer_identity.update(input.conversation.as_str());
        offer_identity.update(provider.binding());
        let name = format!("{:x}", offer_identity.finalize());
        let lock_path = directory.join(format!("{name}.lock"));
        if files.readback(&lock_path).map_err(native)?.is_none() {
            let staging = files.create_staging(&directory).map_err(native)?;
            staging.file.sync_all().map_err(failure)?;
            drop(staging.file);
            match files.publish_no_replace(&staging.path, &lock_path) {
                Ok(()) => (),
                Err(error) if error.code == se_proc::StateFileErrorCode::AlreadyExists => {
                    if let Some(pin) = se_proc::OwnedFile::open(&staging.path).map_err(native)? {
                        pin.remove(Sha256::digest([]).into()).map_err(native)?;
                    }
                }
                Err(error) => return Err(native(error)),
            }
        }
        let lock = files
            .readback(&lock_path)
            .map_err(native)?
            .ok_or_else(|| SeError::invalid("native mail wait", "the protected wait lock"))?;
        match lock.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(failure(error)),
        }
        let offered_path = directory.join(format!("{name}.json"));
        let offered: Vec<se_types::MessageId> =
            if let Some(file) = files.readback(&offered_path).map_err(native)? {
                let mut bytes = Vec::new();
                file.take(262145).read_to_end(&mut bytes).map_err(failure)?;
                se_host::client::wire::decode_json(&bytes, 262144)?
            } else {
                vec![]
            };
        Ok(Some(Self {
            registration,
            provider,
            files,
            directory,
            offered_path,
            offered,
            _lock: lock,
        }))
    }
    fn endpoint(&self, cx: &Bootstrap, input: &Input) -> Result<Option<se_host::EndpointRecord>> {
        // Only lifecycle capture hooks start a host. A late-spawned mail waiter
        // must not reopen a runtime the owner has just stopped.
        let route_files = route::files::Files::open(&cx.home)
            .map_err(|e| se_core::store_error::store_error(&e))?;
        let rendezvous = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match route::execute::endpoint(&route_files)? {
                se_types::Read::Present { value } => return Ok(Some(value)),
                se_types::Read::Absent { .. } => {
                    // The parallel lifecycle hook may still be bootstrapping. Wait
                    // for its publication without starting or reviving any host.
                    if std::time::Instant::now() >= rendezvous
                        || !se_host::adoption::metadata::current(
                            &self.registration,
                            &self.provider,
                            input,
                        )?
                    {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                other => {
                    return se_core::scope::require_present(
                        other,
                        "native mail runtime",
                        "Restore access to the runtime publication.",
                    )
                    .map(|_| None);
                }
            }
        }
    }
    fn run(
        &mut self,
        cx: &Bootstrap,
        mut input: Input,
        target: se_host::EndpointRecord,
    ) -> Result<u8> {
        loop {
            if !se_proc::native_ipc::provider_is_live(&self.provider, &native_bound())
                .map_err(|e| SeError::invalid("native mail wait liveness", &e.to_string()))?
            {
                return Ok(0);
            }
            if !se_host::adoption::metadata::current(&self.registration, &self.provider, &input)? {
                return Ok(0);
            }
            if se_host::adoption::read_for(&cx.home, input.kind)?
                .is_none_or(|r| r.project(&cx.cwd).is_ok_and(|p| p.is_none()))
            {
                return Ok(0);
            }
            input.offered = self.offered.clone();
            let response = match forward_to(cx, input.clone(), &target) {
                Ok(value) => value,
                // Only the authenticated IPC owner ancestry refusal ends this
                // managed-tree waiter. The outer entry retains its diagnostic.
                Err(error) if managed_ancestry_refusal(&error) => return Err(error),
                Err(_) => {
                    match se_host::route_endpoint(&cx.home, Some(&target.address))? {
                        se_host::EndpointRoute::Start { .. } => return Ok(0),
                        se_host::EndpointRoute::Live(current)
                            if current.generation != target.generation =>
                        {
                            return Ok(0);
                        }
                        se_host::EndpointRoute::Live(_) => (),
                    }
                    // Start/Prompt capture can still be preparing the first binding.
                    // Retain this generation; uncertainty never authorizes a restart.
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            if response.get("state").and_then(serde_json::Value::as_str) == Some("ended") {
                return Ok(0);
            }
            let page: Option<se_core::ops::MessagePage> = serde_json::from_value(
                response
                    .get("mail")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|_| {
                SeError::invalid(
                    "native mail wait",
                    "a complete recipient-scoped message page",
                )
            })?;
            let Some(page) = page else { return Ok(0) };
            if self.offer(&input, &response, &page)? {
                return Ok(if input.kind == Kind::Codex { 0 } else { 2 });
            }
            input.cursor = page.page.next().cloned();
            if input.cursor.is_none() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    fn offer(
        &mut self,
        input: &Input,
        response: &serde_json::Value,
        page: &se_core::ops::MessagePage,
    ) -> Result<bool> {
        let mut messages = Vec::new();
        for row in page.page.items() {
            if !self.offered.contains(&row.id) && !row.notification.intent.eq("quiet") {
                messages.push(row.clone());
            }
        }
        if !messages.is_empty() {
            if self.offered.len() + messages.len() > 4096 {
                return Err(SeError::invalid(
                    "native mail offers",
                    "at most 4096 pending offers; read or dismiss older mail using StateEngine",
                ));
            }
            for row in &messages {
                self.offered.push(row.id.clone());
            }
            let bytes = serde_json::to_vec(&self.offered).map_err(|_| {
                SeError::invalid("native mail offers", "serializable offer identifiers")
            })?;
            if let Some(mut pin) = se_proc::OwnedFile::open(&self.offered_path).map_err(native)? {
                let hash = pin.sha256().map_err(native)?;
                pin.replace(hash, &bytes).map_err(native)?;
            } else {
                let mut staged = self.files.create_staging(&self.directory).map_err(native)?;
                staged.file.write_all(&bytes).map_err(failure)?;
                staged.file.sync_all().map_err(failure)?;
                drop(staged.file);
                self.files
                    .publish_no_replace(&staged.path, &self.offered_path)
                    .map_err(native)?;
            }
            // A native wake is an offer, never a durable recipient read or
            // completion receipt. Sender labels are outside untrusted bodies.
            let frame = serde_json::json!({"stateengine_mail":{"agent":response.get("agent"),"messages":messages,"delivery":"offered; provider acceptance and recipient read unconfirmed"}});
            if input.kind == Kind::Codex {
                se_host::adoption::codex::offer(&self.registration, &input.conversation, &frame)?;
            } else {
                writeln!(std::io::stdout(), "{frame}").map_err(failure)?;
            }
            return Ok(true);
        }
        Ok(false)
    }
}
