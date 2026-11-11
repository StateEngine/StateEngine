//! Fail-open native hook entry. Ambient session/config selections never supply
//! authority: this home and project come only from explicit installation.
use crate::{bootstrap::Bootstrap, route};
use se_host::{
    adoption::{Action, Input},
    client::{ClientOptions, lease::Deadline},
};
use se_types::{NativePath, Result, SeError};
use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub fn entry(args: &[OsString]) -> Option<u8> {
    if !args.get(1).is_some_and(|a| a == "__se-claude-adopt") {
        return None;
    }
    // Every refusal remains provider-nonblocking. An unregistered project must
    // be a completely silent success and must never create state or a runtime.
    Some(run(args).unwrap_or(0))
}
#[cfg(any(target_os = "linux", windows))]
fn run(args: &[OsString]) -> Result<u8> {
    if args.len() != 4 {
        return Ok(0);
    }
    let home = PathBuf::from(&args[2]);
    if !home.is_absolute() {
        return Ok(0);
    }
    let Some(registration) = se_host::adoption::read(&home)? else {
        return Ok(0);
    };
    let cwd =
        se_proc::canonicalize_path(&std::env::current_dir().map_err(failure)?).map_err(failure)?;
    let Some(project) = registration.project(&cwd)? else {
        return Ok(0);
    };
    registered(args, home, cwd, project.project.clone()).or_else(|error| {
        let _ = writeln!(
            std::io::stderr(),
            "StateEngine integration is unconfirmed [{}]: {}",
            error.code().as_str(),
            error.body.message()
        );
        Ok(0)
    })
}
#[cfg(any(target_os = "linux", windows))]
fn registered(
    args: &[OsString],
    home: PathBuf,
    cwd: PathBuf,
    project: se_types::ProjectId,
) -> Result<u8> {
    let action = match args[3].to_str() {
        Some("start") => Action::Start,
        Some("prompt") => Action::Prompt,
        Some("capture") => Action::Capture,
        Some("stop") => Action::Stop,
        Some("end") => Action::End,
        Some("mail") => Action::Mail,
        _ => return Ok(0),
    };
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    let payload: serde_json::Value = se_host::client::wire::decode_json(&bytes, 1024 * 1024)?;
    let get = |key| {
        payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SeError::invalid(
                    "native adoption hook",
                    "session_id, transcript_path and cwd strings",
                )
            })
    };
    if se_proc::canonicalize_path(Path::new(get("cwd")?)).map_err(failure)? != cwd {
        return Ok(0);
    }
    let conversation = se_types::ProviderSessionId::new(get("session_id")?.to_owned())?;
    if uuid::Uuid::parse_str(conversation.as_str()).is_err() {
        return Ok(0);
    }
    let transcript = NativePath::from_local(PathBuf::from(get("transcript_path")?))?;
    let input = Input {
        project: project.clone(),
        cwd: NativePath::from_local(cwd.clone())?,
        conversation,
        transcript,
        action,
        cursor: None,
        offered: vec![],
    };
    let config = crate::config::load(&home.join("config.toml"), false)?;
    let cx = Bootstrap {
        home,
        cwd,
        project: Some(project.to_string()),
        selections: Default::default(),
        config,
        session: None,
        log: None,
        no_color: true,
        json: false,
        retry_invocation: None,
        legacy_environment_present: false,
    };
    if action == Action::Mail {
        return mail(&cx, input);
    }
    forward(&cx, input)?;
    Ok(0)
}
#[cfg(not(any(target_os = "linux", windows)))]
fn run(_args: &[OsString]) -> Result<u8> {
    Ok(0)
}
#[cfg(any(target_os = "linux", windows))]
fn forward(cx: &Bootstrap, input: Input) -> Result<serde_json::Value> {
    let files =
        route::files::Files::open(&cx.home).map_err(|e| se_core::store_error::store_error(&e))?;
    let bound = Deadline::from_options(&route::execute::options())?;
    let target = if input.action == Action::End {
        // Closing a user-owned provider never resurrects a host stopped by
        // the owner. Down already retires its observed bindings.
        match route::execute::endpoint(&files)? {
            se_types::Read::Present { value } => value,
            se_types::Read::Absent { .. } => return Ok(serde_json::json!({"state":"detached"})),
            other => se_core::scope::require_present(
                other,
                "observed session end",
                "Restore access to the runtime publication.",
            )?,
        }
    } else {
        route::autostart::endpoint(cx, &files, &bound, &mut |_| Ok(()))?
    };
    forward_to(cx, input, &target)
}
#[cfg(any(target_os = "linux", windows))]
fn forward_to(
    cx: &Bootstrap,
    input: Input,
    target: &se_host::EndpointRecord,
) -> Result<serde_json::Value> {
    let files =
        route::files::Files::open(&cx.home).map_err(|e| se_core::store_error::store_error(&e))?;
    let bound = Deadline::from_options(&route::execute::options())?;
    se_proc::native_ipc::restore_image_cache(&cx.home, target.image_sha256, &bound.native_bound())
        .map_err(|e| se_core::scope::unreadable("native hook image cache", &e.to_string()))?;
    let options = ClientOptions {
        expected_generation: Some(target.generation),
        timeout: Duration::from_secs(25),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let output = crate::ipc::exchange_output(
        target,
        route::execute::credential(cx, &files)?,
        se_host::IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: target.generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: se_host::IpcRequest::Adopt(input),
        },
        &options,
    )?;
    if output.schema != "se.adoption/1" {
        return Err(SeError::invalid(
            "native adoption response",
            "the exact provider adoption family",
        ));
    }
    Ok(output.value)
}
#[cfg(any(target_os = "linux", windows))]
fn mail(cx: &Bootstrap, mut input: Input) -> Result<u8> {
    use sha2::{Digest, Sha256};
    let registration = se_host::adoption::read(&cx.home)?
        .ok_or_else(|| SeError::invalid("native mail wait", "current adoption registration"))?;
    let native_bound = || se_proc::native_ipc::IpcIoBound {
        deadline: std::time::Instant::now() + Duration::from_secs(3),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
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
        Err(std::fs::TryLockError::WouldBlock) => return Ok(0),
        Err(std::fs::TryLockError::Error(error)) => return Err(failure(error)),
    }
    let offered_path = directory.join(format!("{name}.json"));
    let mut offered: Vec<se_types::MessageId> =
        if let Some(file) = files.readback(&offered_path).map_err(native)? {
            let mut bytes = Vec::new();
            file.take(262145).read_to_end(&mut bytes).map_err(failure)?;
            se_host::client::wire::decode_json(&bytes, 262144)?
        } else {
            vec![]
        };
    // A waiter may rendezvous once, but never restarts a host the owner stops.
    // Later provider lifecycle hooks can start a fresh observation normally.
    let route_files =
        route::files::Files::open(&cx.home).map_err(|e| se_core::store_error::store_error(&e))?;
    let route_bound = Deadline::from_options(&route::execute::options())?;
    let target = route::autostart::endpoint(cx, &route_files, &route_bound, &mut |_| Ok(()))?;
    loop {
        if !se_proc::native_ipc::provider_is_live(&provider, &native_bound())
            .map_err(|e| SeError::invalid("native mail wait liveness", &e.to_string()))?
        {
            return Ok(0);
        }
        if !se_host::adoption::metadata::current(&registration, &provider, &input)? {
            return Ok(0);
        }
        if se_host::adoption::read(&cx.home)?
            .is_none_or(|r| r.project(&cx.cwd).is_ok_and(|p| p.is_none()))
        {
            return Ok(0);
        }
        input.offered = offered.clone();
        let response = match forward_to(cx, input.clone(), &target) {
            Ok(value) => value,
            Err(error) => {
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
                let _ = error;
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
        let mut messages = Vec::new();
        for row in page.page.items() {
            if !offered.contains(&row.id) && !row.notification.intent.eq("quiet") {
                messages.push(row.clone());
            }
        }
        if !messages.is_empty() {
            if offered.len() + messages.len() > 4096 {
                return Err(SeError::invalid(
                    "native mail offers",
                    "at most 4096 pending offers; read or dismiss older mail using StateEngine",
                ));
            }
            for row in &messages {
                offered.push(row.id.clone());
            }
            let bytes = serde_json::to_vec(&offered).map_err(|_| {
                SeError::invalid("native mail offers", "serializable offer identifiers")
            })?;
            if let Some(mut pin) = se_proc::OwnedFile::open(&offered_path).map_err(native)? {
                let hash = pin.sha256().map_err(native)?;
                pin.replace(hash, &bytes).map_err(native)?;
            } else {
                let mut staged = files.create_staging(&directory).map_err(native)?;
                staged.file.write_all(&bytes).map_err(failure)?;
                staged.file.sync_all().map_err(failure)?;
                drop(staged.file);
                files
                    .publish_no_replace(&staged.path, &offered_path)
                    .map_err(native)?;
            }
            // A native wake is an offer, never a durable recipient read or
            // completion receipt. Sender labels are outside untrusted bodies.
            let frame = serde_json::json!({"stateengine_mail":{"agent":response.get("agent"),"messages":messages,"delivery":"offered; provider acceptance and recipient read unconfirmed"}});
            writeln!(std::io::stdout(), "{frame}").map_err(failure)?;
            return Ok(2);
        }
        input.cursor = page.page.next().cloned();
        if input.cursor.is_none() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
fn failure(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("native adoption hook", &error.to_string())
}
fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("native adoption file", &error.to_string())
}
