//! Fail-open native hook entry. Ambient session/config selections never supply
//! authority: this home and project come only from explicit installation.
use crate::{bootstrap::Bootstrap, route};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod mail;
use se_host::{
    adoption::{Action, Input, Kind},
    client::{ClientOptions, lease::Deadline},
};
use se_types::{NativePath, Result, SeError};
use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn entry(args: &[OsString]) -> Option<u8> {
    kind(args)?;
    // Every refusal remains provider-nonblocking. An unregistered project must
    // be a completely silent success and must never create state or a runtime.
    Some(run(args).unwrap_or(0))
}
fn kind(args: &[OsString]) -> Option<Kind> {
    match args.get(1)?.to_str()? {
        "__se-claude-adopt" => Some(Kind::Claude),
        "__se-codex-adopt" => Some(Kind::Codex),
        _ => None,
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn run(args: &[OsString]) -> Result<u8> {
    if args.len() != 4 {
        return Ok(0);
    }
    let kind = kind(args)
        .ok_or_else(|| SeError::invalid("native adoption", "a supported provider entry"))?;
    let home = PathBuf::from(&args[2]);
    if !home.is_absolute() {
        return Ok(0);
    }
    let Some(registration) = se_host::adoption::read_for(&home, kind)? else {
        return Ok(0);
    };
    let cwd =
        se_proc::canonicalize_path(&std::env::current_dir().map_err(failure)?).map_err(failure)?;
    let Some(project) = registration.project(&cwd)? else {
        return Ok(0);
    };
    registered(args, home.clone(), cwd, project.project.clone()).or_else(|error| {
        // All six actions (start, prompt, capture, stop, end and mail) can run
        // beneath managed providers. Their IPC owner ancestry refusal skips
        // native adoption; managed hooks own capture and mail. Keep a bounded
        // doctor diagnostic so an unexpected classification remains visible.
        if managed_ancestry_refusal(&error) {
            if let Some(action) = args[3].to_str().and_then(Action::parse)
                && let Err(record_error) =
                    se_host::adoption::diagnostic::record(&home, &project.project, action)
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "StateEngine adoption diagnostic could not be saved: {record_error}"
                );
            }
            return Ok(0);
        }
        if let Some(action) = args[3].to_str().and_then(Action::parse)
            && let Err(record_error) = se_host::adoption::status::record_for(
                &home,
                kind,
                &project.project,
                action,
                Some(&error),
            )
        {
            let _ = writeln!(
                std::io::stderr(),
                "StateEngine adoption status could not be saved: {record_error}"
            );
        }
        let _ = writeln!(
            std::io::stderr(),
            "StateEngine integration is unconfirmed [{}]: {}",
            error.code().as_str(),
            error.body.message()
        );
        Ok(0)
    })
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn managed_ancestry_refusal(error: &SeError) -> bool {
    matches!(error.body.detail(), se_types::Detail::OwnerRequired(detail) if detail.op == "IPC owner")
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
    let kind = kind(args)
        .ok_or_else(|| SeError::invalid("native adoption", "a supported provider entry"))?;
    let input = Input {
        kind,
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
    let registration = se_host::adoption::read_for(&cx.home, input.kind)?
        .ok_or_else(|| SeError::invalid("native adoption hook", "current adoption registration"))?;
    // Cold work is separate from native peer proof. Installation warms these
    // hints; subsequent hooks read image content only after a native file change.
    se_proc::native_ipc::prepare_adoption_image_cache(
        &cx.home,
        &registration.provider.to_local()?,
        &se_proc::native_ipc::IpcIoBound {
            deadline: std::time::Instant::now() + Duration::from_secs(25),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )
    .map_err(|e| se_core::scope::unreadable("adoption executable proof", &e.to_string()))?;
    if action == Action::Mail {
        return mail::wait(&cx, input);
    }
    forward_lifecycle(&cx, input)?;
    Ok(0)
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn forward_lifecycle(cx: &Bootstrap, input: Input) -> Result<serde_json::Value> {
    // A definite contention refusal keeps the original session/event keys.
    // Reauthenticate each attempt within the provider's short end-hook window.
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        match forward(cx, input.clone()) {
            Err(error) if error.code() == se_types::Code::StoreBusy && Instant::now() < until => {
                std::thread::sleep(
                    until
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20)),
                );
            }
            outcome => return outcome,
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn run(_args: &[OsString]) -> Result<u8> {
    Ok(0)
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
    let project = input.project.clone();
    let action = input.action;
    let kind = input.kind;
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
    se_host::adoption::status::record_for(&cx.home, kind, &project, action, None)?;
    Ok(output.value)
}
fn failure(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("native adoption hook", &error.to_string())
}
fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("native adoption file", &error.to_string())
}
#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests {
    use super::managed_ancestry_refusal;
    use se_types::{Detail, SeError, details};

    fn owner(op: &str) -> SeError {
        SeError::new(Detail::OwnerRequired(details::OwnerRequired {
            op: op.into(),
        }))
    }
    #[test]
    fn only_the_ipc_owner_refusal_is_suppressed() {
        assert!(managed_ancestry_refusal(&owner("IPC owner")));
        assert!(!managed_ancestry_refusal(&owner("agent create")));
        assert!(!managed_ancestry_refusal(&owner("")));
        assert!(!managed_ancestry_refusal(&SeError::new(
            Detail::OsUserMismatch(details::OsUserMismatch {
                expected: "1".into(),
                actual: "2".into(),
            })
        )));
        assert!(!managed_ancestry_refusal(&SeError::invalid(
            "native adoption hook",
            "session_id, transcript_path and cwd strings"
        )));
    }
    /// The classifier keys on the producer's literal; renaming either side
    /// must fail here instead of silently resurfacing the refusal.
    #[test]
    fn classifier_matches_the_admission_producer_literal() {
        let producer = include_str!("../../se-host/src/runtime/admission.rs");
        assert_eq!(producer.matches("\"IPC owner\"").count(), 1);
        assert!(producer.contains("op: \"IPC owner\".into()"));
        assert!(managed_ancestry_refusal(&owner("IPC owner")));
    }
}
