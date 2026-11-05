//! A finite optional provider hint: every miss/failure/deadline exits zero and
//! prints nothing. It reads an existing protected endpoint and never starts one.
use se_core::ops::{AnyOp, AnyOutput, AtlasAugment};
use se_host::client::{
    ClientOptions,
    lease::{ClientCredential, Deadline},
};
use se_types::{Read, Secret};
use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
const ENTRY: &str = "--stateengine-private-atlas-hook";
pub fn entry(args: &[OsString]) -> Option<std::process::ExitCode> {
    if args.get(1).is_none_or(|arg| arg != ENTRY) {
        return None;
    }
    if args.len() != 3 {
        return Some(std::process::ExitCode::SUCCESS);
    }
    let home = PathBuf::from(&args[2]);
    let cap = if cfg!(windows) {
        Duration::from_millis(20)
    } else {
        Duration::from_millis(8)
    };
    let end = Instant::now() + cap;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    // Blocking stdin or an unavailable peer cannot delay this process's exit.
    // This thread exists only for the finite hook process, never in the host.
    let worker = std::thread::Builder::new()
        .name("atlas-hook".into())
        .spawn(move || {
            let _ = send.send(run(home, end).ok().flatten());
        });
    if worker.is_ok()
        && let Ok(Some(output)) =
            receive.recv_timeout(end.saturating_duration_since(Instant::now()))
        && output.len() <= 600
        && Instant::now() < end
    {
        let _ = std::io::stdout().write_all(output.as_bytes());
    }
    Some(std::process::ExitCode::SUCCESS)
}
fn run(home: PathBuf, end: Instant) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    if input.len() > 16384 || Instant::now() >= end {
        return Ok(None);
    }
    let payload: serde_json::Value = se_host::client::wire::decode_json(&input, 16384)?;
    let Some(target) = se_host::atlas_hooks::classify(&payload) else {
        return Ok(None);
    };
    let operation = AnyOp::AtlasAugment(AtlasAugment {
        target,
        root: None,
        deadline: None,
    });
    let context = crate::bootstrap::Bootstrap::resolve(Some(home), None, false, false, &operation)?;
    if !context.config.value.atlas.enabled || !context.config.value.atlas.hooks {
        return Ok(None);
    }
    let Some(secret) = context.session.as_ref() else {
        return Ok(None);
    };
    let files = crate::route::files::Files::open(&context.home)?;
    let Read::Present { value: endpoint } = crate::route::execute::endpoint(&files)? else {
        return Ok(None);
    };
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: end
            .checked_duration_since(Instant::now())
            .ok_or("hook deadline")?,
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let bound = Deadline::from_options(&options)?;
    se_proc::native_ipc::restore_image_cache(
        &context.home,
        endpoint.image_sha256,
        &bound.native_bound(),
    )?;
    let options = ClientOptions {
        timeout: end
            .checked_duration_since(Instant::now())
            .ok_or("hook deadline")?,
        ..options
    };
    let output = crate::ipc::forward(
        &endpoint,
        ClientCredential::Session(Secret::new(secret.expose().to_vec())?),
        operation,
        &context.selections,
        None,
        &options,
    )?;
    match output {
        AnyOutput::AtlasAugment(output) => Ok(Some(output.value.stdout)),
        _ => Ok(None),
    }
}
