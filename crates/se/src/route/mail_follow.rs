//! Owner inbox follow keeps one native connection and flushes every bounded
//! page/cursor. Ordinary OS termination releases the socket even during output.
use super::{admit, execute, setup};
use crate::bootstrap::Bootstrap;
use se_core::{ops::AnyOp, scope, store_error::store_error};
use se_host::client::{BlockingConnection, BlockingIpcClient, ClientOptions, lease::Deadline};
use se_store::{Actor, Scope, Snapshot};
use se_types::{Read, Result, SeError};
use std::{
    io::{self, Write},
    num::NonZeroU32,
};

pub(crate) fn run(
    cx: &Bootstrap,
    operation: AnyOp,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    let mut diagnostic = |message: &str| {
        writeln!(stderr, "{message}")?;
        stderr.flush()
    };
    let prepared = prepare(cx, operation, &mut diagnostic);
    let (mut connection, call, options) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return crate::render::error::write(
                &error,
                &Default::default(),
                cx.json,
                stdout,
                stderr,
            );
        }
    };
    let mut sink_error = None;
    let result = connection.follow_mail(call, &options, |output| {
        let rendered = render(output, cx.json, stdout);
        match rendered {
            Ok(()) => Ok(()),
            Err(error) => {
                let refusal = scope::unreadable("mail follow output", &error.to_string());
                sink_error = Some(error);
                Err(refusal)
            }
        }
    });
    if let Some(error) = sink_error {
        return if matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        ) {
            Ok(0)
        } else {
            Err(error)
        };
    }
    match result {
        Ok(()) => Ok(0),
        Err(error) => {
            crate::render::error::write(&error, &Default::default(), cx.json, stdout, stderr)
        }
    }
}

fn prepare(
    cx: &Bootstrap,
    operation: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<(BlockingConnection, se_host::IpcEnvelope, ClientOptions)> {
    if let AnyOp::MessageList(input) = &operation
        && input.newest
    {
        return Err(SeError::invalid(
            "mail follow",
            "follow streams oldest-first, so a newest-first cursor would miss mail sent after the first page; drop --follow for one-shot newest-first pages",
        ));
    }
    let setup::Setup::Present((files, (reader, mut phase))) = setup::inspect_phase(
        &cx.home,
        se_core::ops::receipt::timestamp(execute::now_us()?)?,
    )?
    else {
        return Err(setup::required(cx));
    };
    let mut caller = admit::observe(cx, &mut phase, &files)?;
    if !matches!(caller.admission.actor, Actor::Human(_)) {
        phase.close().map_err(|e| store_error(&e))?;
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "msg list --follow".into(),
            },
        )));
    }
    let mut snapshot = phase
        .into_snapshot(se_core::admission::read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    super::select::apply(cx, &mut snapshot, &mut caller.admission, &operation)?;
    let mut selections = cx.selections.clone();
    if let Scope::Project(project) = &caller.admission.scope {
        selections.project = Some(project.clone());
    }
    snapshot.close().map_err(|e| store_error(&e))?;
    drop(reader);
    selections.validate()?;
    let options = execute::options();
    let deadline = Deadline::from_options(&options)?;
    // An SSH shell may select a different runtime directory. The protected
    // publication and native server proof identify the already-running host;
    // only an absent publication needs the ordinary startup rendezvous.
    let endpoint = match execute::endpoint(&files)? {
        Read::Present { value } => value,
        Read::Absent { .. } => super::autostart::endpoint(cx, &files, &deadline, diagnostic)?,
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("runtime endpoint", &what)),
    };
    let mut call = crate::ipc::operation(operation, &selections, endpoint.generation)?;
    call.presence = caller.owner.as_ref().map(|owner| {
        se_host::client::presence::OwnerPresence::from_observation(owner.native_observation())
    });
    se_proc::native_ipc::restore_image_cache(
        &cx.home,
        endpoint.image_sha256,
        &deadline.native_bound(),
    )
    .map_err(|error| scope::unreadable("protected executable cache", &error.to_string()))?;
    let connection = BlockingIpcClient::connect_authenticated(
        &endpoint,
        execute::credential(cx, &files)?,
        NonZeroU32::new(se_host::client::wire::DEFAULT_REPLY_BYTES)
            .ok_or_else(|| SeError::invalid("reply budget", "positive"))?,
        &options,
    )?;
    Ok((connection, call, options))
}

fn render(output: se_host::OperationOutput, json: bool, stdout: &mut impl Write) -> io::Result<()> {
    if output.schema == "se.message-follow-idle" {
        let cursor = output.value["cursor"]
            .as_str()
            .ok_or_else(|| io::Error::other("mail heartbeat omitted its resume cursor"))?;
        if json {
            writeln!(
                stdout,
                "{}",
                serde_json::json!({"type":"idle", "cursor":cursor})
            )?;
        } else {
            writeln!(stdout, "Follow cursor: {cursor}")?;
        }
    } else {
        let cursor = output.value["window"]["to"]
            .as_str()
            .ok_or_else(|| io::Error::other("mail page omitted its resume cursor"))?
            .to_owned();
        let output = crate::ipc::decode(output, &se_core::ops::MessageList::META.family.schema())
            .map_err(io::Error::other)?;
        crate::render::output(&output, json, false, stdout)?;
        if !json {
            writeln!(stdout, "Follow cursor: {cursor}")?;
        }
    }
    stdout.flush()
}
