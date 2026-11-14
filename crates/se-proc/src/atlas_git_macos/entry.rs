//! Early, closed bootstrap roles. No configuration or repository contents are read.
use super::{
    clock::Expiry,
    identity::{ProcessPin, State},
    invalid, policy, process,
    protocol::{self, Frame, Launch},
    runtime::Runtime,
};
use crate::{NativeExecutablePin, NativeSourceRoot};
use std::{
    ffi::OsString,
    io,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Stdio},
};

pub(super) const SUPERVISOR: &str = "--private-atlas-git-supervisor";
pub(super) const BOOTSTRAP: &str = "--private-atlas-git-bootstrap";
struct Owned(Child, bool);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.1
            && let Err(error) = process::reap(&mut self.0)
        {
            eprintln!(
                "Git direct-child cleanup remains pending for {}: {error}",
                self.0.id()
            );
        }
    }
}
pub(super) fn private_entry(args: &[OsString]) -> Option<io::Result<()>> {
    let role = args.get(1)?.to_str()?;
    if !matches!(role, SUPERVISOR | BOOTSTRAP) {
        return None;
    }
    Some((|| {
        if args.len() != 3 {
            return Err(invalid("closed Git role requires only its original expiry"));
        }
        let expiry = Expiry::parse(&args[2])?;
        // SAFETY: query confirms this private descriptor is live before borrowing it.
        if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the early single-threaded entry just verified descriptor liveness.
        let borrowed = unsafe { BorrowedFd::borrow_raw(3) };
        let parent = ProcessPin::peer(borrowed, crate::native_ipc::IpcPeerSide::Server, expiry)?;
        // SAFETY: immutable native creator query.
        if parent.pid != unsafe { libc::getppid() } as u32 {
            return Err(invalid(
                "Git channel creator differs from its native parent",
            ));
        }
        // SAFETY: authenticated descriptor 3 transfers to this one owned stream.
        let mut channel = unsafe { UnixStream::from_raw_fd(3) };
        let Frame::Launch(launch) = protocol::receive(&mut channel, expiry)? else {
            return Err(invalid("Git initial authorization frame is absent"));
        };
        launch.validate()?;
        if launch.expiry != expiry {
            return Err(invalid(
                "Git role attempted to replace its original deadline",
            ));
        }
        parent.verify(&launch.parent)?;
        if role == SUPERVISOR {
            parent.verify(&launch.host)?;
            supervise(channel, *launch)
        } else {
            bootstrap(channel, *launch)
        }
    })())
}
fn roots(launch: &Launch) -> io::Result<()> {
    for (path, identity) in [
        (&launch.control, launch.control_identity),
        (&launch.objects, launch.object_identity),
    ] {
        let root = NativeSourceRoot::open(&path.to_local().map_err(io::Error::other)?)?;
        if root.physical_identity()? != identity {
            return Err(invalid("Git registered root changed before release"));
        }
    }
    Ok(())
}
fn bootstrap(mut channel: UnixStream, launch: Launch) -> io::Result<()> {
    let expiry = launch.expiry;
    let own = ProcessPin::own(expiry)?;
    if own.image != launch.helper
        || launch.host.state(expiry.native_bound()?.deadline)? != State::Alive
    {
        return Err(invalid("Git bootstrap lost its qualified helper or host"));
    }
    let git = launch.git.to_local().map_err(io::Error::other)?;
    let control = launch.control.to_local().map_err(io::Error::other)?;
    let objects = launch.objects.to_local().map_err(io::Error::other)?;
    let pin = NativeExecutablePin::open(&git)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("qualified Git image disappeared"))?
        .prepare()
        .map_err(io::Error::other)?;
    let runtime = Runtime::discover(&git, expiry)?;
    if policy::build(&git, &control, &objects, &runtime)? != launch.policy {
        return Err(invalid(
            "Git runtime closure changed before its authorization barrier",
        ));
    }
    protocol::send(
        &mut channel,
        &Frame::Receipt {
            nonce: launch.nonce,
            process: own,
        },
        expiry,
    )?;
    match protocol::receive(&mut channel, expiry)? {
        Frame::Release { nonce } if nonce == launch.nonce => (),
        _ => return Err(invalid("Git release did not match its private receipt")),
    }
    roots(&launch)?;
    runtime.check()?;
    // Complete ancestry validation before installing a policy that deliberately
    // permits only metadata access to those directories. Retain the image pin
    // through exec; this remains a pre-exec check, not atomic descriptor exec.
    pin.validate().map_err(io::Error::other)?;
    policy::apply(&launch.policy)?;
    roots(&launch)?;
    expiry.remaining()?;
    let mut command = super::super::command::prepare(&git, &control, &objects, launch.arguments);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // The authorization descriptor must not survive a successful Git exec.
    drop(channel);
    Err(command.exec())
}
fn supervise(mut channel: UnixStream, mut launch: Launch) -> io::Result<()> {
    let mut child = None;
    let mut receipt = None;
    let result = create_tree(&mut channel, &mut launch, &mut child, &mut receipt);
    if let Err(error) = &result {
        let reaped = child.as_mut().is_none_or(|child| {
            let reaped = process::reap(&mut child.0).is_ok();
            child.1 = reaped;
            reaped
        });
        let frame = Frame::Refused {
            nonce: launch.nonce,
            reason: refusal_reason(error),
            child: receipt,
            reaped,
        };
        // A refusal carries the direct owner's reap result. If the original
        // deadline has elapsed, failure to send does not invent a receipt.
        let _ = protocol::send(&mut channel, &frame, launch.expiry);
    }
    result
}
fn create_tree(
    channel: &mut UnixStream,
    launch: &mut Launch,
    owned: &mut Option<Owned>,
    receipt: &mut Option<ProcessPin>,
) -> io::Result<()> {
    let expiry = launch.expiry;
    let own = ProcessPin::own(expiry)?;
    if own.image != launch.helper {
        return Err(invalid("Git supervisor differs from its qualified helper"));
    }
    let helper = launch.helper.to_local().map_err(io::Error::other)?;
    let invocation = NativeExecutablePin::open(&helper)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("Git bootstrap helper disappeared"))?
        .prepare()
        .map_err(io::Error::other)?;
    let (mut command, _creation) = invocation.command().map_err(io::Error::other)?;
    let (mut child_channel, bootstrap_channel) = UnixStream::pair()?;
    command
        .arg(BOOTSTRAP)
        .arg(expiry.argument())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    process::prepare(&mut command, &bootstrap_channel, own.pid)?;
    *owned = Some(Owned(command.spawn()?, false));
    drop(bootstrap_channel);
    let child = owned
        .as_mut()
        .ok_or_else(|| invalid("Git child owner is absent"))?;
    invocation.validate().map_err(io::Error::other)?;
    let observed = ProcessPin::child(child.0.id(), own.pid, expiry)?;
    *receipt = Some(observed.clone());
    launch.parent = own.clone();
    protocol::send(
        &mut child_channel,
        &Frame::Launch(Box::new(launch.clone())),
        expiry,
    )?;
    run_job(channel, &mut child_channel, launch, &own, &observed, child)
}
fn refusal_reason(error: &io::Error) -> String {
    let text = error.to_string();
    if text.chars().count() <= 1024 {
        text
    } else {
        format!(
            "{} [diagnostic exceeded 1024 characters]",
            text.chars().take(1024).collect::<String>()
        )
    }
}
fn run_job(
    channel: &mut UnixStream,
    child_channel: &mut UnixStream,
    launch: &Launch,
    own: &ProcessPin,
    observed: &ProcessPin,
    child: &mut Owned,
) -> io::Result<()> {
    let expiry = launch.expiry;
    let mut peak = 0;
    loop {
        peak = peak.max(process::before_release(own, observed, expiry)?);
        if process::ready(channel.as_raw_fd(), expiry)? {
            return Err(invalid("Git host closed before bootstrap receipt"));
        }
        if process::ready(child_channel.as_raw_fd(), expiry)? {
            break;
        }
    }
    match protocol::receive(child_channel, expiry)? {
        Frame::Receipt { nonce, process } if nonce == launch.nonce => observed.verify(&process)?,
        _ => {
            return Err(invalid(
                "Git bootstrap receipt differs from its native child",
            ));
        }
    }
    protocol::send(
        channel,
        &Frame::Tree {
            nonce: launch.nonce,
            supervisor: own.clone(),
            git: observed.clone(),
        },
        expiry,
    )?;
    loop {
        peak = peak.max(process::before_release(own, observed, expiry)?);
        if process::ready(channel.as_raw_fd(), expiry)? {
            break;
        }
    }
    match protocol::receive(channel, expiry)? {
        Frame::Release { nonce } if nonce == launch.nonce => (),
        _ => {
            return Err(invalid(
                "Git host did not release its published cleanup custody",
            ));
        }
    }
    peak = peak.max(process::before_release(own, observed, expiry)?);
    protocol::send(
        child_channel,
        &Frame::Release {
            nonce: launch.nonce,
        },
        expiry,
    )?;
    loop {
        if let Some(status) = child.0.try_wait()? {
            child.1 = true;
            use std::os::unix::process::ExitStatusExt;
            return protocol::send(
                channel,
                &Frame::Finished {
                    nonce: launch.nonce,
                    status: status.into_raw(),
                    peak_bytes: peak,
                },
                expiry,
            );
        }
        if let Some(bytes) = process::combined(own, observed, expiry)? {
            peak = peak.max(bytes);
        }
        if process::ready(channel.as_raw_fd(), expiry)? {
            return Err(invalid("Git host canceled its finite reader"));
        }
    }
}
