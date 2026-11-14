//! Exact native custody survives exec; an absent or reused PID never grants signal authority.
use super::{clock::Expiry, invalid};
use crate::native_ipc::{IpcPeerSide, IpcPrincipal, NativeIpcPeer};
use se_types::{BootId, NativePath, Sha256, StartIdentity};
use std::{io, os::fd::BorrowedFd, time::Instant};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessPin {
    pub pid: u32,
    pub boot: BootId,
    pub uid: u32,
    pub birth: StartIdentity,
    pub image: NativePath,
    pub digest: Sha256,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum State {
    Alive,
    Exited,
    Absent,
}

impl ProcessPin {
    fn from_peer(peer: NativeIpcPeer) -> io::Result<Self> {
        let uid = match peer.principal() {
            IpcPrincipal::Unix { uid } => *uid,
            _ => return Err(invalid("native Unix Git peer required")),
        };
        Ok(Self {
            pid: peer.pid(),
            boot: crate::observe_boot_id().map_err(io::Error::other)?,
            uid,
            birth: peer.started().clone(),
            image: peer.image().clone(),
            digest: peer.image_sha256(),
        })
    }
    pub(super) fn child(pid: u32, parent: u32, expiry: Expiry) -> io::Result<Self> {
        Self::from_peer(
            crate::native_ipc::observe_direct_child(pid, parent, &expiry.native_bound()?)
                .map_err(io::Error::other)?,
        )
    }
    pub(super) fn own(expiry: Expiry) -> io::Result<Self> {
        Self::from_peer(
            crate::native_ipc::observe_ipc_self_bounded(&expiry.native_bound()?)
                .map_err(io::Error::other)?,
        )
    }
    pub(super) fn peer(
        channel: BorrowedFd<'_>,
        side: IpcPeerSide,
        expiry: Expiry,
    ) -> io::Result<Self> {
        Self::from_peer(
            crate::native_ipc::observe_ipc_peer_bounded(channel, side, &expiry.native_bound()?)
                .map_err(io::Error::other)?,
        )
    }
    pub(super) fn verify(&self, other: &Self) -> io::Result<()> {
        if self.pid != other.pid
            || self.boot != other.boot
            || self.uid != other.uid
            || self.birth != other.birth
            || self.image != other.image
            || self.digest != other.digest
        {
            return Err(invalid(
                "Git native peer differs from the retained instance",
            ));
        }
        Ok(())
    }
    pub(super) fn state(&self, deadline: Instant) -> io::Result<State> {
        if self.pid == 0 || self.pid > i32::MAX as u32 {
            return Err(invalid("positive native Git instance PID required"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Git instance observation deadline elapsed",
            ));
        }
        if self.boot != crate::observe_boot_id().map_err(io::Error::other)? {
            return Ok(State::Absent);
        }
        let native = crate::macos_process::info(crate::ProcessId(self.pid), deadline)
            .map_err(io::Error::other)?;
        let Some(native) = native else {
            return Ok(State::Absent);
        };
        let birth = StartIdentity::Macos {
            start_seconds: native.pbi_start_tvsec,
            start_micros: u32::try_from(native.pbi_start_tvusec)
                .map_err(|_| invalid("Git native birth overflow"))?,
        };
        if birth != self.birth {
            return Ok(State::Absent);
        }
        if native.pbi_uid != self.uid {
            return Err(invalid("Git instance credentials changed"));
        }
        match native.pbi_status {
            libc::SZOMB => Ok(State::Exited),
            libc::SIDL | libc::SRUN | libc::SSLEEP | libc::SSTOP => Ok(State::Alive),
            _ => Err(invalid("Git native process state is unreadable")),
        }
    }
    pub(super) fn terminate(&self, deadline: Instant) -> io::Result<()> {
        if self.state(deadline)? != State::Alive {
            return Ok(());
        }
        // SAFETY: exact UID, boot and native birth were reobserved for this owned instance.
        // Darwin retains a non-atomic check/signal interval; this is not pidfd signalling.
        if unsafe { libc::kill(self.pid as i32, libc::SIGKILL) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) || self.state(deadline)? == State::Alive {
                return Err(error);
            }
        }
        Ok(())
    }
}
