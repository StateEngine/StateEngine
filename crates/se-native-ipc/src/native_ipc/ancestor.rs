//! Native provider ancestry for opt-in observation. No caller-selected PID,
//! pathname or environment marker can construct the returned peer proof.
use super::*;

fn changed(detail: &'static str) -> IpcNativeError {
    refuse(IpcNativeErrorCode::PeerChanged, detail)
}

pub fn provider_ancestor(
    peer: &NativeIpcPeer,
    image: &Path,
    bound: &IpcIoBound,
) -> IpcNativeResult<NativeIpcPeer> {
    let expected =
        crate::canonicalize_path(image).map_err(|e| error("resolve provider image", e))?;
    let expected_hash = hash_image(
        std::fs::File::open(&expected).map_err(|e| error("pin provider image", e))?,
        bound,
    )?;
    let mut pid = peer.pid();
    let mut chain: Vec<(u32, se_types::StartIdentity)> = Vec::new();
    for _ in 0..64 {
        bound
            .remaining()
            .map_err(|e| error("provider ancestry deadline", e))?;
        let (started, matched) = observe_step(pid, peer, &expected, &expected_hash, bound)?;
        if chain.is_empty() && &started != peer.started() {
            return Err(changed("hook peer incarnation changed"));
        }
        if let Some((_, child)) = chain.last()
            && !predates(&started, child)
        {
            return Err(changed("provider parent PID was reused"));
        }
        chain.push((pid, started));
        if let Some(candidate) = matched {
            // Reobserve every retained birth and edge; a stale parent PID is
            // not ancestry, even when it now names the configured image.
            for (index, (orig_pid, orig_started)) in chain.iter().enumerate() {
                let birth_ok = if index + 1 == chain.len() {
                    same_birth(
                        &observe(candidate.pid(), peer.principal(), bound)?,
                        &candidate,
                    )
                } else {
                    &observe_birth(*orig_pid, peer.principal(), bound)? == orig_started
                };
                if !birth_ok
                    || chain.get(index + 1).is_some_and(|(ancestor, _)| {
                        parent(*orig_pid).map_or(true, |p| p != *ancestor)
                    })
                {
                    return Err(changed("provider ancestry changed"));
                }
            }
            return Ok(candidate);
        }
        pid = parent(pid)?;
        if pid == 0 {
            break;
        }
    }
    Err(refuse(
        IpcNativeErrorCode::UnsafeEndpoint,
        "no same-owner configured native provider ancestor",
    ))
}
fn observe_step(
    pid: u32,
    hook_peer: &NativeIpcPeer,
    expected: &Path,
    expected_hash: &se_types::Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<(se_types::StartIdentity, Option<NativeIpcPeer>)> {
    #[cfg(windows)]
    {
        let (principal, started, path) = super::windows_peer::observe_birth(pid, true)?;
        if &principal != hook_peer.principal() {
            return Err(changed("provider owner differs"));
        }
        let path_matches = pid != hook_peer.pid()
            && path
                .as_deref()
                .and_then(|p| crate::canonicalize_path(p).ok())
                .as_deref()
                == Some(expected);
        let matched = path_matches
            .then(|| observe(pid, hook_peer.principal(), bound))
            .transpose()?
            .filter(|c| c.started() == &started && c.image_sha256() == *expected_hash);
        Ok((started, matched))
    }
    #[cfg(not(windows))]
    {
        let current = observe(pid, hook_peer.principal(), bound)?;
        let found = pid != hook_peer.pid()
            && current
                .image()
                .to_local()
                .map_err(|e| error("decode provider image", std::io::Error::other(e)))?
                == expected
            && current.image_sha256() == *expected_hash;
        Ok((current.started().clone(), found.then_some(current)))
    }
}
fn observe_birth(
    pid: u32,
    principal: &IpcPrincipal,
    bound: &IpcIoBound,
) -> IpcNativeResult<se_types::StartIdentity> {
    #[cfg(windows)]
    {
        let _ = bound;
        let (owner, started, _) = super::windows_peer::observe_birth(pid, false)?;
        (&owner == principal)
            .then_some(started)
            .ok_or_else(|| changed("provider owner differs"))
    }
    #[cfg(not(windows))]
    Ok(observe(pid, principal, bound)?.started().clone())
}

fn same_birth(left: &NativeIpcPeer, right: &NativeIpcPeer) -> bool {
    left.pid() == right.pid()
        && left.started() == right.started()
        && left.image() == right.image()
        && left.image_sha256() == right.image_sha256()
}
fn predates(parent: &se_types::StartIdentity, child: &se_types::StartIdentity) -> bool {
    use se_types::StartIdentity::{Linux, Windows};
    match (parent, child) {
        (Linux { start_ticks: a }, Linux { start_ticks: b }) => a <= b,
        (
            Windows {
                creation_filetime: a,
            },
            Windows {
                creation_filetime: b,
            },
        ) => a <= b,
        _ => false,
    }
}
fn observe(
    pid: u32,
    principal: &IpcPrincipal,
    bound: &IpcIoBound,
) -> IpcNativeResult<NativeIpcPeer> {
    #[cfg(target_os = "linux")]
    let current = match principal {
        IpcPrincipal::Unix { uid } => super::linux::observe(pid, *uid, bound)?,
        _ => {
            return Err(refuse(
                IpcNativeErrorCode::Unsupported,
                "native owner kind differs",
            ));
        }
    };
    #[cfg(windows)]
    let current = super::windows_peer::observe(pid, bound)?;
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (pid, principal, bound);
        Err(refuse(
            IpcNativeErrorCode::Unsupported,
            "native provider adoption on Linux or Windows",
        ))
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        if current.principal() != principal {
            return Err(changed("provider owner differs"));
        }
        Ok(current)
    }
}
fn parent(pid: u32) -> IpcNativeResult<u32> {
    #[cfg(target_os = "linux")]
    {
        let bytes = std::fs::read(format!("/proc/{pid}/stat"))
            .map_err(|e| error("read provider ancestry", e))?;
        crate::linux_native::ProcStat::parse(&bytes)
            .and_then(|stat| stat.parent())
            .map_err(|_| refuse(IpcNativeErrorCode::Unreadable, "malformed native ancestry"))
    }
    #[cfg(windows)]
    {
        crate::windows_process::parents()
            .map_err(|e| error("read provider ancestry", e.source))?
            .get(&pid)
            .copied()
            .ok_or_else(|| changed("provider ancestor absent"))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Err(refuse(
            IpcNativeErrorCode::Unsupported,
            "native provider adoption on Linux or Windows",
        ))
    }
}

/// Liveness of the exact retained provider birth, without granting ownership.
/// The image is not compared: an in-place update or rename of the executable
/// changes the path a running provider reports without ending it.
pub fn provider_is_live(provider: &NativeIpcPeer, bound: &IpcIoBound) -> IpcNativeResult<bool> {
    match observe_birth(provider.pid(), provider.principal(), bound) {
        Ok(started) => Ok(&started == provider.started()),
        Err(error) if error.source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        #[cfg(windows)]
        Err(error)
            if error.code == IpcNativeErrorCode::PeerChanged
                || error.source.raw_os_error() == Some(87) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
