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
    let mut chain: Vec<(u32, se_types::StartIdentity, Option<NativeIpcPeer>)> = Vec::new();
    for _ in 0..64 {
        bound
            .remaining()
            .map_err(|e| error("provider ancestry deadline", e))?;
        let (started, stored, matched) = observe_step(pid, peer, &expected, &expected_hash, bound)?;
        if chain.is_empty()
            && stored
                .as_ref()
                .map_or(&started != peer.started(), |s| !same_birth(s, peer))
        {
            return Err(changed("hook peer incarnation changed"));
        }
        if chain
            .last()
            .is_some_and(|(_, child, _)| !predates(&started, child))
        {
            return Err(changed("provider parent PID was reused"));
        }
        chain.push((pid, started, stored));
        if let Some(candidate) = matched {
            // Reobserve every retained birth and edge; a stale parent PID is
            // not ancestry, even when it now names the configured image.
            for (index, (orig_pid, orig_started, orig_peer)) in chain.iter().enumerate() {
                let birth_ok = match orig_peer {
                    _ if index + 1 == chain.len() => same_birth(
                        &observe(candidate.pid(), peer.principal(), bound)?,
                        &candidate,
                    ),
                    Some(orig) => same_birth(&observe(*orig_pid, peer.principal(), bound)?, orig),
                    None => &observe_birth(*orig_pid, peer.principal(), bound)? == orig_started,
                };
                let parent_ok = chain
                    .get(index + 1)
                    .is_none_or(|(a, _, _)| parent(*orig_pid).is_ok_and(|p| p == *a));
                if !birth_ok || !parent_ok {
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
type Step = (
    se_types::StartIdentity,
    Option<NativeIpcPeer>,
    Option<NativeIpcPeer>,
);
fn observe_step(
    pid: u32,
    hook_peer: &NativeIpcPeer,
    expected: &Path,
    expected_hash: &se_types::Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<Step> {
    #[cfg(windows)]
    {
        let (principal, started, path) = super::windows_peer::observe_birth(pid, true)?;
        if &principal != hook_peer.principal() {
            return Err(changed("provider owner differs"));
        }
        let matches_path = |p: &Path| crate::canonicalize_path(p).ok().as_deref() == Some(expected);
        let matched = (pid != hook_peer.pid() && path.as_deref().is_some_and(matches_path))
            .then(|| observe(pid, hook_peer.principal(), bound))
            .transpose()?
            .filter(|c| {
                c.started() == &started
                    && c.image()
                        .to_local()
                        .ok()
                        .as_deref()
                        .is_some_and(matches_path)
                    && c.image_sha256() == *expected_hash
            });
        Ok((started, None, matched))
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
        let started = current.started().clone();
        Ok(if found {
            (started, None, Some(current))
        } else {
            (started, Some(current), None)
        })
    }
}
fn observe_birth(
    pid: u32,
    principal: &IpcPrincipal,
    bound: &IpcIoBound,
) -> IpcNativeResult<se_types::StartIdentity> {
    bound
        .remaining()
        .map_err(|e| error("provider liveness deadline", e))?;
    #[cfg(windows)]
    {
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
    use se_types::StartIdentity as S;
    match (parent, child) {
        (S::Linux { start_ticks: a }, S::Linux { start_ticks: b }) => a <= b,
        (
            S::Windows {
                creation_filetime: a,
            },
            S::Windows {
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
