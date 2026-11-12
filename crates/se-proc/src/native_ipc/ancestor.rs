//! Native provider ancestry for opt-in observation. No caller-selected PID,
//! pathname or environment marker can construct the returned peer proof.
use super::*;

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
    let mut chain: Vec<NativeIpcPeer> = Vec::new();
    for _ in 0..64 {
        bound
            .remaining()
            .map_err(|e| error("provider ancestry deadline", e))?;
        let current = observe(pid, peer.principal(), bound)?;
        if chain.is_empty() && !same_birth(&current, peer) {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "hook peer incarnation changed",
            ));
        }
        if let Some(child) = chain.last()
            && !predates(&current, child)
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "provider parent PID was reused",
            ));
        }
        let found = pid != peer.pid()
            && current
                .image()
                .to_local()
                .map_err(|e| error("decode provider image", std::io::Error::other(e)))?
                == expected
            && current.image_sha256() == expected_hash;
        chain.push(current);
        if found {
            // Reobserve every retained birth and edge; a stale parent PID is
            // not ancestry, even when it now names the configured image.
            for (index, original) in chain.iter().enumerate() {
                let again = observe(original.pid(), peer.principal(), bound)?;
                if !same_birth(&again, original)
                    || chain.get(index + 1).is_some_and(|ancestor| {
                        parent(original.pid()).map_or(true, |pid| pid != ancestor.pid())
                    })
                {
                    return Err(refuse(
                        IpcNativeErrorCode::PeerChanged,
                        "provider ancestry changed",
                    ));
                }
            }
            return chain.pop().ok_or_else(|| {
                refuse(IpcNativeErrorCode::PeerChanged, "provider ancestry absent")
            });
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
fn same_birth(left: &NativeIpcPeer, right: &NativeIpcPeer) -> bool {
    left.pid() == right.pid()
        && left.started() == right.started()
        && left.image() == right.image()
        && left.image_sha256() == right.image_sha256()
}
fn predates(parent: &NativeIpcPeer, child: &NativeIpcPeer) -> bool {
    use se_types::StartIdentity;
    match (parent.started(), child.started()) {
        (StartIdentity::Linux { start_ticks: a }, StartIdentity::Linux { start_ticks: b }) => {
            a <= b
        }
        (
            StartIdentity::Windows {
                creation_filetime: a,
            },
            StartIdentity::Windows {
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
        return Err(refuse(
            IpcNativeErrorCode::Unsupported,
            "native provider adoption on Linux or Windows",
        ));
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        if current.principal() != principal {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "provider owner differs",
            ));
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
        crate::windows_native::parents()
            .map_err(|e| error("read provider ancestry", e.source))?
            .get(&pid)
            .copied()
            .ok_or_else(|| refuse(IpcNativeErrorCode::PeerChanged, "provider ancestor absent"))
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
pub fn provider_is_live(provider: &NativeIpcPeer, bound: &IpcIoBound) -> IpcNativeResult<bool> {
    match observe(provider.pid(), provider.principal(), bound) {
        Ok(current) => {
            Ok(current.started() == provider.started() && current.image() == provider.image())
        }
        Err(error) if error.source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        #[cfg(windows)]
        Err(error) if error.source.raw_os_error() == Some(87) => Ok(false),
        Err(error) => Err(error),
    }
}
