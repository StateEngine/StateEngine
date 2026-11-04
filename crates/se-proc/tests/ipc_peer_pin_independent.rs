#[cfg(target_os = "linux")]
mod linux {
    use se_proc::native_ipc::{IpcPeerSide, observe_ipc_peer};
    use std::{
        collections::BTreeSet,
        error::Error,
        fs,
        io::{Read, Write},
        os::{
            fd::AsFd,
            unix::{
                fs::PermissionsExt,
                net::{UnixListener, UnixStream},
            },
        },
        process::{Command, Stdio},
        time::Duration,
    };
    type Check = Result<(), Box<dyn Error>>;
    fn pidfds() -> Result<BTreeSet<u32>, Box<dyn Error>> {
        let mut pins = BTreeSet::new();
        for item in fs::read_dir("/proc/self/fd")? {
            let item = item?;
            let target = match fs::read_link(item.path()) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if target == std::path::Path::new("anon_inode:[pidfd]") {
                pins.insert(item.file_name().to_string_lossy().parse()?);
            }
        }
        Ok(pins)
    }
    fn one_new_pin(before: &BTreeSet<u32>, pid: u32) -> Result<u32, Box<dyn Error>> {
        let after = pidfds()?;
        let added: Vec<_> = after.difference(before).copied().collect();
        if added.len() != 1 {
            return Err(format!("expected one real socket-origin pidfd, found {added:?}").into());
        }
        let fd = added[0];
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
        if !info
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["Pid:", &pid.to_string()])
        {
            return Err(format!("pidfd does not pin actual peer {pid}: {info}").into());
        }
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .ok_or("pidfd flags absent")?;
        if u32::from_str_radix(flags.trim(), 8)? & 0o2000000 == 0 {
            return Err("pidfd is not close-on-exec".into());
        }
        Ok(fd)
    }
    /// Protects: G6 — the client-side proof retains the actual server's kernel process object.
    #[test]
    #[ignore = "cross-process helper invoked only by socket_peer_pin_survives_peer_exit_and_closes_on_drop"]
    fn pin_client() -> Check {
        let path = std::env::var_os("SE_REVIEW_PIN_SOCKET").ok_or("owned socket absent")?;
        let pid: u32 = std::env::var("SE_REVIEW_PIN_SERVER")?.parse()?;
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let before = pidfds()?;
        let peer = observe_ipc_peer(stream.as_fd(), IpcPeerSide::Server)?;
        if peer.pid() != pid {
            return Err("connection did not prove its actual parent server".into());
        }
        one_new_pin(&before, pid)?;
        stream.write_all(b"P")?;
        stream.read_exact(&mut [0])?;
        drop(peer);
        if pidfds()? != before {
            return Err("client proof drop leaked its pidfd".into());
        }
        Ok(())
    }
    /// Protects: G6 — both native peer proofs hold real close-on-exec pidfds until their own drop.
    #[test]
    #[ignore = "requires native Linux SO_PEERPIDFD (6.5+); run explicitly, older-kernel fallback is a separate bound"]
    fn socket_peer_pin_survives_peer_exit_and_closes_on_drop() -> Check {
        let root = std::env::temp_dir().join(format!("5d-ipc-pin-{}", std::process::id()));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let path = root.join("socket");
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", "linux::pin_client", "--ignored", "--nocapture"])
            .env("SE_REVIEW_PIN_SOCKET", &path)
            .env("SE_REVIEW_PIN_SERVER", std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let child_pid = child.id();
        let result = (|| -> Result<_, Box<dyn Error>> {
            let began = std::time::Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && began.elapsed() < Duration::from_secs(15) =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(15)))?;
            stream.read_exact(&mut [0])?;
            let before = pidfds()?;
            let peer = observe_ipc_peer(stream.as_fd(), IpcPeerSide::Client)?;
            if peer.pid() != child_pid {
                return Err("server proof changed the real client PID".into());
            }
            let fd = one_new_pin(&before, child_pid)?;
            stream.write_all(b"X")?;
            Ok((peer, before, fd))
        })();
        let output = child.wait_with_output()?;
        drop(listener);
        fs::remove_file(path)?;
        fs::remove_dir(root)?;
        let (peer, before, fd) = result.map_err(|error| {
            format!(
                "{error}; native helper stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "native helper failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
        if !info
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["Pid:", "-1"])
        {
            return Err("retained peer pin did not observe exact child exit".into());
        }
        drop(peer);
        if pidfds()? != before {
            return Err("server proof drop leaked its pidfd".into());
        }
        Ok(())
    }
}

#[cfg(windows)]
/// Protects: G6 — native Windows peer observation retains and releases the verified process handle.
#[test]
fn windows_peer_proof_owns_exactly_one_process_handle_until_drop()
-> Result<(), Box<dyn std::error::Error>> {
    use se_proc::native_ipc::observe_ipc_self;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    fn handles() -> std::io::Result<u32> {
        let mut count = 0;
        // SAFETY: current-process pseudo handle and writable native count; observation only.
        if unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(count)
    }
    drop(observe_ipc_self()?); // Warm the actual image cache before counting retained proof handles.
    let before = handles()?;
    let mut peers = Vec::new();
    for _ in 0..3 {
        peers.push(observe_ipc_self()?);
    }
    assert_eq!(
        handles()?,
        before + 3,
        "each live proof must retain its opened native process object"
    );
    for peer in &peers {
        assert_eq!(peer.pid(), std::process::id());
    }
    drop(peers);
    assert_eq!(
        handles()?,
        before,
        "dropping proofs must close every retained handle"
    );
    Ok(())
}
