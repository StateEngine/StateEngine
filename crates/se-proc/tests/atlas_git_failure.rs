//! Real native helper boundaries; this test image stands in for the Git image.
#[cfg(target_os = "linux")]
mod linux {
    use se_proc::atlas_git::{GitRead, read};
    use std::{
        io::{self, Write},
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    type Check = Result<(), Box<dyn std::error::Error>>;
    fn probe(mode: &str) -> Check {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or("private helper home missing")?);
        // The production helper now has a read-only filesystem, including its
        // private control directory. Identity is observed through stderr.
        eprintln!("owned-pid={}", std::process::id());
        assert!(std::fs::write(home.join("child.pid"), b"forbidden").is_err());
        assert!(std::fs::read(home.with_extension("foreign-object")).is_err());
        assert_eq!(std::fs::read(home.join("allowed-object"))?, b"registered");
        assert!(
            std::fs::read(home.join("object-link")).is_err(),
            "linked foreign read escaped native confinement"
        );
        match mode.as_bytes().first().copied() {
            Some(b'1') => {
                io::stdout().write_all(&[b'x'; 65537])?;
                std::thread::sleep(Duration::from_secs(2));
            }
            Some(b'2') => std::thread::sleep(Duration::from_secs(2)),
            _ => {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: fixed resource selector and exact writable POD output.
                if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                // SAFETY: no output pointers; a successful owned descriptor is closed below.
                let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                let socket_error = io::Error::last_os_error().raw_os_error();
                if socket >= 0 {
                    // SAFETY: close only the descriptor returned by this probe.
                    unsafe { libc::close(socket) };
                }
                // SAFETY: null/zero clone3 arguments cannot create a child; EPERM proves the filter ran first.
                let clone =
                    unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0) };
                let clone_error = io::Error::last_os_error().raw_os_error();
                println!(
                    "{}",
                    serde_json::json!({"soft":limit.rlim_cur,"hard":limit.rlim_max,"socket":socket,"socket_error":socket_error,"clone":clone,"clone_error":clone_error})
                );
            }
        }
        Ok(())
    }
    fn invoke(
        root: &Path,
        mode: char,
        deadline: Instant,
    ) -> io::Result<se_proc::atlas_git::GitOutput> {
        let oid = mode.to_string().repeat(40);
        read(
            &std::env::current_exe()?,
            root,
            root,
            GitRead::RootTree { commit: &oid },
            deadline,
        )
    }
    fn gone(_: &Path) -> Check {
        // This harness has one thread and no other children. Zombies remain in
        // this native children file until wait, so empty proves exact reaping.
        let children =
            std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?;
        assert!(
            children.trim().is_empty(),
            "unreaped owned helper: {children}"
        );
        Ok(())
    }
    pub(super) fn run() -> Check {
        let args: Vec<_> = std::env::args().collect();
        if let Some(position) = args.iter().position(|a| a == "rev-parse") {
            return probe(args.get(position + 2).ok_or("helper object missing")?);
        }
        let root = std::env::temp_dir().join(format!("se-git-native-{}", std::process::id()));
        std::fs::create_dir(&root)?;
        let outside = root.with_extension("foreign-object");
        std::fs::write(&outside, b"foreign")?;
        std::fs::write(root.join("allowed-object"), b"registered")?;
        std::os::unix::fs::symlink(&outside, root.join("object-link"))?;
        let result: Check = (|| {
            let output = invoke(&root, '0', Instant::now() + Duration::from_secs(3))?;
            assert!(
                output.status.success(),
                "{}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let facts: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(facts["soft"], 64_000_000u64);
            assert_eq!(facts["hard"], 64_000_000u64);
            assert_eq!(facts["socket"], -1);
            assert_eq!(facts["socket_error"], libc::EPERM);
            assert_eq!(facts["clone"], -1);
            assert_eq!(facts["clone_error"], libc::EPERM);
            gone(&root)?;
            println!(
                "PASS Git helper has actual 64000000-byte limits and denies network/descendants"
            );
            let error = invoke(&root, '1', Instant::now() + Duration::from_secs(3))
                .err()
                .ok_or("output flood was accepted")?;
            assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
            gone(&root)?;
            println!("PASS bounded Git output overflow reaps its exact helper");
            let error = invoke(&root, '2', Instant::now() + Duration::from_millis(200))
                .err()
                .ok_or("deadline was ignored")?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            gone(&root)?;
            assert!(
                invoke(&root, '0', Instant::now() + Duration::from_secs(3))?
                    .status
                    .success()
            );
            gone(&root)?;
            println!("PASS Git timeout reaps the helper and releases its own phase allocation");
            println!("3 passed; 0 failed");
            Ok(())
        })();
        std::fs::remove_file(root.join("allowed-object"))?;
        std::fs::remove_file(root.join("object-link"))?;
        std::fs::remove_dir(&root)?;
        std::fs::remove_file(outside)?;
        result
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("atlas_git_failure: test");
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    linux::run()?;
    #[cfg(not(target_os = "linux"))]
    println!("native Git history containment is unsupported on this platform");
    Ok(())
}
