//! Reviewer-owned native process consumer; built separately from the library.
use std::{
    ffi::CString,
    io,
    os::unix::fs::DirBuilderExt,
    path::Path,
    time::{Duration, Instant},
};

unsafe extern "C" {
    fn review_configure(root: *const libc::c_char, fault: libc::c_int);
}

fn save(path: &Path, value: &serde_json::Value) -> io::Result<()> {
    let temporary = path.with_extension("pending");
    std::fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temporary, path)
}

fn invoke(
    helper: &Path,
    probe: &Path,
    control: &Path,
    objects: &Path,
    mode: char,
    millis: u64,
) -> serde_json::Value {
    let oid = mode.to_string().repeat(40);
    let started = Instant::now();
    let result = se_proc::atlas_git::read_with_helper(
        helper,
        probe,
        control,
        objects,
        se_proc::atlas_git::GitRead::RootTree { commit: &oid },
        Instant::now() + Duration::from_millis(millis),
    );
    use std::os::unix::process::ExitStatusExt;
    let mut value = match result {
        Ok(output) => serde_json::json!({"ok":true,"success":output.status.success(),
            "code":output.status.code(),"signal":output.status.signal(),
            "stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr)}),
        Err(error) => {
            serde_json::json!({"ok":false,"kind":format!("{:?}",error.kind()),"reason":error.to_string()})
        }
    };
    let mut status = 0;
    // SAFETY: this fixture owns its children; a returned child is a failed reap gate.
    let waited = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    let cause = io::Error::last_os_error().raw_os_error();
    value["child_wait"] = serde_json::json!({"result":waited,"errno":cause});
    value["seconds"] = started.elapsed().as_secs_f64().into();
    value
}

fn set_limits(config: &serde_json::Value) -> io::Result<()> {
    for (name, resource) in [("cpu", libc::RLIMIT_CPU), ("fds", libc::RLIMIT_NOFILE)] {
        if let Some(value) = config[name].as_u64() {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: reduce only this disposable host's limits before child creation.
            if unsafe { libc::setrlimit(resource, &limit) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let executable = std::env::current_exe()?.canonicalize()?;
    let root = executable
        .parent()
        .ok_or("fixture executable has no parent")?;
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("config.json"))?)?;
    let role = args.get(1).and_then(|s| s.to_str()).unwrap_or("");
    let fault = match (config["fault"].as_str(), role) {
        (Some("first-unreadable"), "--private-atlas-git-supervisor") => 1,
        (Some("first-over-budget"), "--private-atlas-git-supervisor") => 2,
        (Some("kill-denied"), "host" | "--private-atlas-git-supervisor") => 3,
        _ => 0,
    };
    let native_root = CString::new(root.as_os_str().as_encoded_bytes())?;
    // SAFETY: terminated fixture path, copied by the linked native observer shim.
    unsafe {
        review_configure(native_root.as_ptr(), fault);
    }
    if role == "--private-atlas-git-bootstrap" && config["pause_bootstrap"] == true {
        // SAFETY: an explicit native test pause, equivalent to an outside SIGSTOP.
        // The controller resumes this exact birth before testing EOF/deadline handling.
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
    }
    if let Some(result) = se_proc::atlas_git::private_entry(&args) {
        return result.map_err(Into::into);
    }
    if role == "reconcile" {
        let result = se_proc::atlas_git::reconcile_pending(root);
        let value = match result {
            Ok(()) => serde_json::json!({"ok":true}),
            Err(e) => serde_json::json!({"ok":false,"reason":e.to_string()}),
        };
        save(&root.join("reconcile.json"), &value)?;
        return Ok(());
    }
    if role != "host" {
        return Err("expected a closed reviewer role".into());
    }
    set_limits(&config)?;
    let control = root.join(".se-atlas-git-review");
    se_proc::NativeStateFiles::create(&control).map_err(io::Error::other)?;
    for name in ["objects", "refs"] {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(control.join(name))?;
    }
    std::fs::write(control.join("HEAD"), b"ref: refs/heads/atlas-read-only\n")?;
    std::fs::write(
        control.join("config"),
        b"[core]\nrepositoryformatversion = 0\nbare = true\n",
    )?;
    let objects = root.join("object-root");
    std::fs::DirBuilder::new().mode(0o700).create(&objects)?;
    let probe = Path::new(args.get(2).ok_or("native probe missing")?);
    let clean_helper = Path::new(args.get(3).ok_or("clean helper missing")?);
    let clean_probe = Path::new(args.get(4).ok_or("clean probe missing")?);
    let mode = config["mode"]
        .as_str()
        .and_then(|s| s.chars().next())
        .ok_or("probe mode missing")?;
    let millis = config["deadline_ms"].as_u64().ok_or("deadline missing")?;
    let first = invoke(&executable, probe, &control, &objects, mode, millis);
    let second = invoke(clean_helper, clean_probe, &control, &objects, '0', 5000);
    save(
        &root.join("host-result.json"),
        &serde_json::json!({"first":first,"second":second}),
    )?;
    if config["linger"] == true {
        let end = Instant::now() + Duration::from_secs(10);
        while !root.join("release-host").exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}
