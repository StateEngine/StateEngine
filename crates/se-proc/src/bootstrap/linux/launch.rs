use super::*;

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(in crate::bootstrap) fn spawn(spec: &RuntimeLaunchSpec, frame: Frame) -> ProcResult<Created> {
    let bytes = serde_json::to_vec(&frame).map_err(|e| input("runtime frame", &e.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    let image =
        File::open(&spec.executable).map_err(|e| fail("pin installed runtime executable", e))?;
    if !image
        .metadata()
        .map_err(|e| fail("read installed runtime image", e))?
        .is_file()
    {
        return Err(input(
            "installed runtime executable",
            "regular native executable required",
        ));
    }
    let executable = CString::new(spec.executable.as_os_str().as_bytes())
        .map_err(|_| input("runtime image", "NUL in native path"))?;
    let marker =
        CString::new(ENTRY).map_err(|_| input("runtime entry", "invalid private marker"))?;
    let argv = [
        executable.as_ptr().cast_mut(),
        marker.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut environment = Vec::new();
    for (key, value) in &spec.environment.entries {
        let mut bytes = key.as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend(value.as_bytes());
        environment.push(
            CString::new(bytes).map_err(|_| input("runtime environment", "NUL in native entry"))?,
        );
    }
    let envp: Vec<_> = environment
        .iter()
        .map(|v| v.as_ptr().cast_mut())
        .chain(Some(ptr::null_mut()))
        .collect();
    let (plan_read, plan_write) = socket("create bootstrap plan pipe")?;
    let (diagnostic_reader, diagnostic_writer) = socket("create bootstrap plan pipe")?;
    let diagnostics = diagnostics::Capture::start(diagnostic_reader, spec.deadline)?;
    let (parent, child) = socket("create bootstrap control socket")?;
    let enable: i32 = 1;
    // SAFETY: retained receiving socket and exact native integer option value.
    if unsafe {
        libc::setsockopt(
            parent.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enable as *const i32).cast(),
            std::mem::size_of_val(&enable) as u32,
        )
    } < 0
    {
        return Err(fail(
            "enable kernel bootstrap credentials",
            io::Error::last_os_error(),
        ));
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| fail("open runtime null streams", e))?;
    let null = duplicate(&null)?;
    // SAFETY: actions is initialized by the immediately following POSIX call.
    let mut storage: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    // SAFETY: exact writable POSIX action-list storage.
    code(
        // SAFETY: writable native action storage is initialized exactly once.
        unsafe { libc::posix_spawn_file_actions_init(&mut storage) },
        "initialize bootstrap spawn actions",
    )?;
    let mut actions = Actions(storage);
    for (source, target) in [
        (plan_read.as_raw_fd(), 0),
        (null.as_raw_fd(), 1),
        (diagnostic_writer.as_raw_fd(), 2),
        (child.as_raw_fd(), 3),
    ] {
        // SAFETY: sources are retained >=10; targets are distinct reserved startup descriptors.
        code(
            // SAFETY: retained source descriptor is duplicated to a distinct reserved startup descriptor.
            unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions.0, source, target) },
            "set exact runtime descriptors",
        )?;
    }
    // SAFETY: close-from action runs only in the spawned executable, preserving 0..3 above.
    code(
        // SAFETY: initialized child action closes only descriptors above the reserved private set.
        unsafe { libc::posix_spawn_file_actions_addclosefrom_np(&mut actions.0, 4) },
        "close unrelated runtime descriptors",
    )?;
    let cgroup = crate::platform::runtime_cgroup()?;
    let authorization = parent
        .try_clone()
        .map_err(|e| fail("duplicate bootstrap authorization", e))?;
    let attributes = spawn_attributes()?;
    let mut pid = 0;
    // SAFETY: native argv/envp are terminated arrays of retained C strings;
    // initialized exact descriptor actions run outside the embedding host.
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    code(rc, "posix_spawn installed runtime bootstrap")?;
    // No fallible operation may discard this launched process. All remaining
    // writes and identity reads occur after common code owns this Child.
    Ok(Created {
        native: Child {
            launcher: Some(pid),
            pid: None,
            pin: None,
            image,
        },
        events: parent,
        authorization,
        detachment: RuntimeDetachment::SessionOnly {
            inherited_cgroup: cgroup,
        },
        plan: plan_write,
        encoded: bytes,
        error: None,
        diagnostics,
    })
}

pub(in crate::bootstrap) fn receive() -> ProcResult<(Frame, File, File, File, Instant)> {
    // SAFETY: exact reserved descriptors belong to this private early entry.
    let mut plan = unsafe { File::from_raw_fd(0) };
    // SAFETY: descriptor 3 is the explicit private duplex control descriptor.
    let events = unsafe { File::from_raw_fd(3) };
    let initial = Instant::now() + Duration::from_secs(300);
    let frame: Frame = serde_json::from_slice(&frame_read(&mut plan, initial)?)
        .map_err(|e| input("runtime envelope", &e.to_string()))?;
    let remaining = frame
        .deadline_ms
        .checked_sub(clock()?)
        .filter(|n| *n > 0 && *n <= 300000)
        .ok_or_else(|| input("runtime deadline", "expired or outside the startup bound"))?;
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let mut credentials: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as u32;
    // SAFETY: retained connected socket and correctly sized writable kernel credentials.
    if unsafe {
        libc::getsockopt(
            events.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(fail(
            "authenticate runtime creator",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: immutable current native user read.
    let user = unsafe { libc::geteuid() };
    if length as usize != std::mem::size_of_val(&credentials)
        || credentials.pid as u32 != frame.parent.pid.0
        || credentials.uid != user
    {
        return Err(input(
            "runtime creator",
            "inherited channel does not belong to the exact same-user parent",
        ));
    }
    if let ProcessRead::Present(parent) =
        crate::read_process(frame.parent.machine.clone(), frame.parent.pid)?
    {
        if parent.identity != frame.parent {
            return Err(changed(&frame.parent, Some(&parent.identity)));
        }
    } else {
        return Err(input(
            "runtime creator",
            "parent exited before bootstrap authentication",
        ));
    }
    // Only this executable's early single-threaded entry may fork the final
    // independent runtime. No embedding host/async-runtime thread forks here.
    let count = std::fs::read_dir("/proc/self/task")
        .map_err(|e| fail("inspect bootstrap thread count", e))?
        .try_fold(0usize, |n, entry| entry.map(|_| n + 1))
        .map_err(|e| fail("read bootstrap thread count", e))?;
    if count != 1 {
        return Err(input(
            "runtime private entry",
            "bootstrap must precede every runtime thread",
        ));
    }
    // SAFETY: private early executable is single threaded; setsid has no pointer inputs.
    if unsafe { libc::setsid() } < 0 {
        return Err(fail("detach runtime session", io::Error::last_os_error()));
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| fail("open detached null stream", e))?;
    // Keep the startup diagnostic socket private and CLOEXEC before replacing
    // public stderr. The early launcher and final runtime share no Rust threads.
    // SAFETY: duplicates only this authenticated private entry's stderr socket.
    let diagnostics = owned(unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 10) })?;
    // SAFETY: replacing this private process's startup stdin with its retained null device.
    if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
        return Err(fail("detach runtime stdin", io::Error::last_os_error()));
    }
    // SAFETY: replaces only the authenticated private child's public stderr;
    // its separate CLOEXEC diagnostic reference remains retained by the guard.
    if unsafe { libc::dup2(null.as_raw_fd(), 2) } < 0 {
        return Err(fail("detach runtime stderr", io::Error::last_os_error()));
    }
    // Do not drop the old File(0) after dup2: that would close the new descriptor.
    std::mem::forget(plan);
    // SAFETY: private single-threaded native bootstrap; launcher branch only
    // calls _exit. The final child owns this entire unshared Rust state.
    let fork = unsafe { libc::fork() };
    if fork < 0 {
        return Err(fail("fork final runtime", io::Error::last_os_error()));
    }
    if fork > 0 {
        // SAFETY: only the transient launcher exits; final child owns the channels.
        unsafe {
            libc::_exit(0);
        }
    }
    // SAFETY: changes only this private runtime's reserved control descriptor;
    // never let later agent execs inherit the parent-commit channel.
    if unsafe { libc::fcntl(events.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(fail(
            "close runtime channel inheritance",
            io::Error::last_os_error(),
        ));
    }
    let authorization = events
        .try_clone()
        .map_err(|e| fail("duplicate runtime control", e))?;
    Ok((frame, events, authorization, diagnostics, deadline))
}
