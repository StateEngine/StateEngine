//! Windows foreground observation for background scope interrupt and stream custody.
use super::*;
use std::process::{Command, Stdio};

#[test]
#[ignore = "child selected by the native scope judge"]
fn background_descendants() -> Check {
    let root = PathBuf::from(std::env::var_os("BINDING_SCOPE_HOME").ok_or("fixture home")?);
    let mut expected = String::new();
    std::io::stdin().read_to_string(&mut expected)?;
    assert_eq!(expected, "owned input marker");
    std::io::stdout().write_all(b"PROTOCOL-OUT:0\x00\xff\n")?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(b"PROTOCOL-ERR:0\x00\xfe\n")?;
    std::io::stderr().flush()?;
    for (program, argument, file, label) in [
        ("powershell.exe", "-File", "tool.ps1", "powershell"),
        ("python.exe", "-B", "tool.py", "python"),
    ] {
        let mut child = Command::new(program);
        if label == "powershell" {
            child.args(["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass"]);
        }
        let child = child.arg(argument).arg(root.join(file)).current_dir(&root)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        fs::write(root.join(format!("{label}.pid")),child.id().to_string())?;
    }
    let end = Instant::now() + Duration::from_secs(70);
    while !root.join("normal-exit").try_exists()? && Instant::now() < end {
        std::thread::park_timeout(Duration::from_millis(25));
    }
    Ok(())
}

fn start<'a>(runtime: &'a NativeProcessRuntime, home: &Home, machine: &MachineId,
             host: HostInstanceId, nonce: [u8;16], generation: GenerationId, until: Instant) -> Check<Scope<'a>> {
    let payload = PathBuf::from(std::env::var_os("BINDING_SCOPE_PAYLOAD").ok_or("payload path")?);
    for file in ["tool.ps1", "tool.py"] {
        fs::copy(payload.join(file), home.0.join(file))?;
    }
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let mut entries: Vec<_> = std::env::vars_os().filter(|(key,_)| {
        matches!(key.to_str(),Some("SYSTEMROOT" | "SystemRoot" | "WINDIR" | "PATH" | "PATHEXT" | "TEMP" | "TMP" | "COMSPEC" | "USERPROFILE" | "LOCALAPPDATA" | "APPDATA" | "ProgramFiles"))
    }).collect();
    entries.push(("BINDING_SCOPE_HOME".into(),home.0.as_os_str().to_owned()));
    let prepared = runtime.prepare_launch(LaunchReservation {
            format_version: 1, lifecycle: lifecycle.clone(), host,
            owner:current_process_identity(machine.clone()).map_err(error)?, generation,
            scope_nonce:nonce,parent:ReservationParent::Windows,created_at_unix_ns:1,
        }, LaunchSpec {
            executable_custody:None, lifecycle,generation,executable:std::env::current_exe()?,
            arguments:["--exact","windows_console_scope::background_descendants","--ignored","--nocapture"]
                .map(Into::into).into(),
            cwd:home.0.clone(),environment:Environment{entries},stdio:empty(),mode:LaunchMode::HeadlessConsole,
            window:None, policy:LaunchPolicy{containment:ContainmentRequirement::BestAvailable,
                writes:WritePolicy::Workspace{roots:vec![home.0.clone()],scratch:home.0.clone()},
                network:NetworkPolicy::Allow,hardening:OptionalHardening::Off},
            deadline:until,notifications:Arc::new(Notices),
        }).map_err(error)?;
    let scope = Scope{runtime,process:prepared.process,generation,released:false};
    runtime.bind_stdio(&prepared.prepared,home.endpoints("console")?).map_err(error)?;
    let ticket=match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending{ticket,..}=>ticket,
        LaunchStart::Failed(failure)=>return Err(format!("native launch failed: {:?}",failure.error).into()),
    };
    loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(_)=>break,
            LaunchProgress::AwaitingExecCommit(_)=>runtime.authorize_exec(&ticket).map_err(error)?,
            LaunchProgress::Failed(failure)=>return Err(format!("native exec failed: {:?}",failure.error).into()),
            _ if Instant::now()<until=>std::thread::park_timeout(Duration::from_millis(10)),
            _=>return Err("native launch did not finish".into()),
        }
    }
    Ok(scope)
}

fn ready(home: &Home, deadline: Instant) -> Check {
    while ["powershell.ready", "python.ready"].iter().any(|p| !home.0.join(p).is_file()) {
        if Instant::now()>=deadline {
            return Err(format!("tool readiness missing; console stdout={:?}; stderr={:?}",
                fs::read(home.0.join("output-console")),fs::read(home.0.join("error-console"))).into());
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
    let out=fs::read(home.0.join("output-console"))?;
    let err=fs::read(home.0.join("error-console"))?;
    assert!(out.windows(b"PROTOCOL-OUT:0\x00\xff\n".len()).any(|w| w==b"PROTOCOL-OUT:0\x00\xff\n"));
    assert!(err.windows(b"PROTOCOL-ERR:0\x00\xfe\n".len()).any(|w| w==b"PROTOCOL-ERR:0\x00\xfe\n"));
    println!("PowerShell PID {} and Python PID {} ready; redirected protocol bytes exact",
        fs::read_to_string(home.0.join("powershell.pid"))?,fs::read_to_string(home.0.join("python.pid"))?);
    Ok(())
}

#[test]
fn exact_windows_console_scope_interrupts_real_tools() -> Check {
    let machine=MachineId::new("windows-console-scope-review")?;
    let bytes:[u8;16]=random_secret()?.expose()[..16].try_into()?;
    let host=HostInstanceId(bytes);
    let generation=GenerationId::new(1)?;
    let runtime=NativeProcessRuntime::open(HostConfig{
        machine:machine.clone(),instance:host,
        helper_executable:PathBuf::from(std::env::var_os("BINDING_SCOPE_HELPER").ok_or("exact helper pin")?),
        linux_delegation:LinuxDelegation::CurrentScope,
        limits:ResourceLimits{max_lifecycles:2,max_diagnostic_members:8,max_observation_bytes:65536,max_stdio_buffer_bytes:4096},
    }).map_err(error)?;
    let target_home=Home::new()?;
    let guard_home=Home::new()?;
    let mut a=bytes; a[0]=1;
    let mut b=bytes; b[0]=2;
    let until=Instant::now()+Duration::from_secs(50);
    let mut target=start(&runtime,&target_home,&machine,host,a,generation,until)?;
    let mut guard=start(&runtime,&guard_home,&machine,host,b,generation,until)?;
    ready(&target_home,until)?;
    ready(&guard_home,until)?;
    let token=runtime.prepare_stop(&target.process,generation,until).map_err(error)?;
    let attempt=runtime.request_interrupt(token).map_err(error)?;
    assert_eq!(attempt.dispatch.map_err(error)?,StopDispatch::Requested);
    let witness=loop {
        match runtime.witness_stop(&attempt.ticket).map_err(error)? {
            StopObservation::Complete(witness)=>break witness,
            _ if Instant::now()<until=>std::thread::park_timeout(Duration::from_millis(15)),
            _=>return Err("native interrupt did not close the targeted scope".into()),
        }
    };
    assert_eq!(witness.scope_exit.remaining.population,Population::Empty);
    for label in ["powershell","python"] {
        assert_eq!(fs::read_to_string(target_home.0.join(format!("{label}.interrupt")))?,"0");
        assert!(!guard_home.0.join(format!("{label}.interrupt")).exists());
    }
    assert!(matches!(runtime.observe(&guard.process).map_err(error)?.root,ProcessObservation::Live(_)));
    runtime.release(&target.process,&witness).map_err(error)?;
    target.released=true;
    fs::write(guard_home.0.join("normal-exit"),b"exit")?;
    guard.release()?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    println!("CTRL_C_EVENT (0) received in both target descendants; foreign scope remained live; arena empty after releases");
    Ok(())
}
