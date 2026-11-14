use crate::*;

/// Protects: key-selected configuration presence policies use real native observations at the independent hosted receiver.
pub fn client(args: &[std::ffi::OsString]) -> Check {
    let [_, _, home, project, agent, mode] = args else {
        return Err("owner client fixture arguments".into());
    };
    let home = std::path::Path::new(home);
    let mode = mode.to_str().ok_or("fixture mode encoding")?;
    let files = route::files::Files::open(home)?;
    let reader = present(SqliteFactory::open_reader(&StoreOptions {
        state_directory: home.into(),
        busy_timeout: Duration::from_secs(2),
    })?)?;
    let inventory = route::owner::inventory(&reader, &files)?;
    let owner = route::owner::from_inventory(&inventory)?;
    let observed = owner.native_observation();
    match mode {
        "pipe" => assert!(!observed.stdin_console() && !observed.stdout_console()),
        "terminal" => assert!(
            observed.stdin_console()
                && observed.stdout_console()
                && !observed.provider_marker_present()
                && !observed.session_present()
        ),
        "provider" => assert!(
            observed.stdin_console()
                && observed.stdout_console()
                && observed.provider_marker_present()
        ),
        "session" => assert!(
            observed.stdin_console() && observed.stdout_console() && observed.session_present()
        ),
        _ => return Err("unknown native presence fixture mode".into()),
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut files
            .0
            .readback(&home.join("endpoint.json"))?
            .ok_or("published endpoint absent")?,
        &mut bytes,
    )?;
    let endpoint = se_host::client::endpoint::decode_endpoint(&bytes)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut files
            .0
            .readback(&home.join("credential"))?
            .ok_or("machine credential absent")?,
        &mut bytes,
    )?;
    let credential = Secret::new(bytes)?;
    let selections = se_core::ops::CliSelections {
        project: Some(project.to_str().ok_or("project encoding")?.parse()?),
        ..Default::default()
    };
    let head = reader.info()?.head;
    let operation = se_core::ops::AnyOp::ConfigSet(se_core::ops::ConfigSet {
        key: format!(
            "agent.{}.can-create",
            agent.to_str().ok_or("agent encoding")?
        ),
        value: "true".into(),
        idempotency_key: key(&format!("presence-{mode}"))?,
    });
    {
        let name = operation.meta().name;
        let output = ipc::forward(
            &endpoint,
            se_host::client::lease::ClientCredential::Machine(copy_secret(&credential)?),
            operation,
            &selections,
            Some(observed),
            &options(),
        );
        if mode == "terminal" {
            assert_eq!(serde_json::to_value(output?)?["state"], "committed");
        } else {
            let error = output
                .err()
                .ok_or_else(|| format!("non-human native presence accepted {name}"))?;
            assert!(
                matches!(
                    error.body.detail(),
                    se_types::Detail::HumanTerminalRequired(_)
                ),
                "wrong {name} presence refusal: {error}"
            );
            assert_eq!(reader.info()?.head, head, "refused {name} wrote an event");
        }
    }
    println!(
        "PASS owner_presence_client {mode}: native console={}/{} provider={} session={}",
        observed.stdin_console(),
        observed.stdout_console(),
        observed.provider_marker_present(),
        observed.session_present()
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn clients(f: &Fixture) -> Check {
    let image = std::env::current_exe()?;
    let mut pipe = std::process::Command::new(&image);
    pipe.arg("--owner-client")
        .arg(&f.options.state_directory)
        .arg(f.project.as_str())
        .arg(f.a.as_str())
        .arg("pipe");
    for name in ["SE_SESSION", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"] {
        pipe.env_remove(name);
    }
    let output = pipe.output()?;
    assert!(
        output.status.success(),
        "native pipe client: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    for mode in ["provider", "session", "terminal"] {
        // A real OS pseudo-terminal supplies the native console facts. The
        // Python fixture only owns descriptor plumbing and its exact child;
        // it neither asserts nor serializes a passing presence observation.
        let output=std::process::Command::new("python3").arg("-c").arg(r#"
import os,pty,select,signal,subprocess,sys,time
image,home,project,agent,mode=sys.argv[1:]
env=os.environ.copy()
for key in ['SE_SESSION','CLAUDECODE','CODEX_THREAD_ID','CODEX_CI']: env.pop(key,None)
if mode=='provider': env['CLAUDECODE']='native-fixture-provider'
if mode=='session': env['SE_SESSION']='native-fixture-session'
master,slave=pty.openpty()
args=[image,'--owner-client',home,project,agent,mode]
child=subprocess.Popen(args,stdin=slave,stdout=slave,stderr=slave,env=env,start_new_session=True)
os.close(slave)
deadline=time.monotonic()+25
data=bytearray()
while time.monotonic()<deadline:
    if select.select([master],[],[],.1)[0]:
        try: part=os.read(master,4096)
        except OSError: break
        if not part: break
        data.extend(part)
        if len(data)>65536: raise RuntimeError('native child output exceeded fixture bound')
    if child.poll() is not None: break
else:
    if sys.platform=='darwin':
        actual=subprocess.check_output(['ps','-ww','-p',str(child.pid),'-o','command=']).decode().rstrip('\n')
        same=actual==' '.join(args)
    else:
        actual=open('/proc/'+str(child.pid)+'/cmdline','rb').read().split(b'\0')[:-1]
        same=actual==[os.fsencode(value) for value in args]
    if not same: raise RuntimeError('owned child identity changed; refusing signal')
    os.kill(child.pid,signal.SIGKILL)
    child.wait()
    raise RuntimeError('exact native presence child exceeded deadline')
os.close(master)
sys.stdout.buffer.write(data)
sys.exit(child.wait(timeout=3))
"#).arg(&image).arg(&f.options.state_directory).arg(f.project.as_str()).arg(f.a.as_str()).arg(mode).output()?;
        assert!(
            output.status.success(),
            "native PTY {mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    #[cfg(windows)]
    for mode in ["provider", "session", "terminal"] {
        fn literal(value: &str) -> String {
            format!("'{}'", value.replace('\'', "''"))
        }
        let image_literal = literal(image.to_str().ok_or("native executable encoding")?);
        let home = f
            .options
            .state_directory
            .to_str()
            .ok_or("native home encoding")?;
        let home_argument = literal(&format!("\"{home}\""));
        let marker = match mode {
            "provider" => "$env:CLAUDECODE='native-fixture-provider'",
            "session" => "$env:SE_SESSION='native-fixture-session'",
            _ => "",
        };
        let script = format!(
            r#"
$ErrorActionPreference='Stop'
{marker}
$image={image_literal}
$child=Start-Process -FilePath $image -ArgumentList @('--owner-client',{home_argument},'{project}','{agent}','{mode}') -PassThru -WindowStyle Normal
$birth=$child.StartTime.ToFileTimeUtc()
if(-not $child.WaitForExit(25000)) {{
  $observed=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
  $current=Get-Process -Id $child.Id
  if($observed.ExecutablePath -eq $image -and $observed.CommandLine.Contains('--owner-client') -and $current.StartTime.ToFileTimeUtc() -eq $birth) {{ Stop-Process -Id $child.Id; $child.WaitForExit() }}
  throw 'Exact native console fixture exceeded its deadline'
}}
$child.Refresh()
if($child.ExitCode -ne 0) {{ throw "Native console fixture failed: {mode}, exit $($child.ExitCode)" }}
Write-Output 'PASS owner_presence_client {mode}: real native Windows console and authenticated admission'
"#,
            project = f.project,
            agent = f.a
        );
        let mut command = std::process::Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        for name in ["SE_SESSION", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"] {
            command.env_remove(name);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "native Windows console {mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    let reader = database_check(
        f,
        "presence post-console reader open",
        SqliteFactory::open_reader(&f.options),
    )
    .and_then(present)?;
    let mut read = database_check(
        f,
        "presence post-console grant snapshot",
        reader.snapshot(f.scoped(Visibility::Owner)),
    )?;
    let grant = present(read.grant(
        Actor::Agent(f.a.clone()),
        GrantKey::AgentCanCreate(f.a.clone()),
    )?)?;
    assert_eq!(
        grant.revision.value.get(),
        1,
        "a refused native presence case changed the grant"
    );
    assert!(matches!(
        grant.current.body,
        EventBody::GrantRecorded { active: true, .. }
    ));
    read.close()?;
    Ok(())
}
