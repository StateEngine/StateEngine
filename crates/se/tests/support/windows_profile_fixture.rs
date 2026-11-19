//! Disposable provider for the Windows profile qualification probe.
use std::{
    env, fs,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn value<'a>(args: &'a [String], key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing argument")?;
    Ok(args.get(index + 1).ok_or("missing argument value")?)
}
fn make_private(path: &Path) -> Check {
    let script = r#"$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[IO.Directory]::CreateDirectory($env:SE_TEST_PROFILE_PATH, $acl) | Out-Null"#;
    let result = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("SE_TEST_PROFILE_PATH", path)
        .output()?;
    if !result.status.success() {
        return Err("fixture profile ACL creation failed".into());
    }
    Ok(())
}
fn run() -> Check {
    let args: Vec<String> = env::args().skip(1).collect();
    let image = env::current_exe()?;
    let directory = image.parent().ok_or("fixture image parent absent")?;
    match args.first().map(String::as_str) {
        Some("--version") => println!("secode fixture"),
        Some("--external-host-capabilities") => print!(
            "{}",
            fs::read_to_string(directory.join("capabilities.json"))?
        ),
        Some("init-profile") => {
            let profile = Path::new(value(&args, "--service")?);
            make_private(profile)?;
            fs::write(
                directory.join("bootstrap-pid"),
                std::process::id().to_string(),
            )?;
            let until = Instant::now() + Duration::from_secs(60);
            while !directory.join("bootstrap-release").exists() {
                if Instant::now() >= until {
                    return Err("bootstrap witness timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Some("serve-service") => {
            let profile = Path::new(value(&args, "--service")?);
            let config = env::var_os("SECODE_CONFIG").ok_or("policy path absent")?;
            if !Path::new(&config).is_file() {
                return Err("protected policy absent".into());
            }
            let denied = fs::rename(profile, profile.with_extension("moved")).is_err();
            fs::write(
                directory.join("rename-denied"),
                if denied { b"yes" } else { b"no" },
            )?;
            fs::write(directory.join("service-attempted"), b"yes")?;
            let until = Instant::now() + Duration::from_secs(60);
            while !directory.join("service-release").exists() {
                if Instant::now() >= until {
                    return Err("service witness timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            std::process::exit(81);
        }
        _ => return Err("unsupported fixture command".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("fixture failed: {error}");
        std::process::exit(1);
    }
}
