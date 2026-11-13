use super::*;
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("owned workspace path fixture {}: {error}", self.0.display());
        }
    }
}
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}

#[test]
fn verbatim_only_child_is_inside_plain_workspace_but_not_its_plain_alias()
-> Result<(), Box<dyn std::error::Error>> {
    let entropy: [u8; 16] = crate::random_secret()?.expose()[..16].try_into()?;
    let name: String = se_types::hex_lower(&entropy);
    let path = std::env::temp_dir().join(format!("se-workspace-path-{name}"));
    fs::create_dir(&path)?;
    let home = Home(fs::canonicalize(path)?);
    let plain = crate::canonicalize_path(&home.0)?;
    fs::create_dir(home.0.join("literal"))?;
    let cwd = home.0.join("literal.");
    fs::create_dir(&cwd)?;
    assert!(!plain.to_string_lossy().starts_with(r"\\?\"));
    assert!(
        crate::canonicalize_path(&cwd)?
            .to_string_lossy()
            .starts_with(r"\\?\")
    );
    let machine = MachineId::new("workspace-path-fixture")?;
    let owner = crate::current_process_identity(machine.clone())
        .map_err(|error| format!("native fixture identity: {error:?}"))?;
    let host = HostInstanceId(entropy);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, [1; 10])?;
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        host,
        owner: owner.clone(),
        generation,
        scope_nonce: entropy,
        parent: ReservationParent::Windows,
        created_at_unix_ns: 1,
    };
    let config = HostConfig {
        machine,
        instance: host,
        helper_executable: std::env::current_exe()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 1,
            max_diagnostic_members: 1,
            max_observation_bytes: 4096,
            max_stdio_buffer_bytes: 4096,
        },
    };
    let mut launch = LaunchSpec {
        executable_custody: None,
        lifecycle,
        generation,
        executable: std::env::current_exe()?,
        arguments: vec![],
        cwd,
        environment: Environment { entries: vec![] },
        stdio: StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        },
        mode: LaunchMode::Headless,
        window: None,
        policy: LaunchPolicy {
            containment: ContainmentRequirement::KernelScope,
            writes: WritePolicy::Workspace {
                roots: vec![plain.clone()],
                scratch: plain.clone(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: std::time::Instant::now() + Duration::from_secs(10),
        notifications: Arc::new(Notices),
    };
    spec(&reservation, &launch, &config, &owner)
        .map_err(|error| format!("verbatim child refused inside workspace: {error:?}"))?;
    launch.policy.writes = WritePolicy::Workspace {
        roots: vec![plain.join("literal")],
        scratch: plain,
    };
    let refusal = spec(&reservation, &launch, &config, &owner)
        .err()
        .ok_or("verbatim child was redirected inside its plain alias")?;
    assert_eq!(refusal.code, ProcErrorCode::CwdOutsideWorkspace);
    Ok(())
}
