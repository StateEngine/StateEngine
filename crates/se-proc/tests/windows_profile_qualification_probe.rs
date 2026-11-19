//! Native Windows exploration of private profile ACL and namespace custody.
#![cfg(windows)]
#[path = "../../test-support/directory.rs"]
mod directory;
use std::{path::Path, process::Command};
type Check = Result<(), Box<dyn std::error::Error>>;

fn make_private(path: &Path, grant_other: bool) -> Check {
    let script = r#"$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
if ($env:SE_TEST_GRANT_OTHER -eq '1') {
  $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($everyone, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
[IO.Directory]::CreateDirectory($env:SE_TEST_PROFILE_PATH, $acl) | Out-Null"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("SE_TEST_PROFILE_PATH", path)
        .env("SE_TEST_GRANT_OTHER", if grant_other { "1" } else { "0" })
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "fixture ACL setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
fn junction(link: &Path, target: &Path) -> Check {
    let output = Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "junction setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
#[test]
fn native_profile_acl_and_identity_are_pinned() -> Check {
    let root = directory::private_case_directory()?;
    let result: Check = (|| {
        let path = root.join("profile");
        make_private(&path, false)?;
        let guard = se_proc::NativeProfileFiles::open(&path)?;
        let original = guard.identity()?;
        assert_eq!(guard.identity()?, original);
        let moved = root.join("moved");
        assert!(
            std::fs::rename(&path, &moved).is_err(),
            "held profile was renamed"
        );
        drop(guard);
        std::fs::rename(&path, &moved)?;
        make_private(&path, false)?;
        assert_ne!(
            se_proc::NativeProfileFiles::open(&path)?.identity()?,
            original
        );
        let loose = root.join("loose");
        make_private(&loose, true)?;
        assert!(
            se_proc::NativeProfileFiles::open(&loose).is_err(),
            "foreign ACL was admitted"
        );
        let target = root.join("target");
        make_private(&target, false)?;
        let target_profile = target.join("profile");
        make_private(&target_profile, false)?;
        let link = root.join("junction");
        junction(&link, &target)?;
        let through = link.join("profile");
        assert!(
            se_proc::NativeProfileFiles::open(&through).is_err(),
            "user-controlled junction was admitted"
        );
        std::fs::remove_dir(&link)?;
        let guard = se_proc::NativeProfileFiles::open(&target_profile)?;
        let held = guard.identity()?;
        assert!(
            std::fs::rename(&target, root.join("target-moved")).is_err(),
            "profile ancestor was renamed"
        );
        assert_eq!(guard.identity()?, held);
        drop(guard);
        junction(&link, &target_profile)?;
        assert!(
            se_proc::NativeProfileFiles::open(&link).is_err(),
            "profile reparse root was admitted"
        );
        std::fs::remove_dir(&link)?;
        Ok(())
    })();
    root.finish(result)
}
