//! Add and remove only the synthetic fixture's Everyone read ACE.
use base64::Engine as _;
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn public_read(path: &Path, enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = path
        .to_str()
        .ok_or("fixture key path is not UTF-8")?
        .replace('\'', "''");
    let action = if enabled {
        "AddAccessRule"
    } else {
        "RemoveAccessRuleAll"
    };
    let script = format!(
        "$ErrorActionPreference='Stop'; $p='{path}'; $a=Get-Acl -LiteralPath $p; $s=[Security.Principal.SecurityIdentifier]::new('S-1-1-0'); $r=[Security.AccessControl.FileSystemAccessRule]::new($s,'Read','Allow'); $a.{action}($r); Set-Acl -LiteralPath $p -AclObject $a"
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            let status = child.wait()?;
            return Err(
                format!("owned ACL command exceeded its bound and joined: {status}").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "native fixture ACL update refused: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
