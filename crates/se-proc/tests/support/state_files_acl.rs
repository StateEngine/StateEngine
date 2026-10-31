use super::*;

pub(super) fn acl(path: &Path, action: &str) -> Check {
    use std::process::Command;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = fs::canonicalize(path)?;
    let script = std::env::temp_dir().join(format!(
        "otto-acl-{}-{nonce}-{}.ps1",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut script_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&script)?;
    script_file.write_all(br#"param([string]$Path,[string]$Action)
$ErrorActionPreference='Stop'
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($Action -eq 'protect') {
  $directory=Test-Path -LiteralPath $Path -PathType Container
  if ($directory) { $acl=New-Object System.Security.AccessControl.DirectorySecurity } else { $acl=New-Object System.Security.AccessControl.FileSecurity }
  $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false)
  foreach ($value in @($sid.Value,'S-1-5-18')) {
    $who=New-Object System.Security.Principal.SecurityIdentifier($value)
    if ($directory) { $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow') } else { $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($who,'FullControl','Allow') }
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
} elseif ($Action -eq 'loosen') {
  & icacls.exe $Path '/grant' '*S-1-1-0:R' '/q'
  if ($LASTEXITCODE -ne 0) { throw "DACL-only icacls failed: $LASTEXITCODE" }
} elseif ($Action -eq 'unprotect') {
  & icacls.exe $Path '/inheritance:e' '/q'
  if ($LASTEXITCODE -ne 0) { throw 'DACL inheritance edit failed' }
} elseif ($Action -eq 'owner-self' -or $Action -eq 'foreign-owner') {
  if ($Action -eq 'owner-self') { $owner='*'+$sid.Value } else { $owner='*S-1-5-18' }
  & icacls.exe $Path '/setowner' $owner '/q'
  if ($LASTEXITCODE -ne 0) { throw "owner fixture not reached: $LASTEXITCODE" }
} elseif ($Action -eq 'observe-foreign-owner') {
  $acl=Get-Acl -LiteralPath $Path
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18') { throw 'foreign owner fixture not reached' }
} elseif ($Action -eq 'foreign-parent') {
  & icacls.exe $Path '/grant' '*S-1-1-0:(OI)(CI)R' '/q'
  if ($LASTEXITCODE -ne 0) { throw 'foreign inherited fixture not reached' }
} elseif ($Action -eq 'observe-inherited') {
  $acl=Get-Acl -LiteralPath $Path
  $parent=Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($Path))
  if (!$parent.AreAccessRulesProtected) { throw 'parent is not protected' }
  if (@($acl.Access | Where-Object IsInherited).Count -eq 0) { throw 'inherited fixture not reached' }
  foreach ($rule in $acl.Access) {
    $who=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($who -notin @($sid.Value,'S-1-5-18')) { throw 'unexpected inherited principal' }
  }
} elseif ($Action -eq 'observe-foreign-inherited') {
  $acl=Get-Acl -LiteralPath $Path
  $found=@($acl.Access | Where-Object { $_.IsInherited -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })
  if ($found.Count -eq 0) { throw 'foreign inherited fixture not reached' }
} else {
  $acl=Get-Acl -LiteralPath $Path
  if (!$acl.AreAccessRulesProtected) { throw 'unprotected DACL' }
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'wrong owner' }
  $rules=@($acl.Access)
  if ($rules.Count -eq 0) { throw 'empty DACL' }
  foreach ($rule in $rules) {
    $who=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $who -notin @($sid.Value,'S-1-5-18')) { throw "unexpected ACE: $rule" }
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    if (($rule.FileSystemRights -band $full) -ne $full) { throw 'missing full control' }
  }
  Write-Output "outside ACL readback: owner=$($sid.Value) protected=True explicit-allow-count=$($rules.Count)"
}
"#)?;
    drop(script_file);
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .arg(&path)
        .arg(action)
        .output()?;
    fs::remove_file(&script)?;
    assert!(
        output.status.success(),
        "ACL {action}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if action == "observe" {
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
    }
    Ok(())
}
