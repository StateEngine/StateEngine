param([string]$Path,[string]$Saved,[string]$Action)
$ErrorActionPreference='Stop'
$sections=[System.Security.AccessControl.AccessControlSections]'Access,Owner,Group'
if ($Action -eq 'loosen') {
  $before=Get-Acl -LiteralPath $Path
  [IO.File]::WriteAllText($Saved,$before.GetSecurityDescriptorSddlForm($sections))
  $null=& icacls.exe $Path '/save' ($Saved+'.acl') '/q'
  if ($LASTEXITCODE -ne 0) { throw 'Fixture DACL save failed' }
  $null=& icacls.exe $Path '/grant' '*S-1-1-0:R' '/q'
  if ($LASTEXITCODE -ne 0) { throw 'Fixture DACL change failed' }
  $after=Get-Acl -LiteralPath $Path
  if ($after.GetSecurityDescriptorSddlForm($sections) -eq [IO.File]::ReadAllText($Saved)) {
    throw 'DACL drift was not witnessed'
  }
} elseif ($Action -eq 'restore') {
  $expected=[IO.File]::ReadAllText($Saved)
  $parent=Split-Path -Parent $Path
  $null=& icacls.exe $parent '/restore' ($Saved+'.acl') '/q'
  if ($LASTEXITCODE -ne 0) { throw 'Fixture DACL restore failed' }
  $observed=(Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($sections)
  $normalized=$false
  if ($observed -ne $expected) {
    $before=[System.Security.AccessControl.RawSecurityDescriptor]::new($expected)
    $after=[System.Security.AccessControl.RawSecurityDescriptor]::new($observed)
    $auto=[int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
    $protected=[int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if (([int]$before.ControlFlags -band $protected) -eq 0 -or
        (([int]$after.ControlFlags -bxor [int]$before.ControlFlags) -ne $auto) -or
        (([int]$after.ControlFlags -band $auto) -eq 0)) {
      throw ('Restored security flags changed: expected '+$expected+' observed '+$observed)
    }
    # Compare in memory only: Windows may add this flag while retaining the
    # protected ACL. Owner, group, every ACE and all other flags must match.
    $after.SetFlags($before.ControlFlags)
    if ($after.GetSddlForm($sections) -ne $before.GetSddlForm($sections)) {
      throw ('Restored security access changed: expected '+$expected+' observed '+$observed)
    }
    $normalized=$true
  }
  @{protected_access_restored=$true;dacl_auto_inherited_added=$normalized} | ConvertTo-Json -Compress
} else {
  throw 'Unknown fixture security action'
}
