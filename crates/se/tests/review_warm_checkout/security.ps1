param([string]$Path,[string]$Saved,[string]$Action)
$ErrorActionPreference='Stop'
$sections=[System.Security.AccessControl.AccessControlSections]'Access,Owner,Group'
if ($Action -eq 'loosen') {
  $before=Get-Acl -LiteralPath $Path
  [IO.File]::WriteAllText($Saved,$before.GetSecurityDescriptorSddlForm($sections))
  $null=& icacls.exe $Path '/grant' '*S-1-1-0:R' '/q'
  if ($LASTEXITCODE -ne 0) { throw 'Fixture DACL change failed' }
  $after=Get-Acl -LiteralPath $Path
  if ($after.GetSecurityDescriptorSddlForm($sections) -eq [IO.File]::ReadAllText($Saved)) {
    throw 'DACL drift was not witnessed'
  }
} elseif ($Action -eq 'restore') {
  $expected=[IO.File]::ReadAllText($Saved)
  $acl=Get-Acl -LiteralPath $Path
  $acl.SetSecurityDescriptorSddlForm($expected,$sections)
  Set-Acl -LiteralPath $Path -AclObject $acl
  if ((Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($sections) -ne $expected) {
    throw 'Exact DACL restoration was not witnessed'
  }
} else {
  throw 'Unknown fixture security action'
}
