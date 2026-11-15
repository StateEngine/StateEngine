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
  if ($observed -ne $expected) {
    throw ('Exact DACL restoration was not witnessed: expected '+$expected+' observed '+$observed)
  }
} else {
  throw 'Unknown fixture security action'
}
