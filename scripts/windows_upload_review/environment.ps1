param([Parameter(Mandatory)][ValidateSet('setup','shell','census','drain','cleanup')][string]$Mode,
      [Parameter(Mandatory)][string]$Root, [string]$ShellPath)
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$private = Join-Path $Root 'private'
$statePath = Join-Path $private 'environment.json'
$sshdConfig = Join-Path $env:ProgramData 'ssh/sshd_config'
$clientConfig = Join-Path $env:USERPROFILE '.ssh/config'
$reg = 'HKLM:\SOFTWARE\OpenSSH'

function Save($state) {
    [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json -Depth 8), $utf8)
}
function Protect([string]$Path, [string[]]$Sids, [string]$Owner) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sid in $Sids) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($Owner))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Census([string]$Sid) {
    if ([string]::IsNullOrWhiteSpace($Sid)) { return @() }
    # Enumerate all processes first. Account ownership, never executable name, selects cleanup.
    @(Get-CimInstance Win32_Process | ForEach-Object {
        $p = $_
        $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction SilentlyContinue
        if ($owner.Sid -eq $Sid) {
            [ordered]@{pid=$p.ProcessId;parent=$p.ParentProcessId;created=$p.CreationDate.ToString('o');command=$p.CommandLine}
        }
    })
}

if ($Mode -eq 'setup') {
    if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running') {
        throw 'Refusing to take over an already running SSH service'
    }
    if ((Test-Path $clientConfig) -and (Get-Item $clientConfig).Length -gt 0) {
        throw 'Refusing to replace an existing client SSH configuration'
    }
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    }
    New-Item -ItemType Directory -Path $private -ErrorAction Stop | Out-Null
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Protect $private @($me,'S-1-5-18','S-1-5-32-544') $me
    $user = 'upl' + [Guid]::NewGuid().ToString('N').Substring(0,10)
    $state = [ordered]@{user=$user; sid=$null; me=$me; client_existed=(Test-Path $clientConfig);
        server_existed=(Test-Path $sshdConfig); shell_existed=$false; shell_value=$null;
        shell_kind=$null; setup_complete=$false; cleanup_complete=$false}
    if ($state.server_existed) { [IO.File]::Copy($sshdConfig,(Join-Path $private 'sshd_config.original')) }
    if ($state.client_existed) { [IO.File]::Copy($clientConfig,(Join-Path $private 'client_config.original')) }
    $key = Get-Item $reg -ErrorAction SilentlyContinue
    if ($key -and ($key.GetValueNames() -contains 'DefaultShell')) {
        $state.shell_existed = $true
        $state.shell_value = $key.GetValue('DefaultShell')
        $state.shell_kind = $key.GetValueKind('DefaultShell').ToString()
    }
    Save $state
    # No password is printed, placed on a command line, or written to disk.
    $password = ConvertTo-SecureString ('Aa9!' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $account = New-LocalUser -Name $user -Password $password -PasswordNeverExpires
    $state.sid = $account.SID.Value
    Save $state
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    $clientKey = Join-Path $private 'client_key'
    $hostKey = Join-Path $private 'host_key'
    foreach ($path in @($clientKey,$hostKey)) {
        & "$env:SystemRoot/System32/OpenSSH/ssh-keygen.exe" -q -t ed25519 -N '""' -f $path
        if ($LASTEXITCODE -ne 0) { throw 'Fixture key generation failed' }
    }
    Protect $clientKey @($me,'S-1-5-18','S-1-5-32-544') $me
    Protect $hostKey @('S-1-5-18','S-1-5-32-544') 'S-1-5-32-544'
    $authorized = Join-Path $private 'authorized_keys'
    [IO.File]::WriteAllText($authorized, [IO.File]::ReadAllText($clientKey+'.pub'), $utf8)
    Protect $authorized @($state.sid,'S-1-5-18','S-1-5-32-544') $state.sid
    $known = Join-Path $private 'known_hosts'
    $public = ([IO.File]::ReadAllText($hostKey+'.pub').Trim() -split ' ')[0..1] -join ' '
    [IO.File]::WriteAllText($known, ('[127.0.0.1]:22222 '+$public+"`n"), $utf8)
    $serverText = @"
Port 22222
ListenAddress 127.0.0.1
HostKey "$($hostKey.Replace('\','/'))"
AuthorizedKeysFile "$($authorized.Replace('\','/'))"
PubkeyAuthentication yes
PasswordAuthentication no
AllowUsers $user
Subsystem sftp $env:SystemRoot/System32/OpenSSH/sftp-server.exe
LogLevel VERBOSE
"@
    New-Item -ItemType Directory -Force -Path (Split-Path $sshdConfig) | Out-Null
    [IO.File]::WriteAllText($sshdConfig,$serverText,$utf8)
    New-Item -ItemType Directory -Force -Path (Split-Path $clientConfig) | Out-Null
    $clientText = @"
Host upload-review
  HostName 127.0.0.1
  Port 22222
  User $user
  IdentityFile "$($clientKey.Replace('\','/'))"
  UserKnownHostsFile "$($known.Replace('\','/'))"
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  BatchMode yes
  ConnectTimeout 10
"@
    [IO.File]::WriteAllText($clientConfig,$clientText,$utf8)
    & "$env:SystemRoot/System32/OpenSSH/sshd.exe" -t
    if ($LASTEXITCODE -ne 0) { throw 'Invalid SSH server configuration' }
    $state.setup_complete = $true
    Save $state
    [ordered]@{user=$user;sid=$state.sid;client='native OpenSSH';port=22222} | ConvertTo-Json -Compress
    exit
}

$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
if ($Mode -eq 'cleanup' -and $state.cleanup_complete) {
    @{restored=$true;already_complete=$true;after=@()} | ConvertTo-Json -Compress
    exit
}
if ($Mode -eq 'shell') {
    if (-not (Test-Path -LiteralPath $ShellPath)) { throw 'Default shell executable absent' }
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $before = if ($service.ProcessId) {
        Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" |
            Select-Object ProcessId,CreationDate,CommandLine
    } else { $null }
    if ($before) { Stop-Service sshd; (Get-Service sshd).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20)) }
    New-Item -Path $reg -Force | Out-Null
    New-ItemProperty -Path $reg -Name DefaultShell -Value $ShellPath -PropertyType String -Force | Out-Null
    Start-Service sshd
    (Get-Service sshd).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    $afterService = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $after = Get-CimInstance Win32_Process -Filter "ProcessId=$($afterService.ProcessId)" |
        Select-Object ProcessId,CreationDate,CommandLine
    [ordered]@{shell=$ShellPath;previous_service=$before;current_service=$after} | ConvertTo-Json -Depth 6 -Compress
    exit
}
if ($Mode -eq 'census') {
    ConvertTo-Json -InputObject @(Census $state.sid) -Depth 6 -Compress
    exit
}
if ($Mode -eq 'drain') {
    $pins = @(Census $state.sid)
    foreach ($pin in $pins) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($pin.pid)"
        if ($p -and $p.CreationDate.ToString('o') -eq $pin.created -and $p.CommandLine -eq $pin.command) {
            Stop-Process -Id $pin.pid -Force
        }
    }
    [ordered]@{before=$pins;after=@(Census $state.sid)} | ConvertTo-Json -Depth 6 -Compress
    exit
}

$before = @(Census $state.sid)
$service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
$serviceProcess = if ($service.ProcessId) {
    Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" |
        Select-Object ProcessId,CreationDate,CommandLine
} else { $null }
if ((Get-Service sshd).Status -ne 'Stopped') {
    Stop-Service sshd
    (Get-Service sshd).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
}
foreach ($pin in $before) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($pin.pid)"
    if ($p -and $p.CreationDate.ToString('o') -eq $pin.created -and $p.CommandLine -eq $pin.command) {
        Stop-Process -Id $pin.pid -Force
    }
}
$after = @(Census $state.sid)
if ($after.Count) { throw 'Fixture account processes survived exact-identity cleanup' }
if ($state.server_existed) { [IO.File]::Copy((Join-Path $private 'sshd_config.original'),$sshdConfig,$true) }
else { Remove-Item -LiteralPath $sshdConfig -ErrorAction SilentlyContinue }
if ($state.client_existed) { [IO.File]::Copy((Join-Path $private 'client_config.original'),$clientConfig,$true) }
else { Remove-Item -LiteralPath $clientConfig -ErrorAction SilentlyContinue }
if ($state.shell_existed) {
    New-ItemProperty -Path $reg -Name DefaultShell -Value $state.shell_value -PropertyType $state.shell_kind -Force | Out-Null
} else { Remove-ItemProperty -Path $reg -Name DefaultShell -ErrorAction SilentlyContinue }
if ($state.sid) {
    $account = Get-LocalUser -SID $state.sid -ErrorAction SilentlyContinue
    if ($account) { Remove-LocalUser -SID $state.sid }
    $profile = Get-CimInstance Win32_UserProfile | Where-Object SID -eq $state.sid
    if ($profile) { $profile | Remove-CimInstance }
}
$state.cleanup_complete=$true
Save $state
[ordered]@{before=$before;after=$after;stopped_service=$serviceProcess;service_status=(Get-Service sshd).Status.ToString();restored=$true} | ConvertTo-Json -Depth 8 -Compress
