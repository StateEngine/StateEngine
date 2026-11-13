$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rows = @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    $attribution = 'not-required'
    if (-not $_.CommandLine -and $_.ProcessId -gt 4) {
        $attribution = 'unreadable'
        try {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
            if ($owner.ReturnValue -eq 0 -and $owner.Sid) {
                $attribution = if ($owner.Sid -eq $currentSid) { 'current-user' } else { 'foreign' }
            }
        } catch { $attribution = 'unreadable' }
    }
    @{
        pid = [int]$_.ProcessId
        parent = [int]$_.ParentProcessId
        birth = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        state = 'live'
        command = $_.CommandLine
        owner_state = $attribution
    }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
