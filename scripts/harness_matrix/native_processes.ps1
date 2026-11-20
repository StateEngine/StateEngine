$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rows = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object {
    $attribution = 'not-required'
    $state = 'live'
    $command = $_.CommandLine
    if (-not $_.CommandLine -and $_.ProcessId -gt 4) {
        $attribution = 'unreadable'
        try {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
            if ($owner.ReturnValue -eq 0 -and $owner.Sid) {
                $attribution = if ($owner.Sid -eq $currentSid) { 'current-user' } else { 'foreign' }
            }
        } catch { $attribution = 'unreadable' }
        if ($attribution -in @('current-user', 'unreadable')) {
            # The process can exit between enumeration and its owner query.
            # Only a second native read can distinguish that from missing access.
            $again = @(Get-CimInstance Win32_Process -Filter "ProcessId = $($_.ProcessId)" -ErrorAction Stop)
            if ($again.Count -eq 0 -or ($again.Count -eq 1 -and $again[0].CreationDate -ne $_.CreationDate)) {
                $attribution = 'exited'
                $state = 'X'
            } elseif ($again.Count -eq 1 -and $again[0].CommandLine) {
                $attribution = 'not-required'
                $command = $again[0].CommandLine
            }
        }
    }
    @{
        pid = [int]$_.ProcessId
        parent = [int]$_.ParentProcessId
        birth = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        state = $state
        command = $command
        exe = $_.ExecutablePath
        owner_state = $attribution
    }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
