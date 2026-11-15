$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rows = @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    if (-not $_.Name) { throw 'Native process image name is unreadable' }
    $owner = 'not-needed'
    if ($_.Name -ieq 'se.exe' -and -not $_.ExecutablePath) {
        $owner = 'unreadable'
        try {
            $result = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
            if ($result.ReturnValue -eq 0 -and $result.Sid) {
                $owner = if ($result.Sid -eq $currentSid) { 'current-user' } else { 'foreign' }
            }
        } catch { $owner = 'unreadable' }
    }
    @{
        pid = [int]$_.ProcessId
        parent = [int]$_.ParentProcessId
        birth = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        name = $_.Name
        image = $_.ExecutablePath
        command = if ($_.Name -ieq 'se.exe') { $_.CommandLine } else { $null }
        owner_state = $owner
        rss_bytes = if ($null -ne $_.WorkingSetSize) { [long]$_.WorkingSetSize } else { $null }
        state = 'live'
    }
})
ConvertTo-Json -InputObject @{coverage='complete'; rows=$rows} -Depth 5 -Compress
