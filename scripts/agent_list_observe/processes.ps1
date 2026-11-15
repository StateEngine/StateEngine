$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$known = @{}
foreach ($binding in $request.known) { $known[([string]$binding.pid + '|' + $binding.birth)] = $true }
$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$family = [Collections.Generic.HashSet[int]]::new()
$births = @{}
$prefix = [string]$request.home + '\'
foreach ($process in $processes) {
    $births[[int]$process.ProcessId] = $process.CreationDate
    $birth = if ($process.CreationDate) { $process.CreationDate.ToUniversalTime().ToString('o') } else { '' }
    $retained = $known.ContainsKey(([string]$process.ProcessId + '|' + $birth))
    $private = $process.ExecutablePath -and $process.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    if ($retained -or $private) { [void]$family.Add([int]$process.ProcessId) }
}
do {
    $changed = $false
    foreach ($process in $processes) {
        # Parent PIDs outlive their original parent in native snapshots. An
        # older process cannot descend from a newer reuse of that parent PID.
        $parentBirth = $births[[int]$process.ParentProcessId]
        $possibleChild = -not $process.CreationDate -or -not $parentBirth -or $process.CreationDate -ge $parentBirth
        if ($family.Contains([int]$process.ParentProcessId) -and $possibleChild -and $family.Add([int]$process.ProcessId)) { $changed = $true }
    }
} while ($changed)
$rows = @($processes | ForEach-Object {
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
        command = if ($family.Contains([int]$_.ProcessId)) { $_.CommandLine } else { $null }
        owner_state = $owner
        rss_bytes = if ($null -ne $_.WorkingSetSize) { [long]$_.WorkingSetSize } else { $null }
        state = 'live'
    }
})
ConvertTo-Json -InputObject @{coverage='complete'; rows=$rows} -Depth 5 -Compress
