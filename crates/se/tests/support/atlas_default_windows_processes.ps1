$ErrorActionPreference = 'Stop'
$source = 'AtlasReviewProcessStart'
$root = $env:ATLAS_REVIEW_TRACE_DIR
$image = $env:ATLAS_REVIEW_IMAGE_NAME
$pending = Join-Path $root 'trace-pending'
$finish = Join-Path $root 'trace-finish'
Register-CimIndicationEvent -Namespace 'root/cimv2' -SourceIdentifier $source `
    -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = '$image'" | Out-Null
try {
    New-Item -Path $pending -ItemType File | Out-Null
    $end = [DateTime]::UtcNow.AddSeconds(45)
    while (!(Test-Path -LiteralPath $finish)) {
        if ([DateTime]::UtcNow -ge $end) { throw 'Process-start trace did not receive a finish marker' }
        Start-Sleep -Milliseconds 50
    }
    Start-Sleep -Milliseconds 400
    $records = @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | ForEach-Object {
        $e = $_.SourceEventArgs.NewEvent
        [ordered]@{
            name = [string]$e.ProcessName
            pid = [uint32]$e.ProcessId
            parent_pid = [uint32]$e.ParentProcessId
        }
    })
    ConvertTo-Json -InputObject $records -Compress
} finally {
    Unregister-Event -SourceIdentifier $source
}
