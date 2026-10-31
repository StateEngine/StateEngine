# The installed native operation owns the plan, graceful stop, removal and readback.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    if ($env:OS -ne 'Windows_NT') { throw 'this script requires Windows' }
    $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'StateEngine'))
    $binary = Join-Path $root 'bin\se.exe'
    $record = Join-Path $root 'bin\install.json'
    foreach ($path in @($binary, $record)) {
        $part = [IO.Path]::GetFullPath($path)
        while ($part) {
            if ([IO.File]::Exists($part) -or [IO.Directory]::Exists($part)) {
                if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "linked installation path is preserved: $part"
                }
            }
            $part = [IO.Path]::GetDirectoryName($part)
        }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.files.'se.exe'.sha256 -ne (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'installed se differs from this archive; invoke the current installed se uninstall instead'
    }
} catch {
    [Console]::Error.WriteLine("Uninstall refused: $($_.Exception.Message)")
    exit 1
}
& $binary uninstall @args
exit $LASTEXITCODE
