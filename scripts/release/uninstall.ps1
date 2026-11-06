# The installed native operation owns the plan, graceful stop, removal and readback.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# A PowerShell 7 parent exports a PSModulePath that Windows PowerShell 5.1
# cannot autoload from; restore the 5.1 system module directory.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetEnvironmentVariable('WINDIR'), 'System32', 'WindowsPowerShell', 'v1.0', 'Modules')
function Get-Digest([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try { ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}
try {
    if ($env:OS -ne 'Windows_NT') { throw 'this script requires Windows' }
    $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'StateEngine'))
    $binary = Join-Path $root 'bin\se.exe'
    # Match Bootstrap::state_home: an explicit --home wins over SE_HOME,
    # including an environment value that would be invalid if selected.
    $selectedHome = [Environment]::GetEnvironmentVariable('SE_HOME')
    if ($null -eq $selectedHome) { $selectedHome = $root }
    $homeFlagSeen = $false
    for ($index = 0; $index -lt $args.Count; $index++) {
        $argument = [string]$args[$index]
        if ($argument -ceq '--') { break }
        if ($argument -ceq '--home' -or $argument.StartsWith('--home=', [StringComparison]::Ordinal)) {
            if ($homeFlagSeen) { throw '--home may be specified only once' }
            $homeFlagSeen = $true
            if ($argument -ceq '--home') {
                $index++
                if ($index -ge $args.Count) { throw '--home requires a directory' }
                $selectedHome = [string]$args[$index]
            } else { $selectedHome = $argument.Substring(7) }
        }
    }
    if ([string]::IsNullOrEmpty($selectedHome)) { throw 'selected state home must name a directory' }
    # Native CLI relative homes resolve from the PowerShell command's filesystem
    # location, which can differ from .NET's process-wide current directory.
    if (-not [IO.Path]::IsPathRooted($selectedHome)) {
        $selectedHome = Join-Path $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath $selectedHome
    }
    $data = [IO.Path]::GetFullPath($selectedHome)
    $record = Join-Path $data 'standalone-install.json'
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
    $runner = $binary
    $imageAbsent = $false
    try { $null = [IO.File]::GetAttributes($binary) }
    catch [IO.FileNotFoundException] { $imageAbsent = $true }
    catch [IO.DirectoryNotFoundException] { $imageAbsent = $true }
    if ($imageAbsent) {
        # A working newer archive can recover an absent/quarantined image. The
        # native owner command still validates the retained record and custody;
        # this selection grants no removal authority or absence proof.
        $runner = Join-Path $PSScriptRoot 'se.exe'
        if ($manifest.files.'se.exe'.sha256 -cne (Get-Digest $runner)) { throw 'recovery archive image differs from its manifest' }
        [Console]::Error.WriteLine('Installed se.exe is absent, possibly quarantined by security software. Using this archive for owner-authorized leftover cleanup; retained history, configuration and provider login are preserved.')
    } elseif ($manifest.files.'se.exe'.sha256 -cne (Get-Digest $binary)) {
        throw 'installed se differs from this archive; invoke the current installed se uninstall instead'
    }
} catch {
    [Console]::Error.WriteLine("Uninstall refused: $($_.Exception.Message)")
    exit 1
}

# Keep the native invocation on the caller's console. Capturing its stdout to
# learn about the helper would remove the human-terminal evidence it requires.
# This random output-only channel cannot authorize uninstall or choose a target.
$pipe = $null
$achieved = $null
$oldPipe = $env:SE_UNINSTALL_COMPLETION_PIPE
$oldToken = $env:SE_UNINSTALL_COMPLETION_TOKEN
try {
    $name = 'stateengine-uninstall-' + [Guid]::NewGuid().ToString('N')
    $secret = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
    $token = [BitConverter]::ToString($secret).Replace('-', '').ToLowerInvariant()
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($name, [IO.Pipes.PipeDirection]::In, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
    $connected = $pipe.WaitForConnectionAsync()
    $env:SE_UNINSTALL_COMPLETION_PIPE = $name
    $env:SE_UNINSTALL_COMPLETION_TOKEN = $token
    & $runner uninstall @args
    $code = $LASTEXITCODE
    if ($code -ne 75) { exit $code }

    $clock = [Diagnostics.Stopwatch]::StartNew()
    function Await-CompletionTask($task) {
        $remaining = 45000 - $clock.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $task.Wait([int]$remaining)) {
            throw 'helper completion deadline exhausted; the final uninstall outcome is unknown'
        }
    }
    Await-CompletionTask $connected
    $bytes = [IO.MemoryStream]::new()
    try {
        $buffer = New-Object byte[] 4096
        while ($true) {
            $read = $pipe.ReadAsync($buffer, 0, $buffer.Length)
            Await-CompletionTask $read
            if ($read.Result -eq 0) { break }
            $bytes.Write($buffer, 0, $read.Result)
            if ($bytes.Length -gt (2 * 1024 * 1024)) { throw 'helper completion reply exceeds its bound' }
        }
        if ($bytes.Length -eq 0) { throw 'helper channel closed without a completion verdict' }
        $reply = [Text.Encoding]::UTF8.GetString($bytes.ToArray()) | ConvertFrom-Json
    } finally { $bytes.Dispose() }
    if ($reply.schema -cnotin @('se.uninstall-completion/v1','se.uninstall-completion/v2') -or $reply.token -cne $token) {
        throw 'helper completion reply does not match this invocation'
    }
    if ($null -ne $reply.PSObject.Properties['achieved']) { $achieved = $reply.achieved }
    if ($reply.complete -isnot [bool] -or -not $reply.complete) {
        throw "helper could not complete uninstall: $($reply.error)"
    }
    # A helper cannot witness its own mapped-image teardown. This outside reader
    # treats access errors as failures and waits for every reported name's absence.
    function Completion-Name($path) {
        if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path)) { throw 'helper reported an invalid installed path' }
        $name = [IO.Path]::GetFullPath($path)
        if ($name.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { return '\\' + $name.Substring(8) }
        if ($name.StartsWith('\\?\')) { return $name.Substring(4) }
        return $name
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals((Completion-Name $reply.image), (Completion-Name $binary)) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals((Completion-Name $reply.record), (Completion-Name $record))) {
        throw "completion reply names a different installed image or record; expected $binary and $record"
    }
    # The endpoint's claimed names cannot substitute for the entry's own targets.
    # PATH is witnessed by the native parent; this step verifies file cleanup only.
    $pending = @($binary, $record)
    if ($null -ne $reply.helper) { $pending += $reply.helper }
    if ($null -ne $reply.directory) { $pending += $reply.directory }
    foreach ($path in $pending) {
        if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path)) {
            throw 'helper reported an invalid cleanup path'
        }
        while ($true) {
            $observation = 'name is still present'
            try { $null = [IO.File]::GetAttributes($path) }
            catch [IO.FileNotFoundException] { break }
            catch [IO.DirectoryNotFoundException] { break }
            catch { $observation = $_.Exception.Message }
            if ($clock.ElapsedMilliseconds -ge 45000) {
                throw "cleanup absence was not witnessed: $path ($observation)"
            }
            Start-Sleep -Milliseconds 20
        }
    }
    if ($args -contains '--json') {
        if ($null -eq $achieved -or $achieved.schema -cne 'se.uninstall/v1') { throw 'helper completion lost the achieved uninstall report' }
        [Console]::WriteLine((@{ schema='se.uninstall-completion/v1'; complete=$true;
            image=$binary; record=$record; helper=$reply.helper; directory=$reply.directory;
            achieved=$achieved; path_witness_scope='native parent report only';
            witness='helper verdict and post-exit outside absence' } | ConvertTo-Json -Depth 64 -Compress))
    } else {
        [Console]::WriteLine('Uninstall complete (removal and cleanup verified). Retained user data is preserved.')
    }
    exit 0
} catch {
    $failure = "Uninstall incomplete: $($_.Exception.Message). Pending checks include image $binary and record $record; helper staging may be unknown if no reply arrived. Preserve reported paths and use the matching archive for recovery."
    if ($args -contains '--json') {
        [Console]::WriteLine((@{ schema='se.uninstall-completion/v1'; complete=$false; error=$failure; achieved=$achieved } | ConvertTo-Json -Depth 64 -Compress))
    }
    [Console]::Error.WriteLine($failure)
    exit 2
} finally {
    $env:SE_UNINSTALL_COMPLETION_PIPE = $oldPipe
    $env:SE_UNINSTALL_COMPLETION_TOKEN = $oldToken
    if ($null -ne $pipe) { $pipe.Dispose() }
}
