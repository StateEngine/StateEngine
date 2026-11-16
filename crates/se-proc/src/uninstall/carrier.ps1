# Fixed finalizer: native Rust owns all original installation effects. Only
# newly created, protected staging artifacts may be retired by this interpreter.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$inputStream = [Console]::OpenStandardInput()
$reader = [IO.StreamReader]::new($inputStream, [Text.UTF8Encoding]::new($false, $true))
try {
    $buffer = New-Object char[] ((2 * 1024 * 1024) + 1)
    $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
    if ($count -eq 0) { exit 78 } # Execution-policy admission, without targets.
    if ($count -gt (2 * 1024 * 1024)) { throw 'private envelope exceeds two MiB' }
    $frame = [string]::new($buffer, 0, $count) | ConvertFrom-Json
} finally { $reader.Dispose() }
if ($frame.nonce -cnotmatch '^[0-9a-f]{64}$' -or
    $frame.pipe -cne ('se-uninstall-private-' + $frame.nonce)) { throw 'private nonce differs' }
Initialize-CleanupNative
$clock = [Diagnostics.Stopwatch]::StartNew()
function Remaining {
    $left = 90000 - $clock.ElapsedMilliseconds
    if ($left -le 0) { throw 'private cleanup deadline exhausted' }
    return [int]$left
}
function Private-Stream($handle, [IO.FileAccess]$access) {
    $safe = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr][long]$handle, $false)
    return [IO.FileStream]::new($safe, $access)
}
function Read-Envelope($handle) {
    $stream = Private-Stream $handle ([IO.FileAccess]::Read)
    try {
        $null = $stream.Seek(0, [IO.SeekOrigin]::Begin)
        if ($stream.Length -gt (2 * 1024 * 1024)) { throw 'private report exceeds two MiB' }
        $text = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true))
        try { return ($text.ReadToEnd() | ConvertFrom-Json) } finally { $text.Dispose() }
    } finally { $stream.Dispose() }
}
function Absent([string]$path) {
    try { $null = [IO.File]::GetAttributes($path); return $false }
    catch [IO.FileNotFoundException] { return $true }
    catch [IO.DirectoryNotFoundException] { return $true }
}
$child = [Threading.ManualResetEvent]::new($false)
$child.SafeWaitHandle = [Microsoft.Win32.SafeHandles.SafeWaitHandle]::new([IntPtr][long]$frame.process, $false)
# Retain the account-wide claim through final cleanup and completion delivery.
$claim = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr][long]$frame.claim, $false)
$server = $null
$reply = $null
$authorization = $null
$failure = $null
try {
    # The random private endpoint exists before readiness. Only this account may
    # connect; the Rust writer also uses identification-only SQOS and a nonce.
    $security = [IO.Pipes.PipeSecurity]::new()
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($sid,
        [IO.Pipes.PipeAccessRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
    $server = [IO.Pipes.NamedPipeServerStream]::new($frame.pipe, [IO.Pipes.PipeDirection]::In, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 4096, 4096, $security)
    $connection = $server.WaitForConnectionAsync()
    $ready = Private-Stream $frame.ready ([IO.FileAccess]::Write)
    try {
        $ack = New-Object byte[] 33
        $ack[0] = 82
        for ($index = 0; $index -lt 32; $index++) {
            $ack[$index + 1] = [Convert]::ToByte($frame.nonce.Substring($index * 2, 2), 16)
        }
        $ready.Write($ack, 0, $ack.Length)
        $ready.Flush()
    } finally { $ready.Dispose() }
    while (-not $connection.Wait(20)) {
        $null = Remaining
        if ($child.WaitOne(0)) { throw 'native carrier exited without a private completion' }
    }
    $bytes = [IO.MemoryStream]::new()
    try {
        $chunk = New-Object byte[] 4096
        while ($true) {
            $read = $server.ReadAsync($chunk, 0, $chunk.Length)
            if (-not $read.Wait((Remaining))) { throw 'private completion read deadline' }
            if ($read.Result -eq 0) { break }
            $bytes.Write($chunk, 0, $read.Result)
            if ($bytes.Length -gt (2 * 1024 * 1024)) { throw 'private completion exceeds two MiB' }
        }
        $reply = [Text.UTF8Encoding]::new($false, $true).GetString($bytes.ToArray()) | ConvertFrom-Json
    } finally { $bytes.Dispose() }
    if ($reply.schema -cne 'se.uninstall-completion/v2' -or $reply.token -cne $frame.nonce -or
        $reply.image -cne $frame.image -or $reply.record -cne $frame.record -or $reply.complete -isnot [bool]) {
        throw 'private completion does not match admitted installation'
    }
} catch { $failure = $_.Exception.Message }
finally { if ($null -ne $server) { $server.Dispose() } }
# Read before waiting: a large private completion must not block child exit.
try {
    if (-not $child.WaitOne((Remaining))) { throw 'exact native carrier exit unwitnessed' }
    $authorization = Read-Envelope $frame.report
    if ($authorization.nonce -cne $frame.nonce) { throw 'private authorization differs' }
} catch {
    $failure = "$failure; $($_.Exception.Message)"
    $authorization = $null
}
try {
    # These exact random staging names and object pins came from the inherited
    # private envelope, never from the public completion endpoint.
    if ([IO.Path]::GetFileName($frame.copy) -cnotmatch '^\.se-stage-[0-9a-f]{32}\.exe$' -or
        [IO.Path]::GetFileName($frame.journal) -cne 'uninstall-helper-cleanup.json') {
        throw 'invalid private cleanup inventory'
    }
    Retire-Pin $frame.copy_handle $frame.copy
    if ($null -ne $frame.directory) {
        Retire-Directory $frame.directory $frame.directory_id
    }
    # Retire debt last: any failed copy/directory cleanup remains discoverable.
    Retire-Pin $frame.journal_handle $frame.journal
} catch { $failure = "$failure; $($_.Exception.Message); cleanup custody $($frame.journal); private copy $($frame.copy); private directory $($frame.directory)" }
try {
    if ($null -ne $authorization -and $null -ne $authorization.report.completion) {
        $completion = $authorization.report.completion
        if ($completion.pipe -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or
            $completion.token -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid output-only completion endpoint' }
        if ($null -eq $reply) {
            $reply = [pscustomobject]@{schema='se.uninstall-completion/v2';token=$completion.token;
                complete=$false;error='native completion absent';image=$frame.image;record=$frame.record;
                helper=$frame.copy;directory=$frame.directory;achieved=$authorization.report.achieved}
        }
        $reply.token = $completion.token
        $reply.helper = $frame.copy
        $reply.directory = $frame.directory
        if ($failure) { $reply.complete = $false; $reply.error = "$($reply.error); $failure" }
        $channel = [IO.Pipes.NamedPipeClientStream]::new('.', $completion.pipe, [IO.Pipes.PipeDirection]::Out,
            [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Identification)
        try {
            $channel.Connect(5000)
            $encoded = [Text.Encoding]::UTF8.GetBytes(($reply | ConvertTo-Json -Depth 64 -Compress) + "`n")
            if ($encoded.Length -gt (2 * 1024 * 1024)) { throw 'final completion exceeds two MiB' }
            $channel.Write($encoded, 0, $encoded.Length)
            $channel.Flush()
        } finally { $channel.Dispose() }
    }
} catch { $failure = "$failure; $($_.Exception.Message)" }
[GC]::KeepAlive($claim)
$child.Dispose()
if ($failure -or $null -eq $reply -or -not $reply.complete) {
    [Console]::Error.WriteLine("Uninstall incomplete: $failure; cleanup custody $($frame.journal); private copy $($frame.copy)")
    exit 78
}
exit 0
