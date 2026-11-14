param([string]$Root)
$ErrorActionPreference='Stop'
$p=Get-Content -LiteralPath (Join-Path $Root 'payload.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$taskProfile=[Environment]::GetFolderPath('UserProfile')
if (-not $taskProfile.Contains('Ω') -or -not $taskProfile.Contains('测') -or -not $taskProfile.Contains(' ')) {throw 'OS-created profile lacks required characters'}
if ($HOME -ne $taskProfile) {throw 'PowerShell native profile differs from the OS profile'}
$shells=@()
foreach ($shell in @('cmd','powershell')) {
    foreach ($step in @('prepare','receive','verify_upload','publish','verify','remove_upload','remove_image')) {
        $command=$p.$step
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName=if($shell -eq 'cmd') {(Get-Command cmd.exe).Source} else {(Get-Command powershell.exe).Source}
        $info.Arguments=if($shell -eq 'cmd') {'/d /s /c '+$command} else {'-NoProfile -NonInteractive -Command '+$command}
        $info.UseShellExecute=$false
        $info.RedirectStandardInput=$true
        $info.RedirectStandardOutput=$true
        $info.RedirectStandardError=$true
        $child=[Diagnostics.Process]::new()
        $child.StartInfo=$info
        if (-not $child.Start()) {throw 'owned native shell did not start'}
        $out=$child.StandardOutput.ReadToEndAsync()
        $err=$child.StandardError.ReadToEndAsync()
        if ($step -eq 'receive') {
            $bytes=[Convert]::FromBase64String($p.bytes)
            $child.StandardInput.BaseStream.Write($bytes,0,$bytes.Length)
        }
        $child.StandardInput.Close()
        if (-not $child.WaitForExit(15000)) {
            $observed=Get-CimInstance Win32_Process -Filter ('ProcessId='+$child.Id)
            if ($observed.ExecutablePath -ne $info.FileName -or -not $observed.CommandLine.Contains('-EncodedCommand')) {throw 'owned shell identity unreadable'}
            $child.Kill(); $child.WaitForExit(); throw 'owned native shell exceeded bound'
        }
        if ($child.ExitCode -ne 0) {throw ($shell+' '+$step+' refused: '+$err.Result)}
        if ($out.Result.Length -gt 65536 -or $err.Result.Length -gt 65536) {throw 'native shell output exceeded bound'}
        $child.Dispose()
    }
    if (Test-Path -LiteralPath (Join-Path $HOME $p.image)) {throw 'published fixture image remains'}
    if (Test-Path -LiteralPath (Join-Path $HOME $p.upload)) {throw 'owned fixture upload remains'}
    $shells+=@{shell=$shell;passed=$true}
}
$report=@{profile=$taskProfile;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;shells=$shells}
[IO.File]::WriteAllText((Join-Path $Root 'result.json'),($report|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
