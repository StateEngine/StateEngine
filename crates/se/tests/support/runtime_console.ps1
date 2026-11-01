# Test plumbing only: a real Windows console supplies stdin/stdout; only the
# diagnostic stream is redirected. Production native presence is unchanged.
param(
    [Parameter(Mandatory=$true)][string]$Image,
    [Parameter(Mandatory=$true)][string]$HomePath,
    [Parameter(Mandatory=$true)][ValidateSet('json','human')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [switch]$ConsoleChild
)
$ErrorActionPreference='Stop'
$stderrPath=Join-Path (Split-Path $HomePath -Parent) "$Mode-uninstall.stderr"
$exitPath=Join-Path (Split-Path $HomePath -Parent) "$Mode-uninstall.exit"
function Wait-Owned($child, [string]$expectedImage, [string]$marker, [int]$timeout=30000) {
    # Start-Process can lose ExitCode after exit unless its handle is cached.
    # Keep the actual native process resource available across the finite wait.
    $nativeHandle=$child.Handle
    if($null -eq $nativeHandle -or $nativeHandle -eq [IntPtr]::Zero) {
        throw 'Owned console child process handle is unavailable'
    }
    $birth=$child.StartTime.ToFileTimeUtc()
    if(-not $child.WaitForExit($timeout)) {
        $observed=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
        $current=Get-Process -Id $child.Id
        if($observed.ExecutablePath -eq $expectedImage -and $observed.CommandLine.Contains($marker) -and $current.StartTime.ToFileTimeUtc() -eq $birth) {
            Stop-Process -Id $child.Id
            $child.WaitForExit()
        }
        throw 'Exact runtime console fixture exceeded its deadline'
    }
    $exitCode=$child.ExitCode
    if($null -eq $exitCode) { throw 'Owned console child exit code is unavailable' }
    return [int]$exitCode
}
$powershell=Join-Path $PSHOME 'powershell.exe'
if($ConsoleChild) {
    if([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
        throw 'Runtime uninstall fixture requires a real native console'
    }
    # Exercise the identical NoNewWindow + redirected-stderr exit reader with
    # a real known-nonzero child before trusting any uninstall observation.
    $probeError=Join-Path (Split-Path $HomePath -Parent) "$Mode-exit-probe.stderr"
    $probe=Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 7') -PassThru -NoNewWindow -RedirectStandardError $probeError
    $probeCode=Wait-Owned $probe $powershell 'exit 7'
    if($probeCode -ne 7) { throw "Native exit-code control lost 7: got $probeCode" }
    $arguments=@('--home' , ('"'+$HomePath+'"'), 'uninstall')
    if($Mode -eq 'json') { $arguments=@('--json')+$arguments }
    $cli=Start-Process -FilePath $Image -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardError $stderrPath
    $code=Wait-Owned $cli $Image 'uninstall'
    [IO.File]::WriteAllText($exitPath, [string]$code)
    exit 0
}
function Literal([string]$value) { return "'"+$value.Replace("'", "''")+"'" }
$invocation="& ([ScriptBlock]::Create([IO.File]::ReadAllText($(Literal $ScriptPath)))) -Image $(Literal $Image) -HomePath $(Literal $HomePath) -Mode $Mode -ScriptPath $(Literal $ScriptPath) -ConsoleChild"
$arguments='-NoProfile -NonInteractive -Command "'+$invocation+'"'
$console=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -WindowStyle Normal
$code=Wait-Owned $console $powershell $ScriptPath 45000
if($code -ne 0) { throw "Native console fixture failed with exit $code" }
[Console]::Error.Write([IO.File]::ReadAllText($stderrPath))
$measuredExit=[IO.File]::ReadAllText($exitPath)
$nativeExit=0
if(-not [int]::TryParse($measuredExit, [ref]$nativeExit)) {
    throw "Native uninstall exit file is unreadable as an integer: [$measuredExit]"
}
exit $nativeExit
