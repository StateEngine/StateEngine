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
    $child.Refresh()
    return $child.ExitCode
}
if($ConsoleChild) {
    if([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
        throw 'Runtime uninstall fixture requires a real native console'
    }
    $arguments=@('--home', ('"'+$HomePath+'"'), 'uninstall')
    if($Mode -eq 'json') { $arguments=@('--json')+$arguments }
    $cli=Start-Process -FilePath $Image -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardError $stderrPath
    $code=Wait-Owned $cli $Image 'uninstall'
    [IO.File]::WriteAllText($exitPath, [string]$code)
    exit 0
}
$powershell=Join-Path $PSHOME 'powershell.exe'
function Literal([string]$value) { return "'"+$value.Replace("'", "''")+"'" }
$invocation="& ([ScriptBlock]::Create([IO.File]::ReadAllText($(Literal $ScriptPath)))) -Image $(Literal $Image) -HomePath $(Literal $HomePath) -Mode $Mode -ScriptPath $(Literal $ScriptPath) -ConsoleChild"
$arguments='-NoProfile -NonInteractive -Command "'+$invocation+'"'
$console=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -WindowStyle Normal
$code=Wait-Owned $console $powershell $ScriptPath 45000
if($code -ne 0) { throw "Native console fixture failed with exit $code" }
[Console]::Error.Write([IO.File]::ReadAllText($stderrPath))
exit ([int][IO.File]::ReadAllText($exitPath))
