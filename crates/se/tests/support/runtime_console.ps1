# Test plumbing only: a real Windows console supplies stdin/stdout; only the
# diagnostic stream is redirected. Read the owned console buffer afterward so
# native stdout remains a real console and failures retain their actual verdict.
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
$stdoutPath=Join-Path (Split-Path $HomePath -Parent) "$Mode-uninstall.console"
function Read-OwnedConsole {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class RuntimeConsoleReadback {
    [StructLayout(LayoutKind.Sequential)] struct Coord { public short X, Y; }
    [StructLayout(LayoutKind.Sequential)] struct Rect { public short Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public Coord Size, Cursor; public short Attributes; public Rect Window; public Coord Maximum;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetConsoleScreenBufferInfo(IntPtr handle, out Info info);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool ReadConsoleOutputCharacterW(IntPtr handle, StringBuilder text, uint length, Coord start, out uint read);
    public static string Read() {
        IntPtr handle=GetStdHandle(-11); Info info;
        if(!GetConsoleScreenBufferInfo(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        int width=info.Size.X;
        if(width<=0 || info.Cursor.Y<0) throw new InvalidOperationException("Owned console dimensions unavailable");
        int rows=Math.Min(info.Cursor.Y+1, Math.Max(1, 131072/width));
        Coord start=new Coord { X=0, Y=(short)(info.Cursor.Y+1-rows) };
        int length=checked(rows*width); uint read;
        StringBuilder buffer=new StringBuilder(length);
        if(!ReadConsoleOutputCharacterW(handle, buffer, (uint)length, start, out read)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if(read!=(uint)length) throw new InvalidOperationException("Owned console readback was incomplete");
        string text=buffer.ToString(); StringBuilder lines=new StringBuilder();
        for(int at=0;at<text.Length;at+=width) lines.AppendLine(text.Substring(at, Math.Min(width,text.Length-at)).TrimEnd());
        return lines.ToString();
    }
}
'@
    return [RuntimeConsoleReadback]::Read()
}
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
    [Console]::WriteLine('Runtime uninstall owned console readback control')
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
    $consoleText=Read-OwnedConsole
    if(-not $consoleText.Contains('Runtime uninstall owned console readback control')) {
        throw 'Owned console output readback lost its control marker'
    }
    [IO.File]::WriteAllText($stdoutPath, $consoleText, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($exitPath, [string]$code)
    exit 0
}
function Literal([string]$value) { return "'"+$value.Replace("'", "''")+"'" }
$invocation="& ([ScriptBlock]::Create([IO.File]::ReadAllText($(Literal $ScriptPath)))) -Image $(Literal $Image) -HomePath $(Literal $HomePath) -Mode $Mode -ScriptPath $(Literal $ScriptPath) -ConsoleChild"
$arguments='-NoProfile -NonInteractive -Command "'+$invocation+'"'
$console=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -WindowStyle Normal
$code=Wait-Owned $console $powershell $ScriptPath 45000
if($code -ne 0) { throw "Native console fixture failed with exit $code" }
[Console]::Out.Write([IO.File]::ReadAllText($stdoutPath))
[Console]::Error.Write([IO.File]::ReadAllText($stderrPath))
$measuredExit=[IO.File]::ReadAllText($exitPath)
$nativeExit=0
if(-not [int]::TryParse($measuredExit, [ref]$nativeExit)) {
    throw "Native uninstall exit file is unreadable as an integer: [$measuredExit]"
}
exit $nativeExit
